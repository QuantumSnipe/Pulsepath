#!/usr/bin/env python3
"""Pulsepath metadata-only local network collector for macOS."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import ipaddress
import io
import json
import os
import posixpath
import re
import secrets
import signal
import stat
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, asdict
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlsplit

import references
from behavior import OutboundMonitor


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
VENDOR_DIR = APP_DIR / "vendor"
LSOF = "/usr/sbin/lsof"
NETTOP = "/usr/bin/nettop"
TRACEROUTE = "/usr/sbin/traceroute"
TRACEROUTE6 = "/usr/sbin/traceroute6"
# Reverse lookups run through the Mac's resolver, so leave room beyond the
# one-second probe wait. The collector polls stay numeric.
TRACE_TIMEOUT_SECONDS = 40
MAX_JSON_BODY_BYTES = 4096

# A flow counts as currently connected only if the collector saw it within
# this many seconds; the snapshot itself retains flows for two minutes.
ACTIVE_WINDOW_SECONDS = 10

# Per-address sightings older than this are pruned so the history database
# does not grow without bound on a busy machine.
SIGHTING_RETENTION_SECONDS = 30 * 86400

# The HTTP server exposes only the interface and its basemap; everything else in
# the repository (history database, source, git metadata) stays unreachable.
STATIC_PAGE_ROUTES = {"/", "/index.html"}
STATIC_BASEMAP_ROUTE = re.compile(r"/data/[A-Za-z0-9_\-]+\.geojson")

# One token per process. Loopback and Origin checks do not stop another local
# process, or another macOS account, from calling /api/*. The token is never
# served over HTTP: run() writes it to a 0600 file in the runtime folder, and
# start.command opens the page with it in the URL fragment (#k=...), which the
# browser keeps out of requests and Referer headers. The page sends it back in
# X-Pulsepath-Token; api_token_matches compares it in constant time.
API_TOKEN = secrets.token_urlsafe(32)

# Providers' published address ranges (references/, refreshed by
# `make update-references`) and the curated networks well-known apps use. A
# range match identifies who operates the address and in what role, never
# the physical city or a hosted customer's identity.
PROVIDER_RANGES = references.ProviderRanges.load()
APP_NETWORKS = references.AppNetworks.load()

if VENDOR_DIR.exists():
    # Append so a package dropped in vendor/ cannot shadow the standard library.
    sys.path.append(str(VENDOR_DIR))


def runtime_dir() -> Path:
    """Same per-user runtime folder that start.command and stop.command use."""
    home = os.environ.get("HOME")
    if home:
        return Path(home) / "Library" / "Caches" / "Pulsepath"
    return Path(os.environ.get("TMPDIR") or "/tmp") / "Pulsepath"


def prepare_runtime_dir(directory: Path) -> Path:
    """Create or adopt the runtime folder; refuse a symlink or a foreign owner."""
    if directory.is_symlink():
        raise RuntimeError(f"{directory} is a symlink.")
    if not directory.exists():
        directory.parent.mkdir(parents=True, exist_ok=True)
        directory.mkdir(mode=0o700)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{directory} is not a directory.")
    if info.st_uid != os.getuid():
        raise RuntimeError(f"{directory} is not owned by this user.")
    os.chmod(directory, 0o700)
    return directory


def write_token_file(token: str, directory: Path | None = None) -> Path:
    """Store the session token for start.command, readable by this user only.

    The token is written to a fresh 0600 file that is renamed into place, so a
    planted file or symlink named ``token`` is replaced, never followed.
    """
    folder = prepare_runtime_dir(directory or runtime_dir())
    target = folder / "token"
    temporary = folder / f".token.{os.getpid()}.{secrets.token_hex(4)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(token)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return target


def remove_token_file(path: Path, token: str) -> None:
    """Remove the token file on shutdown if it still belongs to this process."""
    try:
        if not path.is_symlink() and hmac.compare_digest(path.read_bytes(), token.encode("ascii")):
            path.unlink()
    except OSError:
        pass


def api_token_matches(presented: str | None, token: str | None = None) -> bool:
    """Constant-time token check that never raises on odd header bytes.

    http.server decodes header values as latin-1, so any byte sequence maps to
    a str; encoding it back compares bytes instead of non-ASCII text, which
    hmac.compare_digest refuses with TypeError.
    """
    expected = (API_TOKEN if token is None else token).encode("ascii")
    if not presented:
        return False
    return hmac.compare_digest(presented.encode("latin-1", "replace"), expected)


TRACE_SCOPE_ID = re.compile(r"[A-Za-z][A-Za-z0-9]{0,15}|[0-9]{1,5}")


def trace_target_argument(target: str) -> tuple[int, str]:
    """Validate a trace target and return (IP version, argument for traceroute).

    The argument is rebuilt from the parsed address. An IPv6 zone such as
    ``%en0`` is kept only when it looks like an interface name or index, so a
    raw suffix from the flow table never reaches the probe command unchanged.
    """
    host, separator, scope = target.partition("%")
    address = ipaddress.ip_address(host)
    if not separator:
        return address.version, str(address)
    if address.version != 6 or not TRACE_SCOPE_ID.fullmatch(scope):
        raise ValueError("The trace target has an invalid interface scope.")
    return address.version, f"{address}%{scope}"


def index_script_hash(document: bytes) -> str:
    """Hash the inline script from the exact HTML snapshot being served."""
    try:
        start = document.index(b"<script>") + len(b"<script>")
        end = document.index(b"</script>", start)
        digest = hashlib.sha256(document[start:end]).digest()
        return base64.b64encode(digest).decode("ascii")
    except ValueError:
        return ""


def service_name(port: int, protocol: str) -> str:
    if protocol == "UDP" and port == 443:
        return "QUIC"
    return {
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        123: "NTP",
        443: "HTTPS",
        5222: "Messaging",
        5228: "Push service",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP development",
        8443: "HTTPS development",
    }.get(port, f"{protocol} {port}")


def split_endpoint(value: str) -> tuple[str, int] | None:
    value = value.strip()
    if value.startswith("["):
        end = value.rfind("]:")
        if end < 0:
            return None
        host, port_text = value[1:end], value[end + 2 :]
    else:
        if ":" not in value:
            return None
        host, port_text = value.rsplit(":", 1)
    try:
        return host, int(port_text)
    except ValueError:
        return None


def address_scope(host: str) -> str:
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_private:
        return "private"
    return "public"


def canonical_provider(organization: str | None) -> tuple[str, str]:
    """Return a readable provider and category without overstating service identity."""
    value = (organization or "").strip()
    normalized = value.casefold()
    known = (
        (("cloudflare",), "Cloudflare", "CDN / security edge"),
        (("amazon",), "Amazon Web Services", "Cloud / CDN network"),
        (("google",), "Google", "Cloud / application network"),
        (("facebook", "meta platforms"), "Meta", "Application network"),
        (("akamai",), "Akamai", "CDN edge network"),
        (("fastly",), "Fastly", "CDN edge network"),
        (("microsoft",), "Microsoft", "Cloud / application network"),
        (("apple",), "Apple", "Application / CDN network"),
        (("digitalocean",), "DigitalOcean", "Cloud network"),
        (("oracle",), "Oracle", "Cloud network"),
        (("github",), "GitHub", "Application network"),
    )
    for needles, name, category in known:
        if any(needle in normalized for needle in needles):
            return name, category
    return value or "Unknown network", "Autonomous network"


def network_reference(host: str | None, asn: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Return a conservative local reference match for a public edge address."""
    if not host or references.parse_address(host) is None:
        return None
    match = PROVIDER_RANGES.lookup(host)
    if match:
        # The provider published this range, so its claim beats the ASN
        # database. The name stays the canonical provider so novelty history
        # compares the same strings on both paths.
        return {
            "name": match.provider,
            "label": match.label,
            "category": match.category,
            "service_class": match.service_class,
            "tag": match.tag,
            "anycast": match.anycast,
            "location_verified": False,
            "source": f"{match.source_name} published ranges",
            "source_name": match.source_name,
            "source_published": match.published,
            "stale": match.stale,
            "as_number": (asn or {}).get("number"),
            "organization": (asn or {}).get("organization") or match.provider,
            "confidence": "reference",
        }
    if asn and asn.get("organization"):
        name, category = canonical_provider(str(asn["organization"]))
        return {
            "name": name,
            "label": f"{name} network",
            "category": category,
            "anycast": False,
            "location_verified": False,
            "source": "DB-IP ASN Lite",
            "as_number": asn.get("number"),
            "organization": asn.get("organization"),
            "confidence": "inferred",
        }
    return None


def short_owner(name: str) -> str:
    """Drop a registry suffix for prose: 'Anthropic, PBC' reads as 'Anthropic'."""
    return name.split(",", 1)[0].strip() or name


def describe_network(reference: dict[str, Any] | None) -> str:
    """Plain words for where a connection goes, for finding text."""
    reference = reference or {}
    tag = reference.get("tag")
    service_class = reference.get("service_class")
    if service_class == "hosted" and tag:
        return f"{'an' if tag[:1].upper() in 'AEIOU' else 'a'} {tag} customer"
    if service_class == "edge" and tag:
        return f"the {tag} edge"
    if service_class == "service" and tag:
        return f"{tag} services"
    name = reference.get("name")
    return short_owner(str(name)) if name else "a network with no known owner"


def join_names(names: list[str]) -> str:
    names = [short_owner(name) for name in names]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " or " + names[-1]


# Observations for one stream inside this span are one episode. The cap matches
# the outbound cooldown so a later transfer is not glued to an unrelated change.
COINCIDENCE_WINDOW_SECONDS = 30 * 60
_ANCHOR_FIELDS = (
    "process", "remote_ip", "remote_port", "protocol", "destination", "destination_key",
    "service", "provider", "location", "network", "grouping", "geo", "asn", "network_reference",
)
_MEASUREMENT_FIELDS = (
    "measured_socket_count", "bytes_out", "window_seconds", "threshold_bytes_out",
    "baseline_window_seconds", "baseline_window_count", "baseline_bytes_out",
    "consecutive_windows", "coverage", "source",
)


def _finding_kind(evidence: dict[str, Any]) -> str:
    kind = evidence.get("event_type")
    if kind in {"interface_change", "outbound_change", "unexpected_network"}:
        return str(kind)
    return "novelty"


def _finding_stream_key(evidence: dict[str, Any]) -> tuple[str, str, str, str] | None:
    """Identity shared by novelty, interface, and outbound findings for one stream."""
    process = str(evidence.get("process") or "").strip().casefold()
    reference = evidence.get("network_reference") or {}
    destination = evidence.get("destination_key") or reference.get("name") or evidence.get("remote_ip")
    destination_text = str(destination or "").strip().casefold()
    if not process or not destination_text:
        return None
    return (
        process,
        str(evidence.get("protocol") or "").upper(),
        destination_text,
        str(evidence.get("remote_port") or ""),
    )


def _signal_label(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") or {}
    kind = _finding_kind(evidence)
    if kind == "interface_change":
        previous = evidence.get("previous_network") or "previous interface"
        current = evidence.get("network") or "current interface"
        return f"{previous} → {current}"
    if kind == "outbound_change":
        amount = evidence.get("bytes_out")
        if isinstance(amount, int):
            return f"Outbound transfer · {amount} bytes"
        return "Outbound transfer"
    title = str(finding.get("title") or "New destination")
    process = str(evidence.get("process") or "")
    suffix = f" for {process}" if process else ""
    if suffix and title.endswith(suffix):
        return title[: -len(suffix)]
    return title


def _finding_signal(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence") or {}
    signal = {
        "kind": _finding_kind(evidence),
        "label": _signal_label(finding),
        "detail": finding.get("explanation") or "",
        "finding_id": finding.get("id"),
        "created_at": finding.get("created_at"),
        "severity": finding.get("severity"),
    }
    if signal["kind"] == "outbound_change":
        signal.update({field: evidence[field] for field in _MEASUREMENT_FIELDS if field in evidence})
    return signal


def _coincidence_card(members: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(members, key=lambda item: float(item.get("created_at") or 0))
    ranked = list(reversed(ordered))
    evidence: dict[str, Any] = {
        "event_type": "coincidence",
        "window_seconds": COINCIDENCE_WINDOW_SECONDS,
    }
    for field in _ANCHOR_FIELDS:
        for member in ranked:
            value = (member.get("evidence") or {}).get(field)
            if value not in (None, ""):
                evidence[field] = value
                break
    evidence["signals"] = [_finding_signal(member) for member in ordered]
    labels = [signal["label"] for signal in evidence["signals"]]
    process = evidence.get("process") or "Unknown app"
    tokens = [str(member["id"]) if member.get("id") is not None else f"#{index}" for index, member in enumerate(ordered)]
    return {
        "id": "coincidence:" + ",".join(tokens),
        "created_at": float(ranked[0].get("created_at") or 0),
        "severity": "attention" if any(member.get("severity") == "attention" for member in members) else "notice",
        "title": f"Coinciding changes for {process}",
        "explanation": (
            f"{len(labels)} observations of this stream fell within 30 minutes: "
            + "; ".join(labels)
            + ". Together they are a coincidence to review, not a malware verdict."
        ),
        "evidence": evidence,
    }


def _coincide_stream(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(members, key=lambda item: float(item.get("created_at") or 0))
    clusters: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    started = 0.0
    for finding in ordered:
        created = float(finding.get("created_at") or 0)
        if current and created - started > COINCIDENCE_WINDOW_SECONDS:
            clusters.append(current)
            current = []
        if not current:
            started = created
        current.append(finding)
    if current:
        clusters.append(current)
    presented: list[dict[str, Any]] = []
    for cluster in clusters:
        kinds = {_finding_kind(item.get("evidence") or {}) for item in cluster}
        # One detector repeating is a sequence, not reinforcement.
        presented.extend(cluster if len(kinds) < 2 else [_coincidence_card(cluster)])
    return presented


def coincide_security_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Present overlapping detector kinds for one stream as a single card.

    Stored rows stay independent. Only different kinds reinforce each other,
    and only inside one 30-minute episode. The result is a coincidence to
    review, not a verdict.
    """
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    presented: list[dict[str, Any]] = []
    for finding in findings:
        key = _finding_stream_key(finding.get("evidence") or {})
        if key is None:
            presented.append(finding)
        else:
            grouped.setdefault(key, []).append(finding)
    for members in grouped.values():
        presented.extend(_coincide_stream(members))
    presented.sort(key=lambda item: float(item.get("created_at") or 0), reverse=True)
    return presented


def enrich_security_summary(summary: dict[str, Any], locator: Any, asn_locator: Any | None = None) -> dict[str, Any]:
    """Attach current local reference data to historical findings for map previews."""
    unique_findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in summary.get("findings") or []:
        evidence = finding.get("evidence") or {}
        raw_process = str(evidence.get("process") or "Unknown app")
        normalized_process = application_name(raw_process)
        evidence["process"] = normalized_process
        if normalized_process != raw_process and str(finding.get("title") or "").endswith(raw_process):
            finding["title"] = str(finding["title"])[: -len(raw_process)] + normalized_process
        remote_ip = evidence.get("remote_ip")
        asn = asn_locator.lookup(remote_ip) if asn_locator is not None else None
        evidence["geo"] = locator.lookup(remote_ip)
        evidence["asn"] = asn
        evidence["network_reference"] = network_reference(remote_ip, asn)
        provider = (evidence.get("network_reference") or {}).get("name")
        destination_key = evidence.get("destination_key") or provider or remote_ip
        key = "|".join(
            str(part).casefold()
            for part in (
                evidence.get("process"), destination_key, evidence.get("protocol"), evidence.get("remote_port")
            )
        )
        if evidence.get("event_type") in {"interface_change", "outbound_change"}:
            key += f"|{evidence['event_type']}|{finding.get('id')}"
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)
    summary["findings"] = coincide_security_findings(unique_findings)
    summary["attention_count"] = sum(
        1 for finding in summary["findings"]
        if finding.get("severity") == "attention" and float(finding.get("created_at") or 0) >= time.time() - 86400
    )
    return summary


def investigate_address(
    value: str | None,
    locator: Any,
    asn_locator: Any,
    history: "HistoryEngine",
    active_flows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Compose every local evidence source for one IP address, or None if invalid."""
    candidate = (value or "").strip().split("%", 1)[0]
    try:
        ip = str(ipaddress.ip_address(candidate))
    except ValueError:
        return None
    asn = asn_locator.lookup(ip) if asn_locator else None
    now = time.time()

    def currently_connected(flow: dict[str, Any]) -> bool:
        # Group freshness must never make an older member endpoint look active.
        sockets = flow.get("sockets")
        candidates = sockets if sockets is not None else [flow]
        return any(
            str(socket.get("remote_ip") or "").split("%", 1)[0] == ip
            and now - float(socket.get("last_seen") or 0) <= ACTIVE_WINDOW_SECONDS
            for socket in candidates
        )

    active = [
        {key: flow.get(key) for key in ("id", "process", "protocol", "remote_port", "service", "interface", "rtt_ms")}
        for flow in active_flows
        if currently_connected(flow)
    ]
    return {
        "ip": ip,
        "scope": address_scope(ip),
        "geo": locator.lookup(ip) if locator else None,
        "asn": asn,
        "network_reference": network_reference(ip, asn),
        "active": active,
        "history": history.connections_for_ip(ip),
        "captured_at": time.time(),
    }


def flow_identity(pid: int, protocol: str, local_ip: str, local_port: int, remote_ip: str, remote_port: int) -> str:
    identity = f"{pid}|{protocol}|{local_ip}:{local_port}|{remote_ip}:{remote_port}"
    return hashlib.sha1(identity.encode("utf-8")).hexdigest()[:14]


def history_identity(
    process: str,
    protocol: str,
    remote_ip: str,
    remote_port: int,
    destination_key: str | None = None,
) -> str:
    """Stable identity for a destination even when a process PID or local port changes."""
    destination = (destination_key or remote_ip).casefold()
    identity = f"{process.strip().casefold()}|{protocol.upper()}|{destination}|{remote_port}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def application_name(process: str) -> str:
    """Collapse well-known helper process variants into a readable local app family."""
    value = process.strip() or "Unknown app"
    normalized = value.casefold()
    aliases = (
        (("codex",), "Codex"),
        (("brave browser",), "Brave Browser"),
        (("cef_server",), "CEF helper"),
        (("whatsapp",), "WhatsApp"),
        (("pycharm",), "PyCharm"),
    )
    for prefixes, name in aliases:
        if any(normalized.startswith(prefix) for prefix in prefixes):
            return name
    return value


def numeric_value(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(float(value.strip()))
    except ValueError:
        return None


def milliseconds_value(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    match = re.search(r"(\d+(?:\.\d+)?)", value)
    return float(match.group(1)) if match else None


class GeoIPLocator:
    def __init__(self) -> None:
        self.reader: Any | None = None
        self.database_path: Path | None = None
        self.error: str | None = None
        candidates = sorted(DATA_DIR.glob("dbip-city-lite-*.mmdb"), reverse=True)
        if not candidates:
            self.error = "Offline city database is not installed."
            return
        try:
            import maxminddb

            self.database_path = candidates[0]
            self.reader = maxminddb.open_database(str(self.database_path))
        except Exception as error:
            self.error = str(error)

    @property
    def available(self) -> bool:
        return self.reader is not None

    def close(self) -> None:
        if self.reader is not None:
            self.reader.close()

    def lookup(self, ip: str | None) -> dict[str, Any] | None:
        if self.reader is None or not ip:
            return None
        try:
            address = ipaddress.ip_address(ip.split("%", 1)[0])
            if not address.is_global:
                return None
            record = self.reader.get(str(address))
            if not record:
                return None
            location = record.get("location") or {}
            latitude = location.get("latitude")
            longitude = location.get("longitude")
            if latitude is None or longitude is None:
                return None
            country = record.get("country") or {}
            city = record.get("city") or {}
            subdivisions = record.get("subdivisions") or []
            subdivision = subdivisions[0] if subdivisions else {}
            return {
                "latitude": float(latitude),
                "longitude": float(longitude),
                "city": (city.get("names") or {}).get("en"),
                "subdivision": (subdivision.get("names") or {}).get("en"),
                "country": (country.get("names") or {}).get("en"),
                "country_code": country.get("iso_code"),
                "precision": "approximate city",
                "provider": "DB-IP Lite",
            }
        except Exception:
            return None


class ASNLocator:
    """Resolve network ownership from an optional local DB-IP ASN Lite database."""

    def __init__(self) -> None:
        self.reader: Any | None = None
        self.database_path: Path | None = None
        self.error: str | None = None
        candidates = sorted(DATA_DIR.glob("dbip-asn-lite-*.mmdb"), reverse=True)
        if not candidates:
            self.error = "Offline ASN database is not installed."
            return
        try:
            import maxminddb

            self.database_path = candidates[0]
            self.reader = maxminddb.open_database(str(self.database_path))
        except Exception as error:
            self.error = str(error)

    @property
    def available(self) -> bool:
        return self.reader is not None

    def close(self) -> None:
        if self.reader is not None:
            self.reader.close()

    def lookup(self, ip: str | None) -> dict[str, Any] | None:
        if self.reader is None or not ip:
            return None
        try:
            address = ipaddress.ip_address(ip.split("%", 1)[0])
            if not address.is_global:
                return None
            record = self.reader.get(str(address)) or {}
            number = record.get("autonomous_system_number")
            organization = record.get("autonomous_system_organization")
            if number is None and not organization:
                return None
            return {
                "number": int(number) if number is not None else None,
                "organization": organization,
                "provider": "DB-IP ASN Lite",
            }
        except Exception:
            return None


@dataclass
class Flow:
    id: str
    process: str
    pid: int
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    service: str
    scope: str
    first_seen: float
    last_seen: float
    interface: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    rtt_ms: float | None = None
    source: str = "lsof"
    geo: dict[str, Any] | None = None
    asn: dict[str, Any] | None = None
    network_reference: dict[str, Any] | None = None


def flow_destination_key(flow: dict[str, Any]) -> tuple[str, str]:
    """Choose the strongest available key while keeping raw endpoints inspectable."""
    reference = flow.get("network_reference") or {}
    provider = reference.get("name")
    if provider:
        # A provider's own services, its customers and its CDN edge are
        # different networks; one stream never mixes them.
        service_class = reference.get("service_class")
        suffix = f":{service_class}" if service_class else ""
        return f"provider:{str(provider).casefold()}{suffix}", "provider"
    remote_port = int(flow.get("remote_port") or 0)
    protocol = str(flow.get("protocol") or "TCP")
    service = str(flow.get("service") or service_name(remote_port, protocol))
    if remote_port not in {80, 443, 8080, 8443}:
        return f"service:{service.casefold()}", "service"
    return f"endpoint:{str(flow.get('remote_ip') or '').casefold()}", "endpoint"


def flow_group_identity(flow: dict[str, Any]) -> str:
    destination_key, _ = flow_destination_key(flow)
    identity = "|".join(
        (
            application_name(str(flow.get("process") or "Unknown")).casefold(),
            str(flow.get("protocol") or "TCP").upper(),
            str(flow.get("remote_port") or 0),
            destination_key,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:18]


def aggregate_flow_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate sockets into explainable app/provider streams."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for flow in records:
        grouped.setdefault(flow_group_identity(flow), []).append(flow)

    result: list[dict[str, Any]] = []
    for group_id, members in grouped.items():
        members.sort(key=lambda item: float(item.get("last_seen") or 0), reverse=True)
        representative = members[0]
        destination_key, grouping = flow_destination_key(representative)
        application = application_name(str(representative.get("process") or "Unknown"))
        socket_rows = [
            {
                "id": member.get("id"),
                "process": member.get("process"),
                "pid": member.get("pid"),
                "local_ip": member.get("local_ip"),
                "local_port": member.get("local_port"),
                "remote_ip": member.get("remote_ip"),
                "remote_port": member.get("remote_port"),
                "interface": member.get("interface"),
                "bytes_in": member.get("bytes_in"),
                "bytes_out": member.get("bytes_out"),
                "rtt_ms": member.get("rtt_ms"),
                "source": member.get("source"),
                "first_seen": member.get("first_seen"),
                "last_seen": member.get("last_seen"),
            }
            for member in members
        ]

        def sum_counter(name: str) -> int | None:
            values = [int(member[name]) for member in members if member.get(name) is not None]
            return sum(values) if values else None

        rtts = [float(member["rtt_ms"]) for member in members if member.get("rtt_ms") is not None]
        remote_ips = sorted({str(member.get("remote_ip")) for member in members if member.get("remote_ip")})
        interfaces = sorted({str(member.get("interface")) for member in members if member.get("interface")})
        processes = sorted({str(member.get("process")) for member in members if member.get("process")})
        locations = {
            "|".join(str(part or "") for part in (geo.get("city"), geo.get("country")))
            for geo in (member.get("geo") for member in members)
            if geo
        }
        result.append(
            {
                **representative,
                "id": f"group-{group_id}",
                "process": application,
                "processes": processes,
                "first_seen": min(float(member.get("first_seen") or 0) for member in members),
                "last_seen": max(float(member.get("last_seen") or 0) for member in members),
                "bytes_in": sum_counter("bytes_in"),
                "bytes_out": sum_counter("bytes_out"),
                "rtt_ms": sum(rtts) / len(rtts) if rtts else None,
                "interface": interfaces[0] if len(interfaces) == 1 else None,
                "interfaces": interfaces,
                "socket_count": len(members),
                "remote_ip_count": len(remote_ips),
                "remote_ips": remote_ips,
                "location_count": len(locations),
                "sockets": socket_rows,
                "trace_flow_id": representative.get("id"),
                "destination_key": destination_key,
                "grouping": grouping,
            }
        )
    result.sort(key=lambda item: float(item.get("last_seen") or 0), reverse=True)
    return result


class HistoryEngine:
    """Local-only connection history with small, explainable novelty rules."""

    def __init__(
        self,
        database_path: Path | None = None,
        learning_seconds: float = 600,
        learning_connections: int = 30,
        minimum_learning_seconds: float = 180,
    ) -> None:
        self.database_path = database_path or DATA_DIR / "pulsepath-history.sqlite3"
        directory = self.database_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        # History is private to this macOS account; keep it unreadable to other
        # local users. Creating the file at 0600 before SQLite opens it makes
        # the WAL and SHM sidecars inherit the same mode. Only the app-owned
        # data directory is locked down; a caller-chosen location keeps the
        # permissions it already has.
        if directory.resolve() == DATA_DIR.resolve():
            os.chmod(directory, 0o700)
        self.database_path.touch(mode=0o600, exist_ok=True)
        os.chmod(self.database_path, 0o600)
        self.learning_seconds = learning_seconds
        self.learning_connections = learning_connections
        self.minimum_learning_seconds = minimum_learning_seconds
        self.lock = threading.RLock()
        self.last_recorded: dict[str, float] = {}
        self.outbound_monitor = OutboundMonitor()
        self.connection = sqlite3.connect(str(self.database_path), check_same_thread=False, timeout=5)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        for suffix in ("-wal", "-shm"):
            sidecar = self.database_path.with_name(self.database_path.name + suffix)
            if sidecar.exists():
                os.chmod(sidecar, 0o600)
        self._create_schema()

    def _create_schema(self) -> None:
        with self.lock, self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connections (
                    fingerprint TEXT PRIMARY KEY,
                    process_key TEXT NOT NULL,
                    process TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    remote_ip TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    country TEXT,
                    country_code TEXT,
                    city TEXT,
                    interface_class TEXT,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    observation_count INTEGER NOT NULL DEFAULT 1,
                    last_bytes_in INTEGER,
                    last_bytes_out INTEGER,
                    average_rtt_ms REAL,
                    rtt_samples INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS connections_recent ON connections(last_seen DESC);
                CREATE INDEX IF NOT EXISTS connections_process ON connections(process_key);
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(fingerprint)
                );
                CREATE INDEX IF NOT EXISTS findings_recent ON findings(created_at DESC);
                CREATE TABLE IF NOT EXISTS expectations (
                    stream_key TEXT PRIMARY KEY,
                    process TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    destination_key TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    accepted_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ip_sightings (
                    remote_ip TEXT NOT NULL,
                    process_key TEXT NOT NULL,
                    process TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    observation_count INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (remote_ip, process_key, protocol, remote_port)
                );
                CREATE INDEX IF NOT EXISTS ip_sightings_recent ON ip_sightings(last_seen DESC);
                """
            )
            columns = {row[1] for row in self.connection.execute("PRAGMA table_info(connections)")}
            migrations = {
                "provider": "TEXT",
                "network_class": "TEXT",
                "destination_key": "TEXT",
                "grouping": "TEXT",
                "socket_count": "INTEGER NOT NULL DEFAULT 1",
                "remote_ip_count": "INTEGER NOT NULL DEFAULT 1",
            }
            for column, definition in migrations.items():
                if column not in columns:
                    self.connection.execute(f"ALTER TABLE connections ADD COLUMN {column} {definition}")
            self.connection.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES('created_at', ?)",
                ("0",),
            )
            self.connection.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES('recording', '1')"
            )
            if int(self.connection.execute("SELECT COUNT(*) FROM connections").fetchone()[0]) == 0:
                self.connection.execute("UPDATE settings SET value = '0' WHERE key = 'created_at'")

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def _setting(self, key: str, default: str) -> str:
        row = self.connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    @property
    def recording(self) -> bool:
        with self.lock:
            return self._setting("recording", "1") == "1"

    def set_recording(self, enabled: bool) -> None:
        with self.lock, self.connection:
            if enabled != (self._setting("recording", "1") == "1"):
                self.outbound_monitor.reset()
            self.connection.execute(
                "INSERT INTO settings(key, value) VALUES('recording', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                ("1" if enabled else "0",),
            )

    def clear(self) -> None:
        with self.lock, self.connection:
            self.connection.execute("DELETE FROM findings")
            self.connection.execute("DELETE FROM expectations")
            self.connection.execute("DELETE FROM connections")
            self.connection.execute("DELETE FROM ip_sightings")
            self.connection.execute(
                "INSERT INTO settings(key, value) VALUES('created_at', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                ("0",),
            )
            self.last_recorded.clear()
            self.outbound_monitor.reset()

    def enrich_network_ownership(self, asn_locator: ASNLocator) -> None:
        """Backfill non-destructive service keys for existing local history."""
        with self.lock, self.connection:
            rows = self.connection.execute(
                "SELECT fingerprint, process, remote_ip, remote_port, protocol, service FROM connections"
            ).fetchall()
            for row in rows:
                process = application_name(str(row["process"] or "Unknown app"))
                asn = asn_locator.lookup(row["remote_ip"])
                reference = network_reference(row["remote_ip"], asn)
                flow = {
                    "remote_ip": row["remote_ip"],
                    "remote_port": row["remote_port"],
                    "protocol": row["protocol"],
                    "service": row["service"],
                    "network_reference": reference,
                }
                destination_key, grouping = flow_destination_key(flow)
                self.connection.execute(
                    "UPDATE connections SET process = ?, process_key = ?, provider = ?, network_class = ?, "
                    "destination_key = ?, grouping = ? WHERE fingerprint = ?",
                    (
                        process, process.casefold(), (reference or {}).get("name"),
                        (reference or {}).get("service_class"), destination_key, grouping, row["fingerprint"],
                    ),
                )
                # The fingerprint hashes destination_key, so a key that gained
                # (or lost) a network class moves the row and its finding with
                # it. A row that would collide with an existing one stays put.
                fingerprint = history_identity(
                    process, str(row["protocol"] or "TCP"), row["remote_ip"], int(row["remote_port"] or 0),
                    destination_key,
                )
                if fingerprint != row["fingerprint"]:
                    moved = self.connection.execute(
                        "UPDATE OR IGNORE connections SET fingerprint = ? WHERE fingerprint = ?",
                        (fingerprint, row["fingerprint"]),
                    ).rowcount
                    if moved:
                        self.connection.execute(
                            "UPDATE OR IGNORE findings SET fingerprint = ? WHERE fingerprint = ?",
                            (fingerprint, row["fingerprint"]),
                        )

    @staticmethod
    def _interface_class(interface: str | None) -> str | None:
        # An unknown, loopback, or virtual interface is not evidence of a
        # direct connection. These labels describe the observed interface;
        # they do not establish VPN coverage or encryption.
        if not isinstance(interface, str):
            return None
        if interface.startswith("utun") and interface[4:].isdigit():
            return "VPN tunnel"
        if interface.startswith("en") and interface[2:].isdigit():
            return "direct network"
        return None

    @classmethod
    def _flow_interface_class(cls, flow: dict[str, Any]) -> str | None:
        sockets = flow.get("sockets")
        interfaces = (
            [socket.get("interface") for socket in sockets]
            if sockets else flow.get("interfaces") or [flow.get("interface")]
        )
        classes = {cls._interface_class(interface) for interface in interfaces}
        # A grouped destination can have sockets on both kinds of interface.
        # Only compare observations with one unambiguous interface class.
        return next(iter(classes)) if len(classes) == 1 and None not in classes else None

    def _learning_state(self, now: float, count: int) -> tuple[bool, float, float]:
        created_at = float(self._setting("created_at", str(now)))
        if created_at <= 0:
            created_at = now
        age = max(0.0, now - created_at)
        time_progress = age / self.learning_seconds if self.learning_seconds > 0 else 1.0
        connection_progress = count / self.learning_connections if self.learning_connections > 0 else 1.0
        minimum_progress = age / self.minimum_learning_seconds if self.minimum_learning_seconds > 0 else 1.0
        learning = minimum_progress < 1 or (time_progress < 1 and connection_progress < 1)
        progress = min(minimum_progress, max(time_progress, connection_progress))
        return learning, min(1.0, progress), created_at

    def observe_batch(self, flows: list[dict[str, Any]]) -> None:
        now = time.time()
        with self.lock:
            if self._setting("recording", "1") != "1":
                return
            # Sample fresh socket evidence before the ordinary eight-second
            # history write throttle. Do not difference grouped lifetime totals.
            events = self.outbound_monitor.observe(flows, now)
            with self.connection:
                for evidence in events:
                    self._record_outbound_change(evidence, now)
            unique: dict[str, dict[str, Any]] = {}
            for flow in flows:
                fingerprint = history_identity(
                    str(flow.get("process") or "Unknown"),
                    str(flow.get("protocol") or "TCP"),
                    str(flow.get("remote_ip") or ""),
                    int(flow.get("remote_port") or 0),
                    str(flow.get("destination_key") or "") or None,
                )
                due = now - self.last_recorded.get(fingerprint, 0) >= 8
                if not due:
                    previous = self.connection.execute(
                        "SELECT interface_class FROM connections WHERE fingerprint = ?",
                        (fingerprint,),
                    ).fetchone()
                    # Throttle repeated counters, but retain interface changes
                    # and loss of interface evidence between regular writes.
                    due = previous is not None and previous["interface_class"] != self._flow_interface_class(flow)
                if due:
                    unique[fingerprint] = flow
            if not unique:
                return

            known_count = int(self.connection.execute("SELECT COUNT(*) FROM connections").fetchone()[0])
            if known_count == 0 and float(self._setting("created_at", "0")) <= 0:
                with self.connection:
                    self.connection.execute("UPDATE settings SET value = ? WHERE key = 'created_at'", (str(now),))
            learning, _, _ = self._learning_state(now, known_count)
            with self.connection:
                for fingerprint, flow in unique.items():
                    self._observe(fingerprint, flow, now, learning)
                    self.last_recorded[fingerprint] = now
                self.connection.execute(
                    "DELETE FROM ip_sightings WHERE last_seen < ?",
                    (now - SIGHTING_RETENTION_SECONDS,),
                )

    def _observe(self, fingerprint: str, flow: dict[str, Any], now: float, learning: bool) -> None:
        process = application_name(str(flow.get("process") or "Unknown"))
        process_key = process.strip().casefold()
        protocol = str(flow.get("protocol") or "TCP").upper()
        remote_ip = str(flow.get("remote_ip") or "")
        remote_port = int(flow.get("remote_port") or 0)
        service = str(flow.get("service") or service_name(remote_port, protocol))
        # Aggregated service rows keep only their latest remote IP, so every
        # member socket's address is also recorded individually for later
        # investigation.
        sighting_targets = {(remote_ip, remote_port)} if remote_ip else set()
        for socket_entry in flow.get("sockets") or []:
            socket_ip = str(socket_entry.get("remote_ip") or "")
            if socket_ip:
                sighting_targets.add((socket_ip, int(socket_entry.get("remote_port") or remote_port)))
        for sighting_ip, sighting_port in sighting_targets:
            self.connection.execute(
                """
                INSERT INTO ip_sightings(
                    remote_ip, process_key, process, protocol, remote_port, service,
                    first_seen, last_seen, observation_count
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(remote_ip, process_key, protocol, remote_port) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    process = excluded.process,
                    service = excluded.service,
                    observation_count = observation_count + 1
                """,
                (
                    sighting_ip,
                    process_key,
                    process,
                    protocol,
                    sighting_port,
                    service if sighting_port == remote_port else service_name(sighting_port, protocol),
                    now,
                    now,
                ),
            )
        existing = self.connection.execute(
            "SELECT observation_count, average_rtt_ms, rtt_samples, interface_class FROM connections WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if existing is None and flow.get("destination_key"):
            # Rows recorded before the destination_key identity scheme hash by
            # raw remote IP; rehome them so an upgrade does not duplicate every
            # known destination or re-announce it as new.
            legacy_fingerprint = history_identity(
                str(flow.get("process") or "Unknown"),
                str(flow.get("protocol") or "TCP"),
                remote_ip,
                remote_port,
            )
            if self.connection.execute(
                "SELECT 1 FROM connections WHERE fingerprint = ?", (legacy_fingerprint,)
            ).fetchone():
                self.connection.execute(
                    "UPDATE connections SET fingerprint = ? WHERE fingerprint = ?",
                    (fingerprint, legacy_fingerprint),
                )
                self.connection.execute(
                    "UPDATE OR IGNORE findings SET fingerprint = ? WHERE fingerprint = ?",
                    (fingerprint, legacy_fingerprint),
                )
                existing = self.connection.execute(
                    "SELECT observation_count, average_rtt_ms, rtt_samples, interface_class FROM connections WHERE fingerprint = ?",
                    (fingerprint,),
                ).fetchone()
        rtt = flow.get("rtt_ms")
        rtt_value = float(rtt) if rtt is not None else None
        if existing:
            interface_class = self._flow_interface_class(flow)
            previous_interface = existing["interface_class"]
            if not learning and previous_interface and interface_class and previous_interface != interface_class:
                self._record_interface_change(
                    fingerprint, flow, now, int(existing["observation_count"]) + 1,
                    previous_interface, interface_class,
                )
            old_samples = int(existing["rtt_samples"])
            old_average = existing["average_rtt_ms"]
            new_samples = old_samples + (1 if rtt_value is not None else 0)
            average = old_average
            if rtt_value is not None:
                average = rtt_value if old_average is None else (float(old_average) * old_samples + rtt_value) / new_samples
            self.connection.execute(
                """
                UPDATE connections SET last_seen = ?, observation_count = observation_count + 1,
                    last_bytes_in = ?, last_bytes_out = ?, average_rtt_ms = ?, rtt_samples = ?,
                    interface_class = ?, remote_ip = ?,
                    provider = COALESCE(?, provider), network_class = COALESCE(?, network_class),
                    destination_key = COALESCE(?, destination_key),
                    grouping = COALESCE(?, grouping), socket_count = ?, remote_ip_count = ?
                WHERE fingerprint = ?
                """,
                (
                    now,
                    flow.get("bytes_in"),
                    flow.get("bytes_out"),
                    average,
                    new_samples,
                    interface_class,
                    str(flow.get("remote_ip") or ""),
                    ((flow.get("network_reference") or {}).get("name")),
                    ((flow.get("network_reference") or {}).get("service_class")),
                    flow.get("destination_key"),
                    flow.get("grouping"),
                    int(flow.get("socket_count") or 1),
                    int(flow.get("remote_ip_count") or 1),
                    fingerprint,
                ),
            )
            return

        geo = flow.get("geo") or {}
        country = geo.get("country")
        country_code = geo.get("country_code")
        city = geo.get("city")
        interface_class = self._flow_interface_class(flow)
        reference = flow.get("network_reference") or {}
        provider = reference.get("name")
        destination_key = flow.get("destination_key")
        grouping = flow.get("grouping")

        process_rows = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM connections WHERE process_key = ?", (process_key,)
            ).fetchone()[0]
        )
        country_seen = not country or bool(
            self.connection.execute(
                "SELECT 1 FROM connections WHERE process_key = ? AND country = ? LIMIT 1",
                (process_key, country),
            ).fetchone()
        )
        port_seen = bool(
            self.connection.execute(
                "SELECT 1 FROM connections WHERE process_key = ? AND protocol = ? AND remote_port = ? LIMIT 1",
                (process_key, protocol, remote_port),
            ).fetchone()
        )
        interface_seen = not interface_class or bool(
            self.connection.execute(
                "SELECT 1 FROM connections WHERE process_key = ? AND interface_class = ? LIMIT 1",
                (process_key, interface_class),
            ).fetchone()
        )
        service_class = reference.get("service_class")
        provider_any_seen = not provider or bool(
            self.connection.execute(
                "SELECT 1 FROM connections WHERE process_key = ? AND provider = ? LIMIT 1",
                (process_key, provider),
            ).fetchone()
        )
        provider_seen = not provider or (
            provider_any_seen and self._network_class_seen(process_key, provider, service_class, now)
        )

        self.connection.execute(
            """
            INSERT INTO connections(
                fingerprint, process_key, process, protocol, remote_ip, remote_port, service, scope,
                country, country_code, city, interface_class, first_seen, last_seen,
                observation_count, last_bytes_in, last_bytes_out, average_rtt_ms, rtt_samples,
                provider, network_class, destination_key, grouping, socket_count, remote_ip_count
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint, process_key, process, protocol, remote_ip, remote_port,
                service,
                str(flow.get("scope") or "unknown"), country, country_code, city, interface_class,
                now, now, flow.get("bytes_in"), flow.get("bytes_out"), rtt_value,
                1 if rtt_value is not None else 0,
                provider, service_class, destination_key, grouping,
                int(flow.get("socket_count") or 1), int(flow.get("remote_ip_count") or 1),
            ),
        )

        # The app reference depends on the curated list, not on local history,
        # so it alone still speaks while learning and for an app's first stream.
        unexpected = self._unexpected_network(flow, reference, remote_ip)
        history_ready = not learning and process_rows > 0
        if not history_ready and unexpected is None:
            return

        reasons: list[str] = []
        severity = "notice"
        if history_ready:
            if provider and not provider_seen and process_rows >= 3:
                if provider_any_seen:
                    reasons.append(f"first connection to {describe_network(reference)}")
                else:
                    owner = "inferred network owner" if reference.get("confidence") == "inferred" else "network owner"
                    reasons.append(f"the {owner} {provider} has not appeared in this app's local history")
                severity = "attention"
            if not provider and country and not country_seen and process_rows >= 3:
                reasons.append(f"the offline IP estimate suggests {country}, which has not appeared in this app's local history")
                severity = "attention"
            if not port_seen and process_rows >= 4:
                reasons.append(f"{protocol} port {remote_port} is new for this app")
                severity = "attention"
            if not interface_seen and process_rows >= 4:
                reasons.append(f"the app changed to a {interface_class}")
            if not reasons and unexpected is None:
                if grouping == "provider":
                    return
                reasons.append("this app has not contacted this server before")

        if unexpected is not None:
            severity = "attention"
            title = f"Unexpected network for {process}"
            lead = (
                f"{process} usually uses {join_names(unexpected.providers())}. "
                f"This connection goes to {describe_network(reference)}."
            )
            explanation = lead + (f" Also: {'; '.join(reasons)}." if reasons else "")
            reasons = [lead, *reasons]
        else:
            if severity == "attention" and provider and not provider_seen:
                title = f"New network for {process}"
            elif severity == "attention" and country and not country_seen:
                title = f"New estimated country for {process}"
            elif severity == "attention" and not port_seen:
                title = f"New port for {process}"
            else:
                title = f"New destination for {process}"
            explanation_text = "; ".join(reasons)
            explanation = explanation_text[:1].upper() + explanation_text[1:] + "."
        evidence = {
            "process": process,
            "destination": f"{remote_ip}:{remote_port}",
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "protocol": protocol,
            "service": str(flow.get("service") or service_name(remote_port, protocol)),
            "location": "Approx. " + (", ".join(part for part in (city, country) if part) or "location unavailable"),
            "network": interface_class or "Network interface unavailable",
            "provider": provider,
            "destination_key": destination_key,
            "grouping": grouping,
            "socket_count": int(flow.get("socket_count") or 1),
            "remote_ip_count": int(flow.get("remote_ip_count") or 1),
            "prior_destinations_for_app": process_rows,
            "network_class": service_class,
            "network_label": reference.get("label"),
            "reasons": reasons,
        }
        if unexpected is not None:
            evidence.update({
                "event_type": "unexpected_network",
                "reference_app": unexpected.app,
                "reference_expected": unexpected.providers(),
                "reference_source": unexpected.source,
                "reference_reviewed": APP_NETWORKS.reviewed,
            })
        if self._stream_is_expected(evidence):
            return
        self.connection.execute(
            """
            INSERT OR IGNORE INTO findings(
                fingerprint, created_at, severity, title, explanation, evidence_json
            ) VALUES(?, ?, ?, ?, ?, ?)
            """,
            (fingerprint, now, severity, title, explanation, json.dumps(evidence, separators=(",", ":"))),
        )

    def _record_outbound_change(self, evidence: dict[str, Any], now: float) -> None:
        process = application_name(str(evidence["process"]))
        evidence["process"] = process
        evidence["destination"] = f"{evidence['remote_ip']}:{evidence['remote_port']}"
        mib = evidence["bytes_out"] / (1024 * 1024)
        baseline_mib = evidence["baseline_bytes_out"] / (1024 * 1024)
        explanation = (
            f"Observed {mib:.1f} MiB sent in {evidence['window_seconds']:.0f} seconds across "
            f"{evidence['measured_socket_count']} socket(s) in this stream. "
            f"Outbound traffic exceeded the comparison threshold for {evidence['consecutive_windows']} "
            f"consecutive measured windows; the largest of {evidence['baseline_window_count']} baseline "
            f"windows was {baseline_mib:.1f} MiB per {evidence['baseline_window_seconds']:.0f} seconds. "
            "Backups, uploads, and sync can explain this change. This is not a malware verdict."
        )
        evidence["reasons"] = [explanation]
        if self._stream_is_expected(evidence):
            return
        # SQLite allocates a durable event identity; timestamps can coincide.
        next_id = self.connection.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM findings").fetchone()[0]
        self.connection.execute(
            "INSERT INTO findings(fingerprint, created_at, severity, title, explanation, evidence_json) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (f"outbound:{next_id}", now, "attention", f"Unusual outbound transfer for {process}",
             explanation, json.dumps(evidence, separators=(",", ":"))),
        )

    def _record_interface_change(
        self, fingerprint: str, flow: dict[str, Any], now: float, observation: int,
        previous: str, current: str,
    ) -> None:
        process = application_name(str(flow.get("process") or "Unknown"))
        remote_ip = str(flow.get("remote_ip") or "")
        remote_port = int(flow.get("remote_port") or 0)
        protocol = str(flow.get("protocol") or "TCP").upper()
        reason = f"this known connection was previously observed on a {previous} and is now on a {current}"
        evidence = {
            "event_type": "interface_change",
            "connection_fingerprint": fingerprint,
            "process": process,
            "destination": f"{remote_ip}:{remote_port}",
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "protocol": protocol,
            "service": str(flow.get("service") or service_name(remote_port, protocol)),
            "previous_network": previous,
            "network": current,
            "interface": flow.get("interface"),
            "interfaces": flow.get("interfaces") or ([flow["interface"]] if flow.get("interface") else []),
            "provider": (flow.get("network_reference") or {}).get("name"),
            "destination_key": flow.get("destination_key"),
            "grouping": flow.get("grouping"),
            "socket_count": int(flow.get("socket_count") or 1),
            "remote_ip_count": int(flow.get("remote_ip_count") or 1),
            "reasons": [reason],
        }
        if self._stream_is_expected(evidence):
            return
        # Keep the original destination finding intact. The persisted
        # observation count gives every later transition its own identity,
        # including repeated transitions in the same clock tick or after restart.
        event_fingerprint = f"{fingerprint}:interface:{observation}"
        self.connection.execute(
            "INSERT INTO findings(fingerprint, created_at, severity, title, explanation, evidence_json) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (
                event_fingerprint, now, "notice", f"Network interface changed for {process}",
                reason[:1].upper() + reason[1:] + ". Interface names do not establish VPN protection or encryption.",
                json.dumps(evidence, separators=(",", ":")),
            ),
        )

    def _stream_is_expected(self, evidence: dict[str, Any]) -> bool:
        key = _finding_stream_key(evidence)
        if key is None:
            return False
        keys = ["|".join(key)]
        # Streams accepted before network classes existed were keyed by the
        # provider alone; that acceptance still covers every class of it.
        process, protocol, destination, port = key
        provider_key, _, suffix = destination.rpartition(":")
        if destination.startswith("provider:") and suffix in references.CLASSES:
            keys.append("|".join((process, protocol, provider_key, port)))
        return any(
            self.connection.execute("SELECT 1 FROM expectations WHERE stream_key = ?", (stream_key,)).fetchone()
            for stream_key in keys
        )

    def _network_class_seen(self, process_key: str, provider: str, service_class: str | None, now: float) -> bool:
        if self.connection.execute(
            "SELECT 1 FROM connections WHERE process_key = ? AND provider = ? AND network_class IS ? LIMIT 1",
            (process_key, provider, service_class),
        ).fetchone():
            return True
        if service_class is None:
            return False
        # A stream recorded before network classes existed kept only its
        # latest address, so check every address this app contacted earlier
        # before calling the class new. This observation's own new sightings
        # were written at `now` and do not count.
        rows = self.connection.execute(
            "SELECT DISTINCT remote_ip FROM ip_sightings WHERE process_key = ? AND first_seen < ?",
            (process_key, now),
        ).fetchall()
        for row in rows:
            match = PROVIDER_RANGES.lookup(row["remote_ip"])
            if match and match.provider == provider and match.service_class == service_class:
                return True
        return False

    @staticmethod
    def _unexpected_network(
        flow: dict[str, Any], reference: dict[str, Any], remote_ip: str,
    ) -> references.AppExpectation | None:
        """The curated app entry this destination falls outside of, if any.

        Raise-only: an app name can be imitated, so a match never quiets anything.
        """
        expectation = APP_NETWORKS.expectation(str(flow.get("process") or ""))
        if expectation is None or references.is_local_address(remote_ip):
            return None
        if APP_NETWORKS.allows(expectation, reference.get("name"), reference.get("service_class")):
            return None
        return expectation

    def expect_findings(self, finding_ids: list[int]) -> bool:
        """Remember a stream as expected and keep its existing finding rows.

        The accepted cards leave the visible list. Later novelty, interface,
        and outbound findings for that same app, protocol, destination, and
        port are not recorded. Clear local history removes the acceptance.
        """
        ids = [value for value in finding_ids if type(value) is int]
        if not ids:
            return False
        now = time.time()
        with self.lock, self.connection:
            placeholders = ",".join("?" for _ in ids)
            selected = self.connection.execute(
                f"SELECT id, evidence_json FROM findings WHERE id IN ({placeholders})", ids
            ).fetchall()
            if not selected:
                return False
            keys: set[tuple[str, str, str, str]] = set()
            for row in selected:
                key = _finding_stream_key(json.loads(row["evidence_json"]))
                if key is not None:
                    keys.add(key)
            if not keys:
                return False
            for key in keys:
                process, protocol, destination, port = key
                self.connection.execute(
                    """
                    INSERT INTO expectations(
                        stream_key, process, protocol, destination_key, remote_port, accepted_at
                    ) VALUES(?, ?, ?, ?, ?, ?)
                    ON CONFLICT(stream_key) DO UPDATE SET accepted_at = excluded.accepted_at
                    """,
                    ("|".join(key), process, protocol, destination, int(port) if port.isdigit() else 0, now),
                )
            open_rows = self.connection.execute(
                "SELECT id, evidence_json FROM findings WHERE acknowledged = 0"
            ).fetchall()
            for row in open_rows:
                if _finding_stream_key(json.loads(row["evidence_json"])) in keys:
                    self.connection.execute(
                        "UPDATE findings SET acknowledged = 1 WHERE id = ?", (row["id"],)
                    )
        return True

    def summary(self) -> dict[str, Any]:
        now = time.time()
        with self.lock:
            connection_count = int(self.connection.execute("SELECT COUNT(*) FROM connections").fetchone()[0])
            service_count = int(
                self.connection.execute(
                    "SELECT COUNT(DISTINCT process_key || '|' || protocol || '|' || remote_port || '|' || "
                    "COALESCE(destination_key, remote_ip)) FROM connections"
                ).fetchone()[0]
            )
            process_count = int(self.connection.execute("SELECT COUNT(DISTINCT process_key) FROM connections").fetchone()[0])
            country_count = int(
                self.connection.execute("SELECT COUNT(DISTINCT country) FROM connections WHERE country IS NOT NULL").fetchone()[0]
            )
            learning, progress, created_at = self._learning_state(now, connection_count)
            rows = self.connection.execute(
                "SELECT * FROM findings ORDER BY created_at DESC LIMIT 50"
            ).fetchall()
            findings = []
            for row in rows:
                item = dict(row)
                if item["acknowledged"]:
                    continue
                item["evidence"] = json.loads(item.pop("evidence_json"))
                item["acknowledged"] = False
                findings.append(item)
            attention_count = sum(
                1 for item in findings
                if item["severity"] == "attention" and item["created_at"] >= now - 86400
            )
            return {
                "recording": self._setting("recording", "1") == "1",
                "learning": learning,
                "learning_progress": round(progress, 3),
                "learning_seconds": self.learning_seconds,
                "learning_connections": self.learning_connections,
                "minimum_learning_seconds": self.minimum_learning_seconds,
                "history_started_at": created_at,
                "connection_count": connection_count,
                "service_count": service_count,
                "process_count": process_count,
                "country_count": country_count,
                "attention_count": attention_count,
                "findings": findings,
                "database": self.database_path.name,
                "payload_capture": False,
                "external_upload": False,
            }

    def connections_for_ip(self, remote_ip: str, limit: int = 50) -> list[dict[str, Any]]:
        capped = max(1, min(limit, 500))
        with self.lock:
            rows = self.connection.execute(
                """
                SELECT remote_ip, process, protocol, remote_port, service,
                       first_seen, last_seen, observation_count
                FROM ip_sightings WHERE remote_ip = ? ORDER BY last_seen DESC LIMIT ?
                """,
                (remote_ip, capped),
            ).fetchall()
            if not rows:
                # History recorded before per-IP sightings existed only knows each
                # aggregated row's latest address.
                rows = self.connection.execute(
                    """
                    SELECT fingerprint, process, protocol, remote_ip, remote_port, service, scope,
                           country, country_code, city, interface_class, first_seen, last_seen,
                           observation_count, provider, grouping
                    FROM connections WHERE remote_ip = ? ORDER BY last_seen DESC LIMIT ?
                    """,
                    (remote_ip, capped),
                ).fetchall()
            return [dict(row) for row in rows]


class FlowCollector:
    def __init__(self, history: HistoryEngine, interval: float = 1.5) -> None:
        self.interval = interval
        self.history = history
        self.geoip = GeoIPLocator()
        self.asn = ASNLocator()
        self.history.enrich_network_ownership(self.asn)
        self.flows: dict[str, Flow] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.last_error: str | None = None
        self.nettop_available = False
        self.nettop_error: str | None = None
        self.poll_count = 0
        self.last_successful_poll: float | None = None
        self.thread = threading.Thread(target=self._run, name="pulsepath-collector", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)
        self.geoip.close()
        self.asn.close()

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            cutoff = time.time() - 120
            values = sorted(
                (flow for flow in self.flows.values() if flow.last_seen >= cutoff),
                key=lambda flow: flow.last_seen, reverse=True,
            )
            grouped = aggregate_flow_records([asdict(flow) for flow in values[:300]])
            # Equal poll timestamps otherwise keep insertion order, oldest first.
            # Ties keep that order so a routine poll does not reshuffle the list.
            grouped.sort(key=lambda item: float(item.get("first_seen") or 0), reverse=True)
            return grouped

    def get_flow(self, flow_id: str) -> Flow | None:
        with self.lock:
            return self.flows.get(flow_id)

    def status(self) -> dict[str, Any]:
        with self.lock:
            active = sum(1 for flow in self.flows.values() if time.time() - flow.last_seen <= ACTIVE_WINDOW_SECONDS)
            active_groups = len(
                aggregate_flow_records(
                    [
                        asdict(flow) for flow in self.flows.values()
                        if time.time() - flow.last_seen <= ACTIVE_WINDOW_SECONDS
                    ]
                )
            )
        return {
            "collector": "lsof",
            "platform": "macOS",
            "mode": "metadata-only",
            "active_flows": active,
            "active_groups": active_groups,
            "poll_count": self.poll_count,
            "last_successful_poll": self.last_successful_poll,
            "active_window_seconds": ACTIVE_WINDOW_SECONDS,
            "last_error": self.last_error,
            "geolocation": "offline" if self.geoip.available else "disabled",
            "payload_capture": False,
            "protocols": ["TCP", "UDP"],
            "nettop_available": self.nettop_available,
            "nettop_error": self.nettop_error,
            "geoip_available": self.geoip.available,
            "geoip_database": self.geoip.database_path.name if self.geoip.database_path else None,
            "geoip_error": self.geoip.error,
            "asn_available": self.asn.available,
            "asn_database": self.asn.database_path.name if self.asn.database_path else None,
            "asn_error": self.asn.error,
            "provider_references": PROVIDER_RANGES.status(),
            "app_references": APP_NETWORKS.status(),
        }

    def _run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                observed = self._read_lsof()
                try:
                    observed.extend(self._read_nettop())
                    self.nettop_available = True
                    self.nettop_error = None
                except Exception as error:
                    self.nettop_available = False
                    self.nettop_error = str(error)
                now = time.time()
                history_rows: dict[str, dict[str, Any]] = {}
                with self.lock:
                    for item in observed:
                        existing = self.flows.get(item["id"])
                        if existing:
                            existing.last_seen = now
                            if existing.id not in history_rows:
                                # A previous poll's interface is not current evidence.
                                # Later nettop rows can still enrich this poll's lsof row.
                                existing.interface = None
                                existing.bytes_in = None
                                existing.bytes_out = None
                                existing.rtt_ms = None
                                existing.source = item.get("source", "lsof")
                            for field in ("process", "service", "interface", "bytes_in", "bytes_out", "rtt_ms", "source"):
                                value = item.get(field)
                                if value is not None:
                                    setattr(existing, field, value)
                            if existing.geo is None:
                                existing.geo = self.geoip.lookup(existing.remote_ip)
                            if existing.asn is None:
                                existing.asn = self.asn.lookup(existing.remote_ip)
                            if existing.network_reference is None:
                                existing.network_reference = network_reference(existing.remote_ip, existing.asn)
                            history_rows[existing.id] = asdict(existing)
                        else:
                            item["geo"] = self.geoip.lookup(item.get("remote_ip"))
                            item["asn"] = self.asn.lookup(item.get("remote_ip"))
                            item["network_reference"] = network_reference(item.get("remote_ip"), item["asn"])
                            self.flows[item["id"]] = Flow(first_seen=now, last_seen=now, **item)
                            history_rows[item["id"]] = asdict(self.flows[item["id"]])
                    cutoff = now - 120
                    self.flows = {key: flow for key, flow in self.flows.items() if flow.last_seen >= cutoff}
                self.history.observe_batch(aggregate_flow_records(list(history_rows.values())))
                self.last_error = None
                self.last_successful_poll = now
                self.poll_count += 1
            except Exception as error:  # collector should never take down the UI
                self.last_error = str(error)
            remaining = max(0.1, self.interval - (time.monotonic() - started))
            self.stop_event.wait(remaining)

    def _read_lsof(self) -> list[dict[str, Any]]:
        result = subprocess.run(
            [LSOF, "-nP", "-iTCP", "-iUDP", "-sTCP:ESTABLISHED", "-F", "pcPnT"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr.strip() or f"lsof exited with {result.returncode}")

        current_pid = 0
        current_process = "Unknown"
        protocol = "TCP"
        rows: list[dict[str, Any]] = []

        for raw_line in result.stdout.splitlines():
            if not raw_line:
                continue
            code, value = raw_line[0], raw_line[1:]
            if code == "p":
                try:
                    current_pid = int(value)
                except ValueError:
                    current_pid = 0
            elif code == "c":
                current_process = value.replace("\\x20", " ")
            elif code == "P":
                protocol = value
            elif code == "n" and "->" in value:
                local_text, remote_text = value.split("->", 1)
                local = split_endpoint(local_text)
                remote = split_endpoint(remote_text)
                if not local or not remote:
                    continue
                local_ip, local_port = local
                remote_ip, remote_port = remote
                scope = address_scope(remote_ip)
                if scope in {"loopback", "link-local"}:
                    continue
                rows.append(
                    {
                        "id": flow_identity(current_pid, protocol, local_ip, local_port, remote_ip, remote_port),
                        "process": current_process,
                        "pid": current_pid,
                        "protocol": protocol,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "service": service_name(remote_port, protocol),
                        "scope": scope,
                        "source": "lsof",
                    }
                )
        return rows

    def _read_nettop(self) -> list[dict[str, Any]]:
        result = subprocess.run(
            [NETTOP, "-L", "1", "-n", "-x", "-J", "interface,state,bytes_in,bytes_out,rtt_avg"],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
        if result.returncode != 0:
            message = result.stderr.strip() or f"nettop exited with {result.returncode}"
            raise RuntimeError(message)
        return self._parse_nettop(result.stdout)

    @staticmethod
    def _parse_nettop(output: str) -> list[dict[str, Any]]:
        header: dict[str, int] = {}
        descriptor_index = 1
        current_process = "Unknown"
        current_pid = 0
        rows: list[dict[str, Any]] = []

        for values in csv.reader(output.splitlines()):
            if not values:
                continue
            if "interface" in values and "state" in values:
                header = {name: index for index, name in enumerate(values) if name}
                descriptor_index = next(
                    (index for index, name in enumerate(values) if not name and index != header.get("time")),
                    1,
                )
                continue

            if descriptor_index >= len(values):
                continue
            descriptor = values[descriptor_index].strip()
            process_match = re.match(r"^(.+)\.(\d+)$", descriptor)
            connection_match = re.match(r"^(tcp|udp)(?:4|6)?\s+(.+?)<->(.+)$", descriptor, re.IGNORECASE)

            if process_match and not connection_match:
                current_process = process_match.group(1)
                current_pid = int(process_match.group(2))
                continue
            if not connection_match or not current_pid:
                continue

            protocol = connection_match.group(1).upper()
            local = split_endpoint(connection_match.group(2))
            remote = split_endpoint(connection_match.group(3))
            if not local or not remote:
                continue
            local_ip, local_port = local
            remote_ip, remote_port = remote
            scope = address_scope(remote_ip)
            if scope in {"loopback", "link-local"}:
                continue

            def column(name: str) -> str | None:
                index = header.get(name)
                return values[index] if index is not None and index < len(values) else None

            state = (column("state") or "").lower()
            if protocol == "TCP" and state and state != "established":
                continue
            rows.append(
                {
                    "id": flow_identity(current_pid, protocol, local_ip, local_port, remote_ip, remote_port),
                    "process": current_process,
                    "pid": current_pid,
                    "protocol": protocol,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "service": service_name(remote_port, protocol),
                    "scope": scope,
                    "interface": (column("interface") or "").strip() or None,
                    "bytes_in": numeric_value(column("bytes_in")),
                    "bytes_out": numeric_value(column("bytes_out")),
                    "rtt_ms": milliseconds_value(column("rtt_avg")),
                    "source": "nettop",
                }
            )
        return rows


class _TraceRun:
    def __init__(self, job: dict[str, Any]) -> None:
        self.job = job
        self.process: subprocess.Popen | None = None
        self.done = threading.Event()


class TraceManager:
    def __init__(self, collector: FlowCollector) -> None:
        self.collector = collector
        self.jobs: dict[str, dict[str, Any]] = {}
        self._runs: dict[str, _TraceRun] = {}
        self.lock = threading.Lock()

    def get(self, flow_id: str) -> dict[str, Any] | None:
        with self.lock:
            job = self.jobs.get(flow_id)
            return dict(job) if job else None

    def start(self, flow_id: str) -> tuple[dict[str, Any] | None, str | None]:
        flow = self.collector.get_flow(flow_id)
        if flow is None:
            return None, "That connection is no longer available."
        if flow.scope in {"loopback", "link-local"}:
            return None, "Local-only connections cannot be traced."
        with self.lock:
            existing = self.jobs.get(flow_id)
            if existing and existing["status"] == "running":
                return dict(existing), None
            job = {
                "flow_id": flow_id,
                "target": flow.remote_ip,
                "status": "running",
                "started_at": time.time(),
                "finished_at": None,
                "hops": [],
                "error": None,
            }
            self.jobs[flow_id] = job
            run = _TraceRun(job)
            self._runs[flow_id] = run
        threading.Thread(target=self._run, args=(run,), name=f"trace-{flow_id}", daemon=True).start()
        with self.lock:
            return dict(job), None

    def stop(self, flow_id: str) -> tuple[dict[str, Any] | None, str | None]:
        with self.lock:
            job = self.jobs.get(flow_id)
            if job is None:
                return None, "No trace has been started for this flow."
            if job["status"] != "running":
                return dict(job), None
            job.update(status="cancelled", finished_at=time.time(), error=None)
            run = self._runs.get(flow_id)
            process = run.process if run else None
        if process is not None and run is not None:
            self._terminate(process)
            # The worker owns the output pipes. Give it a bounded opportunity
            # to collect and publish the hops emitted before cancellation.
            run.done.wait(timeout=1)
        with self.lock:
            return dict(job), None

    @staticmethod
    def _terminate(process: subprocess.Popen) -> None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                # Keep the HTTP cancellation request bounded even if the OS
                # cannot reap a process immediately after SIGKILL.
                pass

    def _enrich_hops(self, hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for hop in hops:
            hop["geo"] = self.collector.geoip.lookup(hop.get("ip"))
            hop["asn"] = self.collector.asn.lookup(hop.get("ip"))
            hop["network_reference"] = network_reference(hop.get("ip"), hop["asn"])
        return hops

    @staticmethod
    def _combined_output(stdout: Any, stderr: Any) -> str:
        # TimeoutExpired carries bytes even when the run used text=True.
        parts = []
        for value in (stdout, stderr):
            if not value:
                continue
            parts.append(value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value))
        return "\n".join(parts)

    def _run(self, run: _TraceRun) -> None:
        job = run.job
        flow_id, target = job["flow_id"], job["target"]
        status, message, hops = "complete", None, []
        try:
            version, argument = trace_target_argument(target)
            command = TRACEROUTE6 if version == 6 else TRACEROUTE
            # Serialize launch and registration with stop: a stop arriving
            # before launch prevents it; one arriving after sees its process.
            with self.lock:
                if self.jobs.get(flow_id) is not job or job["status"] != "running":
                    return
                process = subprocess.Popen(
                    [command, "-m", "18", "-w", "1", "-q", "1", argument],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                run.process = process
            try:
                stdout, stderr = process.communicate(timeout=TRACE_TIMEOUT_SECONDS)
                output = self._combined_output(stdout, stderr)
            except subprocess.TimeoutExpired as error:
                self._terminate(process)
                output = self._combined_output(error.stdout, error.stderr)
                try:
                    stdout, stderr = process.communicate(timeout=1)
                    output = self._combined_output(stdout, stderr) or output
                except subprocess.TimeoutExpired:
                    pass
                message = f"The trace reached its {TRACE_TIMEOUT_SECONDS}-second limit; partial hops are shown."
            hops = self._enrich_hops(self._parse(output))
            if not hops and process.returncode != 0 and message is None:
                raise RuntimeError("Route probing was blocked by macOS or the network.")
        except PermissionError:
            status, message = "error", "macOS blocked diagnostic route probing for this launch."
        except Exception as error:
            status, message = "error", str(error)
        finally:
            with self.lock:
                # Retracing can replace the job while its previous worker is
                # finishing. Only that worker's own job may be updated.
                if self.jobs.get(flow_id) is job:
                    if job["status"] == "cancelled":
                        job.update(hops=hops, error=None)
                    else:
                        job.update(status=status, finished_at=time.time(), hops=hops, error=message)
                if self._runs.get(flow_id) is run:
                    del self._runs[flow_id]
            run.done.set()

    @staticmethod
    def _parse(output: str) -> list[dict[str, Any]]:
        hops: list[dict[str, Any]] = []
        for line in output.splitlines():
            match = re.match(r"^\s*(\d+)\s+(.+)$", line)
            if not match:
                continue
            index = int(match.group(1))
            remainder = match.group(2).strip()
            if remainder.startswith("*"):
                hops.append({"index": index, "ip": None, "rtt_ms": None, "reply": False})
                continue
            hostname = None
            named = re.match(r"^(.*?)\s+\(([^)]+)\)", remainder)
            if named:
                candidate = named.group(2).strip()
                label = named.group(1).strip()
                if label and label != candidate:
                    hostname = label
            else:
                candidate = remainder.split()[0]
            try:
                ipaddress.ip_address(candidate.split("%", 1)[0])
            except ValueError:
                continue
            rtt_match = re.search(r"(\d+(?:\.\d+)?)\s*ms", remainder)
            hop = {
                "index": index,
                "ip": candidate,
                "rtt_ms": float(rtt_match.group(1)) if rtt_match else None,
                "reply": True,
            }
            if hostname:
                hop["hostname"] = hostname
            hops.append(hop)
        return hops


class PulsepathHandler(SimpleHTTPRequestHandler):
    collector: FlowCollector
    traces: TraceManager
    history: HistoryEngine
    # Socket timeout in seconds: a stalled request line, header, or JSON body
    # releases its thread instead of holding it forever.
    timeout = 10

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(APP_DIR), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(self)")
        script_hash = getattr(self, "page_script_hash", "")
        script_policy = f"'self' 'sha256-{script_hash}'" if script_hash else "'none'"
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            f"script-src {script_policy}; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        super().end_headers()

    def send_head(self):
        self.page_script_hash = ""
        route = posixpath.normpath(unquote(urlsplit(self.path).path))
        if route not in STATIC_PAGE_ROUTES:
            if not self._basemap_file_allowed(route):
                self.send_error(404, "File not found")
                return None
            return super().send_head()
        try:
            # Served as-is: the page never carries the session token.
            document = (APP_DIR / "index.html").read_bytes()
        except OSError:
            self.send_error(404, "Interface file unavailable")
            return None
        # Keep the CSP and body tied to one snapshot, even if the file changes
        # while this request is being served. GET and HEAD share this path.
        self.page_script_hash = index_script_hash(document)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(document)))
        self.end_headers()
        return io.BytesIO(document)

    def do_GET(self) -> None:
        if not self._request_is_local():
            self._json({"error": "Pulsepath accepts local requests only."}, status=403)
            return
        route = self.path.split("?", 1)[0]
        if route.startswith("/api/") and not self._api_token_accepted():
            return
        if route == "/api/status":
            self._json(self.collector.status())
            return
        if route == "/api/flows":
            self._json({"flows": self.collector.snapshot(), "captured_at": time.time()})
            return
        if route == "/api/security/summary":
            self._json(enrich_security_summary(self.history.summary(), self.collector.geoip, self.collector.asn))
            return
        if route.startswith("/api/traces/"):
            flow_id = route.rsplit("/", 1)[-1]
            job = self.traces.get(flow_id)
            if job is None:
                self._json({"error": "No trace has been started for this flow."}, status=404)
            else:
                self._json(job)
            return
        if route == "/api/investigate":
            query = parse_qs(urlsplit(self.path).query)
            value = (query.get("ip") or [""])[0]
            result = investigate_address(
                value, self.collector.geoip, self.collector.asn, self.history, self.collector.snapshot()
            )
            if result is None:
                self._json({"error": "Provide a valid IP address to investigate."}, status=400)
            else:
                self._json(result)
            return
        if self._static_route_allowed(route):
            super().do_GET()
            return
        self._json({"error": "Not found"}, status=404)

    def do_HEAD(self) -> None:
        if not self._request_is_local():
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        route = self.path.split("?", 1)[0]
        if route.startswith("/api/"):
            # Same routing and status codes as GET; _json omits the body.
            self.do_GET()
            return
        if not self._static_route_allowed(route):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        super().do_HEAD()

    @staticmethod
    def _basemap_file_allowed(route: str) -> bool:
        """Serve only regular files that really live in DATA_DIR, not symlinks."""
        candidate = APP_DIR / route.lstrip("/")
        try:
            if candidate.is_symlink() or not candidate.is_file():
                return False
            candidate.resolve(strict=True).relative_to(DATA_DIR.resolve(strict=True))
        except (OSError, ValueError):
            return False
        return True

    @staticmethod
    def _static_route_allowed(route: str) -> bool:
        # Normalize after unquoting so encoded traversal cannot slip past the allowlist.
        clean = posixpath.normpath(unquote(route))
        return clean in STATIC_PAGE_ROUTES or bool(STATIC_BASEMAP_ROUTE.fullmatch(clean))

    def do_POST(self) -> None:
        if not self._request_is_local(require_origin=True):
            self._json({"error": "Pulsepath accepts same-origin local requests only."}, status=403)
            return
        route = self.path.split("?", 1)[0]
        if route.startswith("/api/") and not self._api_token_accepted():
            return
        try:
            content_length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            content_length = 0
        if content_length > MAX_JSON_BODY_BYTES:
            # Refuse instead of truncating; unread body bytes would desync the connection.
            self.close_connection = True
            self._json({"error": "The request body is too large."}, status=413)
            return
        if route == "/api/security/recording":
            body = self._read_json()
            if not isinstance(body.get("enabled"), bool):
                self._json({"error": "The enabled field must be true or false."}, status=400)
                return
            self.history.set_recording(body["enabled"])
            self._json(enrich_security_summary(self.history.summary(), self.collector.geoip, self.collector.asn))
            return
        if route == "/api/security/expect":
            body = self._read_json()
            raw_ids = body.get("finding_ids")
            if not isinstance(raw_ids, list) or not self.history.expect_findings(raw_ids):
                self._json({"error": "No matching local finding could be marked expected."}, status=404)
                return
            self._json(enrich_security_summary(self.history.summary(), self.collector.geoip, self.collector.asn))
            return
        if route == "/api/security/clear":
            self.history.clear()
            self._json(enrich_security_summary(self.history.summary(), self.collector.geoip, self.collector.asn))
            return
        if route.startswith("/api/traces/"):
            trace_path = route.removeprefix("/api/traces/").split("/")
            if len(trace_path) == 2 and trace_path[0] and trace_path[1] == "stop":
                job, error = self.traces.stop(trace_path[0])
                status = 200
            elif len(trace_path) == 1 and trace_path[0]:
                job, error = self.traces.start(trace_path[0])
                status = 202
            else:
                self._json({"error": "Not found"}, status=404)
                return
            if error:
                self._json({"error": error}, status=404)
            else:
                self._json(job, status=status)
            return
        self._json({"error": "Not found"}, status=404)

    def _api_token_accepted(self) -> bool:
        if api_token_matches(self.headers.get("X-Pulsepath-Token")):
            return True
        self._json({"error": "Pulsepath rejected this API request."}, status=403)
        return False

    def _request_is_local(self, require_origin: bool = False) -> bool:
        allowed_hosts = {"127.0.0.1", "localhost", "::1"}
        server_port = cast(ThreadingHTTPServer, self.server).server_port
        try:
            host = urlsplit(f"//{self.headers.get('Host', '')}")
            if host.hostname not in allowed_hosts or host.port not in {None, server_port}:
                return False
            if require_origin:
                origin_value = self.headers.get("Origin")
                if not origin_value:
                    return False
                origin = urlsplit(origin_value)
                if origin.scheme != "http" or origin.hostname not in allowed_hosts or origin.port != server_port:
                    return False
                # Second wall: browsers also state the requesting site's
                # relationship. Reject cross-site even if Origin looks local.
                fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
                if fetch_site and fetch_site not in {"same-origin", "none"}:
                    return False
            return True
        except ValueError:
            return False

    def _read_json(self) -> dict[str, Any]:
        try:
            length = min(int(self.headers.get("Content-Length", "0")), MAX_JSON_BODY_BYTES)
            if length <= 0:
                return {}
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            return body if isinstance(body, dict) else {}
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return {}

    def _json(self, body: Any, status: int = 200) -> None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)


def run() -> None:
    parser = argparse.ArgumentParser(description="Run Pulsepath with local metadata-only capture")
    parser.add_argument("--port", type=int, default=4173)
    parser.add_argument("--no-open", action="store_true", help="Do not open the browser automatically")
    args = parser.parse_args()

    history = HistoryEngine()
    collector = FlowCollector(history)
    traces = TraceManager(collector)
    PulsepathHandler.collector = collector
    PulsepathHandler.traces = traces
    PulsepathHandler.history = history
    server = ThreadingHTTPServer(("127.0.0.1", args.port), PulsepathHandler)
    # Write the token only once the port is ours, so a second launch that
    # fails to bind cannot replace the running instance's token.
    try:
        token_file = write_token_file(API_TOKEN)
    except (OSError, RuntimeError) as error:
        server.server_close()
        history.close()
        raise SystemExit(f"Pulsepath refused to start: could not store the session token ({error}).")
    collector.start()

    def stop_server(*_: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop_server)
    signal.signal(signal.SIGTERM, stop_server)

    url = f"http://127.0.0.1:{args.port}/"
    print(f"Pulsepath is running at {url}")
    print(f"Session token stored in {token_file} (open the page with start.command or as {url}#k=<token>).")
    print("Capturing connection metadata only. Press Control-C to stop.")
    if not args.no_open:
        threading.Timer(0.6, lambda: webbrowser.open(f"{url}#k={API_TOKEN}")).start()

    try:
        server.serve_forever()
    finally:
        server.server_close()
        collector.stop()
        history.close()
        remove_token_file(token_file, API_TOKEN)


if __name__ == "__main__":
    run()
