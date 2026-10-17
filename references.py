"""Offline provider reference data: published address ranges and expected app networks.

Standard library only. The collector consults the ranges before the ASN
database, and the history engine uses the app list to raise findings. See
docs/provider-reference.md for what a match does and does not mean.
"""

from __future__ import annotations

import bisect
import datetime as dt
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent
SNAPSHOT_PATH = APP_DIR / "references" / "provider-ranges.json"
REFRESHED_PATH = APP_DIR / "data" / "provider-ranges.json"
APP_NETWORKS_PATH = APP_DIR / "references" / "app-networks.json"

FORMAT = 1
CLASSES = ("service", "hosted", "edge")
STALE_AFTER_DAYS = 60
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PREFIXES = 200_000

# Addresses that never identify a provider: this Mac, the LAN, the carrier's
# NAT, and non-unicast space. Documentation ranges stay valid for tests.
LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(prefix)
    for prefix in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
        "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    )
)

CLASS_CATEGORIES = {"service": "Provider service", "hosted": "Cloud hosting", "edge": "CDN / security edge"}


def parse_address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return None


def is_local_address(value: Any) -> bool:
    """True for addresses that no provider list can describe, or that do not parse."""
    address = parse_address(value)
    if address is None:
        return True
    return any(address in network for network in LOCAL_NETWORKS if network.version == address.version)


def overlaps_local(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return any(network.overlaps(local) for local in LOCAL_NETWORKS if local.version == network.version)


def network_label(service_class: str, tag: str) -> str:
    return {"service": f"{tag} services", "hosted": f"{tag} customer", "edge": f"{tag} edge"}[service_class]


def _parse_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def age_days(value: Any, now: dt.datetime | None = None) -> int | None:
    published = _parse_time(value)
    if published is None:
        return None
    current = now or dt.datetime.now(dt.timezone.utc)
    return max(0, (current - published).days)


@dataclass(frozen=True)
class RangeMatch:
    provider: str
    service_class: str
    tag: str
    anycast: bool
    source: str
    source_name: str
    published: str | None

    @property
    def label(self) -> str:
        return network_label(self.service_class, self.tag)

    @property
    def category(self) -> str:
        return CLASS_CATEGORIES[self.service_class]

    @property
    def stale(self) -> bool:
        age = age_days(self.published)
        return age is not None and age > STALE_AFTER_DAYS


def read_json(path: Path) -> Any:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("file is larger than the reference size limit")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_ranges(document: Any) -> tuple[list[RangeMatch], dict[int, tuple[list[int], list[int], list[int]]]]:
    """Check a provider-ranges document and build disjoint lookup tables per IP version."""
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        raise ValueError("unsupported provider-ranges format")
    if _parse_time(document.get("generated_at")) is None:
        raise ValueError("generated_at is missing or invalid")
    sources = document.get("sources")
    groups = document.get("groups")
    if not isinstance(sources, dict) or not isinstance(groups, list):
        raise ValueError("sources and groups are required")
    matches: list[RangeMatch] = []
    intervals: dict[int, list[tuple[int, int, int]]] = {4: [], 6: []}
    total = 0
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError("group must be an object")
        provider, service_class, tag, source = (group.get(key) for key in ("provider", "class", "tag", "source"))
        if not all(isinstance(value, str) and value for value in (provider, tag, source)) or service_class not in CLASSES:
            raise ValueError("group needs provider, tag, source and a known class")
        info = sources.get(source)
        if not isinstance(info, dict):
            raise ValueError(f"group names unknown source {source!r}")
        index = len(matches)
        matches.append(RangeMatch(
            provider=provider, service_class=service_class, tag=tag, anycast=bool(group.get("anycast")),
            source=source, source_name=str(info.get("name") or source), published=info.get("published"),
        ))
        for field, version in (("v4", 4), ("v6", 6)):
            prefixes = group.get(field) or []
            if not isinstance(prefixes, list):
                raise ValueError(f"{field} must be a list")
            total += len(prefixes)
            if total > MAX_PREFIXES:
                raise ValueError("too many prefixes")
            for prefix in prefixes:
                network = ipaddress.ip_network(prefix)
                if network.version != version or overlaps_local(network):
                    raise ValueError(f"prefix {prefix} is not a public {field} range")
                intervals[version].append((int(network.network_address), int(network.broadcast_address), index))
    tables: dict[int, tuple[list[int], list[int], list[int]]] = {}
    for version, rows in intervals.items():
        rows.sort()
        for previous, current in zip(rows, rows[1:]):
            if current[0] <= previous[1]:
                raise ValueError("provider ranges overlap")
        tables[version] = ([row[0] for row in rows], [row[1] for row in rows], [row[2] for row in rows])
    return matches, tables


class ProviderRanges:
    """Longest-published-prefix lookup over one validated provider-ranges file."""

    def __init__(
        self, document: dict[str, Any] | None = None, path: Path | None = None, error: str | None = None,
    ) -> None:
        self.document = document
        self.path = path
        self.error = error
        self._matches: list[RangeMatch] = []
        self._tables: dict[int, tuple[list[int], list[int], list[int]]] = {}
        if document is not None:
            self._matches, self._tables = validate_ranges(document)

    @classmethod
    def load(cls, snapshot: Path = SNAPSHOT_PATH, refreshed: Path = REFRESHED_PATH) -> ProviderRanges:
        """Use whichever valid file is newer; a refreshed copy wins a tie."""
        candidates: list[tuple[dt.datetime, int, ProviderRanges]] = []
        errors: list[str] = []
        for rank, path in enumerate((refreshed, snapshot)):
            if not path.exists():
                continue
            try:
                ranges = cls(read_json(path), path)
            except (OSError, ValueError) as error:
                errors.append(f"{path.name}: {error}")
                continue
            candidates.append((_parse_time(ranges.document["generated_at"]), -rank, ranges))
        if not candidates:
            return cls(error="; ".join(errors) or "no provider range file")
        chosen = max(candidates, key=lambda item: (item[0], item[1]))[2]
        chosen.error = "; ".join(errors) or None
        return chosen

    @property
    def available(self) -> bool:
        return self.document is not None

    def lookup(self, host: Any) -> RangeMatch | None:
        address = parse_address(host)
        if address is None:
            return None
        table = self._tables.get(address.version)
        if not table:
            return None
        starts, ends, groups = table
        value = int(address)
        index = bisect.bisect_right(starts, value) - 1
        if index < 0 or value > ends[index]:
            return None
        return self._matches[groups[index]]

    def status(self) -> dict[str, Any]:
        if self.document is None:
            return {"state": "unavailable", "error": self.error}
        sources = {}
        for key, info in sorted(self.document["sources"].items()):
            age = age_days(info.get("published"))
            sources[key] = {
                "name": info.get("name") or key,
                "published": info.get("published"),
                "age_days": age,
                "stale": age is not None and age > STALE_AFTER_DAYS,
            }
        return {
            "state": "stale" if any(source["stale"] for source in sources.values()) else "ok",
            "file": self.path.name if self.path else None,
            "generated_at": self.document["generated_at"],
            "sources": sources,
            "error": self.error,
        }


@dataclass(frozen=True)
class AppExpectation:
    app: str
    processes: tuple[str, ...]
    expected: tuple[tuple[str, str | None], ...]
    source: str

    def providers(self) -> list[str]:
        return list(dict.fromkeys(provider for provider, _ in self.expected))


class AppNetworks:
    """Hand-curated networks that well-known apps are expected to use."""

    def __init__(self, apps: tuple[AppExpectation, ...] = (), reviewed: str | None = None, error: str | None = None) -> None:
        self.apps = apps
        self.reviewed = reviewed
        self.error = error

    @classmethod
    def load(cls, path: Path = APP_NETWORKS_PATH) -> AppNetworks:
        try:
            document = read_json(path)
            return cls(*cls._validate(document))
        except (OSError, ValueError) as error:
            return cls(error=f"{path.name}: {error}")

    @staticmethod
    def _validate(document: Any) -> tuple[tuple[AppExpectation, ...], str]:
        if not isinstance(document, dict) or document.get("format") != FORMAT:
            raise ValueError("unsupported app-networks format")
        reviewed = document.get("reviewed")
        if _parse_time(reviewed) is None:
            raise ValueError("reviewed date is missing or invalid")
        apps = []
        for entry in document.get("apps") or []:
            processes = entry.get("processes") if isinstance(entry, dict) else None
            expected = entry.get("expected") if isinstance(entry, dict) else None
            if (
                not isinstance(entry.get("app"), str) or not entry["app"]
                or not isinstance(entry.get("source"), str) or not entry["source"]
                or not isinstance(processes, list) or not processes
                or not all(isinstance(process, str) and process.strip() for process in processes)
                or not isinstance(expected, list) or not expected
            ):
                raise ValueError("each app needs app, processes, expected and source")
            pairs = []
            for item in expected:
                if not isinstance(item, dict) or not isinstance(item.get("provider"), str) or not item["provider"]:
                    raise ValueError(f"{entry['app']}: expected entries need a provider")
                if item.get("class") is not None and item["class"] not in CLASSES:
                    raise ValueError(f"{entry['app']}: unknown class {item['class']!r}")
                pairs.append((item["provider"], item.get("class")))
            apps.append(AppExpectation(
                app=entry["app"], processes=tuple(process.strip().casefold() for process in processes),
                expected=tuple(pairs), source=entry["source"],
            ))
        return tuple(apps), reviewed

    def expectation(self, process: str) -> AppExpectation | None:
        name = process.strip().casefold()
        return next((app for app in self.apps if any(name.startswith(prefix) for prefix in app.processes)), None)

    @staticmethod
    def allows(app: AppExpectation, provider: str | None, service_class: str | None) -> bool:
        if not provider:
            return False
        return any(
            provider == expected and (wanted is None or wanted == service_class)
            for expected, wanted in app.expected
        )

    def status(self) -> dict[str, Any]:
        if self.error:
            return {"state": "unavailable", "error": self.error}
        return {"state": "ok", "reviewed": self.reviewed, "apps": len(self.apps)}
