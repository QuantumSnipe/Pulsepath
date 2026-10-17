#!/usr/bin/env python3
"""Fetch providers' published address lists into Pulsepath's offline reference.

Run `make update-references`. Every list comes straight from the provider over
HTTPS and is the same download for every user; nothing about this Mac's
connections is sent. See docs/provider-reference.md.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import ipaddress
import json
import os
import sys
import tempfile
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import references

MAX_RESPONSE_BYTES = 16 * 1024 * 1024
TIMEOUT_SECONDS = 45
# A source that suddenly lists fewer than half its previous prefixes is more
# likely broken or tampered with than genuinely shrinking.
SHRINK_LIMIT = 0.5
# When one address appears under several classes, the stronger claim wins:
# a CDN edge over a customer range, and a customer range over the provider's
# own blanket announcement (AWS lists every prefix under AMAZON as well).
CLASS_RANK = {"service": 0, "hosted": 1, "edge": 2}

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Group:
    provider: str
    service_class: str
    tag: str
    anycast: bool = False


@dataclass(frozen=True)
class Parsed:
    entries: list[tuple[str, Group]]
    version: str | None = None
    published: str | None = None


@dataclass(frozen=True)
class Source:
    key: str
    name: str
    urls: tuple[str, ...]
    parse: Callable[[list[bytes]], Parsed]


def iso_time(value: str | None, pattern: str | None = None) -> str | None:
    """Normalize a provider's timestamp to UTC ISO 8601, or None if unreadable."""
    if not value:
        return None
    try:
        parsed = dt.datetime.strptime(value, pattern) if pattern else dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def text_lines(body: bytes) -> list[str]:
    return [line.strip() for line in body.decode("utf-8").splitlines() if line.strip() and not line.startswith("#")]


def parse_cloudflare(bodies: list[bytes]) -> Parsed:
    group = Group("Cloudflare", "edge", "Cloudflare", anycast=True)
    return Parsed([(line, group) for body in bodies for line in text_lines(body)])


def parse_google(bodies: list[bytes]) -> Parsed:
    goog, cloud = (json.loads(body) for body in bodies)

    def prefixes(document: dict[str, Any]) -> list[str]:
        return [item.get("ipv4Prefix") or item.get("ipv6Prefix") for item in document.get("prefixes", [])]

    # goog.json covers everything Google announces; cloud.json is the part
    # customers rent. The class rank makes "goog minus cloud" the service part.
    service, hosted = Group("Google", "service", "Google"), Group("Google", "hosted", "Google Cloud")
    entries = [(prefix, service) for prefix in prefixes(goog) if prefix]
    entries += [(prefix, hosted) for prefix in prefixes(cloud) if prefix]
    return Parsed(entries, str(goog.get("syncToken") or ""), iso_time(goog.get("creationTime")))


AWS_EDGE = {"CLOUDFRONT"}
# Customer workloads and customer content: servers, buckets, APIs and
# accelerators that anyone can rent.
AWS_HOSTED = {"EC2", "S3", "API_GATEWAY", "GLOBALACCELERATOR"}


def parse_aws(bodies: list[bytes]) -> Parsed:
    document = json.loads(bodies[0])
    groups = {
        "edge": Group("Amazon Web Services", "edge", "CloudFront"),
        "hosted": Group("Amazon Web Services", "hosted", "AWS"),
        "service": Group("Amazon Web Services", "service", "Amazon"),
    }
    entries = []
    for field, key in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        for item in document.get(field, []):
            service = item.get("service")
            cls = "edge" if service in AWS_EDGE else "hosted" if service in AWS_HOSTED else "service"
            if item.get(key):
                entries.append((item[key], groups[cls]))
    return Parsed(entries, str(document.get("syncToken") or ""), iso_time(document.get("createDate"), "%Y-%m-%d-%H-%M-%S"))


def parse_fastly(bodies: list[bytes]) -> Parsed:
    document = json.loads(bodies[0])
    group = Group("Fastly", "edge", "Fastly", anycast=True)
    return Parsed([(prefix, group) for field in ("addresses", "ipv6_addresses") for prefix in document.get(field, [])])


def parse_oracle(bodies: list[bytes]) -> Parsed:
    document = json.loads(bodies[0])
    group = Group("Oracle", "hosted", "Oracle Cloud")
    entries = [(cidr["cidr"], group) for region in document.get("regions", []) for cidr in region.get("cidrs", []) if cidr.get("cidr")]
    return Parsed(entries, None, iso_time(document.get("last_updated_timestamp")))


def parse_digitalocean(bodies: list[bytes]) -> Parsed:
    group = Group("DigitalOcean", "hosted", "DigitalOcean")
    rows = csv.reader(io.StringIO("\n".join(text_lines(bodies[0]))))
    return Parsed([(row[0].strip(), group) for row in rows if row and row[0].strip()])


# Only GitHub's own service keys. The Actions and Codespaces lists are large
# Azure customer ranges that GitHub rents, not GitHub services.
GITHUB_KEYS = ("hooks", "web", "api", "git", "packages", "pages", "importer", "copilot")


def parse_github(bodies: list[bytes]) -> Parsed:
    document = json.loads(bodies[0])
    group = Group("GitHub", "service", "GitHub")
    return Parsed([(prefix, group) for key in GITHUB_KEYS for prefix in document.get(key) or []])


def parse_apple(_: list[bytes]) -> Parsed:
    # Apple holds 17.0.0.0/8 in the ARIN registry; there is no list to fetch.
    return Parsed([("17.0.0.0/8", Group("Apple", "service", "Apple"))])


# Order matters: when two sources publish the same prefix, the earlier wins.
SOURCES = (
    Source("cloudflare", "Cloudflare", ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"), parse_cloudflare),
    Source("google", "Google", ("https://www.gstatic.com/ipranges/goog.json", "https://www.gstatic.com/ipranges/cloud.json"), parse_google),
    Source("aws", "AWS", ("https://ip-ranges.amazonaws.com/ip-ranges.json",), parse_aws),
    Source("fastly", "Fastly", ("https://api.fastly.com/public-ip-list",), parse_fastly),
    Source("oracle", "Oracle", ("https://docs.oracle.com/iaas/tools/public_ip_ranges.json",), parse_oracle),
    Source("digitalocean", "DigitalOcean", ("https://digitalocean.com/geo/google.csv",), parse_digitalocean),
    Source("github", "GitHub", ("https://api.github.com/meta",), parse_github),
    Source("apple", "Apple", (), parse_apple),
)


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "Pulsepath/0.1"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        if urlsplit(response.geturl()).scheme != "https":
            raise RuntimeError("redirected away from HTTPS")
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise RuntimeError(f"response exceeded the {MAX_RESPONSE_BYTES // (1024 * 1024)} MB limit")
    return body


def public_networks(entries: list[tuple[str, Group]]) -> tuple[list[tuple[Network, Group]], int]:
    """Parse prefixes, dropping malformed ones and anything overlapping local space."""
    accepted, skipped = [], 0
    for prefix, group in entries:
        try:
            network = ipaddress.ip_network(prefix.strip(), strict=False)
        except (ValueError, AttributeError):
            skipped += 1
            continue
        if references.overlaps_local(network):
            skipped += 1
            continue
        accepted.append((network, group))
    return accepted, skipped


def paint(entries: list[tuple[Network, tuple[Group, str], tuple[int, int]]]) -> dict[tuple[Group, str], dict[int, list[Network]]]:
    """Resolve overlaps so every address belongs to exactly one group.

    CIDR blocks either nest or are disjoint, so a sweep with a stack gives each
    address to its most specific prefix. Identical prefixes keep the highest
    score (earlier source, then stronger class).
    """
    best: dict[Network, tuple[tuple[Group, str], tuple[int, int]]] = {}
    for network, key, score in entries:
        if network not in best or score > best[network][1]:
            best[network] = (key, score)
    painted: dict[tuple[Group, str], dict[int, list[Network]]] = defaultdict(lambda: {4: [], 6: []})
    for version in (4, 6):
        networks = sorted((net for net in best if net.version == version), key=lambda net: (int(net.network_address), net.prefixlen))
        segments: list[tuple[int, int, tuple[Group, str]]] = []
        stack: list[tuple[int, tuple[Group, str]]] = []
        cursor = 0

        def close(until: int) -> None:
            nonlocal cursor
            while stack and stack[-1][0] < until:
                end, key = stack.pop()
                if cursor <= end:
                    segments.append((cursor, end, key))
                cursor = end + 1

        for network in networks:
            start, end = int(network.network_address), int(network.broadcast_address)
            close(start)
            if stack and cursor < start:
                segments.append((cursor, start - 1, stack[-1][1]))
            stack.append((end, best[network][0]))
            cursor = start
        close(1 << 128)
        merged: list[list[Any]] = []
        for start, end, key in segments:
            if merged and merged[-1][2] == key and merged[-1][1] + 1 == start:
                merged[-1][1] = end
            else:
                merged.append([start, end, key])
        address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        for start, end, key in merged:
            painted[key][version].extend(ipaddress.summarize_address_range(address(start), address(end)))
    return painted


def previous_entries(previous: dict[str, Any] | None, key: str) -> list[tuple[Network, Group]]:
    entries = []
    for group in (previous or {}).get("groups", []):
        if group.get("source") != key:
            continue
        identity = Group(group["provider"], group["class"], group["tag"], bool(group.get("anycast")))
        entries += [(ipaddress.ip_network(prefix), identity) for field in ("v4", "v6") for prefix in group.get(field, [])]
    return entries


def build_document(
    fetched: dict[str, list[bytes] | Exception], previous: dict[str, Any] | None, now: dt.datetime,
) -> tuple[dict[str, Any], list[str]]:
    """Normalize fetched bodies into a provider-ranges document.

    Returns the document and one warning per source that kept its previous
    ranges (failed, empty, or shrank past SHRINK_LIMIT).
    """
    generated_at = now.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    previous_sources = (previous or {}).get("sources", {})
    sources: dict[str, Any] = {}
    entries: list[tuple[Network, tuple[Group, str], tuple[int, int]]] = []
    warnings: list[str] = []
    for index, source in enumerate(SOURCES):
        result = fetched.get(source.key, [])
        kept_reason = None
        try:
            if isinstance(result, Exception):
                raise result
            parsed = source.parse(result)
            networks, skipped = public_networks(parsed.entries)
            earlier = int(previous_sources.get(source.key, {}).get("prefix_count") or 0)
            if not networks:
                kept_reason = "returned no usable prefixes"
            elif earlier and len(networks) < earlier * SHRINK_LIMIT:
                kept_reason = f"shrank from {earlier} to {len(networks)} prefixes"
        except Exception as error:  # noqa: BLE001 - any parse failure keeps the previous data
            kept_reason = f"failed: {error}"
        if kept_reason:
            networks = previous_entries(previous, source.key)
            info = dict(previous_sources.get(source.key) or {})
            warnings.append(
                f"{source.name} {kept_reason}; "
                + ("kept its previous ranges." if networks else "no previous ranges to keep.")
            )
            if not networks:
                continue
        else:
            info = {
                "name": source.name,
                "urls": list(source.urls),
                "version": parsed.version or None,
                # Lists without their own timestamp are dated by this fetch,
                # so their age still says how long ago they were checked.
                "published": parsed.published or (generated_at if source.urls else None),
                "prefix_count": len(networks),
                "skipped": skipped,
            }
        sources[source.key] = info
        entries += [(network, (group, source.key), (-index, CLASS_RANK[group.service_class])) for network, group in networks]

    groups = []
    for (group, key), prefixes in paint(entries).items():
        groups.append({
            "provider": group.provider, "class": group.service_class, "tag": group.tag, "source": key,
            "anycast": group.anycast,
            "v4": [str(network) for network in prefixes[4]],
            "v6": [str(network) for network in prefixes[6]],
        })
    groups.sort(key=lambda item: (item["provider"], item["class"], item["tag"], item["source"]))
    document = {"format": references.FORMAT, "generated_at": generated_at, "sources": sources, "groups": groups}
    references.validate_ranges(document)
    return document, warnings


def write_atomically(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".part")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=1)
            output.write("\n")
        # mkstemp creates owner-only files; this is public data meant to be committed.
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def load_previous(paths: list[Path]) -> dict[str, Any] | None:
    """The newest valid existing document, used for per-source fallback."""
    newest = None
    for path in paths:
        try:
            document = references.read_json(path)
            references.validate_ranges(document)
        except (OSError, ValueError):
            continue
        if newest is None or document["generated_at"] > newest["generated_at"]:
            newest = document
    return newest


def main() -> int:
    parser = argparse.ArgumentParser(description="Update Pulsepath's offline provider address reference")
    parser.add_argument(
        "--snapshot", action="store_true",
        help="maintainers: write the committed snapshot in references/ instead of data/",
    )
    args = parser.parse_args()
    target = references.SNAPSHOT_PATH if args.snapshot else references.REFRESHED_PATH
    previous = load_previous([references.SNAPSHOT_PATH] if args.snapshot else [references.REFRESHED_PATH, references.SNAPSHOT_PATH])

    fetched: dict[str, list[bytes] | Exception] = {}
    for source in SOURCES:
        try:
            fetched[source.key] = [fetch(url) for url in source.urls]
        except Exception as error:  # noqa: BLE001 - reported per source below
            fetched[source.key] = error
    document, warnings = build_document(fetched, previous, dt.datetime.now(dt.timezone.utc))
    for key, info in document["sources"].items():
        print(f"{info.get('name', key)}: {info.get('prefix_count', 0)} prefixes"
              + (f", published {info['published']}" if info.get("published") else ""))
    for warning in warnings:
        print(f"Warning: {warning}", file=sys.stderr)
    write_atomically(target, document)
    print(f"Wrote {target.relative_to(references.APP_DIR)} ({len(document['groups'])} groups).")
    if not args.snapshot:
        print("Restart Pulsepath (make restart) to use it.")
    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
