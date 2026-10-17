from __future__ import annotations

import datetime as dt
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import install_references
import pulsepath
import references

GOOGLE_ASN = {"number": 15169, "organization": "Google LLC"}


def ranges_document(generated_at: str = "2026-09-25T00:00:00Z", extra: list[dict] | None = None) -> dict:
    """Synthetic provider ranges on documentation prefixes only."""
    groups = [
        {"provider": "Google", "class": "service", "tag": "Google", "source": "test", "v4": ["192.0.2.0/25"], "v6": []},
        {"provider": "Google", "class": "hosted", "tag": "Google Cloud", "source": "test",
         "v4": ["192.0.2.128/25"], "v6": ["2001:db8::/32"]},
        {"provider": "Cloudflare", "class": "edge", "tag": "Cloudflare", "source": "test", "anycast": True,
         "v4": ["198.51.100.0/24"], "v6": []},
    ]
    return {
        "format": 1,
        "generated_at": generated_at,
        "sources": {"test": {"name": "Test", "published": "2026-09-20T00:00:00Z"}},
        "groups": groups + (extra or []),
    }


class StubASN:
    def lookup(self, ip: str) -> dict:
        return GOOGLE_ASN


class ProviderRangesTests(unittest.TestCase):
    def test_lookup_returns_the_single_matching_group(self) -> None:
        ranges = references.ProviderRanges(ranges_document())
        self.assertEqual(ranges.lookup("192.0.2.10").label, "Google services")
        self.assertEqual(ranges.lookup("192.0.2.200").label, "Google Cloud customer")
        self.assertEqual(ranges.lookup("2001:db8::5").service_class, "hosted")
        self.assertTrue(ranges.lookup("198.51.100.7").anycast)
        self.assertIsNone(ranges.lookup("203.0.113.1"))

    def test_invalid_file_is_skipped_and_newer_valid_file_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot, refreshed = Path(directory, "snapshot.json"), Path(directory, "refreshed.json")
            overlapping = ranges_document("2026-09-26T00:00:00Z", extra=[
                {"provider": "Fastly", "class": "edge", "tag": "Fastly", "source": "test", "v4": ["192.0.2.0/24"], "v6": []},
            ])
            refreshed.write_text(json.dumps(overlapping))
            snapshot.write_text(json.dumps(ranges_document()))
            ranges = references.ProviderRanges.load(snapshot, refreshed)
            self.assertEqual(ranges.path, snapshot, "an overlapping file must not be used")
            self.assertIn("overlap", ranges.error)

            refreshed.write_text(json.dumps(ranges_document("2026-09-26T00:00:00Z")))
            self.assertEqual(references.ProviderRanges.load(snapshot, refreshed).path, refreshed)


class GeneratorTests(unittest.TestCase):
    NOW = dt.datetime(2026, 9, 25, tzinfo=dt.timezone.utc)

    def aws(self, prefixes: list[tuple[str, str]]) -> bytes:
        return json.dumps({
            "syncToken": "1", "createDate": "2026-09-25-01-00-00",
            "prefixes": [{"ip_prefix": prefix, "service": service} for prefix, service in prefixes],
            "ipv6_prefixes": [],
        }).encode()

    def build(self, aws: bytes, previous: dict | None = None) -> tuple[dict, list[str]]:
        google = [
            json.dumps({"syncToken": "2", "prefixes": [{"ipv4Prefix": "203.0.113.0/24"}]}).encode(),
            json.dumps({"prefixes": [{"ipv4Prefix": "203.0.113.0/25"}]}).encode(),
        ]
        return install_references.build_document({"aws": [aws], "google": google}, previous, self.NOW)

    def classes(self, document: dict) -> dict[str, str]:
        ranges = references.ProviderRanges(document)
        return {ip: ranges.lookup(ip).label for ip in ("192.0.2.1", "192.0.2.200", "198.51.100.1", "203.0.113.1", "203.0.113.200")}

    def test_class_rules_resolve_overlapping_listings(self) -> None:
        document, _ = self.build(self.aws([
            ("192.0.2.0/25", "AMAZON"), ("192.0.2.0/25", "CLOUDFRONT"),
            ("192.0.2.128/25", "AMAZON"),
            ("198.51.100.0/24", "AMAZON"), ("198.51.100.0/24", "EC2"),
        ]))
        self.assertEqual(self.classes(document), {
            "192.0.2.1": "CloudFront edge",
            "192.0.2.200": "Amazon services",
            "198.51.100.1": "AWS customer",
            "203.0.113.1": "Google Cloud customer",
            "203.0.113.200": "Google services",
        })

    def test_a_source_that_shrinks_by_half_keeps_its_previous_ranges(self) -> None:
        previous, _ = self.build(self.aws([
            ("192.0.2.0/25", "CLOUDFRONT"), ("192.0.2.128/25", "AMAZON"), ("198.51.100.0/25", "EC2"), ("198.51.100.128/25", "EC2"),
        ]))
        document, warnings = self.build(self.aws([("192.0.2.0/25", "CLOUDFRONT")]), previous)
        self.assertTrue(any("AWS shrank" in warning for warning in warnings))
        self.assertEqual(self.classes(document)["198.51.100.1"], "AWS customer")
        self.assertEqual(document["sources"]["aws"]["prefix_count"], 4)


class ProviderHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.engine = pulsepath.HistoryEngine(
            Path(self.directory.name) / "history.sqlite3",
            learning_seconds=0, learning_connections=0, minimum_learning_seconds=0,
        )
        self.ranges = patch.object(pulsepath, "PROVIDER_RANGES", references.ProviderRanges(ranges_document()))
        self.ranges.start()

    def tearDown(self) -> None:
        self.ranges.stop()
        self.engine.close()
        self.directory.cleanup()

    def observe(self, remote_ip: str, remote_port: int = 443, process: str = "Example App") -> None:
        flow = {
            "process": process, "protocol": "TCP", "remote_ip": remote_ip, "remote_port": remote_port,
            "service": pulsepath.service_name(remote_port, "TCP"), "scope": "public",
            "network_reference": pulsepath.network_reference(remote_ip, GOOGLE_ASN),
        }
        flow["destination_key"], flow["grouping"] = pulsepath.flow_destination_key(flow)
        self.engine.observe_batch([flow])
        self.engine.last_recorded.clear()

    def findings(self) -> list[dict]:
        return self.engine.summary()["findings"]

    def test_a_new_class_of_a_known_provider_is_a_new_network(self) -> None:
        for port in (443, 8443, 5222):
            self.observe("192.0.2.10", port)
        self.observe("192.0.2.200")
        finding = self.findings()[0]
        self.assertEqual(finding["title"], "New network for Example App")
        self.assertIn("First connection to a Google Cloud customer", finding["explanation"])

    def test_a_class_used_before_the_upgrade_is_not_new(self) -> None:
        for port in (443, 8443, 5222):
            self.observe("192.0.2.10", port)
        # A pre-upgrade stream kept only its latest address; the sighting of the
        # hosted address survives in ip_sightings.
        with self.engine.connection:
            self.engine.connection.execute(
                "INSERT INTO ip_sightings(remote_ip, process_key, process, protocol, remote_port, service, "
                "first_seen, last_seen, observation_count) VALUES('192.0.2.201', 'example app', 'Example App', "
                "'TCP', 443, 'HTTPS', ?, ?, 1)", (time.time() - 60, time.time() - 60),
            )
        self.observe("192.0.2.200")
        self.assertEqual(self.findings(), [])

    def test_backfill_classifies_and_rekeys_legacy_rows_with_their_findings(self) -> None:
        with patch.object(pulsepath, "PROVIDER_RANGES", references.ProviderRanges()):
            # A new-port finding needs four earlier streams for the app.
            for port in (443, 8443, 5222, 5223, 993):
                self.observe("192.0.2.200", port)
        legacy = self.engine.connection.execute(
            "SELECT fingerprint FROM connections WHERE remote_port = 993").fetchone()["fingerprint"]
        self.assertTrue(self.engine.connection.execute(
            "SELECT 1 FROM findings WHERE fingerprint = ?", (legacy,)).fetchone())

        self.engine.enrich_network_ownership(StubASN())
        row = self.engine.connection.execute(
            "SELECT fingerprint, network_class, destination_key FROM connections WHERE remote_port = 993").fetchone()
        self.assertEqual((row["network_class"], row["destination_key"]), ("hosted", "provider:google:hosted"))
        self.assertNotEqual(row["fingerprint"], legacy)
        self.assertTrue(self.engine.connection.execute(
            "SELECT 1 FROM findings WHERE fingerprint = ?", (row["fingerprint"],)).fetchone(),
            "the finding follows its re-keyed row")

    def test_unexpected_network_is_raised_while_learning(self) -> None:
        self.engine.learning_seconds = 3600
        self.engine.learning_connections = 1000
        self.engine.minimum_learning_seconds = 3600
        apps = references.AppNetworks((references.AppExpectation(
            app="Example App", processes=("example",), expected=(("Meta", None),), source="test",
        ),), reviewed="2026-09-25")
        with patch.object(pulsepath, "APP_NETWORKS", apps):
            self.observe("192.0.2.200")
        finding = self.findings()[0]
        self.assertEqual(finding["title"], "Unexpected network for Example App")
        self.assertEqual(finding["explanation"], "Example App usually uses Meta. This connection goes to a Google Cloud customer.")
        self.assertEqual(finding["evidence"]["event_type"], "unexpected_network")

    def test_a_stream_accepted_before_classes_stays_accepted(self) -> None:
        with self.engine.connection:
            self.engine.connection.execute(
                "INSERT INTO expectations(stream_key, process, protocol, destination_key, remote_port, accepted_at) "
                "VALUES('example app|TCP|provider:google|443', 'Example App', 'TCP', 'provider:google', 443, 0)")
        self.assertTrue(self.engine._stream_is_expected({
            "process": "Example App", "protocol": "TCP", "destination_key": "provider:google:hosted", "remote_port": 443,
        }))


if __name__ == "__main__":
    unittest.main()
