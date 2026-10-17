from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import pulsepath


def flow(remote_ip: str, remote_port: int = 443, country: str = "United States") -> dict[str, object]:
    return {
        "process": "Example App",
        "protocol": "TCP",
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "service": pulsepath.service_name(remote_port, "TCP"),
        "scope": "public",
        "interface": "utun0",
        "rtt_ms": 25.0,
        "bytes_in": 200,
        "bytes_out": 100,
        "geo": {"country": country, "country_code": "US", "city": "Example City"},
    }


class HistoryEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.engine = pulsepath.HistoryEngine(
            Path(self.temporary_directory.name) / "history.sqlite3",
            learning_seconds=0,
            learning_connections=0,
            minimum_learning_seconds=0,
        )

    def tearDown(self) -> None:
        self.engine.close()
        self.temporary_directory.cleanup()

    def observe_once(self, item: dict[str, object]) -> None:
        self.engine.last_recorded.clear()
        self.engine.observe_batch([item])

    def test_history_identity_ignores_pid_and_local_port(self) -> None:
        first = pulsepath.history_identity("ExampleApp", "TCP", "203.0.113.33", 5222)
        second = pulsepath.history_identity("exampleapp", "tcp", "203.0.113.33", 5222)
        self.assertEqual(first, second)

    def test_first_app_connection_builds_baseline_without_warning(self) -> None:
        self.observe_once(flow("192.0.2.1"))
        summary = self.engine.summary()
        self.assertEqual(summary["connection_count"], 1)
        self.assertEqual(summary["service_count"], 1)
        self.assertEqual(summary["findings"], [])

    def test_known_connection_interface_changes_bypass_counter_throttle(self) -> None:
        item = flow("192.0.2.1")
        with patch("pulsepath.time.time", return_value=1000):
            self.engine.observe_batch([item])
        with patch("pulsepath.time.time", return_value=1001):
            self.engine.observe_batch([{**item, "interface": "en0"}])
            # The same interface class on a different physical interface is
            # not a second VPN/direct transition.
            self.engine.observe_batch([{**item, "interface": "en1"}])
        with patch("pulsepath.time.time", return_value=1002):
            self.engine.observe_batch([item])

        findings = self.engine.summary()["findings"]
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["evidence"]["previous_network"], "direct network")
        self.assertEqual(findings[0]["evidence"]["network"], "VPN tunnel")
        self.assertEqual(findings[1]["evidence"]["previous_network"], "VPN tunnel")
        self.assertEqual(findings[1]["evidence"]["network"], "direct network")
        self.assertTrue(all(finding["evidence"]["event_type"] == "interface_change" for finding in findings))
        self.assertEqual(self.engine.summary()["connection_count"], 1)

    def test_repeated_changes_preserve_novelty_finding_and_survive_restart(self) -> None:
        self.observe_once(flow("192.0.2.1"))
        item = flow("192.0.2.2")
        self.observe_once(item)
        original_id = self.engine.summary()["findings"][0]["id"]
        # Exercise multiple transitions with identical timestamps: event
        # identity must not depend on wall-clock precision.
        with patch("pulsepath.time.time", return_value=time.time() + 1):
            self.engine.observe_batch([{**item, "interface": "en0"}])
            self.engine.observe_batch([item])
        database_path = self.engine.database_path
        self.engine.close()
        self.engine = pulsepath.HistoryEngine(
            database_path, learning_seconds=0, learning_connections=0, minimum_learning_seconds=0,
        )
        self.engine.observe_batch([item])
        self.engine.observe_batch([{**item, "interface": "en0"}])
        findings = self.engine.summary()["findings"]
        self.assertEqual(len(findings), 4)
        self.assertIn(original_id, [finding["id"] for finding in findings])
        self.assertEqual(len({finding["fingerprint"] for finding in findings}), 4)

    def test_learning_updates_interface_baseline_without_findings(self) -> None:
        self.engine.learning_seconds = 10
        self.engine.learning_connections = 30
        item = flow("192.0.2.1")
        with patch("pulsepath.time.time", return_value=1000):
            self.engine.observe_batch([item])
        with patch("pulsepath.time.time", return_value=1001):
            self.engine.observe_batch([{**item, "interface": "en0"}])
        self.assertEqual(self.engine.summary()["findings"], [])
        with patch("pulsepath.time.time", return_value=1011):
            self.engine.observe_batch([{**item, "interface": "en0"}])
        self.assertEqual(self.engine.summary()["findings"], [])
        with patch("pulsepath.time.time", return_value=1012):
            self.engine.observe_batch([item])
        self.assertEqual(len(self.engine.summary()["findings"]), 1)

    def test_paused_interface_observations_do_not_record_events_or_update_baseline(self) -> None:
        item = flow("192.0.2.1")
        self.observe_once(item)
        self.engine.set_recording(False)
        self.engine.observe_batch([{**item, "interface": "en0"}])
        self.assertEqual(self.engine.summary()["findings"], [])
        self.engine.set_recording(True)
        self.engine.observe_batch([item])
        self.assertEqual(self.engine.summary()["findings"], [])
        self.engine.observe_batch([{**item, "interface": "en0"}])
        self.assertEqual(len(self.engine.summary()["findings"]), 1)

    def test_unknown_or_mixed_interfaces_break_transition_comparison(self) -> None:
        item = flow("192.0.2.1")
        for unknown in (None, "", "lo0", "bridge0", "unknown", "utun?", "en?", 42):
            with self.subTest(interface=unknown):
                self.engine.clear()
                self.engine.observe_batch([item])
                self.engine.observe_batch([{**item, "interface": unknown}])
                self.engine.observe_batch([{**item, "interface": "en0"}])
                self.assertEqual(self.engine.summary()["findings"], [])
        self.engine.clear()
        self.engine.observe_batch([item])
        self.engine.observe_batch([{**item, "interface": None, "interfaces": ["utun0", "en0"]}])
        self.engine.observe_batch([{**item, "interface": "en0"}])
        self.assertEqual(self.engine.summary()["findings"], [])

    def test_grouped_interfaces_compare_classes_only_when_unambiguous(self) -> None:
        item = {**flow("192.0.2.1"), "interface": None, "interfaces": ["utun2", "utun0"]}
        self.engine.observe_batch([item])
        self.engine.observe_batch([{**item, "interfaces": ["en0", "en1"]}])
        findings = self.engine.summary()["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["interfaces"], ["en0", "en1"])

    def test_group_with_unknown_socket_does_not_inherit_other_socket_interface(self) -> None:
        item = {**flow("192.0.2.1"), "id": "socket-1", "first_seen": 1000, "last_seen": 1000}
        self.engine.observe_batch(pulsepath.aggregate_flow_records([item]))
        incomplete_group = pulsepath.aggregate_flow_records([
            {**item, "interface": "en0"},
            {**item, "id": "socket-2", "interface": None},
        ])
        # The display summary has only known interface names; the individual
        # socket evidence must keep this partial observation ambiguous.
        self.assertEqual(incomplete_group[0]["interfaces"], ["en0"])
        self.engine.observe_batch(incomplete_group)
        self.assertEqual(self.engine.summary()["findings"], [])
        self.engine.observe_batch(pulsepath.aggregate_flow_records([{**item, "interface": "en0"}]))
        self.assertEqual(self.engine.summary()["findings"], [])
        self.engine.observe_batch(pulsepath.aggregate_flow_records([item]))
        findings = self.engine.summary()["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["previous_network"], "direct network")
        self.assertEqual(findings[0]["evidence"]["network"], "VPN tunnel")

    def test_identity_upgrade_preserves_interface_transition(self) -> None:
        item = flow("192.0.2.1")
        self.observe_once(item)
        upgraded = {**item, "destination_key": "service:https", "grouping": "service", "interface": "en0"}
        self.engine.observe_batch([upgraded])
        self.assertEqual(self.engine.summary()["connection_count"], 1)
        findings = self.engine.summary()["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["event_type"], "interface_change")

    def test_provider_key_keeps_rotating_edge_ips_in_one_service_profile(self) -> None:
        first = flow("104.16.0.1")
        first["network_reference"] = pulsepath.network_reference("104.16.0.1")
        first["destination_key"] = "provider:cloudflare"
        first["grouping"] = "provider"
        second = flow("104.16.0.2")
        second["network_reference"] = pulsepath.network_reference("104.16.0.2")
        second["destination_key"] = "provider:cloudflare"
        second["grouping"] = "provider"

        self.observe_once(first)
        self.observe_once(second)

        summary = self.engine.summary()
        self.assertEqual(summary["connection_count"], 1)
        self.assertEqual(summary["service_count"], 1)
        self.assertEqual(summary["findings"], [])

    def test_new_country_and_port_include_explainable_evidence(self) -> None:
        for index in range(5):
            self.observe_once(flow(f"192.0.2.{index + 1}"))
        self.observe_once(flow("203.0.113.20", remote_port=9443, country="Japan"))

        finding = self.engine.summary()["findings"][0]
        self.assertEqual(finding["severity"], "attention")
        self.assertEqual(finding["title"], "New estimated country for Example App")
        self.assertIn("offline IP estimate suggests Japan", finding["explanation"])
        self.assertEqual(finding["evidence"]["destination"], "203.0.113.20:9443")
        self.assertIn("TCP port 9443 is new", " ".join(finding["evidence"]["reasons"]))

    def test_historical_findings_are_enriched_for_map_preview(self) -> None:
        for index in range(5):
            self.observe_once(flow(f"192.0.2.{index + 1}"))
        self.observe_once(flow("203.0.113.20", remote_port=9443, country="Japan"))

        class Locator:
            @staticmethod
            def lookup(remote_ip: str) -> dict[str, object]:
                return {"city": "Tokyo", "country": "Japan", "latitude": 35.68, "longitude": 139.76}

        summary = pulsepath.enrich_security_summary(self.engine.summary(), Locator())
        evidence = summary["findings"][0]["evidence"]
        self.assertEqual(evidence["geo"]["city"], "Tokyo")
        self.assertIsNone(evidence["network_reference"])

    def test_historical_helper_names_are_normalized_and_deduplicated(self) -> None:
        summary = {
            "findings": [
                {
                    "title": "New destination for Codex (Service)",
                    "severity": "notice",
                    "created_at": 0,
                    "evidence": {
                        "process": "Codex (Service)", "remote_ip": "192.0.2.1",
                        "remote_port": 443, "protocol": "TCP",
                    },
                },
                {
                    "title": "New destination for Codex",
                    "severity": "notice",
                    "created_at": 0,
                    "evidence": {
                        "process": "Codex", "remote_ip": "192.0.2.1",
                        "remote_port": 443, "protocol": "TCP",
                    },
                },
            ]
        }

        class EmptyLocator:
            @staticmethod
            def lookup(remote_ip: str) -> None:
                return None

        enriched = pulsepath.enrich_security_summary(summary, EmptyLocator())
        self.assertEqual(len(enriched["findings"]), 1)
        self.assertEqual(enriched["findings"][0]["title"], "New destination for Codex")
        self.assertEqual(enriched["findings"][0]["evidence"]["process"], "Codex")

    def test_enrichment_preserves_interface_events_alongside_destination_finding(self) -> None:
        self.observe_once(flow("192.0.2.1"))
        item = flow("192.0.2.2")
        self.observe_once(item)
        self.engine.observe_batch([{**item, "interface": "en0"}])
        self.engine.observe_batch([item])

        class EmptyLocator:
            @staticmethod
            def lookup(remote_ip: str) -> None:
                return None

        enriched = pulsepath.enrich_security_summary(self.engine.summary(), EmptyLocator())
        self.assertEqual(len(enriched["findings"]), 1)
        card = enriched["findings"][0]
        self.assertEqual(card["evidence"]["event_type"], "coincidence")
        self.assertIn("not a malware verdict", card["explanation"])
        signals = card["evidence"]["signals"]
        interface_ids = [signal["finding_id"] for signal in signals if signal["kind"] == "interface_change"]
        self.assertEqual(len(interface_ids), 2)
        self.assertEqual(len(set(interface_ids)), 2)
        self.assertTrue(any(signal["kind"] == "novelty" and signal["label"] == "New destination" for signal in signals))

    def finding(self, kind: str, created_at: float, remote_ip: str = "203.0.113.20", **evidence: object) -> dict:
        base = {
            "process": "Example App", "protocol": "TCP", "remote_port": 443, "remote_ip": remote_ip,
            "destination_key": "provider:example", "destination": f"{remote_ip}:443",
        }
        if kind != "novelty":
            base["event_type"] = kind
        if kind == "interface_change":
            base.setdefault("previous_network", "VPN tunnel")
            base.setdefault("network", "direct network")
        if kind == "outbound_change":
            base.setdefault("bytes_out", 20_000_000)
        finding_id = evidence.pop("finding_id", f"{kind}-{created_at}")
        base.update(evidence)
        titles = {
            "novelty": "New destination for Example App",
            "interface_change": "Network interface changed for Example App",
            "outbound_change": "Unusual outbound transfer for Example App",
        }
        return {
            "id": finding_id,
            "created_at": created_at,
            "severity": "attention" if kind == "outbound_change" else "notice",
            "title": titles[kind],
            "explanation": f"{kind} evidence",
            "evidence": base,
        }

    def test_different_detectors_for_one_stream_become_one_coincidence(self) -> None:
        now = time.time()
        summary = {"findings": [
            self.finding("outbound_change", now, finding_id=3),
            self.finding("interface_change", now - 60, finding_id=2),
            self.finding("novelty", now - 120, finding_id=1),
        ]}

        class EmptyLocator:
            @staticmethod
            def lookup(remote_ip: str) -> None:
                return None

        enriched = pulsepath.enrich_security_summary(summary, EmptyLocator())
        self.assertEqual(len(enriched["findings"]), 1)
        card = enriched["findings"][0]
        self.assertEqual(card["severity"], "attention")
        self.assertEqual(card["title"], "Coinciding changes for Example App")
        self.assertIn("not a malware verdict", card["explanation"])
        self.assertEqual(
            [signal["kind"] for signal in card["evidence"]["signals"]],
            ["novelty", "interface_change", "outbound_change"],
        )
        self.assertEqual([signal["finding_id"] for signal in card["evidence"]["signals"]], [1, 2, 3])
        self.assertIn("VPN tunnel → direct network", card["explanation"])
        self.assertEqual(card["evidence"]["remote_ip"], "203.0.113.20")
        self.assertEqual(enriched["attention_count"], 1)

    def test_one_detector_repeating_stays_separate(self) -> None:
        now = time.time()
        summary = {"findings": [
            self.finding("interface_change", now, finding_id=2, previous_network="direct network", network="VPN tunnel"),
            self.finding("interface_change", now - 10, finding_id=1),
        ]}

        class EmptyLocator:
            @staticmethod
            def lookup(remote_ip: str) -> None:
                return None

        enriched = pulsepath.enrich_security_summary(summary, EmptyLocator())
        self.assertEqual(len(enriched["findings"]), 2)
        self.assertTrue(all(item["evidence"].get("event_type") == "interface_change" for item in enriched["findings"]))

    def test_coincidence_does_not_cross_streams_or_outlast_thirty_minutes(self) -> None:
        now = time.time()
        summary = {"findings": [
            self.finding("novelty", now - 40 * 60, finding_id=1),
            self.finding("outbound_change", now, finding_id=2),
            self.finding(
                "interface_change", now - 20 * 60, "198.51.100.8",
                finding_id=4, destination_key="provider:other",
            ),
            self.finding(
                "outbound_change", now, "198.51.100.8",
                finding_id=5, destination_key="provider:other",
            ),
            # Twenty minutes after the first observation, but thirty-one from the episode start.
            self.finding("novelty", now - 31 * 60, "192.0.2.9", finding_id=6, destination_key="endpoint:192.0.2.9"),
            self.finding("interface_change", now - 20 * 60, "192.0.2.9", finding_id=7, destination_key="endpoint:192.0.2.9"),
            self.finding("outbound_change", now, "192.0.2.9", finding_id=8, destination_key="endpoint:192.0.2.9"),
        ]}

        class EmptyLocator:
            @staticmethod
            def lookup(remote_ip: str) -> None:
                return None

        enriched = pulsepath.enrich_security_summary(summary, EmptyLocator())
        cards = {
            item["evidence"]["remote_ip"]: item
            for item in enriched["findings"]
            if item["evidence"].get("event_type") == "coincidence"
        }
        self.assertEqual(set(cards), {"198.51.100.8", "192.0.2.9"})
        self.assertEqual(
            {signal["kind"] for signal in cards["198.51.100.8"]["evidence"]["signals"]},
            {"interface_change", "outbound_change"},
        )
        self.assertEqual(
            [signal["kind"] for signal in cards["192.0.2.9"]["evidence"]["signals"]],
            ["novelty", "interface_change"],
        )
        separate = [item for item in enriched["findings"] if item["evidence"].get("event_type") != "coincidence"]
        self.assertEqual({item["id"] for item in separate}, {1, 2, 8})
        self.assertEqual(enriched["attention_count"], 3)

    def test_expected_stream_keeps_the_row_and_hides_later_repeats(self) -> None:
        self.observe_once(flow("192.0.2.1"))
        item = flow("192.0.2.9")
        self.observe_once(item)
        finding = self.engine.summary()["findings"][0]
        self.assertTrue(self.engine.expect_findings([finding["id"]]))
        self.assertEqual(self.engine.summary()["findings"], [])
        self.assertEqual(self.engine.summary()["attention_count"], 0)
        stored = self.engine.connection.execute(
            "SELECT acknowledged, title FROM findings WHERE id = ?", (finding["id"],)
        ).fetchone()
        self.assertEqual(stored["acknowledged"], 1)
        self.assertEqual(stored["title"], finding["title"])

        self.engine.last_recorded.clear()
        self.engine.observe_batch([{**item, "interface": "en0"}])
        self.assertEqual(self.engine.summary()["findings"], [])

        self.observe_once(flow("198.51.100.8"))
        self.assertEqual(len(self.engine.summary()["findings"]), 1)
        self.assertFalse(self.engine.expect_findings([999999]))
        self.engine.clear()
        self.assertEqual(
            self.engine.connection.execute("SELECT COUNT(*) FROM expectations").fetchone()[0], 0
        )

    def test_pause_and_clear_are_local_controls(self) -> None:
        self.engine.set_recording(False)
        self.observe_once(flow("192.0.2.1"))
        self.assertEqual(self.engine.summary()["connection_count"], 0)

        self.engine.set_recording(True)
        self.observe_once(flow("192.0.2.1"))
        self.engine.clear()
        summary = self.engine.summary()
        self.assertEqual(summary["connection_count"], 0)
        self.assertEqual(summary["findings"], [])

    def test_connections_for_ip_returns_matching_history(self) -> None:
        self.observe_once(flow("192.0.2.9", remote_port=8443))
        self.observe_once(flow("198.51.100.7"))
        records = self.engine.connections_for_ip("192.0.2.9")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["process"], "Example App")
        self.assertEqual(record["remote_port"], 8443)
        self.assertIn("first_seen", record)
        self.assertIn("last_seen", record)
        self.assertIn("observation_count", record)

    def test_rotated_provider_addresses_remain_attributed(self) -> None:
        first = flow("203.0.113.10")
        second = flow("203.0.113.11")
        for item in (first, second):
            item["destination_key"] = "provider:exampleedge"
            item["grouping"] = "provider"
        self.observe_once(first)
        self.observe_once(second)
        for ip in ("203.0.113.10", "203.0.113.11"):
            records = self.engine.connections_for_ip(ip)
            self.assertEqual(len(records), 1, f"{ip} must stay attributed after rotation")
            self.assertEqual(records[0]["process"], "Example App")

    def test_sightings_respect_pause_and_clear(self) -> None:
        self.engine.set_recording(False)
        self.observe_once(flow("198.51.100.20"))
        self.assertEqual(self.engine.connections_for_ip("198.51.100.20"), [])
        self.engine.set_recording(True)
        self.observe_once(flow("198.51.100.20"))
        self.assertEqual(len(self.engine.connections_for_ip("198.51.100.20")), 1)
        self.engine.clear()
        self.assertEqual(self.engine.connections_for_ip("198.51.100.20"), [])

    def test_old_sightings_are_pruned(self) -> None:
        self.observe_once(flow("203.0.113.60"))
        with self.engine.lock, self.engine.connection:
            self.engine.connection.execute(
                "UPDATE ip_sightings SET last_seen = last_seen - ?", (40 * 86400,)
            )
        self.observe_once(flow("203.0.113.61"))
        with self.engine.lock:
            stale = self.engine.connection.execute(
                "SELECT COUNT(*) FROM ip_sightings WHERE remote_ip = ?", ("203.0.113.60",)
            ).fetchone()[0]
        self.assertEqual(stale, 0, "sightings older than the retention horizon must be pruned")

    def test_connections_for_ip_is_empty_for_unknown_address(self) -> None:
        self.observe_once(flow("192.0.2.9"))
        self.assertEqual(self.engine.connections_for_ip("203.0.113.99"), [])

    def test_sightings_cover_all_group_member_sockets(self) -> None:
        item = flow("104.16.0.1")
        item["destination_key"] = "provider:cloudflare"
        item["grouping"] = "provider"
        item["remote_ips"] = ["104.16.0.1", "104.16.0.2"]
        item["sockets"] = [
            {"remote_ip": "104.16.0.1", "remote_port": 443},
            {"remote_ip": "104.16.0.2", "remote_port": 443},
        ]
        self.observe_once(item)
        for ip in ("104.16.0.1", "104.16.0.2"):
            self.assertEqual(len(self.engine.connections_for_ip(ip)), 1, f"{ip} must have a sighting")

    def test_upgraded_identity_rehomes_legacy_rows(self) -> None:
        self.observe_once(flow("203.0.113.40"))
        upgraded = flow("203.0.113.40")
        upgraded["destination_key"] = "service:https"
        upgraded["grouping"] = "service"
        self.observe_once(upgraded)
        summary = self.engine.summary()
        self.assertEqual(summary["connection_count"], 1, "the legacy row must be rehomed, not duplicated")

    def test_investigate_active_matches_group_members_within_freshness_window(self) -> None:
        now = time.time()
        flows = [
            {
                "remote_ip": "104.16.0.1",
                "remote_ips": ["104.16.0.1", "104.16.0.2"],
                "process": "Brave Browser",
                "last_seen": now,
                "sockets": [
                    {"remote_ip": "104.16.0.1", "last_seen": now - 60},
                    {"remote_ip": "104.16.0.2", "last_seen": now},
                ],
            },
            {"remote_ip": "203.0.113.9", "process": "Old App", "last_seen": now - 100},
        ]
        member = pulsepath.investigate_address("104.16.0.2", None, None, self.engine, flows)
        assert member is not None
        self.assertEqual(len(member["active"]), 1)
        stale_member = pulsepath.investigate_address("104.16.0.1", None, None, self.engine, flows)
        assert stale_member is not None
        self.assertEqual(stale_member["active"], [], "a fresh group must not refresh an older member")
        stale = pulsepath.investigate_address("203.0.113.9", None, None, self.engine, flows)
        assert stale is not None
        self.assertEqual(stale["active"], [])

    def test_custom_history_directory_permissions_are_preserved(self) -> None:
        shared = Path(self.temporary_directory.name) / "shared"
        shared.mkdir()
        os.chmod(shared, 0o755)
        engine = pulsepath.HistoryEngine(
            shared / "history.sqlite3",
            learning_seconds=0,
            learning_connections=0,
            minimum_learning_seconds=0,
        )
        try:
            self.assertEqual(shared.stat().st_mode & 0o777, 0o755, "custom parent must keep its permissions")
            self.assertEqual((shared / "history.sqlite3").stat().st_mode & 0o777, 0o600)
        finally:
            engine.close()

    def test_history_files_are_owner_private(self) -> None:
        self.observe_once(flow("192.0.2.1"))
        database_path = self.engine.database_path
        self.assertEqual(database_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(database_path.parent.stat().st_mode & 0o777, 0o700)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(database_path) + suffix)
            if sidecar.exists():
                self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600, sidecar.name)


if __name__ == "__main__":
    unittest.main()
