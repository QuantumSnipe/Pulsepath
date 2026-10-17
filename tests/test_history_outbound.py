"""Replay outbound changes through the real history persistence boundary."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pulsepath
from behavior import OutboundMonitor
from tests.test_behavior import Replay


class HistorySink:
    def __init__(self, engine: pulsepath.HistoryEngine, receipt_lag: float = 0) -> None:
        self.engine = engine
        self.receipt_lag = receipt_lag

    def observe(self, rows: list[dict], now: float) -> list[dict]:
        stamped_rows = [{**row, "last_seen": now} for row in rows]
        with patch("pulsepath.time.time", return_value=now + self.receipt_lag):
            self.engine.observe_batch(stamped_rows)
        return []


class EmptyLocator:
    def lookup(self, address: str) -> None:
        return None


class HistoryOutboundTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.directory.name) / "history.sqlite3"
        self.engine = self.make_engine()
        self.replay = Replay(HistorySink(self.engine))

    def tearDown(self) -> None:
        self.engine.close()
        self.directory.cleanup()

    def make_engine(self) -> pulsepath.HistoryEngine:
        engine = pulsepath.HistoryEngine(
            self.database_path,
            learning_seconds=0,
            minimum_learning_seconds=0,
            learning_connections=0,
        )
        engine.outbound_monitor = OutboundMonitor(
            window_seconds=10, minimum_windows=3, baseline_windows=20,
            minimum_bytes=100, ratio=5, consecutive_windows=2,
            cooldown_seconds=60, max_gap_seconds=3,
        )
        return engine

    def findings(self) -> list[dict]:
        return [item for item in self.engine.summary()["findings"]
                if item["evidence"].get("event_type") == "outbound_change"]

    def trigger(self) -> None:
        self.replay.train()
        self.replay.window(200)
        self.replay.window(200)

    def test_finding_is_persisted_even_when_connection_write_is_throttled(self) -> None:
        self.trigger()
        findings = self.findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "attention")
        self.assertEqual(findings[0]["evidence"]["bytes_out"], 200)
        self.assertEqual(findings[0]["created_at"], 1050)
        connection = self.engine.connection.execute(
            "SELECT last_seen, observation_count FROM connections"
        ).fetchone()
        self.assertEqual(connection["last_seen"], 1048)
        self.assertEqual(connection["observation_count"], 7)
        self.engine.close()
        self.engine = self.make_engine()
        self.assertEqual(self.findings()[0]["evidence"], findings[0]["evidence"])

    def test_enrichment_keeps_novelty_and_repeated_transfer_events_for_same_stream(self) -> None:
        self.trigger()
        for _ in range(6):
            self.replay.window(200)
        summary = self.engine.summary()
        self.assertEqual(len(self.findings()), 2)
        novelty = {
            "id": 99999,
            "created_at": self.replay.now,
            "severity": "notice",
            "title": "New destination for Example App",
            "evidence": {
                "process": "Example App", "remote_ip": "203.0.113.8", "remote_port": 443,
                "protocol": "TCP", "destination_key": "provider:example",
            },
        }
        summary["findings"].append(novelty)
        enriched = pulsepath.enrich_security_summary(summary, EmptyLocator())
        self.assertEqual(len(enriched["findings"]), 1)
        card = enriched["findings"][0]
        self.assertEqual(card["evidence"]["event_type"], "coincidence")
        self.assertIn("not a malware verdict", card["explanation"])
        signals = card["evidence"]["signals"]
        outbound_ids = {signal["finding_id"] for signal in signals if signal["kind"] == "outbound_change"}
        self.assertEqual(outbound_ids, {item["id"] for item in self.findings()})
        self.assertEqual(len(outbound_ids), 2)
        self.assertTrue(any(signal["finding_id"] == novelty["id"] and signal["kind"] == "novelty" for signal in signals))

    def test_collector_timestamp_preceding_history_receipt_remains_valid(self) -> None:
        self.replay.monitor = HistorySink(self.engine, receipt_lag=0.003)
        self.trigger()
        findings = self.findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["window_seconds"], 10)
        self.assertEqual(findings[0]["evidence"]["bytes_out"], 200)
        self.assertAlmostEqual(findings[0]["created_at"], 1050.003)

    def test_pause_resume_discards_learning_and_ignores_counter_jump(self) -> None:
        self.replay.train()
        self.replay.window(200)
        self.engine.set_recording(False)
        before = self.engine.summary()["connection_count"]
        self.replay.window(1000000)
        self.assertEqual(self.findings(), [])
        self.assertEqual(self.engine.summary()["connection_count"], before)
        self.engine.set_recording(True)
        self.replay.sample(10**12)
        self.replay.window(200)
        self.replay.window(200)
        self.assertEqual(self.findings(), [])

    def test_clear_erases_findings_and_requires_a_new_transfer_baseline(self) -> None:
        self.trigger()
        self.assertEqual(len(self.findings()), 1)
        self.engine.clear()
        self.assertEqual(self.engine.summary()["connection_count"], 0)
        self.assertEqual(self.findings(), [])
        self.replay.sample(10**12)
        self.replay.window(200)
        self.replay.window(200)
        self.assertEqual(self.findings(), [])

    def test_restart_preserves_findings_but_cannot_reuse_raw_comparisons_or_baseline(self) -> None:
        self.trigger()
        original_id = self.findings()[0]["id"]
        self.engine.close()
        self.engine = self.make_engine()
        self.replay.monitor = HistorySink(self.engine)
        self.replay.sample(10**12)
        self.replay.window(200)
        self.replay.window(200)
        self.assertEqual([item["id"] for item in self.findings()], [original_id])


if __name__ == "__main__":
    unittest.main()
