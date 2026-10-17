"""Deterministic replays for measured outbound-transfer change detection."""

from __future__ import annotations

import unittest
from typing import Protocol

from behavior import OutboundMonitor


class ObservationSink(Protocol):
    def observe(self, flows: list[dict], now: float, /) -> list[dict]: ...


class Replay:
    def __init__(self, monitor: ObservationSink, process: str = "Example App") -> None:
        self.monitor = monitor
        self.process = process
        self.now = 1000.0
        self.counter = 1000000
        self.socket_id = "socket-one"
        self.first_seen = self.now
        self.events: list[dict] = []

    def row(self, **changes: object) -> dict:
        socket = {
            "id": self.socket_id,
            "first_seen": self.first_seen,
            "last_seen": self.now,
            "source": "nettop",
            "bytes_out": self.counter,
            "remote_ip": "203.0.113.8",
            "remote_port": 443,
        }
        socket.update(changes)
        return {
            "id": "group-example",
            "process": self.process,
            "protocol": "TCP",
            "remote_ip": "203.0.113.8",
            "remote_port": 443,
            "destination_key": "provider:example",
            "grouping": "provider",
            "sockets": [socket],
        }

    def sample(self, delta: int = 0, elapsed: float = 2, **changes: object) -> list[dict]:
        self.now += elapsed
        self.counter += delta
        events = self.monitor.observe([self.row(**changes)], self.now)
        self.events.extend(events)
        return events

    def window(self, bytes_out: int) -> list[dict]:
        events = []
        for _ in range(5):
            events.extend(self.sample(bytes_out // 5))
        return events

    def train(self) -> None:
        self.monitor.observe([self.row()], self.now)
        for _ in range(3):
            self.window(10)


class OutboundMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.monitor = OutboundMonitor(
            window_seconds=10,
            minimum_windows=3,
            baseline_windows=20,
            minimum_bytes=100,
            ratio=5,
            consecutive_windows=2,
            cooldown_seconds=60,
            max_gap_seconds=3,
        )
        self.replay = Replay(self.monitor)

    def test_sustained_transfer_to_known_stream_contains_measured_evidence(self) -> None:
        self.replay.train()
        self.assertEqual(self.replay.events, [])
        self.assertEqual(self.replay.window(200), [])
        events = self.replay.window(200)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["event_type"], "outbound_change")
        self.assertEqual(event["process"], "Example App")
        self.assertEqual(event["destination_key"], "provider:example")
        self.assertEqual(event["remote_ip"], "203.0.113.8")
        self.assertEqual(event["remote_port"], 443)
        self.assertEqual(event["protocol"], "TCP")
        self.assertEqual(event["bytes_out"], 200)
        self.assertEqual(event["window_seconds"], 10)
        self.assertEqual(event["baseline_bytes_out"], 10)
        self.assertEqual(event["threshold_bytes_out"], 100)
        self.assertEqual(event["consecutive_windows"], 2)
        self.assertEqual(event["measured_socket_count"], 1)
        self.assertEqual(event["source"], "nettop")

    def test_initial_huge_lifetime_counters_are_never_counted_as_transfer(self) -> None:
        self.replay.counter = 10**15
        self.replay.train()
        for _ in range(3):
            self.replay.window(0)
        self.assertEqual(self.replay.events, [])
        self.replay.window(200)
        events = self.replay.window(200)
        self.assertEqual(events[0]["baseline_bytes_out"], 10)

    def test_threshold_uses_largest_learned_window_instead_of_average(self) -> None:
        self.monitor.observe([self.replay.row()], self.replay.now)
        for amount in (10, 20, 40):
            self.replay.window(amount)
        self.assertEqual(self.replay.window(300), [])
        events = self.replay.window(300)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["baseline_bytes_out"], 40)
        self.assertEqual(events[0]["threshold_bytes_out"], 200)

    def test_one_high_window_and_inbound_only_traffic_do_not_trigger(self) -> None:
        self.replay.train()
        self.replay.window(200)
        for _ in range(5):
            self.replay.sample(0, bytes_in=10**12)
        self.replay.window(200)
        self.assertEqual(self.replay.events, [])
        events = self.replay.window(200)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["baseline_bytes_out"], 10)

    def test_baseline_requires_complete_learning_before_detection(self) -> None:
        self.monitor.observe([self.replay.row()], self.replay.now)
        for _ in range(2):
            self.replay.window(10)
        self.replay.window(200)
        self.replay.window(200)
        self.assertEqual(self.replay.events, [])

    def test_invalid_or_missing_counter_breaks_consecutive_evidence(self) -> None:
        for invalid in (None, -1, True, "123", 2.5):
            with self.subTest(counter=invalid):
                self.setUp()
                self.replay.train()
                self.replay.window(200)
                self.replay.sample(1000000, bytes_out=invalid)
                self.replay.sample(1000000)
                self.replay.window(200)
                self.assertEqual(self.replay.events, [])

    def test_counter_reset_and_socket_reuse_break_comparison(self) -> None:
        for change in ("counter-reset", "new-first-seen", "new-id"):
            with self.subTest(change=change):
                self.setUp()
                self.replay.train()
                self.replay.window(200)
                if change == "counter-reset":
                    self.replay.counter = 0
                elif change == "new-first-seen":
                    self.replay.first_seen = self.replay.now
                    self.replay.counter = 10**12
                else:
                    self.replay.socket_id = "replacement-socket"
                    self.replay.counter = 10**12
                self.replay.sample()
                self.replay.window(200)
                self.assertEqual(self.replay.events, [])

    def test_lsof_or_stale_samples_do_not_supply_current_counter_evidence(self) -> None:
        for changes in ({"source": "lsof"}, {"last_seen": 999}):
            with self.subTest(changes=changes):
                self.setUp()
                self.replay.train()
                self.replay.window(200)
                self.replay.sample(10**9, 2, **changes)
                self.replay.sample(10**9)
                self.replay.window(200)
                self.assertEqual(self.replay.events, [])

    def test_polling_gap_and_backward_or_duplicate_clock_break_comparison(self) -> None:
        for elapsed in (30, -5, 0):
            with self.subTest(elapsed=elapsed):
                self.setUp()
                self.replay.train()
                self.replay.window(200)
                self.replay.sample(10**9, elapsed=elapsed)
                self.replay.window(200)
                self.assertEqual(self.replay.events, [])

    def test_socket_group_churn_does_not_difference_aggregate_lifetime_totals(self) -> None:
        self.replay.train()
        self.replay.window(200)
        self.replay.now += 2
        row = self.replay.row()
        row["sockets"].append({
            **row["sockets"][0], "id": "new-socket", "bytes_out": 10**12,
            "first_seen": self.replay.now,
        })
        self.assertEqual(self.monitor.observe([row], self.replay.now), [])
        self.replay.sample()
        self.replay.window(200)
        self.assertEqual(self.replay.events, [])

    def test_grouped_socket_deltas_are_added_to_measured_evidence(self) -> None:
        second_counter = 10**12
        for tick in range(26):
            if tick:
                self.replay.now += 2
                delta = 1 if tick <= 15 else 20
                self.replay.counter += delta
                second_counter += delta
            row = self.replay.row()
            row["sockets"].append({
                **row["sockets"][0], "id": "second-socket", "bytes_out": second_counter,
                "remote_ip": "203.0.113.9",
            })
            self.replay.events.extend(self.monitor.observe([row], self.replay.now))
        self.assertEqual(len(self.replay.events), 1)
        self.assertEqual(self.replay.events[0]["bytes_out"], 200)
        self.assertEqual(self.replay.events[0]["measured_socket_count"], 2)

    def test_separate_application_does_not_inherit_another_apps_baseline(self) -> None:
        self.replay.train()
        self.replay.process = "Different App"
        self.replay.sample(10**9)
        self.replay.window(200)
        self.replay.window(200)
        self.assertEqual(self.replay.events, [])

    def test_cooldown_suppresses_repeated_findings_without_training_on_anomaly(self) -> None:
        self.replay.train()
        self.replay.window(200)
        self.replay.window(200)
        for _ in range(5):
            self.assertEqual(self.replay.window(200), [])
        self.assertEqual(len(self.replay.events), 1)
        events = []
        for _ in range(3):
            events.extend(self.replay.window(200))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["baseline_bytes_out"], 10)

    def test_reset_removes_baseline_and_pending_anomaly(self) -> None:
        self.replay.train()
        self.replay.window(200)
        self.monitor.reset()
        self.replay.sample(10**12)
        self.replay.window(200)
        self.replay.window(200)
        self.assertEqual(self.replay.events, [])

    def test_raw_single_socket_rows_are_supported(self) -> None:
        events = []
        for tick in range(26):
            if tick:
                self.replay.now += 2
                self.replay.counter += 2 if tick <= 15 else 40
            grouped = self.replay.row()
            socket = grouped.pop("sockets")[0]
            events.extend(self.monitor.observe([{**grouped, **socket}], self.replay.now))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["bytes_out"], 200)


if __name__ == "__main__":
    unittest.main()
