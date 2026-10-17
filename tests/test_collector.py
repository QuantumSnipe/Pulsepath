from __future__ import annotations

import threading
import unittest
from unittest import mock

import pulsepath


class EndpointTests(unittest.TestCase):
    def test_split_ipv4_endpoint(self) -> None:
        self.assertEqual(pulsepath.split_endpoint("10.0.0.2:50000"), ("10.0.0.2", 50000))

    def test_split_ipv6_endpoint(self) -> None:
        self.assertEqual(pulsepath.split_endpoint("[2606:4700::1]:443"), ("2606:4700::1", 443))

    def test_address_scope(self) -> None:
        self.assertEqual(pulsepath.address_scope("127.0.0.1"), "loopback")
        self.assertEqual(pulsepath.address_scope("10.0.0.1"), "private")
        self.assertEqual(pulsepath.address_scope("104.16.0.1"), "public")

    def test_cloudflare_ipv4_reference_is_anycast_aware(self) -> None:
        reference = pulsepath.network_reference("104.16.0.1")
        assert reference is not None
        self.assertEqual(reference["name"], "Cloudflare")
        self.assertTrue(reference["anycast"])
        self.assertFalse(reference["location_verified"])

    def test_cloudflare_ipv6_reference_is_detected(self) -> None:
        reference = pulsepath.network_reference("2606:4700::1111")
        assert reference is not None
        self.assertEqual(reference["label"], "Cloudflare edge")

    def test_unmatched_address_has_no_provider_claim(self) -> None:
        self.assertIsNone(pulsepath.network_reference("203.0.113.1"))

    def test_asn_record_is_reported_as_inferred_network_owner(self) -> None:
        reference = pulsepath.network_reference(
            "203.0.113.33",
            {"number": 32934, "organization": "Facebook, Inc."},
        )
        assert reference is not None
        self.assertEqual(reference["name"], "Meta")
        self.assertEqual(reference["as_number"], 32934)
        self.assertEqual(reference["confidence"], "inferred")
        self.assertFalse(reference["anycast"])

    def test_application_helpers_are_collapsed_to_app_family(self) -> None:
        self.assertEqual(pulsepath.application_name("Brave Browser Helper"), "Brave Browser")
        self.assertEqual(pulsepath.application_name("codex app-server"), "Codex")


class CollectorParserTests(unittest.TestCase):
    NETTOP_SAMPLE = """time,,interface,state,bytes_in,bytes_out,rtt_avg
17:08:59.000001,ExampleApp.1234,,,120000,80000,
17:08:59.000002,tcp4 10.0.0.2:50000<->203.0.113.33:5222,utun0,Established,120000,80000,150.50 ms
"""

    def test_nettop_attributes_connection_to_process(self) -> None:
        rows = pulsepath.FlowCollector._parse_nettop(self.NETTOP_SAMPLE)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["process"], "ExampleApp")
        self.assertEqual(row["pid"], 1234)
        self.assertEqual(row["remote_ip"], "203.0.113.33")
        self.assertEqual(row["remote_port"], 5222)
        self.assertEqual(row["interface"], "utun0")
        self.assertAlmostEqual(row["rtt_ms"], 150.50)

    def test_traceroute_preserves_silent_hops(self) -> None:
        output = """traceroute to 203.0.113.1, 18 hops max
 1  10.0.0.1  4.120 ms
 2  * * *
 3  203.0.113.1  18.700 ms
"""
        hops = pulsepath.TraceManager._parse(output)
        self.assertEqual([hop["index"] for hop in hops], [1, 2, 3])
        self.assertTrue(hops[0]["reply"])
        self.assertFalse(hops[1]["reply"])
        self.assertEqual(hops[2]["ip"], "203.0.113.1")
        self.assertNotIn("hostname", hops[0])

    def test_traceroute_keeps_reverse_dns_name_beside_the_address(self) -> None:
        output = """traceroute to 203.0.113.1 (203.0.113.1), 18 hops max, 40 byte packets
 1  edge.example.net (192.0.2.1)  4.120 ms
 2  198.51.100.8 (198.51.100.8)  9.000 ms
 3  2001:db8::1  11.000 ms
 4  * 
"""
        hops = pulsepath.TraceManager._parse(output)
        self.assertEqual(hops[0]["ip"], "192.0.2.1")
        self.assertEqual(hops[0]["hostname"], "edge.example.net")
        self.assertEqual(hops[0]["rtt_ms"], 4.12)
        self.assertNotIn("hostname", hops[1])
        self.assertEqual(hops[2]["ip"], "2001:db8::1")
        self.assertFalse(hops[3]["reply"])


class FlowAggregationTests(unittest.TestCase):
    def test_sockets_are_grouped_by_app_provider_protocol_and_port(self) -> None:
        reference = pulsepath.network_reference("104.16.0.1")
        rows = []
        for index, remote_ip in enumerate(("104.16.0.1", "104.16.0.2"), start=1):
            rows.append(
                {
                    "id": f"raw-{index}",
                    "process": "Brave Browser Helper" if index == 1 else "Brave Browser",
                    "pid": 100 + index,
                    "protocol": "TCP",
                    "local_ip": "10.0.0.2",
                    "local_port": 50000 + index,
                    "remote_ip": remote_ip,
                    "remote_port": 443,
                    "service": "HTTPS",
                    "scope": "public",
                    "first_seen": float(index),
                    "last_seen": float(index),
                    "bytes_in": 100 * index,
                    "bytes_out": 50 * index,
                    "network_reference": reference,
                }
            )

        groups = pulsepath.aggregate_flow_records(rows)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["process"], "Brave Browser")
        self.assertEqual(groups[0]["socket_count"], 2)
        self.assertEqual(groups[0]["remote_ip_count"], 2)
        self.assertEqual(groups[0]["bytes_in"], 300)
        self.assertEqual(groups[0]["trace_flow_id"], "raw-2")
        self.assertEqual(groups[0]["grouping"], "provider")


class CollectorFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        for name in ("GeoIPLocator", "ASNLocator"):
            locator = mock.Mock(available=False, database_path=None, error=None)
            locator.lookup.return_value = None
            patcher = mock.patch.object(pulsepath, name, return_value=locator)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.history = mock.Mock()
        self.collector = pulsepath.FlowCollector(self.history)

    @staticmethod
    def sample_flow(flow_id: str, last_seen: float) -> pulsepath.Flow:
        return pulsepath.Flow(
            id=flow_id, process="Example App", pid=123, protocol="TCP",
            local_ip="10.0.0.2", local_port=50000, remote_ip="104.16.0.1",
            remote_port=443, service="HTTPS", scope="public",
            first_seen=800, last_seen=last_seen,
            network_reference=pulsepath.network_reference("104.16.0.1"),
        )

    def test_snapshot_expires_retained_sockets_without_a_running_collection_loop(self) -> None:
        self.collector.flows = {
            "expired": self.sample_flow("expired", 879),
            "recent": self.sample_flow("recent", 995),
        }
        self.collector.stop_event.set()
        with mock.patch("pulsepath.time.time", return_value=1000):
            snapshot = self.collector.snapshot()
        self.assertEqual(len(snapshot), 1)
        self.assertEqual(snapshot[0]["socket_count"], 1)
        self.assertEqual(snapshot[0]["sockets"][0]["id"], "recent")
        with mock.patch("pulsepath.time.time", return_value=1116):
            self.assertEqual(self.collector.snapshot(), [])

    def test_snapshot_lists_the_newest_connection_first(self) -> None:
        older = self.sample_flow("older", 1000)
        older.remote_ip = "192.0.2.1"
        older.network_reference = None
        older.first_seen = 900
        newer = self.sample_flow("newer", 1000)
        newer.remote_ip = "198.51.100.8"
        newer.local_port = 50001
        newer.network_reference = None
        newer.first_seen = 990
        self.collector.flows = {"older": older, "newer": newer}
        self.collector.stop_event.set()
        with mock.patch("pulsepath.time.time", return_value=1000):
            snapshot = self.collector.snapshot()
        self.assertEqual([item["remote_ip"] for item in snapshot], ["198.51.100.8", "192.0.2.1"])

    def test_status_exposes_last_successful_poll_and_ages_active_counts(self) -> None:
        self.assertIsNone(self.collector.status()["last_successful_poll"])
        self.collector.last_successful_poll = 999
        self.collector.flows = {
            "active": self.sample_flow("active", 995),
            "recent": self.sample_flow("recent", 980),
        }
        with mock.patch("pulsepath.time.time", return_value=1000):
            status = self.collector.status()
        self.assertEqual(status["last_successful_poll"], 999)
        self.assertEqual(status["active_window_seconds"], pulsepath.ACTIVE_WINDOW_SECONDS)
        self.assertEqual(status["active_flows"], 1)
        self.assertEqual(status["active_groups"], 1)
        with mock.patch("pulsepath.time.time", return_value=1011):
            status = self.collector.status()
        self.assertEqual(status["active_flows"], 0)
        self.assertEqual(status["active_groups"], 0)
        self.assertEqual(status["last_successful_poll"], 999)

    def test_successful_empty_poll_updates_timestamp_and_failed_poll_preserves_it(self) -> None:
        def end_poll(_timeout: float) -> None:
            self.collector.stop_event.set()

        with mock.patch.object(self.collector, "_read_lsof", return_value=[]), \
                mock.patch.object(self.collector, "_read_nettop", return_value=[]), \
                mock.patch.object(self.collector.stop_event, "wait", side_effect=end_poll), \
                mock.patch("pulsepath.time.time", return_value=1000):
            self.collector._run()
        self.assertEqual(self.collector.status()["last_successful_poll"], 1000)
        self.assertEqual(self.collector.status()["poll_count"], 1)
        self.assertEqual(self.collector.snapshot(), [])
        self.collector.stop_event.clear()
        with mock.patch.object(self.collector, "_read_lsof", side_effect=RuntimeError("collection failed")), \
                mock.patch.object(self.collector.stop_event, "wait", side_effect=end_poll), \
                mock.patch("pulsepath.time.time", return_value=1002):
            self.collector._run()
        status = self.collector.status()
        self.assertEqual(status["last_successful_poll"], 1000)
        self.assertEqual(status["poll_count"], 1)
        self.assertEqual(status["last_error"], "collection failed")

    def test_nettop_outage_clears_old_counters_from_current_lsof_observation(self) -> None:
        old = self.sample_flow("socket", 999)
        old.source, old.bytes_in, old.bytes_out, old.rtt_ms = "nettop", 200, 100, 12.0
        self.collector.flows = {old.id: old}
        current = pulsepath.asdict(old)
        for name in ("first_seen", "last_seen", "bytes_in", "bytes_out", "rtt_ms"):
            current.pop(name)
        current["source"] = "lsof"
        with mock.patch.object(self.collector, "_read_lsof", return_value=[current]), \
                mock.patch.object(self.collector, "_read_nettop", side_effect=RuntimeError("unavailable")), \
                mock.patch.object(self.collector.stop_event, "wait", side_effect=lambda _: self.collector.stop_event.set()), \
                mock.patch("pulsepath.time.time", return_value=1000):
            self.collector._run()
        recorded = self.history.observe_batch.call_args.args[0][0]
        self.assertEqual(recorded["source"], "lsof")
        self.assertIsNone(recorded["bytes_out"])
        self.assertIsNone(recorded["bytes_in"])
        self.assertIsNone(recorded["rtt_ms"])
        self.assertIsNone(recorded["sockets"][0]["bytes_out"])


class TraceLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.collector = mock.Mock()
        self.collector.get_flow.return_value = mock.Mock(remote_ip="203.0.113.5", scope="public")
        self.collector.geoip.lookup.return_value = None
        self.collector.asn.lookup.return_value = None
        self.manager = pulsepath.TraceManager(self.collector)

    def pending_run(self) -> pulsepath._TraceRun:
        with mock.patch.object(pulsepath.threading, "Thread"):
            job, error = self.manager.start("flow-1")
        self.assertIsNone(error)
        assert job is not None
        self.assertEqual(job["status"], "running")
        return self.manager._runs["flow-1"]

    def test_timeout_terminates_process_and_preserves_bytes_output(self) -> None:
        run = self.pending_run()
        timeout = pulsepath.subprocess.TimeoutExpired(
            cmd=["traceroute"], timeout=pulsepath.TRACE_TIMEOUT_SECONDS,
            output=b" 1  10.0.0.1  1.500 ms\n", stderr=b"",
        )
        process = mock.Mock(returncode=-15)
        process.communicate.side_effect = [timeout, ("", "")]
        with mock.patch.object(pulsepath.subprocess, "Popen", return_value=process):
            self.manager._run(run)
        job = self.manager.get("flow-1")
        assert job is not None
        self.assertEqual(job["status"], "complete")
        self.assertEqual(job["hops"][0]["ip"], "10.0.0.1")
        self.assertIn(f"{pulsepath.TRACE_TIMEOUT_SECONDS}-second limit", job["error"])
        process.terminate.assert_called_once()
        self.assertEqual(
            process.communicate.call_args_list,
            [mock.call(timeout=pulsepath.TRACE_TIMEOUT_SECONDS), mock.call(timeout=1)],
        )

    def test_trace_argument_is_rebuilt_from_the_parsed_address(self) -> None:
        self.assertEqual(pulsepath.trace_target_argument("203.0.113.5"), (4, "203.0.113.5"))
        self.assertEqual(pulsepath.trace_target_argument("2001:0db8::0001"), (6, "2001:db8::1"))
        self.assertEqual(pulsepath.trace_target_argument("fe80::1%en0"), (6, "fe80::1%en0"))
        for hostile in ("2001:db8::1%-x;touch PWNED", "2001:db8::1%", "203.0.113.5%en0", "-203.0.113.5"):
            with self.subTest(target=hostile), self.assertRaises(ValueError):
                pulsepath.trace_target_argument(hostile)

    def test_raw_scope_suffix_never_reaches_the_probe(self) -> None:
        self.collector.get_flow.return_value = mock.Mock(remote_ip="2001:db8::1%-x;touch PWNED", scope="public")
        run = self.pending_run()
        with mock.patch.object(pulsepath.subprocess, "Popen") as launch:
            self.manager._run(run)
        launch.assert_not_called()
        job = self.manager.get("flow-1")
        assert job is not None
        self.assertEqual(job["status"], "error")

    def test_stop_before_worker_launch_prevents_probe(self) -> None:
        run = self.pending_run()
        job, error = self.manager.stop("flow-1")
        with mock.patch.object(pulsepath.subprocess, "Popen") as launch:
            self.manager._run(run)
        launch.assert_not_called()
        self.assertIsNone(error)
        assert job is not None
        self.assertEqual(job["status"], "cancelled")
        self.assertIsNotNone(job["finished_at"])
        stored_job = self.manager.get("flow-1")
        assert stored_job is not None
        self.assertEqual(stored_job["status"], "cancelled")

    def test_stop_terminates_running_probe_and_keeps_partial_hops(self) -> None:
        run = self.pending_run()
        communicating, terminated = threading.Event(), threading.Event()
        process = mock.Mock(returncode=-15)

        def communicate(timeout: float) -> tuple[str, str]:
            communicating.set()
            if not terminated.wait(timeout=2):
                raise RuntimeError("Test probe was not terminated")
            return " 1  10.0.0.1  1.500 ms\n 2  *\n", ""

        process.communicate.side_effect = communicate
        process.terminate.side_effect = terminated.set
        with mock.patch.object(pulsepath.subprocess, "Popen", return_value=process):
            worker = threading.Thread(target=self.manager._run, args=(run,))
            worker.start()
            try:
                self.assertTrue(communicating.wait(timeout=2))
                job, error = self.manager.stop("flow-1")
            finally:
                terminated.set()
                worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertIsNone(error)
        assert job is not None
        self.assertEqual(job["status"], "cancelled")
        self.assertEqual([hop["index"] for hop in job["hops"]], [1, 2])
        self.assertIsNone(job["error"])
        process.terminate.assert_called_once()
        self.assertEqual(self.manager.stop("flow-1"), (job, None))
        process.terminate.assert_called_once()

    def test_unresponsive_probe_is_killed_with_bounded_waits(self) -> None:
        process = mock.Mock()
        process.wait.side_effect = [
            pulsepath.subprocess.TimeoutExpired(cmd=["traceroute"], timeout=0.5),
            pulsepath.subprocess.TimeoutExpired(cmd=["traceroute"], timeout=0.5),
        ]
        self.manager._terminate(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_args_list, [mock.call(timeout=0.5), mock.call(timeout=0.5)])

    def test_old_worker_cannot_overwrite_retrace(self) -> None:
        old = self.pending_run()
        process = mock.Mock(returncode=-15)
        new_run: pulsepath._TraceRun | None = None

        def replace_while_finishing(timeout: float) -> tuple[str, str]:
            nonlocal new_run
            # Arrange the same interleaving as stop followed by retrace while
            # the old worker still owns output from its process.
            with self.manager.lock:
                old.job.update(status="cancelled")
            new_run = self.pending_run()
            return " 1  10.0.0.1  1.500 ms\n", ""

        process.communicate.side_effect = replace_while_finishing
        with mock.patch.object(pulsepath.subprocess, "Popen", return_value=process):
            self.manager._run(old)
        job = self.manager.get("flow-1")
        assert job is not None
        self.assertEqual(job["status"], "running")
        self.assertEqual(job["hops"], [])
        assert new_run is not None
        self.assertIs(self.manager._runs["flow-1"], new_run)
        self.assertTrue(old.done.is_set())

    def test_stop_after_completion_preserves_result(self) -> None:
        run = self.pending_run()
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (" 1  203.0.113.5  1.500 ms\n", "")
        with mock.patch.object(pulsepath.subprocess, "Popen", return_value=process):
            self.manager._run(run)
        result = self.manager.get("flow-1")
        assert result is not None
        self.assertEqual(self.manager.stop("flow-1"), (result, None))
        self.assertEqual(result["status"], "complete")
        process.terminate.assert_not_called()

    def test_stop_unknown_job_returns_error(self) -> None:
        job, error = self.manager.stop("missing")
        self.assertIsNone(job)
        assert error is not None
        self.assertIn("No trace", error)


if __name__ == "__main__":
    unittest.main()
