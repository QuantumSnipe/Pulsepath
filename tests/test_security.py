from __future__ import annotations

import http.client
import base64
import hashlib
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

import pulsepath


class LocalServerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), pulsepath.PulsepathHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> http.client.HTTPResponse:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        connection.close()
        return response

    def local_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"Host": f"127.0.0.1:{self.server.server_port}"}
        if extra:
            headers.update(extra)
        return headers

    def api_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        return self.local_headers({"X-Pulsepath-Token": pulsepath.API_TOKEN, **(extra or {})})

class LocalRequestSecurityTests(LocalServerTestCase):
    def test_updated_page_keeps_csp_in_sync_without_server_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(pulsepath, "APP_DIR", Path(directory)):
            page = Path(directory) / "index.html"
            for script in (b"console.log('first');", b"console.log('updated');"):
                document = b"<!doctype html><script>" + script + b"</script>"
                page.write_bytes(document)
                served = pulsepath.with_api_token(document)
                expected_hash = base64.b64encode(hashlib.sha256(script).digest()).decode("ascii")
                self.assertEqual(pulsepath.index_script_hash(served), expected_hash)
                for method, route in (("GET", "/"), ("GET", "/index.html?refresh=1"), ("HEAD", "/")):
                    with self.subTest(script=script, method=method, route=route):
                        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
                        try:
                            connection.request(method, route, headers=self.local_headers())
                            response = connection.getresponse()
                            body = response.read()
                            self.assertEqual(response.status, 200)
                            self.assertEqual(body, served if method == "GET" else b"")
                            content_length = response.getheader("Content-Length")
                            assert content_length is not None
                            self.assertEqual(int(content_length), len(served))
                            policy = response.getheader("Content-Security-Policy")
                            assert policy is not None
                            self.assertIn(f"'sha256-{expected_hash}'", policy)
                            self.assertNotIn("unsafe-inline", policy.split("script-src", 1)[1].split(";", 1)[0])
                        finally:
                            connection.close()

    def test_rejects_untrusted_host_header(self) -> None:
        response = self.request("GET", "/", {"Host": "attacker.example"})
        self.assertEqual(response.status, 403)

    def test_rejects_cross_origin_mutation(self) -> None:
        response = self.request(
            "POST",
            "/api/security/clear",
            self.api_headers({"Origin": "https://attacker.example"}),
        )
        self.assertEqual(response.status, 403)

    def test_security_headers_are_strict_for_scripts(self) -> None:
        response = self.request("GET", "/", {"Host": f"127.0.0.1:{self.server.server_port}"})
        self.assertEqual(response.status, 200)
        csp = response.getheader("Content-Security-Policy") or ""
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("object-src 'none'", csp)
        script_policy = csp.split("script-src", 1)[1].split(";", 1)[0]
        self.assertNotIn("unsafe-inline", script_policy)
        self.assertIn("sha256-", script_policy)
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")


class ApiTokenTests(LocalServerTestCase):
    def test_rejects_missing_token(self) -> None:
        response = self.request("GET", "/api/flows", self.local_headers())
        self.assertEqual(response.status, 403)

    def test_rejects_wrong_token(self) -> None:
        response = self.request(
            "GET",
            "/api/flows",
            self.local_headers({"X-Pulsepath-Token": "not-the-session-token"}),
        )
        self.assertEqual(response.status, 403)

    def test_accepts_the_session_token(self) -> None:
        response = self.request("GET", "/api/does-not-exist", self.api_headers())
        self.assertEqual(response.status, 404)

    def test_post_rejects_missing_or_wrong_token(self) -> None:
        origin = {"Origin": f"http://127.0.0.1:{self.server.server_port}"}
        missing = self.request("POST", "/api/security/clear", self.local_headers(origin))
        self.assertEqual(missing.status, 403)
        wrong = self.request(
            "POST",
            "/api/security/clear",
            self.api_headers({**origin, "X-Pulsepath-Token": "not-the-session-token"}),
        )
        self.assertEqual(wrong.status, 403)


class StaticFileExposureTests(LocalServerTestCase):
    def test_does_not_serve_private_history_database(self) -> None:
        response = self.request("GET", "/data/pulsepath-history.sqlite3", self.local_headers())
        self.assertEqual(response.status, 404)

    def test_does_not_serve_repository_internals(self) -> None:
        for path in (
            "/pulsepath.py", "/.git/config", "/SECURITY.md", "/vendor/",
            "/references/app-networks.json", "/data/provider-ranges.json",
        ):
            response = self.request("GET", path, self.local_headers())
            self.assertEqual(response.status, 404, f"{path} must not be served")

    def test_head_requests_follow_the_same_allowlist(self) -> None:
        response = self.request("HEAD", "/data/pulsepath-history.sqlite3", self.local_headers())
        self.assertEqual(response.status, 404)

    def test_head_requests_validate_the_host_header(self) -> None:
        response = self.request("HEAD", "/", {"Host": "attacker.example"})
        self.assertEqual(response.status, 403)

    def test_serves_interface_and_basemap_files(self) -> None:
        for path in ("/", "/index.html", "/data/ne_50m_lakes.geojson"):
            response = self.request("GET", path, self.local_headers())
            self.assertEqual(response.status, 200, f"{path} must stay available")


class FetchMetadataTests(LocalServerTestCase):
    def same_origin_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        port = self.server.server_port
        headers = self.api_headers({"Origin": f"http://127.0.0.1:{port}"})
        if extra:
            headers.update(extra)
        return headers

    def test_rejects_missing_origin_on_mutation(self) -> None:
        response = self.request("POST", "/api/security/clear", self.api_headers())
        self.assertEqual(response.status, 403)

    def test_rejects_cross_site_mutation_via_fetch_metadata(self) -> None:
        response = self.request(
            "POST",
            "/api/security/recording",
            self.same_origin_headers({"Sec-Fetch-Site": "cross-site"}),
        )
        self.assertEqual(response.status, 403)

    def test_allows_same_origin_fetch_metadata(self) -> None:
        response = self.request(
            "POST",
            "/api/does-not-exist",
            self.same_origin_headers({"Sec-Fetch-Site": "same-origin"}),
        )
        self.assertEqual(response.status, 404)


class TraceApiTests(LocalServerTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.traces = Mock()
        patcher = patch.object(pulsepath.PulsepathHandler, "traces", self.traces, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def post_json(self, path: str, headers: dict[str, str] | None = None) -> tuple[int, dict]:
        if headers is None:
            headers = self.api_headers({"Origin": f"http://127.0.0.1:{self.server.server_port}"})
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request("POST", path, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_stop_returns_job_and_does_not_start_a_probe(self) -> None:
        job = {"flow_id": "flow-1", "target": "203.0.113.5", "status": "cancelled",
               "hops": [], "started_at": 1, "finished_at": 2, "error": None}
        self.traces.stop.return_value = job, None
        status, body = self.post_json("/api/traces/flow-1/stop")
        self.assertEqual(status, 200)
        self.assertEqual(body, job)
        self.traces.stop.assert_called_once_with("flow-1")
        self.traces.start.assert_not_called()

    def test_stop_unknown_job_returns_404(self) -> None:
        self.traces.stop.return_value = None, "No trace has been started for this flow."
        status, body = self.post_json("/api/traces/missing/stop")
        self.assertEqual(status, 404)
        self.assertIn("No trace", body["error"])

    def test_stop_requires_same_origin_and_local_host(self) -> None:
        for extra in ({}, {"Origin": "https://attacker.example"},
                      {"Origin": f"http://127.0.0.1:{self.server.server_port}", "Sec-Fetch-Site": "cross-site"},
                      {"Origin": f"http://127.0.0.1:{self.server.server_port}", "Host": "attacker.example"}):
            with self.subTest(headers=extra):
                status, _ = self.post_json("/api/traces/flow-1/stop", self.api_headers(extra))
                self.assertEqual(status, 403)
        self.traces.stop.assert_not_called()
        self.traces.start.assert_not_called()

    def test_start_retains_202_response(self) -> None:
        self.traces.start.return_value = {"flow_id": "flow-1", "status": "running"}, None
        status, body = self.post_json("/api/traces/flow-1")
        self.assertEqual(status, 202)
        self.assertEqual(body["status"], "running")
        self.traces.start.assert_called_once_with("flow-1")

    def test_unknown_trace_action_does_not_start_a_probe(self) -> None:
        status, _ = self.post_json("/api/traces/flow-1/unknown")
        self.assertEqual(status, 404)
        self.traces.start.assert_not_called()
        self.traces.stop.assert_not_called()


class InvestigateApiTests(LocalServerTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.history = pulsepath.HistoryEngine(
            Path(self.temporary_directory.name) / "history.sqlite3",
            learning_seconds=0,
            learning_connections=0,
            minimum_learning_seconds=0,
        )
        self.collector = pulsepath.FlowCollector(self.history)
        pulsepath.PulsepathHandler.history = self.history
        pulsepath.PulsepathHandler.collector = self.collector

    def tearDown(self) -> None:
        self.history.close()
        self.temporary_directory.cleanup()
        super().tearDown()

    def get_json(self, path: str) -> tuple[int, dict]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request("GET", path, headers=self.api_headers())
        response = connection.getresponse()
        body = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, body

    def test_expect_hides_a_finding_without_deleting_it(self) -> None:
        self.history.observe_batch([{
            "process": "Example App", "protocol": "TCP", "remote_ip": "192.0.2.1",
            "remote_port": 443, "service": "HTTPS", "scope": "public", "interface": "utun0",
        }])
        self.history.last_recorded.clear()
        self.history.observe_batch([{
            "process": "Example App", "protocol": "TCP", "remote_ip": "192.0.2.9",
            "remote_port": 443, "service": "HTTPS", "scope": "public", "interface": "utun0",
        }])
        finding_id = self.history.summary()["findings"][0]["id"]
        body = json.dumps({"finding_ids": [finding_id]}).encode()
        headers = self.api_headers({
            "Origin": f"http://127.0.0.1:{self.server.server_port}",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        })
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request("POST", "/api/security/expect", body=body, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        connection.close()
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(
            self.history.connection.execute("SELECT acknowledged FROM findings WHERE id = ?", (finding_id,)).fetchone()[0],
            1,
        )
        missing = json.dumps({"finding_ids": [999999]}).encode()
        headers["Content-Length"] = str(len(missing))
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request("POST", "/api/security/expect", body=missing, headers=headers)
        rejected = connection.getresponse()
        rejected.read()
        connection.close()
        self.assertEqual(rejected.status, 404)

    def test_invalid_address_is_rejected(self) -> None:
        status, body = self.get_json("/api/investigate?ip=not-an-ip")
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_missing_address_is_rejected(self) -> None:
        status, _ = self.get_json("/api/investigate")
        self.assertEqual(status, 400)

    def test_investigation_reports_local_evidence(self) -> None:
        self.history.observe_batch(
            [
                {
                    "process": "Example App",
                    "protocol": "TCP",
                    "remote_ip": "192.0.2.55",
                    "remote_port": 443,
                    "service": "HTTPS",
                    "scope": "public",
                    "interface": "en0",
                    "rtt_ms": 12.0,
                    "bytes_in": 10,
                    "bytes_out": 20,
                    "geo": {"country": "United States", "country_code": "US", "city": "Example City"},
                }
            ]
        )
        status, body = self.get_json("/api/investigate?ip=192.0.2.55")
        self.assertEqual(status, 200)
        self.assertEqual(body["ip"], "192.0.2.55")
        # 192.0.2.55 sits in the TEST-NET-1 documentation range, which the
        # ipaddress module classifies as private.
        self.assertEqual(body["scope"], "private")
        for key in ("geo", "asn", "network_reference", "active", "history"):
            self.assertIn(key, body)
        self.assertEqual(len(body["history"]), 1)
        self.assertEqual(body["history"][0]["process"], "Example App")
        self.assertEqual(body["active"], [])

    def test_head_matches_get_for_api_routes(self) -> None:
        ok = self.request("HEAD", "/api/investigate?ip=104.16.0.1", self.api_headers())
        self.assertEqual(ok.status, 200)
        missing = self.request("HEAD", "/api/does-not-exist", self.api_headers())
        self.assertEqual(missing.status, 404)

    def test_history_dump_endpoint_is_gone(self) -> None:
        status, _ = self.get_json("/api/security/history")
        self.assertEqual(status, 404)

    def test_investigation_recognizes_known_edge_networks(self) -> None:
        status, body = self.get_json("/api/investigate?ip=104.16.0.1")
        self.assertEqual(status, 200)
        self.assertIsNotNone(body["network_reference"])
        self.assertEqual(body["history"], [])


class RequestBodyLimitTests(LocalServerTestCase):
    def test_rejects_oversized_json_bodies(self) -> None:
        body = b'{"enabled": true, "padding": "' + b"a" * 5000 + b'"}'
        port = self.server.server_port
        response = self.request(
            "POST",
            "/api/security/recording",
            self.api_headers({
                "Origin": f"http://127.0.0.1:{port}",
                "Content-Type": "application/json",
            }),
            body=body,
        )
        self.assertEqual(response.status, 413)


if __name__ == "__main__":
    unittest.main()
