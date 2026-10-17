from __future__ import annotations

import unittest
from pathlib import Path


APP_DIR = Path(__file__).resolve().parents[1]


class FrontendSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = (APP_DIR / "index.html").read_text(encoding="utf-8")

    def test_avoids_html_injection_sinks(self) -> None:
        self.assertNotIn(".innerHTML", self.document)
        self.assertNotIn("insertAdjacentHTML", self.document)
        self.assertNotIn("document.write", self.document)

    def test_avoids_string_to_code_execution(self) -> None:
        self.assertNotIn("eval(", self.document)
        self.assertNotIn("new Function", self.document)

    def test_has_no_remote_script_dependencies(self) -> None:
        self.assertNotRegex(self.document, r"<script[^>]+src=[\"']https?://")

    def test_external_links_do_not_receive_opener(self) -> None:
        external_links = [line for line in self.document.splitlines() if "target=\"_blank\"" in line]
        self.assertTrue(external_links)
        self.assertTrue(all("rel=\"noreferrer\"" in line for line in external_links))


if __name__ == "__main__":
    unittest.main()
