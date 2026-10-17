from __future__ import annotations

import gzip
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import install_geoip


class ReaderSupplyChainTests(unittest.TestCase):
    def test_reader_install_requires_hash_verification(self) -> None:
        command = install_geoip.reader_install_command()
        self.assertIn("--require-hashes", command)
        self.assertIn("-r", command)
        self.assertIn(str(install_geoip.READER_REQUIREMENTS), command)
        self.assertTrue(
            all(not part.startswith("maxminddb==") for part in command),
            "the version must come from the hash-pinned requirements file only",
        )

    def test_reader_requirements_pin_package_and_hashes(self) -> None:
        text = install_geoip.READER_REQUIREMENTS.read_text(encoding="utf-8")
        logical = " ".join(
            line.strip().rstrip("\\").strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertTrue(logical.startswith("maxminddb=="))
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})\b", logical)
        self.assertGreaterEqual(len(hashes), 1)
        self.assertEqual(len(hashes), len(set(hashes)), "duplicate hashes suggest a bad regeneration")
        self.assertEqual(logical.count("--hash="), len(hashes), "every hash option must be a full sha256 digest")


class DownloadIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def gzip_of(self, payload: bytes) -> Path:
        archive = self.directory / "payload.gz"
        archive.write_bytes(gzip.compress(payload))
        return archive

    def test_decompression_stops_at_the_size_cap(self) -> None:
        archive = self.gzip_of(b"\0" * (2 * 1024 * 1024))
        destination = self.directory / "database.mmdb.part"
        with self.assertRaises(RuntimeError):
            install_geoip.decompress_archive(archive, destination, max_bytes=1024 * 1024)
        self.assertFalse(destination.exists(), "a partial oversized file must not be left behind")

    def test_decompression_succeeds_under_the_cap(self) -> None:
        archive = self.gzip_of(b"pulsepath")
        destination = self.directory / "database.mmdb.part"
        install_geoip.decompress_archive(archive, destination, max_bytes=1024)
        self.assertEqual(destination.read_bytes(), b"pulsepath")

    def test_database_without_mmdb_marker_is_rejected(self) -> None:
        fake = self.directory / "database.mmdb"
        fake.write_bytes(b"<html>Not the database you were hoping for</html>")
        self.assertFalse(install_geoip.database_is_valid(fake))

    def test_download_stream_is_capped(self) -> None:
        import io

        source = io.BytesIO(b"\0" * (2 * 1024 * 1024))
        target = self.directory / "archive.part"
        with self.assertRaises(RuntimeError):
            install_geoip.copy_stream(source, target, max_bytes=1024 * 1024)
        self.assertFalse(target.exists(), "a partial oversized download must not be left behind")

    def test_download_refuses_a_redirect_off_https(self) -> None:
        response = MagicMock()
        response.geturl.return_value = "http://example.invalid/dbip-city-lite.mmdb.gz"
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(install_geoip, "DATA_DIR", Path(directory)), \
                patch.object(install_geoip.urllib.request, "urlopen", return_value=response) as urlopen:
            with self.assertRaises(RuntimeError) as caught:
                install_geoip.download_database("city", "1 MB")
            self.assertIn("HTTPS", str(caught.exception))
            urlopen.assert_called()
            self.assertFalse(any(Path(directory).iterdir()), "a redirected download must not be stored")

    def test_database_with_mmdb_marker_is_accepted(self) -> None:
        database = self.directory / "database.mmdb"
        database.write_bytes(b"\0" * 4096 + install_geoip.MMDB_METADATA_MARKER + b"trailing metadata")
        self.assertTrue(install_geoip.database_is_valid(database))
