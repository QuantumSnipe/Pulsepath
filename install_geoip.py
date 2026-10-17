#!/usr/bin/env python3
"""Install Pulsepath's offline DB-IP City and ASN Lite databases and MMDB reader."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
VENDOR_DIR = APP_DIR / "vendor"
READER_REQUIREMENTS = APP_DIR / "requirements-geoip.txt"

# The City Lite database is ~124 MB today; the cap only guards against a
# compromised or broken mirror serving an effectively unbounded gzip stream.
MAX_DATABASE_BYTES = 512 * 1024 * 1024

# Every MaxMind-format database carries this marker at the start of its
# metadata section, within the last 128 KiB of the file.
MMDB_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


def copy_stream(source, target: Path, max_bytes: int = MAX_DATABASE_BYTES, total: int = 0) -> None:
    """Stream a download to disk, refusing to write past the safety limit."""
    copied = 0
    try:
        with target.open("wb") as handle:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > max_bytes:
                    raise RuntimeError(
                        f"The download exceeded the {max_bytes // (1024 * 1024)} MB safety limit."
                    )
                handle.write(block)
                if total:
                    print(f"\r{copied / total:6.1%}", end="", flush=True)
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def decompress_archive(archive: Path, destination: Path, max_bytes: int = MAX_DATABASE_BYTES) -> None:
    written = 0
    try:
        with gzip.open(archive, "rb") as source, destination.open("wb") as target:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                written += len(block)
                if written > max_bytes:
                    raise RuntimeError(
                        f"{archive.name} decompresses beyond the {max_bytes // (1024 * 1024)} MB safety limit."
                    )
                target.write(block)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def database_is_valid(database: Path) -> bool:
    size = database.stat().st_size
    if size < len(MMDB_METADATA_MARKER):
        return False
    with database.open("rb") as handle:
        handle.seek(max(0, size - 128 * 1024))
        return MMDB_METADATA_MARKER in handle.read()


def database_opens(database: Path) -> bool:
    """Open the file with the MMDB reader; the marker alone is easy to fake.

    install_reader() runs before any download, so a missing reader means the
    database cannot be checked and is refused.
    """
    if VENDOR_DIR.exists() and str(VENDOR_DIR) not in sys.path:
        # Append, as pulsepath.py does, so vendor/ cannot shadow the stdlib.
        sys.path.append(str(VENDOR_DIR))
    try:
        import maxminddb
    except ImportError:
        return False
    try:
        reader = maxminddb.open_database(str(database))
    except Exception:
        return False
    try:
        metadata = reader.metadata()
        return bool(metadata.database_type) and metadata.node_count > 0
    except Exception:
        return False
    finally:
        reader.close()


def reader_install_command() -> list[str]:
    return [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--upgrade",
        "--require-hashes",
        "--target",
        str(VENDOR_DIR),
        "-r",
        str(READER_REQUIREMENTS),
    ]


def release_candidates() -> list[str]:
    today = dt.date.today().replace(day=1)
    candidates = []
    year, month = today.year, today.month
    for _ in range(3):
        candidates.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return candidates


def download_database(kind: str, size_label: str) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for release in release_candidates():
        url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{release}.mmdb.gz"
        archive = DATA_DIR / f"dbip-{kind}-lite-{release}.mmdb.gz.part"
        database = DATA_DIR / f"dbip-{kind}-lite-{release}.mmdb"
        if database.exists():
            print(f"Using existing {database.name}")
            return database
        temporary_database = database.with_suffix(".mmdb.part")
        try:
            print(f"Downloading DB-IP {kind.upper()} Lite {release} ({size_label})…")
            request = urllib.request.Request(url, headers={"User-Agent": "Pulsepath/0.1"})
            with urllib.request.urlopen(request, timeout=45) as response:
                if urlsplit(response.geturl()).scheme != "https":
                    raise RuntimeError("redirected away from HTTPS")
                total = int(response.headers.get("Content-Length", "0"))
                copy_stream(response, archive, total=total)
            print()
            print("Decompressing database…")
            decompress_archive(archive, temporary_database)
            if not database_is_valid(temporary_database) or not database_opens(temporary_database):
                raise RuntimeError(
                    f"The downloaded {database.name} is not a valid MaxMind-format database; refusing to install it."
                )
            temporary_database.replace(database)
            return database
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue
            raise
        finally:
            # Every exit, including a truncated gzip or a size-cap refusal,
            # leaves no partial archive or unverified database behind.
            archive.unlink(missing_ok=True)
            temporary_database.unlink(missing_ok=True)
    raise RuntimeError(f"No current DB-IP {kind.upper()} Lite release could be downloaded.")


def install_reader() -> None:
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    print("Installing the local MMDB reader (sha256-verified)…")
    subprocess.run(reader_install_command(), check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Install Pulsepath offline IP location and network ownership data")
    parser.add_argument("--yes", action="store_true", help="Accept the DB-IP Lite CC BY 4.0 license prompt")
    args = parser.parse_args()

    if not args.yes:
        print("This downloads DB-IP City Lite and ASN Lite (approximately 134 MB uncompressed).")
        print("The data is licensed under Creative Commons Attribution 4.0.")
        answer = input("Install offline city and network intelligence? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("Installation cancelled.")
            return

    install_reader()
    city_database = download_database("city", "about 124 MB uncompressed")
    asn_database = download_database("asn", "about 10 MB uncompressed")
    print(f"Offline geolocation installed: {city_database.name}")
    print(f"Offline network ownership installed: {asn_database.name}")
    print("Restart Pulsepath to activate it.")


if __name__ == "__main__":
    main()
