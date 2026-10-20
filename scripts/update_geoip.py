"""Install or refresh the local GeoIP City database used for sign-in travel alerts.

Default source: DB-IP "IP to City Lite" (free, monthly, CC BY 4.0, no account):
https://db-ip.com/db/download/ip-to-city-lite. Any other City MMDB, such as a
MaxMind GeoLite2-City file you downloaded with your own licence, can be
installed with ``--source-file``.

The file is checked before it replaces the current one: size bounds, MaxMind DB
metadata (a City database built within the allowed age) and, when the
``maxminddb`` package is available, a real lookup. Only the standard library is
required, so the command also runs on the VPS host:

    python3 -m scripts.update_geoip --dir /root/scap-security --refresh-after-days 25

The application reads the file at start-up; restart it to load a new database.
Output is ASCII so it prints on any console.
"""

from __future__ import annotations

import argparse
import gzip
import os
import shutil
import struct
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

DATABASE_NAME = "geoip-city.mmdb"
DBIP_URL = "https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz"
_DOWNLOAD_HOST = "download.db-ip.com"
_MAX_COMPRESSED = 160 * 1024 * 1024
# Same ceiling as the application's reader (src/app/sign_in_risk.py).
_MAX_DATABASE = 256 * 1024 * 1024
_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
_CHUNK = 1024 * 1024
# Public addresses every real City feed locates (81.2.69.160 is also in MaxMind's test data).
_PROBES = ("8.8.8.8", "1.1.1.1", "81.2.69.160")


class GeoIpUpdateError(RuntimeError):
    """The database could not be obtained or failed validation; nothing was replaced."""


# ----------------------------------------------------------------- metadata


def _decode(data: bytes, offset: int, base: int, depth: int = 0):
    """Decode one MaxMind DB data-section value; pointers are relative to ``base``."""
    if depth > 16 or offset >= len(data):
        raise GeoIpUpdateError("Malformed MaxMind DB metadata.")
    control = data[offset]
    offset += 1
    kind = control >> 5
    if kind == 1:  # pointer: SS selects 1-4 extra bytes, VVV are high bits
        size, low = (control >> 3) & 0x3, control & 0x7
        value = int.from_bytes(data[offset:offset + size + 1], "big")
        target = ((0, 2048, 526_336)[size] + ((low << (8 * (size + 1))) | value)
                  if size < 3 else value)
        return _decode(data, base + target, base, depth + 1)[0], offset + size + 1
    if kind == 0:  # extended type
        kind = 7 + data[offset]
        offset += 1
    size = control & 0x1F
    if size >= 29:
        extra = size - 28
        value = int.from_bytes(data[offset:offset + extra], "big")
        offset += extra
        size = (29, 285, 65_821)[extra - 1] + value
    if kind == 2:  # utf-8 string
        return data[offset:offset + size].decode("utf-8"), offset + size
    if kind == 3:  # double
        return struct.unpack(">d", data[offset:offset + 8])[0], offset + 8
    if kind == 4:  # bytes
        return data[offset:offset + size], offset + size
    if kind in (5, 6, 9, 10):  # unsigned integers
        return int.from_bytes(data[offset:offset + size], "big"), offset + size
    if kind == 8:  # int32
        return int.from_bytes(data[offset:offset + size], "big", signed=True), offset + size
    if kind == 7:  # map
        result = {}
        for _ in range(size):
            key, offset = _decode(data, offset, base, depth + 1)
            result[key], offset = _decode(data, offset, base, depth + 1)
        return result, offset
    if kind == 11:  # array
        items = []
        for _ in range(size):
            item, offset = _decode(data, offset, base, depth + 1)
            items.append(item)
        return items, offset
    if kind == 14:  # boolean
        return bool(size), offset
    if kind == 15:  # float
        return struct.unpack(">f", data[offset:offset + 4])[0], offset + 4
    raise GeoIpUpdateError("Unsupported MaxMind DB metadata type.")


def read_metadata(path: Path) -> dict:
    """Return the metadata map stored at the end of a MaxMind DB file."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - 128 * 1024))
        tail = stream.read()
    start = tail.rfind(_METADATA_MARKER)
    if start < 0:
        raise GeoIpUpdateError("Not a MaxMind DB (.mmdb) file.")
    base = start + len(_METADATA_MARKER)
    metadata, _ = _decode(tail, base, base)
    if not isinstance(metadata, dict):
        raise GeoIpUpdateError("Malformed MaxMind DB metadata.")
    return metadata


def validate(path: Path, *, now: datetime, max_age_days: int) -> dict:
    """Check a candidate database the same way the application will load it."""
    size = path.stat().st_size
    if not 1024 <= size <= _MAX_DATABASE:
        raise GeoIpUpdateError("GeoIP database size is outside the supported bounds.")
    metadata = read_metadata(path)
    kind, epoch = metadata.get("database_type"), metadata.get("build_epoch")
    if not isinstance(kind, str) or "City" not in kind:
        raise GeoIpUpdateError("The file is not a City database.")
    if (type(epoch) is not int or metadata.get("record_size") not in (24, 28, 32)
            or metadata.get("ip_version") not in (4, 6) or not metadata.get("node_count")):
        raise GeoIpUpdateError("Malformed MaxMind DB metadata.")
    age = now.timestamp() - epoch
    if age < -86_400 or age > max_age_days * 86_400:
        raise GeoIpUpdateError(f"The database is older than {max_age_days} days (or dated in the future).")
    try:
        import maxminddb
    except ImportError:
        return metadata
    try:
        with maxminddb.open_database(str(path)) as reader:
            records = [reader.get(address) for address in _PROBES]
    except Exception as exc:
        raise GeoIpUpdateError("The database could not be read.") from exc
    if not any(isinstance(record, dict) and "latitude" in (record.get("location") or {})
               for record in records):
        raise GeoIpUpdateError("The database has no coordinates for well-known addresses.")
    return metadata


# ----------------------------------------------------------------- download


def _months(now: datetime) -> list[str]:
    previous = now.replace(day=1) - timedelta(days=1)
    return [now.strftime("%Y-%m"), previous.strftime("%Y-%m")]


def _download(url: str, destination: Path, opener=urllib.request.urlopen) -> bool:
    """Stream an HTTPS download; False when the monthly file is not published yet."""
    request = urllib.request.Request(url, headers={"User-Agent": "SCAP-GeoIP-Updater/1.0"})
    try:
        response = opener(request, timeout=60)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise GeoIpUpdateError(f"Download failed with HTTP {exc.code}.") from None
    except (urllib.error.URLError, OSError) as exc:
        raise GeoIpUpdateError("Download failed; check the server's Internet access.") from exc
    with response:
        final = urlsplit(response.geturl() or url)
        if final.scheme != "https" or final.hostname != _DOWNLOAD_HOST:
            raise GeoIpUpdateError("Download was redirected to an unexpected location.")
        total = 0
        with destination.open("wb") as output:
            while chunk := response.read(_CHUNK):
                total += len(chunk)
                if total > _MAX_COMPRESSED:
                    raise GeoIpUpdateError("Download exceeds the size limit.")
                output.write(chunk)
    return True


def _expand(source: Path, destination: Path) -> None:
    """Copy a .mmdb, or decompress a .mmdb.gz, within the size limit."""
    with source.open("rb") as raw:
        gzipped = raw.read(2) == b"\x1f\x8b"
    total = 0
    with (gzip.open(source, "rb") if gzipped else source.open("rb")) as stream, destination.open("wb") as output:
        while chunk := stream.read(_CHUNK):
            total += len(chunk)
            if total > _MAX_DATABASE:
                raise GeoIpUpdateError("The database exceeds the size limit.")
            output.write(chunk)


# ----------------------------------------------------------------- install


def install(directory: Path, *, source: Path | None = None, now: datetime | None = None,
            refresh_after_days: int = 0, max_age_days: int = 90,
            opener=urllib.request.urlopen) -> tuple[str, dict]:
    """Install a validated database; returns ("installed" | "unchanged", metadata)."""
    now = now or datetime.now(timezone.utc)
    directory = Path(os.path.abspath(directory))
    if not directory.parent.is_dir():
        raise GeoIpUpdateError("The parent of the GeoIP directory must already exist.")
    directory.mkdir(mode=0o755, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise GeoIpUpdateError("The GeoIP directory must be an ordinary directory.")
    target = directory / DATABASE_NAME
    if target.is_symlink():
        raise GeoIpUpdateError("Refusing to replace a symbolic link.")
    if source is None and refresh_after_days > 0 and target.is_file():
        try:
            current = validate(target, now=now, max_age_days=max_age_days)
        except GeoIpUpdateError:
            current = None
        if current and now.timestamp() - current["build_epoch"] < refresh_after_days * 86_400:
            return "unchanged", current

    workspace = Path(tempfile.mkdtemp(prefix=".geoip-", dir=directory))
    try:
        candidate = workspace / DATABASE_NAME
        if source is not None:
            _expand(Path(source), candidate)
        else:
            archive = workspace / "download.mmdb.gz"
            for month in _months(now):
                if _download(DBIP_URL.format(month=month), archive, opener):
                    break
            else:
                raise GeoIpUpdateError("No DB-IP City Lite file is published for this or last month.")
            _expand(archive, candidate)
        metadata = validate(candidate, now=now, max_age_days=max_age_days)
        os.chmod(candidate, 0o644)  # the app runs as a non-root user in Docker
        os.replace(candidate, target)
        return "installed", metadata
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dir", required=True, type=Path,
                        help=f"Folder that will hold {DATABASE_NAME}, e.g. local_data/geoip.")
    parser.add_argument("--source-file", type=Path,
                        help="Install this .mmdb or .mmdb.gz instead of downloading DB-IP City Lite.")
    parser.add_argument("--refresh-after-days", type=int, default=0,
                        help="Keep a valid database younger than this many days (0 = always fetch).")
    parser.add_argument("--max-age-days", type=int, default=90,
                        help="Oldest database accepted; match GEOIP_MAX_DATABASE_AGE_DAYS.")
    args = parser.parse_args(argv)
    if not 1 <= args.max_age_days <= 365 or not 0 <= args.refresh_after_days <= 365:
        parser.error("--max-age-days must be 1-365 and --refresh-after-days 0-365.")
    try:
        status, metadata = install(args.dir, source=args.source_file,
                                   refresh_after_days=args.refresh_after_days,
                                   max_age_days=args.max_age_days)
    except (GeoIpUpdateError, OSError, EOFError, gzip.BadGzipFile) as exc:
        print(f"GeoIP update failed: {exc}", file=sys.stderr)
        return 1
    built = datetime.fromtimestamp(metadata["build_epoch"], timezone.utc).date().isoformat()
    path = Path(os.path.abspath(args.dir)) / DATABASE_NAME
    if status == "unchanged":
        print(f"GeoIP database is up to date: {metadata['database_type']} built {built} ({path}).")
    else:
        print(f"GeoIP database installed: {metadata['database_type']} built {built} -> {path}")
        print("Restart the application to load it.")
        if str(metadata["database_type"]).startswith("DBIP"):
            print("Data licence: IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
