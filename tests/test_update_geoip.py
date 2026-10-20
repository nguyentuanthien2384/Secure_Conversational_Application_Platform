"""The GeoIP updater installs only a validated, recent City database, atomically."""
from __future__ import annotations

import gzip
import io
import os
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts import update_geoip
from scripts.update_geoip import DATABASE_NAME, GeoIpUpdateError, install, read_metadata

FIXTURE = Path(__file__).parent / "fixtures/maxmind/GeoIP2-City-Test.mmdb"
EPOCH = read_metadata(FIXTURE)["build_epoch"]
FRESH = datetime.fromtimestamp(EPOCH + 86_400, tz=timezone.utc)


class _Response(io.BytesIO):
    def __init__(self, payload: bytes, url: str):
        super().__init__(payload)
        self.url = url

    def geturl(self):
        return self.url


def _opener(responses: dict[str, bytes], requested: list[str], final_url: str | None = None):
    def opener(request, timeout):
        assert timeout <= 60
        requested.append(request.full_url)
        if request.full_url not in responses:
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", None, None)
        return _Response(responses[request.full_url], final_url or request.full_url)
    return opener


def test_metadata_parser_matches_the_maxminddb_reader():
    maxminddb = pytest.importorskip("maxminddb")
    with maxminddb.open_database(str(FIXTURE)) as reader:
        expected = reader.metadata()
    metadata = read_metadata(FIXTURE)
    assert metadata["database_type"] == expected.database_type == "GeoIP2-City"
    assert metadata["build_epoch"] == expected.build_epoch
    assert metadata["languages"] == expected.languages  # decoded through pointers
    assert metadata["description"] == expected.description


def test_downloads_db_ip_falls_back_to_last_month_and_installs_atomically(tmp_path):
    now = FRESH
    this_month = update_geoip.DBIP_URL.format(month=now.strftime("%Y-%m"))
    last_month = update_geoip.DBIP_URL.format(month=(now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m"))
    requested: list[str] = []
    opener = _opener({last_month: gzip.compress(FIXTURE.read_bytes())}, requested)
    status, metadata = install(tmp_path / "geoip", now=now, max_age_days=90, opener=opener)
    assert status == "installed" and metadata["database_type"] == "GeoIP2-City"
    assert requested == [this_month, last_month]
    target = tmp_path / "geoip" / DATABASE_NAME
    assert target.read_bytes() == FIXTURE.read_bytes()
    assert os.listdir(tmp_path / "geoip") == [DATABASE_NAME]  # no partial files left behind
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o644  # readable by the container's app user


def test_fresh_database_is_kept_without_network_access(tmp_path):
    install(tmp_path, source=FIXTURE, now=FRESH)

    def no_network(*_args, **_kwargs):
        raise AssertionError("must not download")

    status, _ = install(tmp_path, now=FRESH, refresh_after_days=25, opener=no_network)
    assert status == "unchanged"


@pytest.mark.parametrize("payload,message", [
    (b"plain text, not a database" * 100, "Not a MaxMind DB"),
    (b"short", "size"),
])
def test_invalid_download_never_replaces_the_working_database(tmp_path, payload, message):
    install(tmp_path, source=FIXTURE, now=FRESH)
    url = update_geoip.DBIP_URL.format(month=FRESH.strftime("%Y-%m"))
    with pytest.raises(GeoIpUpdateError, match=message):
        install(tmp_path, now=FRESH, opener=_opener({url: gzip.compress(payload)}, []))
    assert (tmp_path / DATABASE_NAME).read_bytes() == FIXTURE.read_bytes()
    assert os.listdir(tmp_path) == [DATABASE_NAME]


def test_stale_or_future_database_is_rejected(tmp_path):
    with pytest.raises(GeoIpUpdateError, match="older than 90 days"):
        install(tmp_path, source=FIXTURE, now=FRESH + timedelta(days=120))
    with pytest.raises(GeoIpUpdateError, match="older than"):
        install(tmp_path, source=FIXTURE, now=FRESH - timedelta(days=10))
    assert not (tmp_path / DATABASE_NAME).exists()


def test_redirect_away_from_db_ip_is_refused(tmp_path):
    url = update_geoip.DBIP_URL.format(month=FRESH.strftime("%Y-%m"))
    opener = _opener({url: gzip.compress(FIXTURE.read_bytes())}, [], final_url="https://evil.example/x.gz")
    with pytest.raises(GeoIpUpdateError, match="redirected"):
        install(tmp_path, now=FRESH, opener=opener)


def test_cli_reports_failures_without_a_traceback(tmp_path, capsys):
    assert update_geoip.main(["--dir", str(tmp_path / "geoip"), "--source-file",
                              str(tmp_path / "missing.mmdb.gz")]) == 1
    assert "GeoIP update failed" in capsys.readouterr().err
