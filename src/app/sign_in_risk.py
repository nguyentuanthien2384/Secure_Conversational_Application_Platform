"""Local GeoIP signals: approximate travel evidence, never an authentication factor."""

from __future__ import annotations

import ipaddress
import math
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.app.account_security import SIGN_IN_EVENT_TYPES
from src.app.models import AuditEvent
from src.app.private_storage import read_regular_file

TRAVEL_EVENT = "auth.login.impossible_travel"


@dataclass(frozen=True)
class SignInRiskSettings:
    backend: str = "disabled"
    database_file: str = ""
    max_database_age_days: int = 90
    history_hours: int = 24
    min_distance_km: int = 500
    max_speed_kmh: int = 900

    def __post_init__(self):
        if self.backend not in {"disabled", "maxmind"}:
            raise ValueError("GEOIP_BACKEND must be disabled or maxmind.")
        for value, low, high in (
            (self.max_database_age_days, 1, 365), (self.history_hours, 1, 168),
            (self.min_distance_km, 100, 20_000), (self.max_speed_kmh, 100, 3_000),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("GeoIP risk thresholds are outside their supported bounds.")
        if self.backend == "maxmind" and not self.database_file:
            raise ValueError("GEOIP_DATABASE_FILE is required for local MaxMind lookup.")

    @classmethod
    def from_env(cls):
        return cls(
            backend=os.getenv("GEOIP_BACKEND", "disabled").strip().lower(),
            database_file=os.getenv("GEOIP_DATABASE_FILE", "").strip(),
            max_database_age_days=int(os.getenv("GEOIP_MAX_DATABASE_AGE_DAYS", "90")),
            history_hours=int(os.getenv("GEOIP_HISTORY_HOURS", "24")),
            min_distance_km=int(os.getenv("GEOIP_MIN_DISTANCE_KM", "500")),
            max_speed_kmh=int(os.getenv("GEOIP_MAX_SPEED_KMH", "900")),
        )


@dataclass(frozen=True)
class Location:
    latitude: float
    longitude: float
    accuracy_km: float
    country: str


class LocalGeoIp:
    """Read a bounded operator-provided City MMDB without network lookups."""

    def __init__(self, settings: SignInRiskSettings):
        self.settings = settings
        self.reader = None
        self.build_epoch = None
        self.available = settings.backend == "disabled"
        if settings.backend == "disabled":
            return
        try:
            import maxminddb

            # FD mode avoids reopening a changed symlink/path after validation.
            # The regular-file helper rejects devices, FIFOs and symlinks.
            with read_regular_file(Path(settings.database_file)) as source:
                if os.fstat(source.fileno()).st_size > 256 * 1024 * 1024:
                    raise ValueError("GeoIP database exceeds the memory budget.")
                self.reader = maxminddb.open_database(source, maxminddb.MODE_FD)
            metadata = self.reader.metadata()
            self.build_epoch = metadata.build_epoch
            age = datetime.now(timezone.utc).timestamp() - metadata.build_epoch
            if ("City" not in metadata.database_type or age < -86_400
                    or age > settings.max_database_age_days * 86_400):
                raise ValueError("GeoIP database must be a recent City database.")
            self.available = True
        except Exception:
            self.close()
            raise RuntimeError("Cannot load a recent local GeoIP City database; check the geoip extra and file.") from None

    def close(self):
        if self.reader is not None:
            self.reader.close()
            self.reader = None

    def lookup(self, value: str) -> Location | None:
        if self.reader is None:
            return None
        if not self.check_freshness():
            return None
        try:
            address = ipaddress.ip_address(value)
            if not address.is_global:
                return None
            document = self.reader.get(str(address))
            if not isinstance(document, dict):
                return None
            location = document.get("location", {})
            country = document.get("country", {}).get("iso_code", "")
            coordinates = [location.get(key) for key in ("latitude", "longitude", "accuracy_radius")]
            if any(type(number) not in (int, float) or not math.isfinite(number) for number in coordinates):
                return None
            latitude, longitude, accuracy = coordinates
            if (not -90 <= latitude <= 90 or not -180 <= longitude <= 180 or not 0 <= accuracy <= 500
                    or not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country)):
                return None
            return Location(latitude, longitude, accuracy, country)
        except ValueError:
            return None
        except Exception:
            # A corrupt/unavailable optional risk feed cannot be reported as a
            # clean result or turn geolocation into an account lockout vector.
            self.available = False
            return None

    def check_freshness(self) -> bool:
        if self.build_epoch is not None:
            age = datetime.now(timezone.utc).timestamp() - self.build_epoch
            if age < -86_400 or age > self.settings.max_database_age_days * 86_400:
                self.available = False
        return self.available


def conservative_distance_km(a: Location, b: Location) -> float:
    lat_a, lat_b = math.radians(a.latitude), math.radians(b.latitude)
    delta_lat = lat_b - lat_a
    delta_lon = math.radians(b.longitude - a.longitude)
    haversine = math.sin(delta_lat / 2) ** 2 + math.cos(lat_a) * math.cos(lat_b) * math.sin(delta_lon / 2) ** 2
    distance = 2 * 6371.0088 * math.asin(math.sqrt(min(1, max(0, haversine))))
    return max(0, distance - a.accuracy_km - b.accuracy_km)


class SignInRiskService:
    def __init__(self, settings: SignInRiskSettings):
        self.settings = settings
        self.geoip = LocalGeoIp(settings)

    def close(self):
        self.geoip.close()

    def status(self):
        return {"backend": self.settings.backend, "available": self.geoip.check_freshness(),
                "action": "alert_only", "external_ip_lookup": False}

    def assess(self, db: Session, user_id: str, ip: str, now: datetime) -> dict | None:
        current = self.geoip.lookup(ip)
        if current is None:
            return None
        previous = db.execute(select(AuditEvent.id, AuditEvent.ip_address, AuditEvent.created_at).where(
            AuditEvent.actor_id == user_id,
            AuditEvent.event_type.in_(SIGN_IN_EVENT_TYPES), AuditEvent.outcome == "success",
            AuditEvent.created_at >= now - timedelta(hours=self.settings.history_hours),
        ).order_by(AuditEvent.id.desc()).limit(20)).all()
        for row in previous:
            # The last resolvable successful source is the comparison boundary.
            if row.ip_address == ip:
                return None
            past = self.geoip.lookup(row.ip_address or "")
            if past is None:
                continue
            timestamp = row.created_at.replace(tzinfo=timezone.utc) if row.created_at.tzinfo is None else row.created_at
            seconds = (now - timestamp).total_seconds()
            if seconds < 0:
                return None
            distance = conservative_distance_km(past, current)
            speed = distance / (max(seconds, 60) / 3600)
            if distance < self.settings.min_distance_km or speed <= self.settings.max_speed_kmh:
                return None
            # Never store coordinates, resolved city names or a location trail.
            return {"from_country": past.country, "to_country": current.country,
                    "distance_km_lower_bound": round(distance), "speed_kmh_lower_bound": round(speed),
                    "elapsed_minutes": round(seconds / 60), "previous_audit_id": row.id,
                    "action": "alert_only", "approximate": True}
        return None
