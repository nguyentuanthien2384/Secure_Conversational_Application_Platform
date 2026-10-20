"""Local GeoIP signals: approximate travel evidence, never an authentication factor."""

from __future__ import annotations

import ipaddress
import logging
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
logger = logging.getLogger("secure_chat.geoip")


@dataclass(frozen=True)
class SignInRiskSettings:
    backend: str = "disabled"
    database_file: str = ""
    max_database_age_days: int = 90
    history_hours: int = 24
    min_distance_km: int = 500
    max_speed_kmh: int = 900
    # Feeds such as DB-IP City Lite publish city coordinates without MaxMind's
    # accuracy_radius. Assume this uncertainty so a distance stays a lower bound.
    default_accuracy_km: int = 200

    def __post_init__(self):
        if self.backend not in {"disabled", "maxmind"}:
            raise ValueError("GEOIP_BACKEND must be disabled or maxmind.")
        for value, low, high in (
            (self.max_database_age_days, 1, 365), (self.history_hours, 1, 168),
            (self.min_distance_km, 100, 20_000), (self.max_speed_kmh, 100, 3_000),
            (self.default_accuracy_km, 1, 500),
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
            default_accuracy_km=int(os.getenv("GEOIP_DEFAULT_ACCURACY_KM", "200")),
        )


@dataclass(frozen=True)
class Location:
    latitude: float
    longitude: float
    accuracy_km: float
    country: str
    # Shown only to the account owner for their own address; never stored.
    city: str = ""


class LocalGeoIp:
    """Read a bounded operator-provided City MMDB without network lookups."""

    def __init__(self, settings: SignInRiskSettings):
        self.settings = settings
        self.reader = None
        self.build_epoch = None
        self.database_type = ""
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
            if "City" not in metadata.database_type or type(metadata.build_epoch) is not int:
                raise ValueError("GeoIP database must be a City database.")
            self.build_epoch = metadata.build_epoch
            self.database_type = str(metadata.database_type)[:64]
        except Exception:
            self.close()
            raise RuntimeError("Cannot load a recent local GeoIP City database; check the geoip extra and file.") from None
        # An outdated feed is reported unavailable, exactly as when it expires
        # while running: an optional advisory signal must not stop sign-in.
        self.available = True
        if not self.check_freshness():
            logger.warning("GeoIP City database is older than GEOIP_MAX_DATABASE_AGE_DAYS; "
                           "travel checks are paused until it is updated.")

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
            coordinates = [location.get("latitude"), location.get("longitude"),
                           location.get("accuracy_radius", self.settings.default_accuracy_km)]
            if any(type(number) not in (int, float) or not math.isfinite(number) for number in coordinates):
                return None
            latitude, longitude, accuracy = coordinates
            if (not -90 <= latitude <= 90 or not -180 <= longitude <= 180 or not 0 <= accuracy <= 500
                    or not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country)):
                return None
            city = (document.get("city") or {}).get("names", {}).get("en", "")
            if not isinstance(city, str) or len(city) > 100 or not city.isprintable():
                city = ""
            return Location(latitude, longitude, accuracy, country, city)
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

    def status(self, ip: str | None = None) -> dict:
        """Readiness for the account page; ``ip`` is the caller's own address."""
        available = self.geoip.check_freshness()
        result = {"backend": self.settings.backend, "available": available,
                  "action": "alert_only", "external_ip_lookup": False,
                  "checked_at": datetime.now(timezone.utc).isoformat(),
                  "history_hours": self.settings.history_hours,
                  "min_distance_km": self.settings.min_distance_km,
                  "max_speed_kmh": self.settings.max_speed_kmh}
        if self.geoip.build_epoch is not None:
            built = datetime.fromtimestamp(self.geoip.build_epoch, timezone.utc)
            result["database"] = {
                "type": self.geoip.database_type, "built": built.date().isoformat(),
                "age_days": max(0, (datetime.now(timezone.utc) - built).days),
                "max_age_days": self.settings.max_database_age_days,
            }
        if ip is not None and self.settings.backend != "disabled":
            try:
                public = ipaddress.ip_address(ip).is_global
            except ValueError:
                public = False
            place = self.geoip.lookup(ip) if public and available else None
            # Coordinates stay server-side; the owner sees an approximate place.
            result["current"] = (
                {"resolved": True, "country": place.country, "city": place.city} if place
                else {"resolved": False, "reason": "unknown" if public else "private"}
            )
        return result

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
