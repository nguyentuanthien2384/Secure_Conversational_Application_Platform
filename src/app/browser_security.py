"""Browser origin checks for unsafe requests, including mounted Gradio routes.

Inspired by Go net/http CrossOriginProtection and OWASP Fetch Metadata policy.
This complements bearer authentication: it does not authenticate API clients,
which can set these headers themselves. Header-less non-browser clients remain
supported. Never derive a trusted origin from client-supplied proxy headers.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from starlette.requests import Request

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_FETCH_SITES = frozenset({"same-origin", "same-site", "cross-site", "none"})


def _origin(value: str) -> tuple[str, str, int] | None:
    """Parse a serialized HTTP origin without forgiving ambiguous syntax."""
    if (
        not value
        or len(value) > 2048
        or any(ord(char) <= 32 or ord(char) >= 127 for char in value)
        or any(char in value for char in "\\?#")
    ):
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.netloc.endswith(":")
            or "*" in parsed.netloc
            or "%" in parsed.netloc
        ):
            return None
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return None
        return parsed.scheme, parsed.hostname.lower(), port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def browser_request_denial(
    request: Request, allowed_origins: tuple[str, ...] = ()
) -> str | None:
    """Return a fixed denial reason, never an attacker-controlled header value.

    Safe reads/preflights remain available. State-changing requests need either
    an exact trusted Origin, a same-origin Fetch Metadata signal, or no browser
    origin signals (CLI/server clients). Sibling subdomains are not implicitly
    trusted. An explicit Origin must be valid even alongside same-origin metadata.
    """
    if request.method in _SAFE_METHODS:
        return None
    origins = request.headers.getlist("origin")
    sites = request.headers.getlist("sec-fetch-site")
    if len(origins) > 1 or len(sites) > 1:
        return "ambiguous_origin_headers"
    site = sites[0] if sites else None
    if site is not None and site not in _FETCH_SITES:
        return "invalid_fetch_metadata"
    if origins:
        origin = _origin(origins[0])
        if origin is None:
            return "invalid_origin"
        # The existing explicit CORS allowlist is also the cross-origin write
        # allowlist. Wildcards/invalid entries never grant this exemption.
        if any(origin == _origin(value) for value in allowed_origins):
            return None
        if site in {"same-site", "cross-site"}:
            return "untrusted_cross_origin"
        hosts = request.headers.getlist("host")
        if len(hosts) != 1:
            return "ambiguous_host"
        target = _origin(f"{request.scope['scheme']}://{hosts[0]}")
        if origin != target:
            return "untrusted_origin"
        return None
    if site in {"same-site", "cross-site"}:
        return "untrusted_cross_origin"
    return None
