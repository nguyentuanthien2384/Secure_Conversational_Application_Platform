"""Render only Gradio's trusted bootstrap template with a response nonce.

Never modify Gradio's global template environment or nonce scripts found in a
rendered response. The allowlist below is checked against the installed vendor
template before compiling an application-owned copy.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

import gradio.routes
from fastapi import FastAPI
from fastapi.routing import APIRoute
from jinja2 import ChoiceLoader, DictLoader
from starlette.templating import Jinja2Templates, _TemplateResponse

_TEMPLATE = "frontend/index.html"
_SCRIPT_OPEN = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
_CONFIG_SCRIPT = "window.gradio_config = {{ config | toorjson }};"
_API_SCRIPT = "window.gradio_api_info = {{ gradio_api_info | toorjson }};"
_MODE_SCRIPT = '''
window.__gradio_mode__ = "app";
window.iFrameResizer = { autoResize: false, sizeWidth: false };
window.parent?.postMessage({ type: "SET_SCROLLING", enabled: false }, "*");
'''
_DOM_SCRIPT = '''
const ce = document.getElementsByTagName("gradio-app");
if (ce[0]) {
ce[0].addEventListener("domchange", () => { document.body.style.padding = "0"; });
document.body.style.padding = "0";
}
'''
_HEAD_ASSETS = (
    "/api/ui-session/bridge.js",
    "/api/ui-session/login-credentials.js",
    "/api/ui-session/passkey.js",
)


class _Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.scripts: list[tuple[dict[str, str | None], str]] = []
        self._current: dict[str, str | None] | None = None
        self._body: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            if self._current is not None or len(dict(attrs)) != len(attrs):
                raise RuntimeError("Unexpected Gradio script structure.")
            self._current = dict(attrs)
            self._body = []

    def handle_data(self, data):
        if self._current is not None:
            self._body.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._current is not None:
            self.scripts.append((self._current, "".join(self._body)))
            self._current = None


def _compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _trusted_template(source: str) -> str:
    parser = _Scripts()
    parser.feed(source)
    expected_inline = [_CONFIG_SCRIPT, _API_SCRIPT, _MODE_SCRIPT, _DOM_SCRIPT]
    inline = [body for attrs, body in parser.scripts if "src" not in attrs]
    external = [(attrs, body) for attrs, body in parser.scripts if "src" in attrs]
    if (
        parser._current is not None or len(parser.scripts) != 6
        or [_compact(body) for body in inline] != [_compact(body) for body in expected_inline]
        or len(external) != 2 or len(_SCRIPT_OPEN.findall(source)) != 6
        or any(body.strip() for _, body in external)
        or external[0][0] != {
            "src": "{{ config.get('root', '') }}/static/js/iframeResizer.contentWindow.min.js",
            "async": None,
        }
        or not re.fullmatch(r"\./assets/index-[A-Za-z0-9_-]+\.js", external[1][0].get("src") or "")
        or set(external[1][0]) != {"type", "crossorigin", "src"}
        or external[1][0]["type"] != "module"
        or any(set(attrs) - {"data-gradio-mode"} for attrs, _ in parser.scripts if "src" not in attrs)
    ):
        raise RuntimeError("Installed Gradio bootstrap is incompatible with nonce CSP.")

    def add_nonce(match: re.Match) -> str:
        tag = match.group()
        # These tags come from the validated package template, before any data
        # is interpolated. User content cannot acquire this nonce.
        return tag[:-1] + ' nonce="{{ scap_csp_nonce }}">'

    return _SCRIPT_OPEN.sub(add_nonce, source)


def _validate_custom_scripts(blocks) -> None:
    if blocks.share or blocks.config.get("js"):
        raise RuntimeError("SCAP nonce CSP does not allow Gradio sharing or custom inline JavaScript.")
    parser = _Scripts()
    parser.feed(blocks.config.get("head") or "")
    if (
        parser._current is not None or len(parser.scripts) != len(_HEAD_ASSETS)
        or [(attrs, body.strip()) for attrs, body in parser.scripts] != [
            ({"src": asset, "defer": None}, "") for asset in _HEAD_ASSETS
        ]
    ):
        raise RuntimeError("SCAP nonce CSP requires the packaged same-origin script assets.")


def attach_gradio_csp(blocks, mounted_app: FastAPI) -> None:
    """Replace this mounted app's page callable, preserving vendor dependencies."""
    _validate_custom_scripts(blocks)
    vendor = gradio.routes.templates
    source, _, _ = vendor.env.loader.get_source(vendor.env, _TEMPLATE)
    hardened = _trusted_template(source)
    environment = vendor.env.overlay()
    environment.loader = ChoiceLoader([DictLoader({_TEMPLATE: hardened}), vendor.env.loader])
    renderer = Jinja2Templates(env=environment, context_processors=list(vendor.context_processors))
    targets = [
        route for route in mounted_app.routes
        if isinstance(route, APIRoute) and route.path == "/" and route.methods & {"GET", "HEAD"}
    ]
    if len(targets) != 2:
        raise RuntimeError("Installed Gradio page routes are incompatible with nonce CSP.")
    for route in targets:
        original = route.dependant.call

        def page(*args, _original=original, **kwargs):
            _validate_custom_scripts(blocks)
            response = _original(*args, **kwargs)
            if not isinstance(response, _TemplateResponse) or response.template.name != _TEMPLATE:
                raise RuntimeError("Unexpected Gradio page response.")
            request = response.context["request"]
            nonce = getattr(request.state, "scap_csp_nonce", None)
            if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32}", nonce):
                raise RuntimeError("Gradio page requires a fresh application CSP nonce.")
            context = {**response.context, "scap_csp_nonce": nonce}
            headers = {name: value for name, value in response.headers.items() if name != "content-length"}
            return renderer.TemplateResponse(
                request=request, name=_TEMPLATE, context=context,
                status_code=response.status_code, headers=headers, background=response.background,
            )

        route.dependant.call = page
        route.endpoint = page
