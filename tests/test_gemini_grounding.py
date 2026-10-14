"""Search tools, source provenance and complete answer handling without Google calls."""

from types import SimpleNamespace

import pytest
from google.genai import types

from src.core.ai_core.gemini_ai import (
    GeminiClient,
    GroundedAnswer,
    validate_search_suggestions_html,
)


def _response(*, text="A verified answer.", reason="STOP", metadata=None, thought=None):
    parts = []
    if thought is not None:
        parts.append(SimpleNamespace(text=thought, thought=True))
    parts.append(SimpleNamespace(text=text, thought=False))
    return SimpleNamespace(candidates=[SimpleNamespace(
        content=SimpleNamespace(parts=parts), finish_reason=reason,
        grounding_metadata=metadata,
    )])


def _client(response):
    captured = {}
    client = GeminiClient(api_key="synthetic-test-key", max_output_tokens=2048)

    def generate_content(**kwargs):
        captured.update(kwargs)
        return response

    client.client = SimpleNamespace(models=SimpleNamespace(generate_content=generate_content))
    return client, captured


def _metadata(*, source="https://www.example.com/article", title="Verified source", suggestions=None):
    if suggestions is None:
        suggestions = '<a href="https://www.google.com/search?q=verified+fact">verified fact</a>'
    return SimpleNamespace(
        grounding_chunks=[SimpleNamespace(web=SimpleNamespace(uri=source, title=title))],
        search_entry_point=SimpleNamespace(rendered_content=suggestions),
        web_search_queries=["verified fact"],
    )


def test_search_is_not_enabled_for_ordinary_chat():
    client, captured = _client(_response(metadata=_metadata()))
    assert client.generate("hello") == "A verified answer."
    assert not captured["config"].tools


def test_explicit_search_grants_only_google_search_and_keeps_provider_sources():
    client, captured = _client(_response(metadata=_metadata()))
    text = client.generate("Check a public fact", use_web_search=True)
    tools = captured["config"].tools
    assert len(tools) == 1 and isinstance(tools[0].google_search, types.GoogleSearch)
    assert tools[0].function_declarations is None and tools[0].code_execution is None
    assert text.startswith("A verified answer.")
    assert "https://www.example.com/article" in text
    assert isinstance(text, GroundedAnswer)
    assert text.search_suggestions_html == _metadata().search_entry_point.rendered_content
    assert "google.com/search" not in text
    assert "Google Search" in text


def test_search_does_not_allow_extra_config_to_replace_the_search_tool():
    client, captured = _client(_response(metadata=_metadata()))
    client.generate("Public fact", use_web_search=True, extra_config={
        "tools": [types.Tool(code_execution=types.ToolCodeExecution())],
        "max_output_tokens": 6000,
    })
    assert captured["config"].tools[0].code_execution is None
    assert captured["config"].max_output_tokens == 2048


@pytest.mark.parametrize("uri", [
    "javascript:alert(1)", "data:text/html,example", "http://www.example.com/article",
    "https://localhost/private", "https://127.0.0.1/private", "https://10.0.0.1/private",
    "https://app.internal/private", "https://user:password@www.example.com/private",
    "https://www.example.com:8443/private", "https://www.example.com/\nscript",
    "https://www.example.com/<img>", "https://www.example.com\\@evil.example/path",
])
def test_unsafe_source_urls_fail_closed(uri):
    client, _ = _client(_response(metadata=_metadata(source=uri)))
    with pytest.raises(RuntimeError, match="nguồn tra cứu không an toàn"):
        client.generate("Public fact", use_web_search=True)


def test_source_titles_cannot_inject_additional_markdown_links_or_images():
    title = "Verified [click](https://evil.example) ![beacon](https://evil.example/image)"
    client, _ = _client(_response(metadata=_metadata(title=title)))
    output = client.generate("Public fact", use_web_search=True)
    assert "\\[click\\]" in output and "\\!\\[beacon\\]" in output


def test_unsafe_provider_widget_is_withheld_instead_of_modified():
    html = (
        '<script>private-script-detail</script><img src="https://evil.example/beacon">'
        '<a href="javascript:alert(1)">unsafe suggestion</a>'
        '<a href="https://www.google.com/search?q=verified+fact" onclick="alert(1)">verified fact</a>'
    )
    client, _ = _client(_response(metadata=_metadata(suggestions=html)))
    with pytest.raises(RuntimeError, match="gợi ý Google Search"):
        client.generate("Public fact", use_web_search=True)


@pytest.mark.parametrize("suggestions", [None, "", '<a href="https://evil.example/search">wrong service</a>'])
def test_grounded_answers_require_associated_google_suggestions(suggestions):
    metadata = _metadata()
    metadata.search_entry_point.rendered_content = suggestions
    client, _ = _client(_response(metadata=metadata))
    with pytest.raises(RuntimeError, match="gợi ý Google Search"):
        client.generate("Public fact", use_web_search=True)


def test_search_without_grounding_does_not_claim_the_answer_was_verified():
    client, _ = _client(_response())
    output = client.generate("Simple arithmetic", use_web_search=True)
    assert "không có nguồn kiểm chứng" in output
    assert "Nguồn kiểm chứng từ Google Search" not in output


def test_search_metadata_cannot_display_results_without_its_required_sources():
    metadata = _metadata()
    metadata.grounding_chunks = []
    client, _ = _client(_response(metadata=metadata))
    with pytest.raises(RuntimeError, match="thông tin nguồn"):
        client.generate("Public fact", use_web_search=True)


def test_google_widget_markup_and_branding_are_preserved_verbatim():
    widget = (
        '<style>.container { display: flex; color: #444; } '
        '@media (prefers-color-scheme: dark) { .container { color: white; } }</style>'
        '<div class="container"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
        '<path d="M1 1 L2 2" fill="#4285f4"/></svg>'
        '<a href="https://www.google.com/search?q=verified+fact" target="_blank">'
        'verified fact</a></div>'
    )
    assert validate_search_suggestions_html(widget)
    client, _ = _client(_response(metadata=_metadata(suggestions=widget)))
    assert client.generate("Public fact", use_web_search=True).search_suggestions_html == widget


def test_google_signed_search_widget_redirect_is_preserved():
    widget = ('<a class="chip" href="https://vertexaisearch.cloud.google.com/'
              'grounding-api-redirect/Synthetic_Provider-Token==">public fact</a>')
    assert validate_search_suggestions_html(widget)
    client, _ = _client(_response(metadata=_metadata(suggestions=widget)))
    assert client.generate("Public fact", use_web_search=True).search_suggestions_html == widget


@pytest.mark.parametrize("url", [
    "https://vertexaisearch.cloud.google.com/other/path",
    "https://vertexaisearch.cloud.google.com/grounding-api-redirect/token?next=https://evil.example",
    "https://vertexaisearch.cloud.google.com.evil.example/grounding-api-redirect/token",
])
def test_search_widget_cannot_redirect_to_unapproved_services(url):
    assert not validate_search_suggestions_html(f'<a href="{url}">fact</a>')


@pytest.mark.parametrize("widget", [
    '<a href="https://www.google.com/search?q=x" onclick="alert(1)">x</a>',
    '<a href="javascript:alert(1)">x</a>',
    '<a href="https://www.google.com/search?q=x" target="_top">x</a>',
    '<style>@import "https://tracker.example/x";</style>',
    '<style>@im/**/port "https://tracker.example/x";</style>',
    '<style>div{background:u\\72l(https://tracker.example/x)}</style>',
    '<style>div{background:url(https://tracker.example/x)}</style>',
    '<style>div{background:image-set("https://tracker.example/x" 1x)}</style>',
    '<div style="background: u&#114;l(https://tracker.example/x)">x</div>',
    '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>',
    '<svg><use href="https://tracker.example/x"/></svg>',
    '<svg><image href="https://tracker.example/x"/></svg>',
    '<link rel="stylesheet" href="https://tracker.example/x">',
    '<iframe src="https://tracker.example/x"></iframe>',
    '<form action="https://tracker.example/x"></form>',
    '<div><span></div></span>',
])
def test_search_widget_rejects_scripts_network_loads_and_html_parser_ambiguities(widget):
    assert not validate_search_suggestions_html(widget + _metadata().search_entry_point.rendered_content)


def test_grounding_citations_use_utf8_part_offsets_without_changing_answer_words():
    text = "Việt Nam. Một kết luận khác."
    segment = "Việt Nam."
    metadata = _metadata()
    metadata.grounding_supports = [SimpleNamespace(
        segment=SimpleNamespace(start_index=0, end_index=len(segment.encode('utf-8')),
                                text=segment, part_index=0), grounding_chunk_indices=[0],
    )]
    client, _ = _client(_response(text=text, metadata=metadata))
    answer = client.generate("Public fact", use_web_search=True)
    assert answer.startswith(segment + "[1](<https://www.example.com/article>) Một kết luận khác.")


def test_first_grounding_segment_can_omit_its_zero_start_index():
    metadata = _metadata()
    metadata.grounding_supports = [SimpleNamespace(
        segment=SimpleNamespace(end_index=4, text="Fact"), grounding_chunk_indices=[0],
    )]
    client, _ = _client(_response(text="Fact. More text.", metadata=metadata))
    assert client.generate("Public fact", use_web_search=True).startswith(
        "Fact[1](<https://www.example.com/article>). More text."
    )


@pytest.mark.parametrize("end, text, indices", [(3, None, [0]), (9000, None, [0]),
                                              (6, "wrong text", [0]), (6, None, [7])])
def test_invalid_grounding_supports_fail_closed(end, text, indices):
    metadata = _metadata()
    metadata.grounding_supports = [SimpleNamespace(
        segment=SimpleNamespace(start_index=0, end_index=end, text=text, part_index=0),
        grounding_chunk_indices=indices,
    )]
    client, _ = _client(_response(text="Việt Nam", metadata=metadata))
    with pytest.raises(RuntimeError, match="trích dẫn"):
        client.generate("Public fact", use_web_search=True)


def test_partial_grounded_answer_is_withheld_without_modifying_google_result():
    client, _ = _client(_response(reason="MAX_TOKENS", metadata=_metadata()))
    with pytest.raises(RuntimeError, match="chưa hoàn tất"):
        client.generate("Public fact", use_web_search=True)


def test_private_thought_parts_never_enter_a_visible_answer():
    client, _ = _client(_response(thought="private internal reasoning"))
    assert client.generate("hello") == "A verified answer."


def test_max_tokens_partial_answer_is_marked_as_incomplete():
    client, _ = _client(_response(text="A partial explanation", reason=types.FinishReason.MAX_TOKENS))
    output = client.generate("Explain", use_web_search=False)
    assert output.startswith("A partial explanation")
    assert "có thể chưa đầy đủ" in output and "tiếp tục" in output


@pytest.mark.parametrize("reason", ["SAFETY", "RECITATION", "PROHIBITED_CONTENT", "SPII"])
def test_blocked_provider_results_are_not_presented_as_complete_answers(reason):
    client, _ = _client(_response(text="potentially unsafe partial content", reason=reason))
    with pytest.raises(RuntimeError, match="hoàn tất"):
        client.generate("hello")
