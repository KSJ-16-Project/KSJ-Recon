"""
Reflection context analyzer.

This module is intentionally heuristic. It does not attempt full browser or
JavaScript data-flow analysis. It extracts report-friendly evidence:
- where the marker appears
- whether the marker is inside HTML body, an HTML attribute, a URL sink,
  a <script> block, or an event-handler JavaScript context
- whether quote breakout should be tested with a browser
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from html import unescape
import re


@dataclass
class ContextResult:
    reflected: bool
    context: str | None = None
    escaped: bool | None = None
    quote: str | None = None
    quote_breakout_possible: bool | None = None
    snippet: str = ""
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class ContextAnalyzer:
    URL_ATTRS = {"href", "src", "action", "formaction", "data", "url", "poster"}

    def analyze(self, response_text: str, marker: str, probe: str | None = None) -> ContextResult:
        idx = response_text.find(marker)
        if idx < 0:
            return ContextResult(reflected=False, reason="marker_not_reflected")

        snippet = self._snippet(response_text, idx, len(marker))
        context, quote = self._classify(response_text, idx, marker)
        escaped = self._is_escaped(response_text, marker, probe, context, quote)
        quote_breakout = self._quote_breakout_possible(snippet, quote, marker)
        reason = self._reason(context, escaped, quote_breakout)

        return ContextResult(
            reflected=True,
            context=context,
            escaped=escaped,
            quote=quote,
            quote_breakout_possible=quote_breakout,
            snippet=snippet,
            reason=reason,
        )

    def _snippet(self, text: str, idx: int, marker_len: int, radius: int = 120) -> str:
        start = max(0, idx - radius)
        end = min(len(text), idx + marker_len + radius)
        return text[start:end].replace("\n", " ").replace("\r", " ")

    def _classify(self, text: str, idx: int, marker: str) -> tuple[str, str | None]:
        before = text[:idx]
        after = text[idx + len(marker):]

        # HTML comment context
        last_comment_open = before.rfind("<!--")
        last_comment_close = before.rfind("-->")
        if last_comment_open > last_comment_close:
            return "html_comment", None

        # <script> block context
        last_script_open = before.lower().rfind("<script")
        last_script_close = before.lower().rfind("</script>")
        if last_script_open > last_script_close:
            quote = self._infer_js_quote(text, idx, start=last_script_open)
            if quote == '"':
                return "js_string_double", quote
            if quote == "'":
                return "js_string_single", quote
            return "js_block", None

        # Inside an HTML tag / attribute?
        last_lt = before.rfind("<")
        last_gt = before.rfind(">")
        next_gt = after.find(">")
        if last_lt > last_gt and next_gt >= 0:
            tag_fragment = text[last_lt: idx + len(marker) + next_gt + 1]
            attr = self._attribute_containing_marker(tag_fragment, marker)
            if attr:
                attr_name, attr_quote, attr_value = attr
                lower_name = attr_name.lower()

                # URL sink: <a href="...marker...">, <form action="...">
                if lower_name in self.URL_ATTRS:
                    return "url_context", attr_quote

                # Event-handler sink: onload="startTimer('marker')"
                # Use the JavaScript quote around marker, not the outer HTML attr quote.
                if lower_name.startswith("on"):
                    marker_pos = attr_value.find(marker)
                    js_quote = self._infer_js_quote_from_code(attr_value[:marker_pos])
                    if js_quote == '"':
                        return "event_handler_js_string_double", js_quote
                    if js_quote == "'":
                        return "event_handler_js_string_single", js_quote
                    return "event_handler_js", None

                if attr_quote == '"':
                    return "html_attribute_double", attr_quote
                if attr_quote == "'":
                    return "html_attribute_single", attr_quote
                return "html_attribute_unquoted", None

            return "html_attribute_unquoted", None

        return "html_body", None

    def _attribute_containing_marker(self, tag_fragment: str, marker: str) -> tuple[str, str | None, str] | None:
        """Return (attribute_name, quote_char, attribute_value) for the attr containing marker."""
        pattern = re.compile(
            r"([a-zA-Z_:][\-\w:.]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]*))",
            re.DOTALL,
        )
        for m in pattern.finditer(tag_fragment):
            value = m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else m.group(4) or ""
            quote = '"' if m.group(2) is not None else "'" if m.group(3) is not None else None
            if marker in value:
                return m.group(1), quote, value
        return None

    def _infer_js_quote(self, text: str, idx: int, start: int | None = None) -> str | None:
        if start is None:
            start = text.lower().rfind("<script", 0, idx)
        if start is None or start < 0:
            start = max(0, idx - 500)
        return self._infer_js_quote_from_code(text[start:idx])

    def _infer_js_quote_from_code(self, code: str) -> str | None:
        # Simple quote-state scan. Good enough for an explainable lightweight module.
        in_single = False
        in_double = False
        escaped = False
        for ch in code:
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
        if in_double:
            return '"'
        if in_single:
            return "'"
        return None

    def _is_escaped(self, response_text: str, marker: str, probe: str | None, context: str | None, quote: str | None) -> bool:
        """
        Return whether dangerous characters appear encoded around the reflected marker.

        Important: escaping can be partial. For example, a page may encode double
        quotes but leave single quotes raw, which is still exploitable in a single-
        quoted JavaScript string. Therefore this value is only evidence; risk logic
        still verifies event-handler and URL contexts in a browser.
        """
        if not probe:
            return False
        idx = response_text.find(marker)
        if idx < 0:
            return True
        snippet = self._snippet(response_text, idx, len(marker), radius=220)
        lower = snippet.lower()
        encoded_forms = ["&lt;", "&gt;", "&quot;", "&#34;", "&#x22;", "&#39;", "&#x27;", "&apos;"]
        has_encoded = any(e in lower for e in encoded_forms)

        # If the quote needed for breakout survived raw, treat as not fully escaped.
        if quote and quote in snippet:
            return False

        # Raw probe fragments mean not fully escaped.
        if "<xssmark>" in snippet or "<" + "xssmark" in snippet:
            return False

        # Otherwise, encoded dangerous chars are evidence of escaping.
        if has_encoded and any(ch in unescape(snippet) for ch in ["<", ">", "'", '"']):
            return True
        return has_encoded

    def _quote_breakout_possible(self, snippet: str, quote: str | None, marker: str) -> bool | None:
        if quote is None:
            return None
        marker_idx = snippet.find(marker)
        if marker_idx < 0:
            return None
        after = snippet[marker_idx + len(marker):]
        # This is a heuristic: seeing the same raw quote later in the same snippet
        # means the response context is quote-delimited and quote-breakout should
        # be tested with a browser.
        return quote in after or quote in snippet[:marker_idx]

    def _reason(self, context: str, escaped: bool, quote_breakout: bool | None) -> str:
        if context in {"event_handler_js_string_double", "event_handler_js_string_single", "event_handler_js"}:
            return f"marker reflected in {context}; JavaScript event-handler payload should be tested in browser"
        if context == "url_context":
            return "marker reflected in URL-bearing attribute; javascript: URL payload should be tested with browser click"
        if escaped:
            return f"marker reflected in {context}, but some dangerous characters appear encoded"
        if context in {"html_attribute_double", "html_attribute_single", "js_string_double", "js_string_single"}:
            return f"marker reflected in {context}; quote breakout should be tested in browser"
        if context in {"html_body", "html_comment", "js_block"}:
            return f"marker reflected in {context}; context-specific payload should be tested"
        return "marker reflected; context unknown"
