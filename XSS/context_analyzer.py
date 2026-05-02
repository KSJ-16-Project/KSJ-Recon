"""
컨텍스트 분석기
반사된 마커가 HTML 어느 위치에 있는지 분류
→ 분류 결과에 따라 적절한 페이로드 선택
"""

import re
from typing import Optional
from payloads import MARKER


class ContextAnalyzer:

    def analyze(self, response_text: str, marker: str) -> Optional[str]:
        """
        반사된 마커의 컨텍스트 분류

        Returns:
            "html_body"  - HTML 본문에 반사
            "html_attr"  - HTML 속성 안에 반사
            "js_string"  - JS 문자열 안에 반사 (<script> 또는 이벤트 핸들러)
            "url_context"- URL/href 속성에 반사
            None         - 반사 없음
        """
        if marker not in response_text:
            return None

        idx = response_text.find(marker)
        context_start = max(0, idx - 200)
        context_end = min(len(response_text), idx + len(marker) + 200)
        surrounding = response_text[context_start:context_end]

        # 1. <script> 태그 안 JS 문자열
        if self._is_in_js_string(response_text, idx):
            return "js_string"

        # 2. 이벤트 핸들러 안 JS 문자열
        # 예: onload="startTimer('마커')"
        if self._is_in_js_event_handler(surrounding, marker):
            return "js_string"

        # 3. href/src URL 컨텍스트
        if self._is_in_url_attr(surrounding, marker):
            return "url_context"

        # 4. HTML 속성 값
        if self._is_in_html_attr(surrounding, marker):
            return "html_attr"

        # 5. 기본값: HTML 본문
        return "html_body"

    def _is_in_js_string(self, text: str, marker_idx: int) -> bool:
        """마커가 <script> 태그 안 문자열에 있는지 확인"""
        script_open = text.rfind("<script", 0, marker_idx)
        script_close = text.rfind("</script>", 0, marker_idx)

        if script_open == -1:
            return False

        if script_open > script_close:
            return True

        return False

    def _is_in_js_event_handler(self, surrounding: str, marker: str) -> bool:
        """
        onload, onclick 등 이벤트 핸들러 안 JS 문자열인지 확인
        예: onload="startTimer('마커');"
            onclick="doSomething('마커')"
        """
        event_handlers = [
            "onload", "onclick", "onerror", "onmouseover",
            "onfocus", "onblur", "onchange", "onsubmit",
            "onkeyup", "onkeydown", "onkeypress", "oninput",
        ]
        marker_pos = surrounding.find(marker)
        before_marker = surrounding[:marker_pos]

        for handler in event_handlers:
            handler_idx = before_marker.lower().rfind(handler)
            if handler_idx == -1:
                continue
            # 이벤트 핸들러 이후에 ( 가 있으면 JS 함수 호출 안에 있는 것
            after_handler = before_marker[handler_idx:]
            if "(" in after_handler:
                return True

        return False

    def _is_in_url_attr(self, surrounding: str, marker: str) -> bool:
        """href, src, action 속성 안에 마커가 있는지 확인"""
        url_attr_pattern = re.compile(
            r'(?:href|src|action|data|formaction)\s*=\s*["\']([^"\']*)',
            re.IGNORECASE
        )
        for match in url_attr_pattern.finditer(surrounding):
            if marker in match.group(1):
                return True
        return False

    def _is_in_html_attr(self, surrounding: str, marker: str) -> bool:
        """HTML 속성 값 안에 마커가 있는지 확인"""
        marker_pos = surrounding.find(marker)
        before_marker = surrounding[:marker_pos]

        last_tag_open = before_marker.rfind("<")
        last_tag_close = before_marker.rfind(">")

        if last_tag_open > last_tag_close:
            return True

        return False

    def check_special_chars_escaped(
        self, response_text: str, special_chars: list
    ) -> bool:
        """
        특수문자가 인코딩됐는지 확인
        True: 인코딩됨 (안전)
        False: 인코딩 안 됨 (위험)
        """
        marker_idx = response_text.find(MARKER) if MARKER in response_text else -1

        if marker_idx == -1:
            for char in special_chars:
                if char in response_text:
                    return False
            return True

        start = max(0, marker_idx - 100)
        end = min(len(response_text), marker_idx + len(MARKER) + 100)
        surrounding = response_text[start:end]

        encode_map = {
            "<": ["&lt;"],
            ">": ["&gt;"],
            '"': ["&quot;", "&#34;", "&#x22;"],
            "'": ["&#x27;", "&#39;", "&apos;"],
        }

        for char in special_chars:
            if char not in surrounding:
                continue
            encoded_forms = encode_map.get(char, [])
            if not any(enc in surrounding for enc in encoded_forms):
                return False

        return True
