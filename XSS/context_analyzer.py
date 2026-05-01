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
            "js_string"  - JS 문자열 안에 반사
            "url_context"- URL/href 속성에 반사
            None         - 반사 없음
        """
        if marker not in response_text:
            return None

        # 마커 위치 찾기
        idx = response_text.find(marker)
        # 마커 앞뒤 200자 컨텍스트 추출
        context_start = max(0, idx - 200)
        context_end = min(len(response_text), idx + len(marker) + 200)
        surrounding = response_text[context_start:context_end]

        # JS 문자열 안인지 확인
        # 예: var x = "마커" 또는 var x = '마커'
        if self._is_in_js_string(response_text, idx):
            return "js_string"

        # href/src URL 컨텍스트인지 확인
        if self._is_in_url_attr(surrounding, marker):
            return "url_context"

        # HTML 속성 안인지 확인
        # 예: <input value="마커">
        if self._is_in_html_attr(surrounding, marker):
            return "html_attr"

        # 기본값: HTML 본문
        return "html_body"

    def _is_in_js_string(self, text: str, marker_idx: int) -> bool:
        """마커가 <script> 태그 안 문자열에 있는지 확인"""
        # 마커 앞에서 가장 가까운 <script> 찾기
        script_open = text.rfind("<script", 0, marker_idx)
        script_close = text.rfind("</script>", 0, marker_idx)

        if script_open == -1:
            return False

        # <script> 다음에 </script>가 오기 전에 마커가 있으면 JS 안
        if script_open > script_close:
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
        # 마커 앞에서 가장 가까운 따옴표 찾기
        marker_pos = surrounding.find(marker)
        before_marker = surrounding[:marker_pos]

        # 열린 태그 안에 있는지 확인
        last_tag_open = before_marker.rfind("<")
        last_tag_close = before_marker.rfind(">")

        if last_tag_open > last_tag_close:
            # 태그 안에 있음 → 속성 컨텍스트
            return True

        return False

    def check_special_chars_escaped(
        self, response_text: str, special_chars: list
    ) -> bool:
        """
        특수문자가 인코딩됐는지 확인
        True: 인코딩됨 (안전)
        False: 인코딩 안 됨 (위험)

        HTML 태그 자체(<div> 등)는 무시하고
        마커 주변에 특수문자가 raw하게 있는지만 확인
        """
        # 마커 주변 컨텍스트만 추출해서 확인
        marker_idx = response_text.find(MARKER) if MARKER in response_text else -1

        if marker_idx == -1:
            # 마커가 없으면 전체 텍스트에서 확인
            for char in special_chars:
                if char in response_text:
                    return False
            return True

        # 마커 앞뒤 100자만 확인 (HTML 태그 자체는 제외)
        start = max(0, marker_idx - 100)
        end = min(len(response_text), marker_idx + len(MARKER) + 100)
        surrounding = response_text[start:end]

        # HTML 엔티티로 인코딩된 경우 확인
        encode_map = {
            "<": ["&lt;"],
            ">": ["&gt;"],
            '"': ["&quot;", "&#34;", "&#x22;"],
            "'": ["&#x27;", "&#39;", "&apos;"],
        }

        for char in special_chars:
            if char not in surrounding:
                continue
            # 원본 특수문자가 있지만 인코딩 형태도 있으면 인코딩된 것
            encoded_forms = encode_map.get(char, [])
            if not any(enc in surrounding for enc in encoded_forms):
                # 인코딩 안 됨
                return False

        return True
