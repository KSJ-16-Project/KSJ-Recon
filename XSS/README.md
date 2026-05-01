# XSS Scanner Module

## 구조

```
xss_module/
├── xss_scanner.py          # 메인 진입점 (Middle Core에서 호출)
├── requirements.txt
│
├── core/
│   ├── payloads.py         # 페이로드 / 마커 정의
│   ├── context_analyzer.py # 반사 위치 컨텍스트 분류
│   └── result_builder.py   # 결과 JSON 빌더
│
├── modules/
│   ├── reflected_xss.py    # Reflected XSS (requests 기반)
│   ├── stored_xss.py       # Stored XSS (POST + URL 순회)
│   └── browser_verifier.py # 브라우저 실행 확인 (Playwright)
│
├── evidence/               # 스크린샷 저장 (자동 생성)
└── tests/
    ├── test_unit.py        # 유닛 테스트 (네트워크 불필요)
    └── test_real.py        # 실제 사이트 테스트
```

## 실행 방법

### 1. 설치
```bash
pip install -r requirements.txt
# Playwright는 Crawler 팀 환경에서 이미 설치됨
```

### 2. Middle Core에서 호출
```python
from xss_scanner import run_xss_scan

result = run_xss_scan(input_json)
```

### 3. 직접 실행 (테스트)
```bash
# 유닛 테스트 (네트워크 불필요)
python tests/test_unit.py

# 실제 사이트 테스트 (인터넷 필요)
python tests/test_real.py --target vulnweb

# DVWA 테스트 (로컬 설치 필요)
python tests/test_real.py --target dvwa
```

## 입력 JSON 스펙

```json
{
  "base_url": "https://target.com",
  "urls": [
    {
      "url": "https://target.com/search?q=test",
      "type": "spider",
      "method": "GET",
      "params": {"q": "test"},
      "cookies": {"session": "abc123"},
      "headers": {"Authorization": "Bearer xxx"}
    }
  ]
}
```

**필수 필드**: `url`  
**선택 필드**: `method` (기본: GET), `params`, `cookies`, `headers`

## 출력 JSON 스펙

```json
{
  "scan_info": { "base_url": "...", "scan_time": "...", "scanner": "..." },
  "xss_results": [
    {
      "url": "https://target.com/search",
      "method": "GET",
      "param": "q",
      "xss_type": "reflected",
      "risk_level": "high",
      "marker_reflected": true,
      "context": "html_body",
      "special_chars_escaped": false,
      "payload_tried": "<script>alert(1)</script>",
      "browser_verified": true,
      "screenshot_alert": "evidence/20240101_target.com_q_alert.png",
      "screenshot_after": "evidence/20240101_target.com_q_after.png",
      "waf_detected": false,
      "evidence": "...반사 위치..."
    }
  ],
  "summary": {
    "total_tested": 50,
    "total_found": 3,
    "high": 1,
    "medium": 1,
    "low": 1,
    "waf_detected": false,
    "scope_excluded": ["DOM XSS - 스코프 외", "WAF 우회 - 감지만 수행"]
  }
}
```

## risk_level 기준

| 레벨 | 조건 |
|------|------|
| HIGH | 브라우저에서 실제 JS 실행 확인 |
| MEDIUM | 마커 반사 + 특수문자 미인코딩 |
| LOW | 마커 반사됐지만 특수문자 인코딩됨 |

## 스코프 외

- **DOM XSS**: JS 코드 흐름 분석 필요, 이번 스코프 제외
- **WAF 우회**: 감지만 하고 보고서에 명시
