# Lightweight XSS Module v2.1

Recon 결과 URL을 입력받아 Reflected XSS 후보, 제한적 Stored XSS 후보, hash/fragment 기반 DOM XSS를 경량 검증합니다.

## 설치

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

## 실행

```bash
python xss_cli.py input.json
```

입력 파일을 생략하면 `input.json`을 기본으로 읽습니다.

## v2.1 수정 사항

- `onload="startTimer('...')"` 같은 HTML 이벤트 핸들러 내부 JS 문자열 context 분류 추가
- 이벤트 핸들러 context용 payload 추가: `');alert(1);//`
- URL context에서 `javascript:alert(1)` 링크 클릭 검증 추가
- hash/fragment DOM XSS payload 추가: `1' onerror='alert(1)`
- Level 3/4/5 유형이 정적 분석에서 LOW로 떨어지는 문제 개선

## 범위

지원:
- GET 파라미터 기반 Reflected XSS 후보 탐지
- 고위험 후보의 Playwright 기반 alert 검증
- `#fragment` 기반 DOM XSS 제한 검증
- 명시적으로 안전한 POST form에 대한 제한적 Stored XSS 후보 검증

제외/제한:
- 전체 DOM XSS data-flow 분석은 미구현
- WAF 우회 및 대량 payload fuzzing 미구현
- 인증/세션이 필요한 흐름은 입력 JSON의 headers/cookies가 필요
