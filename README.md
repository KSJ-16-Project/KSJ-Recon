# KSJ-Recon

KSJ-Recon은 웹 애플리케이션을 대상으로 정찰, 엔드포인트 수집, 퍼징, 취약점 점검, LLM 기반 보고서 생성을 하나의 흐름으로 묶은 모듈형 공격표면 수집 도구입니다.

이 프로젝트는 학습, 연구, 허가된 보안 진단 환경에서의 사용을 전제로 합니다. 본인 소유가 아니거나 명시적으로 허가받지 않은 시스템에는 사용하지 마세요.

## 주요 기능

- Playwright 기반 크롤링: 정적/동적 페이지, SPA 라우트, 폼, XHR/Fetch, WebSocket 힌트 수집
- Nmap 기반 서비스 식별: 포트, 서비스, 제품명, 버전, CPE 정보 수집
- FFUF 기반 퍼징: 디렉터리/파일 경로 및 크롤러 연동 URL 퍼징
- 공격 모듈: SQL Injection, XSS, File Download/LFI, SSRF 점검
- 인증 연동: 로그인 세션 획득 및 일부 모듈의 세션 재사용
- LLM 전처리 및 보고서 생성: 정찰 결과를 공격 모듈 입력으로 변환하고 HTML 대시보드 생성

## 동작 흐름

```text
사용자 입력
  -> Crawler / Nmap / Fuzzer
  -> Middle Core 결과 통합
  -> Mode A: LLM 보고서 생성
  -> Mode B: LLM 전처리 -> SQLi/XSS/FileDownload/SSRF 모듈 실행 -> LLM 보고서 생성
```

## 실행 모드

| 모드 | 설명 |
| --- | --- |
| Mode A: Recon | 크롤러, Nmap, Fuzzer 결과를 통합해 정찰 보고서를 생성합니다. |
| Mode B: Recon + Attack | 정찰 결과를 기반으로 공격 모듈 입력을 생성하고 SQLi, XSS, File Download, SSRF 점검까지 수행합니다. |

진단 강도는 4단계로 선택합니다.

| 레벨 | Nmap | Fuzzer |
| --- | --- | --- |
| Level 1 | Low | Low |
| Level 2 | Hard | Low |
| Level 3 | Low | Hard |
| Level 4 | Hard | Hard |

## 프로젝트 구조

```text
KSJ-Recon/
├── core/                 # 통합 CLI 진입점과 중간 결과 통합 로직
├── crawler/              # Playwright 기반 크롤러 및 인증 감지
├── ffuf_module/          # FFUF 실행 래퍼, wordlist, 플랫폼별 ffuf 바이너리
├── ksj_nmap/             # Nmap 실행 래퍼 및 Windows용 Nmap 바이너리
├── ksj_login/            # 로그인 폼 분석, 세션 획득, 쿠키 변환
├── ksj_llm/              # LLM 전처리, 보고서 생성, HTML 대시보드 렌더링
├── sql_injection/        # SQL Injection 탐지 모듈
├── XSS/                  # Reflected/Stored/DOM XSS 탐지 모듈
├── attacker_module_3/    # SSRF, File Download/LFI 공격 모듈
├── prompts/              # LLM 전처리/보고서 프롬프트
├── output/               # 실행 결과 저장 위치, git ignore 대상
└── results/              # 모듈별 실행 결과 저장 위치, git ignore 대상
```

## 요구 사항

- Python 3.10 이상
- Windows 환경 권장
- Chromium 브라우저 런타임
- Anthropic API 키
- 네트워크 스캔 대상에 대한 명시적 허가

현재 Nmap 래퍼는 Windows 번들 바이너리(`ksj_nmap/bin/win/nmap.exe`)를 기본으로 사용합니다. Linux 지원 경로는 코드상 아직 완성되어 있지 않습니다.

## 설치

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install playwright anthropic python-dotenv rich pyfiglet questionary PyYAML pytest
python -m playwright install chromium
```

`requirements.txt`에는 일부 통합 CLI/LLM/크롤러 의존성이 빠져 있을 수 있어 위 추가 패키지 설치를 함께 권장합니다.

## 환경 변수

`.env.example`을 복사해 `.env`를 만든 뒤 API 키와 모델명을 설정합니다.

```powershell
Copy-Item .env.example .env
```

```env
ANTHROPIC_API_KEY=your_api_key_here
MODEL_NAME=claude-opus-4-7
PREPROCESS_MODEL_NAME=claude-sonnet-4-6
```

## 통합 실행

프로젝트 루트에서 실행합니다.

```powershell
python .\core\entry_core.py
```

실행 중 다음 항목을 대화형으로 선택하거나 입력합니다.

- Mode A 또는 Mode B
- 진단 레벨 1~4
- 로그인 필요 여부
- 로그인 URL, 아이디, 비밀번호
- 진단 대상 URL

## 출력물

기본 출력 위치는 `output/`입니다.

| 파일 | 설명 |
| --- | --- |
| `output/recon_report.json` | Crawler, Nmap, Fuzzer 정찰 결과 통합 JSON |
| `output/attack_senario.json` | Mode B에서 정찰 결과와 공격 모듈 결과를 통합한 JSON |
| `output/preprocess_data_new1.json` | Mode B에서 공격 모듈 입력으로 변환된 전처리 JSON |
| `output/dashboard.html` | LLM 기반 HTML 보안 보고서 |
