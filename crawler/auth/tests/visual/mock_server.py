"""
시각적 통합 테스트용 모의 로그인 서버.

엔드포인트:
  GET  /          → 다양한 폼이 섞인 홈페이지 (로그인 폼 외에 검색 폼, 회원가입 링크 포함)
  GET  /login     → 로그인 페이지 (한국식 비표준 필드명 사용)
  POST /auth      → 로그인 처리 (admin/1234 만 성공)
  GET  /dashboard → 인증 후 대시보드 (쿠키 검사)
  GET  /search    → 검색 폼만 있는 페이지 (오탐 테스트)
  GET  /signup    → 회원가입 폼 (오탐 테스트, 필드 8개)

  실행: python -m crawler.auth.tests.visual.mock_server
"""

from __future__ import annotations

import http.server
import threading
import urllib.parse


HOST = "127.0.0.1"
PORT = 8765
VALID_USER = "admin"
VALID_PASS = "1234"
SESSION_COOKIE = "piscovery_session=abcd1234"


_HOME_HTML = """<!doctype html>
<html><body>
  <h1>Piscovery 모의 사이트</h1>
  <ul>
    <li><a href="/login">로그인</a></li>
    <li><a href="/search">검색</a></li>
    <li><a href="/signup">회원가입</a></li>
    <li><a href="/dashboard">대시보드 (인증 필요)</a></li>
  </ul>

  <!-- GET 검색폼: detector가 무시해야 함 -->
  <form action="/search" method="GET">
    <input type="text" name="q" placeholder="검색어">
    <button type="submit">검색</button>
  </form>
</body></html>"""


_LOGIN_HTML = """<!doctype html>
<html><body>
  <h1>로그인</h1>
  <form action="/auth" method="POST">
    <input type="hidden" name="csrf_token" value="dummy_csrf">
    <input type="text" name="mb_id" id="login-id" placeholder="아이디를 입력하세요" required>
    <input type="password" name="mb_password" id="login-pw" placeholder="비밀번호" required>
    <label><input type="checkbox" name="remember"> 자동 로그인</label>
    <button type="submit">로그인</button>
  </form>
</body></html>"""


_SEARCH_HTML = """<!doctype html>
<html><body>
  <h1>검색</h1>
  <form action="/search" method="GET">
    <input type="text" name="query" placeholder="검색어 입력">
    <button type="submit">검색</button>
  </form>
</body></html>"""


_SIGNUP_HTML = """<!doctype html>
<html><body>
  <h1>회원가입</h1>
  <form action="/signup" method="POST">
    <input type="email" name="email" placeholder="이메일">
    <input type="password" name="pwd" placeholder="비밀번호">
    <input type="text" name="name" placeholder="이름">
    <input type="tel" name="phone" placeholder="전화번호">
    <input type="text" name="address" placeholder="주소">
    <input type="text" name="birth" placeholder="생년월일">
    <input type="text" name="zip" placeholder="우편번호">
    <input type="text" name="company" placeholder="소속">
    <button type="submit">가입</button>
  </form>
</body></html>"""


_DASHBOARD_OK_HTML = """<!doctype html>
<html><body>
  <h1>환영합니다, admin</h1>
  <p>인증된 대시보드 페이지입니다.</p>
  <p><a href="/logout">로그아웃</a></p>
</body></html>"""


_LOGIN_FAIL_HTML = """<!doctype html>
<html><body>
  <h1>로그인 실패</h1>
  <p>아이디 또는 비밀번호가 잘못되었습니다.</p>
  <a href="/login">다시 시도</a>
</body></html>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # 깔끔한 출력을 위해 기본 로그 비활성화 (필요시 print로 교체)
        return

    def _send_html(self, html: str, status: int = 200, set_cookie: str | None = None,
                   extra_headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/":
            self._send_html(_HOME_HTML)
        elif path == "/login":
            self._send_html(_LOGIN_HTML)
        elif path == "/search":
            self._send_html(_SEARCH_HTML)
        elif path == "/signup":
            self._send_html(_SIGNUP_HTML)
        elif path == "/dashboard":
            cookie = self.headers.get("Cookie", "")
            if "piscovery_session" in cookie:
                self._send_html(_DASHBOARD_OK_HTML)
            else:
                self._send_html("<h1>401 Unauthorized</h1>", status=401)
        else:
            self._send_html("<h1>404 Not Found</h1>", status=404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8")
        params = urllib.parse.parse_qs(body)

        if path == "/auth":
            user = params.get("mb_id", [""])[0]
            pwd = params.get("mb_password", [""])[0]
            if user == VALID_USER and pwd == VALID_PASS:
                # 성공 → 쿠키 발급 후 /dashboard로 리다이렉트
                self._send_html(
                    "",
                    status=302,
                    set_cookie=f"{SESSION_COOKIE}; Path=/; HttpOnly",
                    extra_headers={"Location": "/dashboard"},
                )
            else:
                self._send_html(_LOGIN_FAIL_HTML, status=401)
        else:
            self._send_html("<h1>404 Not Found</h1>", status=404)


def start_server() -> tuple[http.server.HTTPServer, threading.Thread]:
    """별도 스레드에서 모의 서버를 띄운다."""
    server = http.server.HTTPServer((HOST, PORT), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def base_url() -> str:
    return f"http://{HOST}:{PORT}"


if __name__ == "__main__":
    srv, _ = start_server()
    print(f"모의 서버 실행 중: {base_url()}")
    print("종료: Ctrl+C")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
