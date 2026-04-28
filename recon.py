"""
recon.py — SPA 동적 크롤링 + API 정찰 프로토타입

파이프라인:
  1) 익명 동적 크롤  (history.pushState 후킹 + 클릭 탐색 + XHR/fetch 캡처)
  2) 비인증 API 프로브 (발견된 GET 엔드포인트 호출)
  3) 인증 후 재크롤 (자격증명 제공 시) — 보호 라우트에서 추가 엔드포인트 캡처
  4) Bearer 토큰 프로브 — JWT 추출 후 발견 엔드포인트 전부 재호출
  5) 통합 리포트

사용법:
  python recon.py <target_url>
  python recon.py <target_url> --id USER --pw PASS
  python recon.py <target_url> --id USER --pw PASS --explore-authed
"""

import argparse
import asyncio
import json
import os
import re
import sys
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from playwright.async_api import async_playwright


# ────────────────────────────────────────────────────────────────
# 공통 유틸
# ────────────────────────────────────────────────────────────────

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconProto/1.0"

# 토큰 키 패턴 — 키 이름이 아래 정규식에 매칭되면 토큰 후보로 간주
TOKEN_KEY_PATTERN = re.compile(
    r"(access[_-]?token|^token$|^jwt$|id[_-]?token|auth[_-]?token|bearer)",
    re.I,
)
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

# 로그인 라우트 자동 탐지에 쓰이는 후보 (홈에서 링크를 못 찾았을 때 폴백)
LOGIN_ROUTE_CANDIDATES = (
    "/login", "/auth", "/signin", "/sign-in",
    "/account/login", "/user/login", "/users/sign_in",
    "/#/login", "/#/auth", "/#/signin",
)

# 홈페이지에서 로그인 링크를 찾는 셀렉터들
LOGIN_LINK_SELECTORS = (
    'a[href*="login" i]',
    'a[href*="signin" i]',
    'a[href*="sign-in" i]',
    'a[href*="auth" i]',
    'button:has-text("로그인")',
    'a:has-text("로그인")',
    'button:has-text("Login")',
    'a:has-text("Login")',
    'button:has-text("Log in")',
    'a:has-text("Log in")',
    'button:has-text("Sign in")',
    'a:has-text("Sign in")',
    '[aria-label*="login" i]',
    '[aria-label*="sign in" i]',
)


def normalize_url(base, href, hash_mode=False):
    """hash_mode=True 이면 #/ 로 시작하는 fragment를 라우트의 일부로 보존."""
    if href is None:
        return None
    try:
        full = urljoin(base, href)
        p = urlparse(full)
        if p.scheme not in ("http", "https"):
            return None
        url = f"{p.scheme}://{p.netloc}{p.path or '/'}"
        if hash_mode and p.fragment and p.fragment.startswith("/"):
            url = url + "#" + p.fragment
        return url
    except Exception:
        return None


def is_in_scope(url, base_target):
    try:
        return urlparse(url).netloc == urlparse(base_target).netloc
    except Exception:
        return False


def base_url(target):
    p = urlparse(target)
    return f"{p.scheme}://{p.netloc}"


def strip_bearer(s):
    if isinstance(s, str) and s.lower().startswith("bearer "):
        return s[7:].strip()
    return s.strip() if isinstance(s, str) else s


def looks_like_jwt(s):
    return isinstance(s, str) and bool(JWT_RE.match(s.strip()))


def looks_like_token(s):
    if not isinstance(s, str):
        return False
    s = strip_bearer(s)
    if looks_like_jwt(s):
        return True
    return len(s) >= 20 and bool(re.match(r"^[A-Za-z0-9._\-+/=]+$", s))


def extract_token_recursive(obj, _depth=0, _max_depth=8):
    """JSON-like 객체에서 토큰 후보 재귀 탐색.
       (1) 키 이름이 토큰 패턴에 매칭되고 값이 토큰처럼 보이면 즉시 반환
       (2) JWT 모양 문자열이 발견되면 반환"""
    if _depth > _max_depth:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and TOKEN_KEY_PATTERN.search(k) and looks_like_token(v):
                return strip_bearer(v)
        for v in obj.values():
            t = extract_token_recursive(v, _depth + 1, _max_depth)
            if t:
                return t
    elif isinstance(obj, list):
        for v in obj:
            t = extract_token_recursive(v, _depth + 1, _max_depth)
            if t:
                return t
    elif isinstance(obj, str):
        if looks_like_jwt(strip_bearer(obj)):
            return strip_bearer(obj)
    return None


def safe_sample(text, n=300):
    return (text or "").replace("\n", " ").replace("\r", " ")[:n]


# ────────────────────────────────────────────────────────────────
# 브라우저 후킹 / 셀렉터
# ────────────────────────────────────────────────────────────────

HISTORY_HOOK = """
(() => {
  if (window.__hookInstalled) return;
  window.__hookInstalled = true;
  window.__routeLog = [];
  const log = (type, url) => {
    try { window.__routeLog.push({type, url: new URL(url, location.href).href}); } catch (e) {}
  };
  const _push = history.pushState, _replace = history.replaceState;
  history.pushState = function(s,t,u){ if(u) log('pushState', u); return _push.apply(this, arguments); };
  history.replaceState = function(s,t,u){ if(u) log('replaceState', u); return _replace.apply(this, arguments); };
  window.addEventListener('popstate', () => log('popstate', location.href));
  window.addEventListener('hashchange', () => log('hashchange', location.href));
})();
"""

CLICKABLE_SELECTOR = (
    'button:not([type="submit"]), [role="button"], [onclick], '
    '[data-href], [data-to], nav a, nav li, '
    '[class*="card"], [class*="Card"], '
    '[class*="link"], [class*="Link"], '
    '[class*="menu"], [class*="Menu"], '
    '[class*="nav"], [class*="Nav"]'
)


# ────────────────────────────────────────────────────────────────
# 동적 크롤러 (익명/인증 공용)
# ────────────────────────────────────────────────────────────────

class DynamicSpider:
    def __init__(self, target, max_depth=2, max_clicks=30, page_timeout_ms=20000,
                 label="anon", hash_mode=None):
        self.target = target
        self.max_depth = max_depth
        self.max_clicks = max_clicks
        self.page_timeout_ms = page_timeout_ms
        self.label = label

        # hash_mode: None=미정(첫 페이지에서 감지), True/False=강제
        self.hash_mode = bool(hash_mode) if hash_mode is not None else False
        self._mode_detected = hash_mode is not None

        self.visited = set()
        self.collected_urls = []
        self.client_routes = set()
        self.network_requests = []
        self.api_endpoints_status = {}   # (METHOD, path) → 마지막 status
        self.headers = {}

    def _harvest(self, log):
        out = []
        for entry in log:
            n = normalize_url(self.target, entry.get("url", ""), self.hash_mode)
            if n and is_in_scope(n, self.target):
                self.client_routes.add(n)
                out.append(n)
        return out

    async def _detect_mode(self, page):
        """첫 페이지에서 location.hash 검사하여 hash-route SPA 여부 판단."""
        if self._mode_detected:
            return
        try:
            hv = await page.evaluate("() => location.hash")
            if hv and hv.startswith("#/"):
                self.hash_mode = True
                print(f"  [*] hash-route SPA 감지 (location.hash={hv!r}) — fragment 보존 모드")
        except Exception:
            pass
        self._mode_detected = True

    async def attach(self, context, page):
        await context.add_init_script(HISTORY_HOOK)

        def on_response(resp):
            try:
                req = resp.request
                if req.resource_type in ("xhr", "fetch"):
                    p = urlparse(resp.url)
                    if p.netloc == urlparse(self.target).netloc:
                        key = (req.method, p.path)
                        self.api_endpoints_status[key] = resp.status
                        self.network_requests.append({
                            "method": req.method, "path": p.path,
                            "query": p.query, "status": resp.status,
                        })
            except Exception:
                pass
        page.on("response", on_response)

    async def _harvest_routes(self, page):
        try:
            log = await page.evaluate(
                "() => { const x = window.__routeLog || []; window.__routeLog = []; return x; }"
            )
            return self._harvest(log)
        except Exception:
            return []

    async def click_explore(self, page, current_url):
        out = []
        try:
            handles = await page.query_selector_all(CLICKABLE_SELECTOR)
        except Exception:
            return out
        count = min(len(handles), self.max_clicks)
        print(f"  [c] 클릭 후보 {len(handles)} (시도 {count})")

        for i in range(count):
            try:
                handles = await page.query_selector_all(CLICKABLE_SELECTOR)
                if i >= len(handles):
                    break
                el = handles[i]
                if not await el.is_visible():
                    continue
                before = page.url
                try:
                    await el.click(timeout=1500, no_wait_after=True)
                except Exception:
                    continue
                await page.wait_for_timeout(400)
                out.extend(await self._harvest_routes(page))
                if page.url != before:
                    n = normalize_url(self.target, page.url, self.hash_mode)
                    if n and is_in_scope(n, self.target):
                        out.append(n)
                    try:
                        await page.goto(current_url, wait_until="networkidle", timeout=self.page_timeout_ms)
                        await page.wait_for_timeout(800)
                    except Exception:
                        break
            except Exception:
                continue
        return out

    async def fetch_one(self, page, url, depth):
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=self.page_timeout_ms)
        except Exception as e:
            print(f"  [!] goto 실패: {url} ({e})")
            return None
        if resp is None:
            return None
        await page.wait_for_timeout(1500)
        await self._detect_mode(page)

        h = await resp.all_headers()
        self.collected_urls.append({
            "url": url, "status": resp.status,
            "content_type": h.get("content-type", ""), "depth": depth,
        })
        if not self.headers:
            self.headers = {k: v for k, v in h.items() if k.lower() in (
                "server", "x-powered-by", "x-frame-options",
                "content-security-policy", "strict-transport-security",
                "x-content-type-options", "x-xss-protection", "set-cookie",
            )}
        return await self._harvest_routes(page)

    async def crawl(self, browser=None, seed_routes=None):
        """seed_routes가 주어지면 그것을 시드로 사용 (인증 후 재크롤용)."""
        print(f"\n[*] DynamicSpider({self.label}) 시작: {self.target}")

        own_browser = browser is None
        async with async_playwright() as p:
            if own_browser:
                browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(user_agent=UA)
            page = await context.new_page()
            await self.attach(context, page)

            if seed_routes:
                queue = deque((r, 0) for r in seed_routes)
                self.visited.update(seed_routes)
            else:
                queue = deque([(self.target, 0)])
                self.visited.add(self.target)

            while queue:
                cur, d = queue.popleft()
                if d > self.max_depth:
                    continue
                print(f"[{self.label}][depth={d}] {cur}")
                pre = await self.fetch_one(page, cur, d)
                if pre is None:
                    continue
                for r in pre:
                    if r not in self.visited and is_in_scope(r, self.target):
                        self.visited.add(r)
                        queue.append((r, d + 1))
                if d < self.max_depth:
                    clicked = await self.click_explore(page, cur)
                    for r in clicked:
                        if r not in self.visited and is_in_scope(r, self.target):
                            self.visited.add(r)
                            queue.append((r, d + 1))
                            print(f"  [+] 신규 라우트: {r}")

            cookies = await context.cookies()
            storage = await page.evaluate(
                "() => ({local: Object.keys(localStorage), session: Object.keys(sessionStorage)})"
            )
            if own_browser:
                await browser.close()

        print(f"[*] {self.label} 완료 — URL {len(self.collected_urls)}, 라우트 {len(self.client_routes)}, "
              f"엔드포인트 {len(self.api_endpoints_status)}")
        return cookies, storage

    def to_dict(self):
        return {
            "label": self.label,
            "target": self.target,
            "visited_urls": self.collected_urls,
            "client_routes": sorted(self.client_routes),
            "api_endpoints": sorted(f"{m} {p}" for (m, p) in self.api_endpoints_status),
            "api_endpoints_with_status": [
                {"method": m, "path": p, "status": s}
                for (m, p), s in sorted(self.api_endpoints_status.items())
            ],
            "headers": self.headers,
        }


# ────────────────────────────────────────────────────────────────
# 브라우저 로그인 + 인증 컨텍스트 생성
# ────────────────────────────────────────────────────────────────

async def autodetect_login_form(page):
    pw = await page.query_selector('input[type="password"]')
    if not pw:
        return None, None, None
    text_inputs = await page.query_selector_all(
        'input:not([type="password"]):not([type="hidden"]):not([type="checkbox"]):not([type="submit"]):not([type="button"])'
    )
    visible = []
    for el in text_inputs:
        try:
            if await el.is_visible():
                visible.append(el)
        except Exception:
            pass
    if not visible:
        return None, pw, None
    chosen = visible[0]
    hint = await page.evaluate(
        "el => (el.getAttribute('name') || el.getAttribute('id') || el.getAttribute('placeholder') || '')",
        chosen,
    )
    return chosen, pw, hint


async def submit_login(page, pw_input):
    for sel in [
        'button[type="submit"]',
        'button:has-text("로그인")',
        'button:has-text("Login")',
        'button:has-text("Sign in")',
        'input[type="submit"]',
    ]:
        try:
            btn = await page.query_selector(sel)
            if btn and await btn.is_visible():
                await btn.click()
                return sel
        except Exception:
            continue
    await pw_input.press("Enter")
    return "Enter"


def _route_from_url(target_url, full_url):
    """동일 origin이면 path(+fragment)를 라우트 형태로 반환. 아니면 None."""
    p = urlparse(full_url)
    if p.netloc != urlparse(target_url).netloc:
        return None
    route = p.path or "/"
    if p.fragment:
        route = route + "#" + p.fragment
    return route


def _login_url(target, login_route):
    """login_route가 path든 hash든 모두 처리. 외부 URL이면 그대로 반환."""
    if login_route.startswith(("http://", "https://")):
        return login_route
    if not login_route.startswith("/"):
        login_route = "/" + login_route
    return base_url(target) + login_route


async def detect_login_route(browser, target):
    """홈에서 로그인 링크 탐색 → 후보 라우트 폴백. 라우트 문자열 반환 (실패 시 None)."""
    context = await browser.new_context(user_agent=UA)
    page = await context.new_page()

    # 1) 홈에서 로그인 링크 찾기
    print("[*] 홈에서 로그인 링크 탐색 중...")
    try:
        await page.goto(target, wait_until="networkidle", timeout=20000)
        await page.wait_for_timeout(1500)
    except Exception as e:
        print(f"  [!] 홈 로드 실패: {e}")

    found = None
    for sel in LOGIN_LINK_SELECTORS:
        try:
            els = await page.query_selector_all(sel)
        except Exception:
            continue
        for el in els:
            try:
                if not await el.is_visible():
                    continue
                # href 우선
                href = await el.get_attribute("href")
                if href and not href.startswith(("javascript:", "mailto:", "#")):
                    resolved = urljoin(page.url, href)
                    route = _route_from_url(target, resolved)
                    if route:
                        found = route
                        print(f"  [+] 링크에서 발견: {sel} → {found}")
                        break
                # href가 fragment-only 거나 없으면 클릭으로 이동
                before_url = page.url
                try:
                    await el.click(timeout=2000, no_wait_after=True)
                    await page.wait_for_timeout(2000)
                except Exception:
                    continue
                if page.url != before_url:
                    route = _route_from_url(target, page.url)
                    pw = await page.query_selector('input[type="password"]')
                    if route and pw:
                        found = route
                        print(f"  [+] 클릭 후 이동 + 패스워드 필드 확인: {found}")
                        break
            except Exception:
                continue
        if found:
            break

    # 2) 폴백: 후보 라우트 직접 방문 → 패스워드 필드 존재 시 채택
    if not found:
        print("[*] 홈에서 미탐지 — 후보 라우트 시도")
        for cand in LOGIN_ROUTE_CANDIDATES:
            url = _login_url(target, cand)
            try:
                await page.goto(url, wait_until="networkidle", timeout=15000)
                await page.wait_for_timeout(1500)
            except Exception as e:
                print(f"  [-] {cand}: goto 실패 ({e})")
                continue
            try:
                pw = await page.query_selector('input[type="password"]')
                ok = pw and await pw.is_visible()
            except Exception:
                ok = False
            if ok:
                found = cand
                print(f"  [+] 후보 적중: {cand}")
                break
            print(f"  [-] {cand}: 패스워드 필드 없음")

    try:
        await page.close()
        await context.close()
    except Exception:
        pass
    return found


async def browser_login(browser, target, login_route, login_id, login_pw):
    """브라우저로 로그인 폼을 채우고 제출. 사이트가 보낸 실제 POST를 가로채 토큰 추출.

    반환: (context, token, cookies, login_meta) — 실패 시 (None, None, None, None)
    - 토큰은 (1) 로그인 직전·직후 동일 origin POST 응답 본문 재귀 탐색,
            (2) localStorage/sessionStorage 값에서 JWT 모양 스캔,
            (3) 쿠키 값에서 JWT 모양 스캔 순으로 시도.
    """
    context = await browser.new_context(user_agent=UA)
    page = await context.new_page()
    url = _login_url(target, login_route)
    print(f"[*] 로그인 페이지: {url}")
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
    except Exception as e:
        print(f"[!] 로그인 페이지 로드 실패: {e}")
        return None, None, None, None
    await page.wait_for_timeout(1500)

    text_in, pw_in, hint = await autodetect_login_form(page)
    if not (text_in and pw_in):
        print("[!] 로그인 폼 자동 탐지 실패")
        return None, None, None, None
    print(f"[*] id 필드 힌트: {hint!r}")
    await text_in.fill(login_id)
    await pw_in.fill(login_pw)

    target_netloc = urlparse(target).netloc
    captured = []  # 동일 origin POST 응답 모음

    async def on_response(resp):
        try:
            req = resp.request
            if req.method != "POST":
                return
            if urlparse(resp.url).netloc != target_netloc:
                return
            ct = (resp.headers.get("content-type") or "").lower()
            body = None
            if "json" in ct:
                try:
                    body = await resp.json()
                except Exception:
                    try:
                        body = json.loads(await resp.text())
                    except Exception:
                        body = None
            captured.append({"url": resp.url, "status": resp.status, "body": body})
        except Exception:
            pass

    page.on("response", on_response)

    submitted = await submit_login(page, pw_in)
    print(f"[*] 제출: {submitted}")
    await page.wait_for_timeout(3500)

    cookies = await context.cookies()
    try:
        storage_keys = await page.evaluate(
            "() => ({local: Object.keys(localStorage), session: Object.keys(sessionStorage)})"
        )
        storage_values = await page.evaluate("""() => {
            const dump = (s) => {
                const o = {};
                for (let i = 0; i < s.length; i++) {
                    const k = s.key(i);
                    o[k] = s.getItem(k);
                }
                return o;
            };
            return { local: dump(localStorage), session: dump(sessionStorage) };
        }""")
    except Exception as e:
        print(f"  [!] storage 읽기 실패: {e}")
        storage_keys = {"local": [], "session": []}
        storage_values = {"local": {}, "session": {}}

    # 토큰 추출 우선순위 1: 캡처된 POST 응답 본문 (성공 status 우선)
    token = None
    login_url = None
    login_body_sample = None
    for cr in sorted(captured, key=lambda c: 0 if 200 <= (c.get("status") or 0) < 300 else 1):
        if not cr.get("body"):
            continue
        t = extract_token_recursive(cr["body"])
        if t:
            token = t
            login_url = cr["url"]
            login_body_sample = cr["body"]
            print(f"[+] 로그인 응답 본문에서 토큰 추출: {login_url}")
            break

    # 우선순위 2: localStorage/sessionStorage 값
    if not token:
        for store_name in ("local", "session"):
            for k, v in (storage_values.get(store_name) or {}).items():
                if looks_like_token(v):
                    token = strip_bearer(v)
                    print(f"[+] {store_name}Storage[{k!r}]에서 토큰 추출 (len={len(token)})")
                    break
            if token:
                break

    # 우선순위 3: 쿠키 값에서 JWT 형태
    if not token:
        for c in cookies:
            if looks_like_jwt(c.get("value", "")):
                token = c["value"].strip()
                print(f"[+] cookie[{c['name']!r}]에서 JWT 추출")
                break

    print(f"[*] 쿠키: {[c['name'] for c in cookies]}")
    print(f"[*] localStorage: {storage_keys['local']}, sessionStorage: {storage_keys['session']}")
    print(f"[*] 캡처된 POST: {len(captured)}건")
    if token:
        print(f"[+] 토큰 확보 (len={len(token)})")
    else:
        print("[!] 토큰 미확보 — 쿠키 세션만으로 진행")

    await page.close()
    return context, token, cookies, {
        "login_url": login_url,
        "login_body_sample": login_body_sample,
        "captured_posts": [{"url": c["url"], "status": c["status"]} for c in captured],
        "storage_keys": storage_keys,
    }


# ────────────────────────────────────────────────────────────────
# 인증 세션 빌드 (브라우저 → requests)
# ────────────────────────────────────────────────────────────────

def build_authed_session(target, cookies, token):
    """브라우저 컨텍스트의 쿠키 + (있다면) Bearer 토큰으로 requests.Session 구성."""
    base = base_url(target)
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Origin": base,
        "Referer": base + "/",
    })
    for c in (cookies or []):
        try:
            s.cookies.set(
                c["name"], c["value"],
                domain=c.get("domain") or urlparse(target).netloc,
                path=c.get("path") or "/",
            )
        except Exception:
            pass
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


# ────────────────────────────────────────────────────────────────
# 엔드포인트 프로브
# ────────────────────────────────────────────────────────────────

def probe_endpoints(target, endpoints, session=None, label="probe"):
    """endpoints: ['METHOD /path', ...]. GET만 호출, /cdn-cgi/* 스킵."""
    base = base_url(target)
    s = session or requests.Session()
    s.headers.setdefault("User-Agent", UA)
    s.headers.setdefault("Accept", "application/json, text/plain, */*")
    s.headers.setdefault("Origin", base)
    s.headers.setdefault("Referer", base + "/")

    results = []
    for line in endpoints:
        try:
            method, path = line.split(" ", 1)
        except ValueError:
            continue
        if path.startswith("/cdn-cgi/"):
            results.append({"method": method, "path": path, "skipped": "cloudflare"})
            continue
        if method != "GET":
            results.append({"method": method, "path": path, "skipped": "non-GET"})
            continue
        try:
            r = s.get(base + path, timeout=10, allow_redirects=False)
            results.append({
                "method": method, "path": path,
                "status": r.status_code,
                "content_type": r.headers.get("content-type", ""),
                "size": len(r.content),
                "sample": safe_sample(r.text),
            })
            print(f"  [{label}] {r.status_code} {method:5} {path}  ({len(r.content)}B)")
        except Exception as e:
            results.append({"method": method, "path": path, "error": str(e)})
            print(f"  [{label}] ERR {method} {path}  {e}")
    return results


# ────────────────────────────────────────────────────────────────
# 통합 파이프라인
# ────────────────────────────────────────────────────────────────

class Recon:
    def __init__(self, target, login_id=None, login_pw=None,
                 login_route=None,
                 explore_authed=False, depth=2, clicks=30, output_dir="recon_out"):
        self.target = target
        self.login_id = login_id
        self.login_pw = login_pw
        self.login_route = login_route
        self.explore_authed = explore_authed
        self.depth = depth
        self.clicks = clicks
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.report = {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "config": {
                "depth": depth, "clicks": clicks,
                "login_route": login_route if login_id else None,
                "explore_authed": explore_authed,
                "authed": bool(login_id),
            },
        }

    def _save(self, name, data):
        path = os.path.join(self.output_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return path

    async def run(self):
        # ── 1) 익명 동적 크롤
        anon = DynamicSpider(self.target, max_depth=self.depth, max_clicks=self.clicks, label="anon")
        await anon.crawl()
        self._anon_hash_mode = anon.hash_mode
        anon_dict = anon.to_dict()
        anon_dict["hash_mode"] = anon.hash_mode
        self._save("01_anon_crawl.json", anon_dict)
        self.report["anon_crawl"] = anon_dict

        # ── 2) 비인증 API 프로브
        print("\n[*] (2) 비인증 API 프로브")
        anon_results = probe_endpoints(self.target, anon_dict["api_endpoints"], label="anon")
        self._save("02_anon_probe.json", {"target": self.target, "results": anon_results})
        self.report["anon_probe"] = anon_results

        # 인증 정보 없으면 종료
        if not (self.login_id and self.login_pw):
            self.report["authed"] = None
            self._finalize()
            return

        # ── 3) 인증 후 재크롤 (브라우저 + 같은 컨텍스트)
        print("\n[*] (3) 인증 후 재크롤")
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            # 사용자가 --login-route를 명시하지 않은 경우 자동 탐지
            login_route = self.login_route
            if login_route is None:
                login_route = await detect_login_route(browser, self.target)
                if not login_route:
                    print("[!] 로그인 라우트 탐지 실패 — 인증 단계 스킵")
                    await browser.close()
                    self.report["authed"] = {"error": "login_route_not_found"}
                    self._finalize()
                    return
                self.report["config"]["login_route"] = login_route
                print(f"[*] 사용할 로그인 라우트: {login_route}")

            context, token, login_cookies, login_meta = await browser_login(
                browser, self.target, login_route, self.login_id, self.login_pw
            )
            if context is None:
                print("[!] 브라우저 로그인 실패 — 인증 단계 스킵")
                await browser.close()
                self.report["authed"] = {"error": "browser_login_failed"}
                self._finalize()
                return

            authed = DynamicSpider(self.target, max_depth=self.depth, max_clicks=self.clicks,
                                   label="authed", hash_mode=self._anon_hash_mode)
            authed_storage = await self._crawl_in_context(authed, context, anon_dict["client_routes"])
            authed_cookies = await context.cookies()
            await browser.close()

        authed_dict = authed.to_dict()
        authed_dict["cookies"] = [{"name": c["name"], "domain": c["domain"]} for c in authed_cookies]
        authed_dict["storage_keys"] = authed_storage
        authed_dict["login_meta"] = {
            "login_url": login_meta.get("login_url"),
            "captured_posts": login_meta.get("captured_posts"),
            "token_acquired": bool(token),
        }
        self._save("03_authed_crawl.json", authed_dict)
        self.report["authed_crawl"] = authed_dict

        # ── 4) 인증 세션 프로브 (브라우저에서 추출한 쿠키 + 토큰 사용)
        print("\n[*] (4) 인증 세션으로 엔드포인트 프로브")
        sess = build_authed_session(self.target, authed_cookies, token)
        all_eps = set(anon_dict["api_endpoints"]) | set(authed_dict["api_endpoints"])
        probe_results = probe_endpoints(self.target, sorted(all_eps), session=sess, label="authed")
        self._save("04_token_probe.json", {
            "target": self.target,
            "token_acquired": bool(token),
            "login_url": login_meta.get("login_url"),
            "login_response_sample": login_meta.get("login_body_sample"),
            "results": probe_results,
        })
        self.report["token_probe"] = probe_results
        self.report["authed"] = {
            "token_acquired": bool(token),
            "login_url": login_meta.get("login_url"),
        }

        self._finalize()

    async def _crawl_in_context(self, spider, context, seed_routes):
        """browser_login으로 만든 context 재사용해 BFS(+클릭). storage 키를 반환."""
        # add_init_script는 이후 생성되는 페이지에만 적용되므로 new_page 전에 호출
        await context.add_init_script(HISTORY_HOOK)
        page = await context.new_page()

        def on_response(resp):
            try:
                req = resp.request
                if req.resource_type in ("xhr", "fetch"):
                    pp = urlparse(resp.url)
                    if pp.netloc == urlparse(spider.target).netloc:
                        spider.api_endpoints_status[(req.method, pp.path)] = resp.status
                        spider.network_requests.append({
                            "method": req.method, "path": pp.path,
                            "query": pp.query, "status": resp.status,
                        })
            except Exception:
                pass
        page.on("response", on_response)

        if self.explore_authed:
            queue = deque((r, 0) for r in seed_routes)
            spider.visited.update(seed_routes)
        else:
            queue = deque((r, spider.max_depth) for r in seed_routes)
            spider.visited.update(seed_routes)

        while queue:
            cur, d = queue.popleft()
            if d > spider.max_depth:
                continue
            print(f"[authed][depth={d}] {cur}")
            pre = await spider.fetch_one(page, cur, d)
            if pre is None:
                continue
            for r in pre:
                if r not in spider.visited and is_in_scope(r, spider.target):
                    spider.visited.add(r)
                    queue.append((r, d + 1))
            if self.explore_authed and d < spider.max_depth:
                clicked = await spider.click_explore(page, cur)
                for r in clicked:
                    if r not in spider.visited and is_in_scope(r, spider.target):
                        spider.visited.add(r)
                        queue.append((r, d + 1))
                        print(f"  [+] 신규 라우트: {r}")

        # 페이지를 닫기 전에 storage 키 읽기 (about:blank가 되면 SecurityError 발생)
        try:
            storage = await page.evaluate(
                "() => ({local: Object.keys(localStorage), session: Object.keys(sessionStorage)})"
            )
        except Exception as e:
            print(f"  [!] storage 읽기 실패: {e}")
            storage = {"local": [], "session": []}
        await page.close()
        return storage

    def _finalize(self):
        self._save("report.json", self.report)
        print("\n" + "=" * 60)
        print("정찰 리포트 요약")
        print("=" * 60)

        a = self.report.get("anon_crawl", {})
        print(f"[익명 크롤]  URL {len(a.get('visited_urls',[]))}, "
              f"라우트 {len(a.get('client_routes',[]))}, "
              f"엔드포인트 {len(a.get('api_endpoints',[]))}")

        ap = self.report.get("anon_probe", []) or []
        ap_status = {}
        for r in ap:
            st = r.get("status")
            if st is not None:
                ap_status.setdefault(st, 0); ap_status[st] += 1
        if ap_status:
            print(f"[익명 프로브] 상태분포: {dict(sorted(ap_status.items()))}")

        au = self.report.get("authed_crawl")
        if au:
            print(f"[인증 크롤]  URL {len(au.get('visited_urls',[]))}, "
                  f"엔드포인트 {len(au.get('api_endpoints',[]))}")

        tp = self.report.get("token_probe")
        if tp:
            tp_status = {}
            for r in tp:
                st = r.get("status")
                if st is not None:
                    tp_status.setdefault(st, 0); tp_status[st] += 1
            print(f"[Bearer]    상태분포: {dict(sorted(tp_status.items()))}")
            anomalies = [r for r in tp if r.get("status") in (500,)]
            if anomalies:
                print(f"            500 응답 {len(anomalies)}개:")
                for r in anomalies:
                    print(f"              {r['method']} {r['path']}")

        print(f"\n[*] 결과 디렉터리: {self.output_dir}/")
        for f in sorted(os.listdir(self.output_dir)):
            print(f"     - {f}")


# ────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="SPA 동적 크롤링 + API 정찰 프로토타입")
    ap.add_argument("target", help="타겟 URL (예: https://example.com/)")
    ap.add_argument("--id", dest="login_id", help="로그인 ID (생략 시 익명 단계만)")
    ap.add_argument("--pw", dest="login_pw", help="로그인 패스워드")
    ap.add_argument("--login-route", default=None,
                    help="로그인 페이지 라우트 (생략 시 홈 링크 → 후보 라우트 순으로 자동 탐지)")
    ap.add_argument("--explore-authed", action="store_true",
                    help="인증 후에도 클릭 탐색 수행 (기본: 라우트 방문만)")
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--clicks", type=int, default=30)
    ap.add_argument("-o", "--output-dir", default="recon_out")
    args = ap.parse_args()

    if bool(args.login_id) != bool(args.login_pw):
        print("[!] --id 와 --pw 는 함께 지정해야 합니다.")
        sys.exit(2)

    recon = Recon(
        target=args.target,
        login_id=args.login_id, login_pw=args.login_pw,
        login_route=args.login_route,
        explore_authed=args.explore_authed,
        depth=args.depth, clicks=args.clicks,
        output_dir=args.output_dir,
    )
    asyncio.run(recon.run())


if __name__ == "__main__":
    main()
