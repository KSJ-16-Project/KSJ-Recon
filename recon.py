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
TOKEN_KEYS = ("accessToken", "access_token", "token", "jwt", "id_token", "idToken")
PAYLOAD_KEY_CANDIDATES = ("id", "loginId", "username", "email", "userId", "user_id")


def normalize_url(base, href):
    if href is None:
        return None
    try:
        full = urljoin(base, href)
        p = urlparse(full)
        if p.scheme not in ("http", "https"):
            return None
        return f"{p.scheme}://{p.netloc}{p.path}"
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


def extract_token(body):
    if not isinstance(body, dict):
        return None
    for k in TOKEN_KEYS:
        v = body.get(k)
        if isinstance(v, str) and len(v) > 20:
            return v
    if isinstance(body.get("data"), dict):
        for k in TOKEN_KEYS:
            v = body["data"].get(k)
            if isinstance(v, str) and len(v) > 20:
                return v
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
    def __init__(self, target, max_depth=2, max_clicks=30, page_timeout_ms=20000, label="anon"):
        self.target = target
        self.max_depth = max_depth
        self.max_clicks = max_clicks
        self.page_timeout_ms = page_timeout_ms
        self.label = label

        self.visited = set()
        self.collected_urls = []
        self.client_routes = set()
        self.network_requests = []
        self.api_endpoints_status = {}   # (METHOD, path) → 마지막 status
        self.headers = {}

    def _harvest(self, log):
        out = []
        for entry in log:
            n = normalize_url(self.target, entry.get("url", ""))
            if n and is_in_scope(n, self.target):
                self.client_routes.add(n)
                out.append(n)
        return out

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
                    n = normalize_url(self.target, page.url)
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


async def browser_login(browser, target, login_route, login_id, login_pw):
    """브라우저 로그인. 성공 시 (context, cookies, storage) 반환 / 실패 시 (None,...)"""
    context = await browser.new_context(user_agent=UA)
    page = await context.new_page()
    url = base_url(target) + login_route
    print(f"[*] 로그인 페이지: {url}")
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
    except Exception as e:
        print(f"[!] 로그인 페이지 로드 실패: {e}")
        return None, None, None
    await page.wait_for_timeout(1500)

    text_in, pw_in, hint = await autodetect_login_form(page)
    if not (text_in and pw_in):
        print("[!] 로그인 폼 자동 탐지 실패")
        return None, None, None
    print(f"[*] id 필드 힌트: {hint!r}")
    await text_in.fill(login_id)
    await pw_in.fill(login_pw)

    login_resp = {"status": None, "url": None}
    def cap(resp):
        try:
            r = resp.request
            if r.method == "POST" and "/auth/" in resp.url and "refresh" not in resp.url:
                login_resp["status"] = resp.status
                login_resp["url"] = resp.url
        except Exception:
            pass
    page.on("response", cap)

    submitted = await submit_login(page, pw_in)
    print(f"[*] 제출: {submitted}")
    await page.wait_for_timeout(3500)

    cookies = await context.cookies()
    storage = await page.evaluate(
        "() => ({local: Object.keys(localStorage), session: Object.keys(sessionStorage)})"
    )
    print(f"[*] 응답: {login_resp.get('status')} {login_resp.get('url')}")
    print(f"[*] 쿠키 {[c['name'] for c in cookies]}, "
          f"localStorage {storage['local']}, sessionStorage {storage['session']}")

    has_token = (
        any(any(k in n.lower() for k in ("token", "auth", "session", "jwt")) for n in [c["name"] for c in cookies])
        or any(any(k in s.lower() for k in ("token", "auth", "user")) for s in storage["local"])
        or any(any(k in s.lower() for k in ("token", "auth", "user")) for s in storage["session"])
    )
    if not (has_token or login_resp.get("status") == 200):
        print("[!] 인증 토큰이 확인되지 않음 (그래도 컨텍스트는 반환)")
    await page.close()
    return context, cookies, storage


# ────────────────────────────────────────────────────────────────
# HTTP 로그인 (페이로드 키 자동 탐지)
# ────────────────────────────────────────────────────────────────

def http_login(target, login_path, login_id, login_pw):
    base = base_url(target)
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Origin": base,
        "Referer": base + "/",
        "Content-Type": "application/json",
    })
    last = None
    for key in PAYLOAD_KEY_CANDIDATES:
        payload = {key: login_id, "password": login_pw}
        try:
            r = s.post(base + login_path, json=payload, timeout=10)
        except Exception as e:
            last = str(e); continue
        try:
            body = r.json()
        except Exception:
            body = {}
        print(f"  [http-login try {key:>10}] {r.status_code}")
        if r.status_code == 200:
            tok = extract_token(body) or extract_token(body.get("data") if isinstance(body, dict) else None)
            return s, tok, body, key
        last = body.get("message") if isinstance(body, dict) else None
    print(f"[!] HTTP 로그인 실패: {last}")
    return s, None, None, None


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
                 login_route="/auth", login_path="/api/auth/login",
                 explore_authed=False, depth=2, clicks=30, output_dir="recon_out"):
        self.target = target
        self.login_id = login_id
        self.login_pw = login_pw
        self.login_route = login_route
        self.login_path = login_path
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
                "login_path": login_path if login_id else None,
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
        anon_dict = anon.to_dict()
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
            context, cookies, storage = await browser_login(
                browser, self.target, self.login_route, self.login_id, self.login_pw
            )
            if context is None:
                print("[!] 브라우저 로그인 실패 — 인증 단계 스킵")
                await browser.close()
                self.report["authed"] = {"error": "browser_login_failed"}
                self._finalize()
                return

            authed = DynamicSpider(self.target, max_depth=self.depth, max_clicks=self.clicks, label="authed")
            authed_storage = await self._crawl_in_context(authed, context, anon_dict["client_routes"])
            authed_cookies = await context.cookies()
            await browser.close()

        authed_dict = authed.to_dict()
        authed_dict["cookies"] = [{"name": c["name"], "domain": c["domain"]} for c in authed_cookies]
        authed_dict["storage_keys"] = authed_storage
        self._save("03_authed_crawl.json", authed_dict)
        self.report["authed_crawl"] = authed_dict

        # ── 4) Bearer 프로브
        print("\n[*] (4) HTTP 로그인 + Bearer 토큰 프로브")
        sess, token, body, key = http_login(self.target, self.login_path, self.login_id, self.login_pw)
        if token:
            print(f"[+] access token (len={len(token)}) — payload key: {key!r}")
            sess.headers["Authorization"] = f"Bearer {token}"
        else:
            print("[!] 토큰 미확보 — 쿠키만으로 진행")

        # 익명 + 인증 단계에서 발견된 모든 엔드포인트 합치기
        all_eps = set(anon_dict["api_endpoints"]) | set(authed_dict["api_endpoints"])
        token_results = probe_endpoints(self.target, sorted(all_eps), session=sess, label="token")
        self._save("04_token_probe.json", {
            "target": self.target,
            "token_acquired": bool(token),
            "payload_key": key,
            "login_response_sample": body if isinstance(body, dict) else None,
            "results": token_results,
        })
        self.report["token_probe"] = token_results
        self.report["authed"] = {
            "token_acquired": bool(token),
            "payload_key": key,
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
    ap.add_argument("--login-route", default="/auth", help="로그인 페이지 라우트 (기본 /auth)")
    ap.add_argument("--login-path", default="/api/auth/login", help="HTTP 로그인 API 경로")
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
        login_route=args.login_route, login_path=args.login_path,
        explore_authed=args.explore_authed,
        depth=args.depth, clicks=args.clicks,
        output_dir=args.output_dir,
    )
    asyncio.run(recon.run())


if __name__ == "__main__":
    main()
