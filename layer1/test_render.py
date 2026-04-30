#동작 확인용 코드입니다.

import asyncio
import sys
sys.path.insert(0, "..")

from layer1.browser import BrowserManager
from layer1.render import render, probe, _block_heavy


async def main():
    print("=== probe() 기본 검증 ===")
    ok, msg = await probe()
    print(f"결과: {ok}, 메시지: {msg}\n")

    print("=== httpbin.org/get (단순 GET, XHR 없음) ===")
    async with BrowserManager() as bm:
        result = await render(bm.browser, "https://httpbin.org/get")
        if result is None:
            print("결과: None (렌더링 실패)")
            return
        print(f"status      : {result.status}")
        print(f"html 길이   : {len(result.rendered_html)}")
        print(f"xhr_list    : {len(result.xhr_list)}개")
        print(f"ws_list     : {len(result.ws_list)}개")
        print(f"cookies     : {result.cookies}")

    print("\n=== example.com — HTML 내용 확인 ===")
    async with BrowserManager() as bm:
        result = await render(bm.browser, "https://example.com")
        if result is None:
            print("결과: None")
            return
        print(f"status        : {result.status}")
        print(f"raw_html 앞   : {result.raw_html[:200]}")
        print(f"rendered 앞   : {result.rendered_html[:200]}")

    print("\n=== .glb 차단 검증 — Three.js GLTF Loader ===")
    async with BrowserManager() as bm:
        ctx = await bm.browser.new_context()
        await ctx.route("**/*", _block_heavy)
        page = await ctx.new_page()

        all_requested = []
        all_responded = []
        all_failed = []
        page.on("request", lambda r: all_requested.append(r.url))
        page.on("response", lambda r: all_responded.append(r.url))
        page.on("requestfailed", lambda r: all_failed.append(r.url))

        try:
            await page.goto(
                "https://threejs.org/examples/webgl_loader_gltf.html",
                wait_until="load",
                timeout=30000,
            )
            await page.wait_for_timeout(3000)
        except Exception as e:
            print(f"페이지 로딩 오류: {e}")

        glb_req = [u for u in all_requested if u.split("?")[0].lower().endswith(".glb")]
        glb_resp = [u for u in all_responded if u.split("?")[0].lower().endswith(".glb")]
        glb_fail = [u for u in all_failed if u.split("?")[0].lower().endswith(".glb")]

        print(f"  .glb 요청 시도 : {len(glb_req)}건")
        print(f"  .glb 응답 수신 : {len(glb_resp)}건  (차단되면 0이어야 함)")
        print(f"  .glb 차단(fail): {len(glb_fail)}건  (요청 시도와 같으면 모두 차단)")

        if not glb_req:
            print("  → .glb 요청 자체가 없음. 테스트 무효 (페이지가 .glb 안 씀)")
        elif glb_resp == [] and len(glb_fail) == len(glb_req):
            print("  → 모든 .glb 차단 성공 ✅")
        else:
            print("  → 차단 실패 ❌")
            for u in glb_resp:
                print(f"    응답 받음: {u}")

        await ctx.close()

    print("\n=== WS 인터셉트 검증 — Binance BTC/USDT ===")
    async with BrowserManager() as bm:
        result = await render(bm.browser, "https://www.binance.com/en/trade/BTC_USDT", render_wait=5000)
        if result is None:
            print("결과: None")
            return
        print(f"status        : {result.status}")
        print(f"xhr_list      : {len(result.xhr_list)}개")
        print(f"ws_list       : {len(result.ws_list)}개")
        for ws in result.ws_list:
            print(f"\n  [WS] {ws.url[:80]}")
            print(f"       sent     : {ws.sent_preview[:200]}")
            print(f"       received : {ws.received_preview[:200]}")
            print(f"       closed   : {ws.closed}, code={ws.close_code}")


asyncio.run(main())
