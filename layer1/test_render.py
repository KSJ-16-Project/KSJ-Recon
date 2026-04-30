#동작 확인용 코드입니다.

import asyncio
import sys
sys.path.insert(0, "..")

from layer1.browser import BrowserManager
from layer1.render import render, probe


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

    print("\n=== .glb 필터링 검증 — Three.js GLTF Loader ===")
    async with BrowserManager() as bm:
        result = await render(bm.browser, "https://threejs.org/examples/webgl_loader_gltf.html", render_wait=3000)
        if result is None:
            print("결과: None")
            return
        print(f"status        : {result.status}")
        print(f"xhr_list      : {len(result.xhr_list)}개")
        glb_found = [x for x in result.xhr_list if ".glb" in x.url or ".gltf" in x.url]
        if glb_found:
            print(f"  .glb/.gltf 잡힘 (필터링 실패): {len(glb_found)}개")
            for x in glb_found:
                print(f"    {x.url}")
        else:
            print("  .glb/.gltf 없음 (필터링 성공)")

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
