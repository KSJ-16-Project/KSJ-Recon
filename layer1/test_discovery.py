import asyncio
import sys
sys.path.insert(0, "..")

from layer1.browser import BrowserManager
from layer2.discovery import history_urls, HISTORY_SHIM, _safe


TARGET = "https://hotspotfan.online/"
TIMEOUT = 120  # 탐색 최대 시간 (초)


async def main():
    print(f"=== click_walk 디버그 — {TARGET} ===\n")

    async with BrowserManager() as bm:
        ctx = await bm.browser.new_context(ignore_https_errors=True)
        await ctx.add_init_script(HISTORY_SHIM)
        page = await ctx.new_page()

        print("1. 페이지 이동 중...")
        try:
            await page.goto(TARGET, timeout=30000, wait_until="load")
        except Exception as e:
            print(f"   오류: {e}")
        await page.wait_for_timeout(3000)
        print("   완료\n")

        locator = page.locator("a, button, [role=button]")
        count = await locator.count()
        print(f"2. 클릭 가능한 요소: {count}개\n")

        deadline = asyncio.get_event_loop().time() + TIMEOUT

        for i in range(count):
            if asyncio.get_event_loop().time() > deadline:
                print("   시간 초과 → 탐색 중단")
                break

            el = locator.nth(i)

            # _safe 체크
            try:
                safe = await _safe(el)
            except Exception as e:
                print(f"   [{i}] _safe() 실패 → 스킵 ({e.__class__.__name__})")
                continue

            if not safe:
                try:
                    label = (await el.inner_text()).strip()[:40] or "(no text)"
                except Exception:
                    label = "(no text)"
                print(f"   [{i}] _safe=False → 스킵  | {label}")
                continue

            try:
                label = (await el.inner_text()).strip()[:40] or "(no text)"
            except Exception:
                label = "(no text)"

            before_url = page.url
            print(f"   [{i}] 클릭 시도 → '{label}'")

            try:
                await el.click(timeout=3000)
            except Exception as e:
                print(f"        클릭 실패: {e.__class__.__name__} → Escape 시도")
                try:
                    await page.keyboard.press("Escape")
                except Exception:
                    pass
                try:
                    await page.click("body", position={"x": 10, "y": 10}, timeout=1000)
                except Exception:
                    pass
                continue

            try:
                await page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                pass

            after_url = page.url
            new_urls = await history_urls(page, TARGET)

            print(f"        before: {before_url}")
            print(f"        after : {after_url}")
            print(f"        history_urls: {new_urls}")

            if after_url != before_url:
                print(f"        → URL 변경 감지, 원래 페이지로 복귀")
                await page.goto(before_url)
                await page.wait_for_load_state("networkidle", timeout=3000)
                count = await locator.count()
                print(f"        → 복귀 완료, 요소 수: {count}개\n")

        await ctx.close()

    print("\n완료")


asyncio.run(main())
