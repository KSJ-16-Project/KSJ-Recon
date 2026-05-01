from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from crawler.auth.models import AuthConfig
from crawler.browser import BrowserManager
from crawler.engine import crawl_target
from crawler.models import CrawlerConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the integrated crawler engine.")
    parser.add_argument("--url", default="http://localhost/", help="Target URL")
    parser.add_argument("--username", default="", help="Optional login username")
    parser.add_argument("--password", default="", help="Optional login password")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--render-wait", type=int, default=1000)
    parser.add_argument("--headless", action="store_true", help="Run without opening a browser window")
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    auth = None
    if args.username or args.password:
        auth = AuthConfig(username=args.username, password=args.password)

    config = CrawlerConfig(
        target_url=args.url,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        render_wait=args.render_wait,
        auth=auth,
    )

    async with BrowserManager(headless=args.headless) as bm:
        if bm.browser is None:
            print("BROWSER_FAIL")
            return 1
        result = await crawl_target(config, browser=bm.browser)

    print("TARGET", result.target_url)
    print("PUBLIC_PAGES", len(result.public_pages))
    print("AUTH_PAGES", len(result.authenticated_pages))
    print("ENDPOINT_HINTS", len(result.endpoint_hints))
    print("SITEMAP_URLS", len(result.sitemap_urls))
    if result.auth is not None:
        print("AUTH_REASON", result.auth.reason)
        print("AUTH_ATTEMPTED", result.auth.attempted)
        print("AUTH_SUCCESS", result.auth.success)
        print("AUTH_LOGIN_URL", result.auth.login_url)
        print("AUTH_FINAL_URL", result.auth.final_url)
        print("AUTH_COOKIE_COUNT", len(result.auth.cookies))
    if result.errors:
        print("ERRORS")
        for error in result.errors:
            print(" -", error)

    print("PAGES")
    for page in result.pages:
        print(
            f" - depth={page.depth} status={page.status} "
            f"links={len(page.links)} routes={len(page.routes)} "
            f"forms={len(page.forms)} endpoints={len(page.endpoint_hints)} {page.url}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
