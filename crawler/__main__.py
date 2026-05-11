from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
from urllib.parse import urlparse

from crawler.browser import BrowserManager
from crawler.engine import crawl_target
from crawler.models import CrawlerConfig, CrawlResult
from crawler.playwright_setup import ensure_chromium


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="crawler", description="Run the integrated crawler engine.")
    parser.add_argument("--url", default="http://localhost/", help="Target URL")
    parser.add_argument("--username", default="", help="Optional login username")
    parser.add_argument("--password", default="", help="Optional login password")
    parser.add_argument("--login-url", default="", help="Login page URL")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--render-wait", type=int, default=1000)
    parser.add_argument("--headless", action="store_true",
                        help="Run without opening a browser window")
    parser.add_argument("--format", choices=["text", "json"], default="json",
                        help="Output format (default: json)")
    return parser.parse_args()

def _rel_path(url: str, base: str) -> str:
    """Strip scheme+host so URLs render as relative paths when on the same host."""
    p, b = urlparse(url), urlparse(base)
    if p.netloc != b.netloc:
        return url
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"
    return path


def _render_text(result: CrawlResult, target_url: str)->None:
    bar = "=" * 64

    print(bar)
    print("  Crawl Summary")
    print(bar)
    print(f"  Target            {result.target_url}")
    print(f"  Pages (unauth)    {len(result.public_pages)}")
    print(f"  Pages (auth)      {len(result.authenticated_pages)}")
    print(f"  Endpoint hints    {len(result.endpoint_hints)}")
    print(f"  Sitemap URLs      {len(result.sitemap_urls)}")
    print(bar)

    if result.auth is not None:
        a = result.auth
        print()
        print("  Auth")
        print(f"    Attempted   {a.attempted}")
        print(f"    Success     {a.success}")
        print(f"    Reason      {a.reason}")
        print(f"    Login URL   {a.login_url}")
        print(f"    Final URL   {a.final_url}")
        print(f"    Cookies     {len(a.cookies)}")
        if not a.success and a.error:
            print(f"    Error       {a.error}")

    if result.errors:
        print()
        print("  Errors")
        for err in result.errors:
            print(f"    - {err}")

    if not result.pages:
        return

    print()
    print("  Pages")
    print(f"    {'DEP':>3}  {'STAT':>4}  {'FORMS':>5}  {'EP':>4}  PATH")
    for p in result.pages:
        path = _rel_path(p.url, target_url)
        print(f"    {p.depth:>3}  {p.status:>4}  "
              f"{len(p.forms):>5}  {len(p.endpoint_hints):>4}  {path}")

    if result.endpoint_hints:
        print()
        print("  Endpoint Hints")
        print(f"    {'METHOD':<8}  {'SOURCE':<12}  URL")
        for h in result.endpoint_hints:
            params_str = f"  {h.params}" if h.params else ""
            print(f"    {h.method:<8}  {h.source:<12}  {_rel_path(h.url, target_url)}{params_str}")


def _render_json(result: CrawlResult) -> None:
    payload = dataclasses.asdict(result)
    print(json.dumps(payload, default=str, indent=2))


async def main() -> int:
    args = parse_args()
    if args.login_url and args.username and args.password:
        import ksj_login
        ksj_login.store_credentials(args.login_url, args.username, args.password)

    config = CrawlerConfig(
        target_url=args.url,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        render_wait=args.render_wait,
    )

    async with BrowserManager(headless=args.headless) as bm:
        if bm.browser is None:
            print("BROWSER_FAIL")
            return 1
        result = await crawl_target(config, browser=bm.browser)

    if args.format == "json":
        _render_json(result)
    else:
        _render_text(result, args.url)
    return 0


def _suppress_playwright_teardown(loop, context):
    exc = context.get("exception")
    msg = str(exc) if exc else context.get("message", "")
    if "Target page, context or browser has been closed" in msg:
        return
    loop.default_exception_handler(context)


if __name__ == "__main__":
    ensure_chromium()
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(_suppress_playwright_teardown)
    raise SystemExit(loop.run_until_complete(main()))
