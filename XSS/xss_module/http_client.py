"""Small requests wrapper with shared defaults."""

from __future__ import annotations

import logging

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; KShield-XSS-Module/2.0; security-testing)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class HttpClient:
    def __init__(self, *, headers: dict | None = None, cookies: dict | None = None, timeout: int = 10, verify_tls: bool = False):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        self.timeout = timeout
        self.verify_tls = verify_tls

    def get(self, url: str, *, params: dict | None = None, headers: dict | None = None, cookies: dict | None = None):
        return self.session.get(url, params=params, headers=headers, cookies=cookies, timeout=self.timeout, verify=self.verify_tls, allow_redirects=True)

    def post(self, url: str, *, data: dict | None = None, json: dict | None = None, headers: dict | None = None, cookies: dict | None = None):
        return self.session.post(url, data=data, json=json, headers=headers, cookies=cookies, timeout=self.timeout, verify=self.verify_tls, allow_redirects=True)

    def update_auth(self, *, session_id: str | None = None, token: str | None = None, cookies: dict | None = None) -> None:
        """Apply refreshed credentials to the live session."""
        if session_id:
            self.session.cookies.set("session_id", session_id)
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        if cookies:
            self.session.cookies.update(cookies)
        logger.debug("session auth updated")
