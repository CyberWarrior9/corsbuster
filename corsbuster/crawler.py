"""Website crawler — spider pages and extract endpoints from HTML + JavaScript."""

import asyncio
import re
import ssl as ssl_mod
from urllib.parse import urljoin, urlparse

import aiohttp

from . import DEFAULT_USER_AGENT


class Crawler:
    """Async web crawler that extracts URLs from HTML and JavaScript files."""

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        timeout: int = 10,
        proxy: str = None,
        verify_ssl: bool = True,
        threads: int = 10,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.threads = threads

        self.visited: set = set()
        self.found_urls: set = set()
        self.js_urls: set = set()
        self.semaphore = asyncio.Semaphore(threads)

    # ── URL extraction patterns ───────────────────────────────────────

    # HTML: href and src attributes
    HTML_URL_RE = re.compile(
        r'''(?:href|src|action|data-url)\s*=\s*["']([^"'#\s]+)["']''',
        re.IGNORECASE,
    )

    # JavaScript: API endpoints, fetch calls, axios calls
    JS_ENDPOINT_RE = re.compile(
        r'''(?:'''
        r'''["'`](\/(?:api|v[0-9]|graphql|rest|auth|oauth|user|admin|dashboard|search)'''
        r'''[^"'`\s]{0,200})["'`]'''
        r'''|fetch\s*\(\s*["'`]([^"'`\s]+)["'`]'''
        r'''|\.(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`\s]+)["'`]'''
        r'''|url\s*[:=]\s*["'`]([^"'`\s]+)["'`]'''
        r''')''',
        re.IGNORECASE,
    )

    # JavaScript file references
    JS_FILE_RE = re.compile(
        r'''(?:src)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']''',
        re.IGNORECASE,
    )

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain."""
        parsed = urlparse(url)
        return parsed.netloc == "" or parsed.netloc == self.base_domain

    def _normalize_url(self, url: str, page_url: str) -> str | None:
        """Normalize a URL relative to the page it was found on."""
        if not url or url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return None

        # Resolve relative URLs
        full_url = urljoin(page_url, url)
        parsed = urlparse(full_url)

        # Only keep same-domain URLs
        if parsed.netloc != self.base_domain:
            return None

        # Only http/https
        if parsed.scheme not in ("http", "https"):
            return None

        # Strip fragment
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"

        return clean

    def _extract_urls_from_html(self, html: str, page_url: str) -> set:
        """Extract URLs from HTML content."""
        urls = set()
        for match in self.HTML_URL_RE.finditer(html):
            url = self._normalize_url(match.group(1), page_url)
            if url:
                urls.add(url)
        return urls

    def _extract_js_files(self, html: str, page_url: str) -> set:
        """Extract JavaScript file URLs from HTML."""
        js_files = set()
        for match in self.JS_FILE_RE.finditer(html):
            url = self._normalize_url(match.group(1), page_url)
            if url:
                js_files.add(url)
        return js_files

    def _extract_endpoints_from_js(self, js_content: str, page_url: str) -> set:
        """Extract API endpoints from JavaScript code."""
        endpoints = set()
        for match in self.JS_ENDPOINT_RE.finditer(js_content):
            # Get the first non-None group
            for group in match.groups():
                if group:
                    url = self._normalize_url(group, page_url)
                    if url:
                        endpoints.add(url)
                    elif group.startswith("/"):
                        # Relative path — resolve against base URL
                        full = urljoin(self.base_url, group)
                        endpoints.add(full)
                    break
        return endpoints

    async def _fetch_page(self, session: aiohttp.ClientSession, url: str) -> str:
        """Fetch a page and return its content."""
        try:
            client_timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with session.get(
                url, timeout=client_timeout, proxy=self.proxy,
                allow_redirects=True,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            ) as resp:
                if resp.status >= 400:
                    return ""
                content_type = resp.headers.get("Content-Type", "")
                if not any(t in content_type for t in ["text/", "javascript", "json", "xml"]):
                    return ""  # Skip binary files
                return await resp.text(errors="replace")
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
            return ""

    async def _crawl_page(
        self,
        session: aiohttp.ClientSession,
        url: str,
        depth: int,
    ):
        """Crawl a single page: extract URLs, JS files, and API endpoints."""
        if depth > self.max_depth:
            return
        if url in self.visited:
            return

        self.visited.add(url)

        async with self.semaphore:
            content = await self._fetch_page(session, url)

        if not content:
            return

        # Extract URLs from HTML
        page_urls = self._extract_urls_from_html(content, url)
        self.found_urls.update(page_urls)

        # Extract JS file URLs
        js_files = self._extract_js_files(content, url)

        # If this IS a JS file, extract endpoints from it
        if url.endswith(".js") or "javascript" in url:
            endpoints = self._extract_endpoints_from_js(content, url)
            self.found_urls.update(endpoints)

        # Fetch and parse JS files for API endpoints
        for js_url in js_files:
            if js_url not in self.js_urls:
                self.js_urls.add(js_url)
                async with self.semaphore:
                    js_content = await self._fetch_page(session, js_url)
                if js_content:
                    endpoints = self._extract_endpoints_from_js(js_content, js_url)
                    self.found_urls.update(endpoints)

        # Recursively crawl discovered same-domain pages
        if depth < self.max_depth:
            tasks = []
            for new_url in page_urls:
                if new_url not in self.visited and self._is_same_domain(new_url):
                    tasks.append(self._crawl_page(session, new_url, depth + 1))
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def crawl(self) -> list:
        """Start crawling from base_url. Returns list of discovered URLs."""
        ssl_ctx = None
        if not self.verify_ssl:
            ssl_ctx = ssl_mod.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl_mod.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=self.threads)

        async with aiohttp.ClientSession(
            connector=connector,
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            await self._crawl_page(session, self.base_url, depth=0)

        # Include the base URL itself
        self.found_urls.add(self.base_url)

        # Sort and return
        return sorted(self.found_urls)
