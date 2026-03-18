"""Wayback Machine integration — fetch historical URLs from web.archive.org."""

import asyncio
from urllib.parse import urlparse

import aiohttp

from . import DEFAULT_USER_AGENT

# skip these extensions — they won't have CORS headers
SKIP_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".map", ".webp", ".webm", ".flv", ".swf",
}


def _should_skip(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


async def fetch_wayback_urls(
    domain: str,
    timeout: int = 30,
    on_found=None,
) -> list:
    """Fetch historical URLs from Wayback Machine CDX API.

    Returns unique, filtered URLs for the given domain.
    """
    api_url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&collapse=urlkey&fl=original"
        f"&limit=5000"
    )

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(
            timeout=client_timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        ) as session:
            async with session.get(api_url) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError, ValueError):
        return []

    if not data or len(data) < 2:
        return []

    # first row is the header ["original"], skip it
    seen = set()
    urls = []
    for row in data[1:]:
        if not row:
            continue
        url = row[0] if isinstance(row, list) else str(row)

        # skip static files
        if _should_skip(url):
            continue

        # normalize
        url = url.split("?")[0].rstrip("/")  # strip query params and trailing slash

        if url not in seen:
            seen.add(url)
            urls.append(url)
            if on_found:
                on_found(url)

    return urls
