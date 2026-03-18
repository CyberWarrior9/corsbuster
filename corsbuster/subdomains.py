"""Subdomain enumeration via crt.sh certificate transparency."""

import asyncio
import ssl as ssl_mod

import aiohttp

from . import DEFAULT_USER_AGENT


async def enumerate_subdomains(
    domain: str,
    timeout: int = 30,
    verify_ssl: bool = True,
    threads: int = 10,
    on_found=None,
) -> list:
    """Find subdomains using crt.sh, then check which ones are alive.

    Returns list of alive subdomain base URLs (e.g., https://api.target.com).
    """
    # query crt.sh
    api_url = f"https://crt.sh/?q=%25.{domain}&output=json"

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

    if not data:
        return []

    # extract unique subdomain names
    subdomains = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower()
            if line.startswith("*."):
                line = line[2:]
            if line.endswith(f".{domain}") or line == domain:
                subdomains.add(line)

    # dedupe and remove the base domain itself (we already have it)
    subdomains.discard(domain)

    if not subdomains:
        return []

    # check which subdomains are alive
    ssl_ctx = None
    if not verify_ssl:
        ssl_ctx = ssl_mod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_mod.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=threads)
    alive = []
    semaphore = asyncio.Semaphore(threads)

    async def check_alive(sub):
        url = f"https://{sub}"
        async with semaphore:
            try:
                check_timeout = aiohttp.ClientTimeout(total=5)
                async with aiohttp.ClientSession(
                    connector=connector, timeout=check_timeout,
                    headers={"User-Agent": DEFAULT_USER_AGENT},
                ) as s:
                    async with s.head(url, allow_redirects=True) as resp:
                        if resp.status < 500:
                            alive.append(url)
                            if on_found:
                                on_found(url)
            except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
                # try http if https fails
                try:
                    http_url = f"http://{sub}"
                    async with aiohttp.ClientSession(
                        connector=connector, timeout=check_timeout,
                        headers={"User-Agent": DEFAULT_USER_AGENT},
                    ) as s:
                        async with s.head(http_url, allow_redirects=True) as resp:
                            if resp.status < 500:
                                alive.append(http_url)
                                if on_found:
                                    on_found(http_url)
                except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
                    pass

    tasks = [check_alive(sub) for sub in sorted(subdomains)]
    await asyncio.gather(*tasks, return_exceptions=True)

    return alive
