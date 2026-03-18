"""Endpoint discovery — find common API paths on a target domain."""

import asyncio
from urllib.parse import urljoin

import aiohttp

# Common API endpoints that often have CORS misconfigurations
COMMON_PATHS = [
    # User/Auth endpoints (most likely to have sensitive data)
    "/api/user", "/api/users", "/api/me", "/api/profile",
    "/api/account", "/api/auth", "/api/login", "/api/session",
    "/api/v1/user", "/api/v1/users", "/api/v1/me", "/api/v1/profile",
    "/api/v2/user", "/api/v2/users", "/api/v2/me",
    "/api/v1/account", "/api/v2/account",
    "/user", "/users", "/me", "/profile", "/account",
    "/v1/user", "/v1/me", "/v2/user", "/v2/me",

    # Data endpoints
    "/api/data", "/api/config", "/api/settings", "/api/info",
    "/api/v1/data", "/api/v1/config", "/api/v1/settings",
    "/api/dashboard", "/api/v1/dashboard",

    # GraphQL
    "/graphql", "/api/graphql", "/graphql/v1", "/gql",

    # Common frameworks
    "/wp-json/wp/v2/users",          # WordPress
    "/rest/api/latest/myself",        # Jira/Atlassian
    "/_api/web/currentuser",          # SharePoint
    "/api/v4/user",                   # GitLab
    "/api/0/",                        # Sentry

    # Health/Info (less sensitive but reveals structure)
    "/api/health", "/api/status", "/api/version", "/api/ping",
    "/health", "/status", "/version", "/info",
    "/.well-known/openid-configuration",

    # Token/Key endpoints
    "/api/token", "/api/keys", "/api/v1/token",
    "/oauth/token", "/oauth2/token",

    # Admin
    "/api/admin", "/api/v1/admin", "/admin/api",

    # Search/Export (can leak data)
    "/api/search", "/api/export", "/api/download",
    "/api/v1/search", "/api/v1/export",
]


async def _check_path(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    timeout: int = 5,
    proxy: str = None,
) -> str | None:
    """Check if a path exists (returns 2xx/3xx). Returns full URL or None."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.get(
            url, timeout=client_timeout, proxy=proxy,
            allow_redirects=True,
        ) as resp:
            # Accept 2xx and 3xx as "exists"
            if resp.status < 400:
                return url
            return None
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return None


async def discover_endpoints(
    base_url: str,
    timeout: int = 5,
    proxy: str = None,
    verify_ssl: bool = True,
    threads: int = 20,
    on_found=None,
) -> list:
    """Discover existing API endpoints on a target.

    Args:
        base_url: The target base URL (e.g., https://target.com)
        timeout: Request timeout per path
        proxy: HTTP proxy
        verify_ssl: Whether to verify SSL
        threads: Concurrent path checks
        on_found: Optional callback(url) called when an endpoint is found

    Returns:
        List of discovered URLs
    """
    import ssl as ssl_mod

    ssl_ctx = None
    if not verify_ssl:
        ssl_ctx = ssl_mod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_mod.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=threads)
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    found_urls = []
    semaphore = asyncio.Semaphore(threads)

    async def check_with_semaphore(path):
        async with semaphore:
            return await _check_path(session, base_url, path, timeout, proxy)

    async with aiohttp.ClientSession(
        connector=connector, timeout=client_timeout,
        cookie_jar=aiohttp.DummyCookieJar(),
    ) as session:
        tasks = [check_with_semaphore(path) for path in COMMON_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, str) and result:
                found_urls.append(result)
                if on_found:
                    on_found(result)

    return found_urls
