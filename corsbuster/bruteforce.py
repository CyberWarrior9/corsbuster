"""Directory bruteforce with built-in 1000-path wordlist."""

import asyncio
import random
from urllib.parse import urljoin

import aiohttp

from . import DEFAULT_USER_AGENT

# 1000 common paths for directory bruteforcing
WORDLIST = [
    # ── Common directories (~150) ─────────────────────────────────────
    "/admin", "/administrator", "/admin-panel", "/adminpanel", "/admin-console",
    "/login", "/signin", "/signup", "/register", "/auth",
    "/dashboard", "/panel", "/portal", "/console", "/control",
    "/config", "/configuration", "/settings", "/preferences", "/options",
    "/backup", "/backups", "/bak", "/old", "/archive",
    "/upload", "/uploads", "/files", "/documents", "/docs",
    "/images", "/img", "/media", "/assets", "/static",
    "/css", "/js", "/javascript", "/scripts", "/fonts",
    "/include", "/includes", "/inc", "/lib", "/libs",
    "/tmp", "/temp", "/cache", "/log", "/logs",
    "/data", "/database", "/db", "/sql", "/dump",
    "/private", "/secret", "/hidden", "/internal", "/restricted",
    "/public", "/pub", "/www", "/web", "/html",
    "/cgi-bin", "/cgi", "/bin", "/sbin", "/scripts",
    "/test", "/testing", "/tests", "/debug", "/dev",
    "/staging", "/stage", "/beta", "/alpha", "/demo",
    "/new", "/old", "/legacy", "/archive", "/deprecated",
    "/error", "/errors", "/404", "/500", "/maintenance",
    "/help", "/support", "/faq", "/about", "/contact",
    "/home", "/index", "/default", "/main", "/start",
    "/system", "/sys", "/server", "/service", "/services",
    "/tools", "/utilities", "/util", "/utils", "/misc",
    "/downloads", "/download", "/dl", "/get", "/fetch",
    "/resources", "/resource", "/res", "/content", "/contents",
    "/reports", "/report", "/stats", "/statistics", "/analytics",
    "/monitor", "/monitoring", "/health", "/status", "/ping",
    "/build", "/dist", "/output", "/release", "/releases",
    "/src", "/source", "/sources", "/code", "/app",

    # ── API endpoints (~200) ──────────────────────────────────────────
    "/api", "/api/", "/apis", "/rest", "/restapi",
    "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3", "/v4",
    "/api/user", "/api/users", "/api/me", "/api/profile", "/api/account",
    "/api/v1/user", "/api/v1/users", "/api/v1/me", "/api/v1/profile",
    "/api/v2/user", "/api/v2/users", "/api/v2/me", "/api/v2/profile",
    "/api/v1/account", "/api/v2/account", "/api/v1/accounts",
    "/api/auth", "/api/login", "/api/logout", "/api/session",
    "/api/v1/auth", "/api/v1/login", "/api/v1/session",
    "/api/token", "/api/tokens", "/api/keys", "/api/key",
    "/api/v1/token", "/api/v1/tokens", "/api/v1/keys",
    "/api/config", "/api/settings", "/api/preferences",
    "/api/v1/config", "/api/v1/settings",
    "/api/data", "/api/info", "/api/metadata",
    "/api/v1/data", "/api/v1/info", "/api/v1/metadata",
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/api/search", "/api/query", "/api/find", "/api/lookup",
    "/api/v1/search", "/api/v1/query",
    "/api/export", "/api/import", "/api/upload", "/api/download",
    "/api/v1/export", "/api/v1/import",
    "/api/report", "/api/reports", "/api/analytics", "/api/stats",
    "/api/v1/report", "/api/v1/reports", "/api/v1/stats",
    "/api/dashboard", "/api/v1/dashboard",
    "/api/notification", "/api/notifications",
    "/api/message", "/api/messages", "/api/chat",
    "/api/payment", "/api/payments", "/api/billing", "/api/invoice",
    "/api/order", "/api/orders", "/api/cart", "/api/checkout",
    "/api/product", "/api/products", "/api/item", "/api/items",
    "/api/category", "/api/categories", "/api/tag", "/api/tags",
    "/api/comment", "/api/comments", "/api/review", "/api/reviews",
    "/api/post", "/api/posts", "/api/article", "/api/articles",
    "/api/page", "/api/pages", "/api/content",
    "/api/file", "/api/files", "/api/document", "/api/documents",
    "/api/image", "/api/images", "/api/media",
    "/api/log", "/api/logs", "/api/audit", "/api/events",
    "/api/webhook", "/api/webhooks", "/api/callback",
    "/api/health", "/api/status", "/api/version", "/api/ping",
    "/api/v1/health", "/api/v1/status", "/api/v1/version",
    "/graphql", "/api/graphql", "/graphql/v1", "/gql",
    "/api/graphiql", "/graphiql", "/playground",
    "/rest/api", "/rest/v1", "/rest/v2",
    "/jsonapi", "/json-api", "/json",
    "/rpc", "/xmlrpc", "/jsonrpc", "/soap", "/wsdl",
    "/api/swagger", "/api/openapi", "/api/docs", "/api/spec",
    "/api/v1/swagger", "/api/v1/docs",

    # ── Sensitive files (~100) ────────────────────────────────────────
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.backup", "/.env.bak", "/.env.old", "/.env.save",
    "/.git", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn", "/.svn/entries", "/.hg",
    "/.htaccess", "/.htpasswd", "/.htpasswd.bak",
    "/.DS_Store", "/Thumbs.db",
    "/robots.txt", "/sitemap.xml", "/sitemap.xml.gz",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/config.json", "/config.yaml", "/config.yml", "/config.xml",
    "/config.php", "/config.inc.php", "/config.bak",
    "/settings.json", "/settings.yaml", "/settings.py",
    "/database.yml", "/database.json", "/db.json", "/db.sqlite3",
    "/credentials.json", "/secrets.json", "/keys.json",
    "/package.json", "/package-lock.json", "/composer.json",
    "/composer.lock", "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/yarn.lock", "/pnpm-lock.yaml",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/.dockerignore",
    "/Makefile", "/Rakefile", "/Gruntfile.js", "/gulpfile.js",
    "/webpack.config.js", "/tsconfig.json", "/babel.config.js",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/elmah.axd", "/trace.axd",
    "/web.config", "/web.config.bak", "/applicationhost.config",
    "/error_log", "/access_log", "/debug.log",
    "/wp-config.php", "/wp-config.php.bak",
    "/.aws/credentials", "/.ssh/id_rsa", "/.npmrc",
    "/id_rsa", "/id_dsa", "/.bash_history",
    "/backup.sql", "/backup.zip", "/backup.tar.gz",
    "/dump.sql", "/database.sql", "/db.sql",

    # ── Framework-specific (~150) ─────────────────────────────────────
    # WordPress
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-content",
    "/wp-includes", "/wp-json", "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
    "/wp-cron.php", "/xmlrpc.php", "/wp-signup.php",
    "/wp-config.php", "/wp-content/uploads",
    "/wp-content/plugins", "/wp-content/themes",
    # Joomla
    "/administrator", "/administrator/index.php",
    "/components", "/modules", "/plugins", "/templates",
    "/cache", "/tmp", "/media",
    # Drupal
    "/node", "/user", "/user/login", "/user/register",
    "/admin/content", "/admin/config", "/admin/structure",
    "/sites/default/files", "/sites/default/settings.php",
    # Laravel
    "/storage", "/storage/logs", "/storage/framework",
    "/vendor", "/artisan", "/telescope",
    "/horizon", "/nova", "/vapor",
    "/_debugbar", "/clockwork",
    # Django
    "/admin/", "/admin/login/", "/admin/logout/",
    "/django-admin", "/media", "/staticfiles",
    "/__debug__", "/silk",
    # Node.js / Express
    "/node_modules", "/package.json",
    "/npm-debug.log", "/yarn-error.log",
    "/.next", "/.nuxt", "/dist",
    # Spring / Java
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings", "/actuator/configprops",
    "/actuator/info", "/actuator/metrics", "/actuator/loggers",
    "/swagger-ui.html", "/swagger-ui", "/swagger-ui/",
    "/swagger-resources", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/webjars", "/h2-console",
    # .NET / ASP
    "/elmah", "/Elmah.axd", "/trace.axd",
    "/bin", "/App_Data", "/App_Code",
    # Ruby on Rails
    "/rails/info", "/rails/info/routes", "/rails/mailers",
    "/sidekiq", "/delayed_job",
    # PHP
    "/phpmyadmin", "/phpMyAdmin", "/pma",
    "/adminer", "/adminer.php",
    "/info.php", "/phpinfo.php", "/test.php",
    "/cPanel", "/cpanel", "/webmail",
    # Flask
    "/debugger", "/console",

    # ── Auth/User paths (~100) ────────────────────────────────────────
    "/login", "/logout", "/signin", "/signout", "/sign-in", "/sign-out",
    "/signup", "/sign-up", "/register", "/registration",
    "/forgot-password", "/reset-password", "/change-password",
    "/forgot", "/reset", "/recover", "/activate",
    "/verify", "/confirm", "/validate", "/verification",
    "/oauth", "/oauth2", "/oauth/authorize", "/oauth/token",
    "/oauth2/authorize", "/oauth2/token", "/oauth/callback",
    "/auth/login", "/auth/logout", "/auth/register",
    "/auth/callback", "/auth/verify", "/auth/reset",
    "/sso", "/sso/login", "/sso/callback", "/saml", "/saml/login",
    "/cas", "/cas/login", "/openid", "/openid/login",
    "/token", "/tokens", "/session", "/sessions",
    "/profile", "/account", "/my-account", "/myaccount",
    "/user/profile", "/user/settings", "/user/account",
    "/users/sign_in", "/users/sign_up", "/users/password",
    "/api/authenticate", "/api/authorize",
    "/2fa", "/mfa", "/two-factor", "/multi-factor",
    "/connect/token", "/connect/authorize",
    "/.well-known/jwks.json", "/.well-known/openid-configuration",
    "/userinfo", "/introspect", "/revoke",

    # ── Data/Export paths (~100) ──────────────────────────────────────
    "/export", "/export/csv", "/export/pdf", "/export/excel",
    "/download", "/downloads", "/dl",
    "/import", "/upload", "/uploads",
    "/search", "/search/results", "/find",
    "/report", "/reports", "/reporting",
    "/analytics", "/metrics", "/stats", "/statistics",
    "/chart", "/charts", "/graph", "/graphs",
    "/feed", "/feeds", "/rss", "/atom",
    "/sitemap", "/sitemaps",
    "/newsletter", "/subscribe", "/unsubscribe",
    "/webhook", "/webhooks", "/hooks",
    "/callback", "/callbacks",
    "/cron", "/cronjob", "/scheduled",
    "/queue", "/queues", "/jobs", "/workers",
    "/batch", "/bulk", "/mass",
    "/migrate", "/migration", "/migrations",
    "/seed", "/seeds", "/fixtures",
    "/sync", "/synchronize",
    "/preview", "/draft", "/publish",
    "/archive", "/archives", "/history",
    "/audit", "/audit-log", "/activity",
    "/event", "/events", "/stream",
    "/notification", "/notifications", "/alerts",

    # ── Versioned API (~100) ──────────────────────────────────────────
    "/v1/users", "/v1/user", "/v1/me", "/v1/profile",
    "/v1/auth", "/v1/login", "/v1/token", "/v1/session",
    "/v1/config", "/v1/settings", "/v1/admin",
    "/v1/data", "/v1/search", "/v1/export",
    "/v1/products", "/v1/orders", "/v1/payments",
    "/v1/messages", "/v1/notifications",
    "/v2/users", "/v2/user", "/v2/me", "/v2/profile",
    "/v2/auth", "/v2/login", "/v2/token", "/v2/session",
    "/v2/config", "/v2/settings", "/v2/admin",
    "/v2/data", "/v2/search", "/v2/export",
    "/v2/products", "/v2/orders", "/v2/payments",
    "/v2/messages", "/v2/notifications",
    "/v3/users", "/v3/user", "/v3/me",
    "/v3/auth", "/v3/config", "/v3/admin",
    "/api/latest", "/api/current",
    "/api/internal", "/api/private", "/api/public",
    "/api/external", "/api/partner", "/api/third-party",
    "/api/mobile", "/api/app", "/api/web",
    "/api/legacy", "/api/deprecated", "/api/beta",
    "/api/sandbox", "/api/test", "/api/dev",
    "/api/staging", "/api/production", "/api/live",

    # ── Misc/Common (~100) ────────────────────────────────────────────
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/openapi", "/openapi.json", "/openapi.yaml",
    "/docs", "/documentation", "/doc", "/apidoc", "/apidocs",
    "/redoc", "/rapidoc",
    "/postman", "/postman-collection",
    "/changelog", "/readme", "/license",
    "/health", "/healthz", "/healthcheck", "/ready", "/readyz",
    "/live", "/livez", "/alive",
    "/version", "/build-info", "/app-info",
    "/env", "/environment", "/properties",
    "/feature", "/features", "/flags", "/feature-flags",
    "/socket", "/websocket", "/ws", "/wss",
    "/socket.io", "/sockjs",
    "/proxy", "/gateway", "/redirect", "/forward",
    "/cdn", "/edge", "/origin",
    "/storage", "/bucket", "/blob", "/s3",
    "/mail", "/email", "/smtp", "/imap",
    "/ftp", "/sftp", "/ssh",
    "/ldap", "/directory",
    "/dns", "/resolve",
    "/cert", "/certificate", "/ssl", "/tls",
    "/vpn", "/tunnel",
    "/metrics", "/prometheus", "/grafana",
    "/kibana", "/elasticsearch", "/logstash",
    "/jenkins", "/ci", "/cd", "/pipeline",
    "/deploy", "/deployment", "/releases",
    "/terraform", "/ansible", "/puppet", "/chef",
    "/kubernetes", "/k8s", "/docker",
    "/consul", "/vault", "/nomad",
    "/redis", "/memcached", "/mongo", "/mysql", "/postgres",
    "/phpmyadmin", "/adminer", "/pgadmin",
    "/rabbitmq", "/kafka", "/celery",
    "/flower", "/supervisor",
    "/traefik", "/nginx", "/apache", "/caddy",
    "/haproxy", "/envoy",
]

# Valid status codes for "endpoint exists"
VALID_STATUS_CODES = {200, 201, 202, 204, 301, 302, 303, 307, 308, 403}


async def _check_path(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    timeout: int = 5,
    proxy: str = None,
) -> tuple:
    """Check if a path exists. Returns (full_url, status_code) or (None, 0)."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.get(
            url, timeout=client_timeout, proxy=proxy,
            allow_redirects=True,
        ) as resp:
            if resp.status in VALID_STATUS_CODES:
                return url, resp.status
            return None, resp.status
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return None, 0


async def bruteforce_paths(
    base_url: str,
    timeout: int = 5,
    proxy: str = None,
    verify_ssl: bool = True,
    threads: int = 10,
    stealth: bool = False,
    on_found=None,
    on_progress=None,
) -> list:
    """Bruteforce directories on a target using built-in wordlist.

    Args:
        base_url: Base URL to bruteforce (e.g., https://target.com)
        timeout: Request timeout per path
        proxy: HTTP proxy
        verify_ssl: Whether to verify SSL
        threads: Concurrent requests
        stealth: Enable stealth mode (random delays, backoff on 429)
        on_found: Optional callback(url, status_code) when endpoint found
        on_progress: Optional callback(checked, total, found_count)

    Returns:
        List of discovered URLs
    """
    import ssl as ssl_mod

    # Stealth mode reduces threads
    if stealth:
        threads = min(threads, 3)

    ssl_ctx = None
    if not verify_ssl:
        ssl_ctx = ssl_mod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_mod.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=threads)
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    found_urls = []
    checked = 0
    total = len(WORDLIST)
    semaphore = asyncio.Semaphore(threads)
    lock = asyncio.Lock()
    backoff = 0  # seconds to wait on 429

    async def check_with_semaphore(path):
        nonlocal checked, backoff
        async with semaphore:
            # Backoff if server returned 429
            if backoff > 0:
                await asyncio.sleep(backoff)

            result_url, status = await _check_path(session, base_url, path, timeout, proxy)

            # Handle 429 rate limiting
            if status == 429:
                async with lock:
                    backoff = min((backoff or 2) * 2, 16)
                await asyncio.sleep(backoff)
                # Retry once
                result_url, status = await _check_path(session, base_url, path, timeout, proxy)
            elif backoff > 0:
                # Gradually reduce backoff on success
                async with lock:
                    backoff = max(backoff - 1, 0)

            # Stealth: random delay between requests
            if stealth:
                await asyncio.sleep(random.uniform(0.3, 1.5))

        async with lock:
            checked += 1
            if result_url:
                found_urls.append(result_url)
                if on_found:
                    on_found(result_url, status)
            if on_progress and checked % 50 == 0:
                on_progress(checked, total, len(found_urls))

        return result_url

    async with aiohttp.ClientSession(
        connector=connector, timeout=client_timeout,
        cookie_jar=aiohttp.DummyCookieJar(),
        headers={"User-Agent": DEFAULT_USER_AGENT},
    ) as session:
        tasks = [check_with_semaphore(path) for path in WORDLIST]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Final progress
    if on_progress:
        on_progress(total, total, len(found_urls))

    return found_urls
