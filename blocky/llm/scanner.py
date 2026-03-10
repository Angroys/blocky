"""
Background scanner: reads /proc/net/tcp{,6} for live HTTP/HTTPS connections,
resolves IPs to domain names (SSL cert → reverse DNS), fetches page content,
and classifies it via an LLM agent. Adult domains trigger the on_adult callback.

Domain resolution strategy (in order):
  1. SSL certificate SANs — most reliable for non-CDN sites on port 443
  2. Reverse DNS — works when PTR record matches the actual domain
  3. Skip — if neither produces a usable domain

Link pre-scanning:
  After classifying a visited page, all outbound links are extracted and their
  domains are queued for background pre-classification (no temp-block, no user
  delay). This means when the user clicks a link, its domain is already cached
  and the temp-block check completes instantly.
  Pre-scanning is recursive up to PRESCAN_DEPTH hops so browsing sessions stay
  lag-free end-to-end.
"""

import asyncio
import html.parser
import json
import logging
import socket
import ssl
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

from blocky.engine.helper_client import HelperError, run_helper

logger = logging.getLogger(__name__)

# ── Scan log ─────────────────────────────────────────────────────────────────

_SCAN_LOG_DIR = Path.home() / ".local" / "share" / "blocky"
_SCAN_LOG_PATH = _SCAN_LOG_DIR / "scan_log.jsonl"
_SCAN_LOG_MAX_SIZE = 5 * 1024 * 1024  # 5 MB — rotate when exceeded


_CONTENT_LOG_DIR = _SCAN_LOG_DIR / "page_content"


def _log_scan(
    domain: str,
    result: str,
    method: str,
    confidence: float = 0.0,
    reason: str = "",
    source: str = "live",
    page_text: str = "",
) -> None:
    """Append one scan record to the JSONL log file.

    *result*: "blocked", "safe", "skipped", "error"
    *method*: "keyword-domain", "keyword-content", "llm", "image", "cached",
              "cdn", "cdn-cert", "cdn-rdns", "no-rdns",
              "category", "already-blocked", "no-content"
    *source*: "live" (real-time connection) or "prescan" (background link scan)
    *page_text*: extracted page text (saved to separate file for analysis)
    """
    try:
        _SCAN_LOG_DIR.mkdir(parents=True, exist_ok=True)
        # Simple rotation: if the file exceeds max size, rename to .old
        if _SCAN_LOG_PATH.exists() and _SCAN_LOG_PATH.stat().st_size > _SCAN_LOG_MAX_SIZE:
            old = _SCAN_LOG_PATH.with_suffix(".jsonl.old")
            _SCAN_LOG_PATH.rename(old)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "domain": domain,
            "result": result,
            "method": method,
            "confidence": round(confidence, 3),
            "reason": reason,
            "source": source,
        }
        with open(_SCAN_LOG_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")

        # Save page content for pattern analysis (only for classified domains)
        if page_text and method in ("llm", "all-checks", "keyword-content"):
            _save_page_content(domain, result, page_text)
    except Exception:
        pass  # never let logging break the scanner


def _save_page_content(domain: str, result: str, page_text: str) -> None:
    """Save extracted page text to a file for offline pattern analysis."""
    try:
        _CONTENT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = domain.replace("/", "_").replace(":", "_")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = _CONTENT_LOG_DIR / f"{result}_{safe_name}_{ts}.txt"
        with open(path, "w") as f:
            f.write(f"Domain: {domain}\n")
            f.write(f"Result: {result}\n")
            f.write(f"Time: {ts}\n")
            f.write("=" * 60 + "\n")
            f.write(page_text[:5000])
        # Keep directory manageable — delete oldest if >200 files
        files = sorted(_CONTENT_LOG_DIR.iterdir(), key=lambda p: p.stat().st_mtime)
        for old in files[:-200]:
            old.unlink(missing_ok=True)
    except Exception:
        pass

# ── HTML parsing ──────────────────────────────────────────────────────────────

_SKIP_TAGS = frozenset({"script", "style", "noscript", "svg", "path"})

_META_KEEP = frozenset({
    "description", "keywords",
    "og:title", "og:description", "og:site_name",
    "twitter:title", "twitter:description",
})

# ── CDN / infrastructure filters ─────────────────────────────────────────────

_CDN_SUFFIXES = (
    "1e100.net",
    "googleusercontent.com",
    "cloudfront.net",
    "amazonaws.com",
    "akamaiedge.net",
    "akamaitechnologies.com",
    "fastly.net",
    "cloudflare.com",
    "cloudflare.net",
    "edgecastcdn.net",
    "llnwd.net",
    "footprint.net",
    "compute-1.amazonaws.com",
    "bc.googleusercontent.com",
    "tailscale.com",
    "your-server.de",
    "clients.your-server.de",
    "azureedge.net",
    "azure.com",
    "microsoft.com",
    "msedge.net",
    "windows.net",
    "office.net",
    "office.com",
    "live.com",
    "digicert.com",
    "verisign.com",
    "letsencrypt.org",
    "sentry.io",
    "datadoghq.com",
    "newrelic.com",
    "nr-data.net",
    "segment.io",
    "segment.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "gstatic.com",
    "googleapis.com",
    "google.com",
    "gvt1.com",
    "gvt2.com",
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "mozilla.com",
    "mozilla.org",
    "mozilla.net",
    "firefox.com",
    "firefox.settings.services.mozilla.com",
    "yandex.ru",
    "yandex.net",
    "yandex.com",
    "yandex.md",
    "ya.ru",
    "yango.com",
    "yango.tech",
    "meteum.ai",
)

# Well-known infrastructure / service domains the LLM should never classify.
# These produce no meaningful page content and waste API tokens.
_SKIP_DOMAINS = frozenset({
    "push.services.mozilla.com",
    "detectportal.firefox.com",
    "contile.services.mozilla.com",
    "shavar.services.mozilla.com",
    "tracking-protection.cdn.mozilla.net",
    "aus5.mozilla.org",
    "balrog.services.mozilla.com",
    "safebrowsing.googleapis.com",
    "ocsp.pki.goog",
    "accounts.google.com",
    "clients1.google.com",
    "clients2.google.com",
    "update.googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "connectivitycheck.gstatic.com",
    "play.googleapis.com",
    "firebaseinstallations.googleapis.com",
    "fcm.googleapis.com",
    "android.clients.google.com",
    "dns.google",
    "ocsp.digicert.com",
    "ocsp.sectigo.com",
    "ocsp.usertrust.com",
    "crl.microsoft.com",
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "settings-win.data.microsoft.com",
    "self.events.data.microsoft.com",
    "vortex.data.microsoft.com",
    "config.edge.skype.com",
    "edge.microsoft.com",
    "api.github.com",
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "alive.github.com",
    "collector.github.com",
    "lastpass.com",
    "lastpass.eu",
    "bitwarden.com",
    "1password.com",
    "sentry.io",
    "cloudflareinsights.com",
    "plausible.io",
    "analytics.google.com",
    "challenges.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "r2.dev",
    "docker.io",
    "docker.com",
    "registry.npmjs.org",
    "pypi.org",
    "rubygems.org",
    "crates.io",
    "packagist.org",
    "api.snapcraft.io",
    "flathub.org",
    "archlinux.org",
    "aur.archlinux.org",
    "deb.debian.org",
    "ubuntu.com",
    "fedoraproject.org",
    "ntp.org",
    "pool.ntp.org",
    "time.google.com",
    "time.windows.com",
    "ipinfo.io",
    "ifconfig.me",
    "icanhazip.com",
    "wttr.in",
    "openai.com",
    "api.openai.com",
    "anthropic.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "api.x.ai",
    # URL shorteners & wikimedia
    "w.wiki",
    "t.co",
    "bit.ly",
    "goo.gl",
    "tinyurl.com",
    "is.gd",
    "wikimedia.org",
    "wikipedia.org",
    "wikidata.org",
    "mediawiki.org",
    # CDN / caching
    "ttcache.com",
    "akamai.net",
    "edgekey.net",
    "edgesuite.net",
    "steamcontent.com",
    "steamstatic.com",
})

_BOGUS_TLDS = frozenset({
    "invalid", "local", "localhost", "test", "example",
    "internal", "intranet", "corp", "home",
})

# ── Pre-scan settings ─────────────────────────────────────────────────────────

# How many hops deep to recursively pre-scan linked domains.
# 1 = scan domains linked from the current page
# 2 = also scan domains linked from those pages, etc.
PRESCAN_DEPTH = 2

# Maximum queue length — prevents runaway memory use on link-heavy pages.
PRESCAN_QUEUE_MAX = 500

# ── HTML text extractor ───────────────────────────────────────────────────────

class _HTMLTextExtractor(html.parser.HTMLParser):
    """Extract structured text (title, meta, body) from HTML for LLM classification."""

    def __init__(self) -> None:
        super().__init__()
        self._title_parts: list[str] = []
        self._meta_parts: list[str] = []
        self._body_parts: list[str] = []
        self._skip_depth = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        t = tag.lower()
        if t in _SKIP_TAGS:
            self._skip_depth += 1
            return
        if t == "title":
            self._in_title = True
            return
        if t == "meta":
            d = {k.lower(): (v or "") for k, v in attrs}
            key = d.get("name", d.get("property", "")).lower()
            if key in _META_KEEP:
                content = d.get("content", "").strip()
                if content:
                    self._meta_parts.append(content)

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        elif t == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        s = data.strip()
        if not s:
            return
        if self._in_title:
            self._title_parts.append(s)
        elif self._skip_depth == 0:
            self._body_parts.append(s)

    def result(self, max_chars: int = 1800) -> str:
        """Return structured text with labeled Title/Meta/Content sections."""
        sections: list[str] = []
        title = " ".join(self._title_parts).strip()
        if title:
            sections.append(f"Title: {title}")
        meta = " | ".join(self._meta_parts)
        if meta:
            sections.append(f"Meta: {meta}")
        body = " ".join(self._body_parts).strip()
        if body:
            sections.append(f"Content: {body}")
        return "\n".join(sections)[:max_chars]


def _extract_text(html_content: str, max_chars: int = 1800) -> str:
    """Extract structured text from HTML for LLM classification."""
    extractor = _HTMLTextExtractor()
    try:
        extractor.feed(html_content)
    except Exception:
        pass
    return extractor.result(max_chars)


# ── Link extractor ────────────────────────────────────────────────────────────

class _LinkExtractor(html.parser.HTMLParser):
    """
    Extracts unique hostnames from every <a href> tag in an HTML page.
    Handles absolute URLs only — relative paths can't meaningfully be
    pre-scanned without knowing the full URL of the source page.
    """

    def __init__(self) -> None:
        super().__init__()
        self.domains: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                try:
                    parsed = urlparse(value)
                    # Accept http://, https://, and protocol-relative //domain/
                    if parsed.scheme in ("http", "https"):
                        netloc = parsed.netloc
                    elif not parsed.scheme and parsed.netloc:
                        # protocol-relative: //other-site.com/path
                        netloc = parsed.netloc
                    else:
                        continue
                    host = netloc.split(":")[0].lower()
                    if host.startswith("www."):
                        host = host[4:]
                    if "." in host:
                        self.domains.add(host)
                except Exception:
                    pass


def _extract_linked_domains(html_content: str, source_domain: str) -> set[str]:
    """Return all external domains linked from html_content, excluding source_domain."""
    extractor = _LinkExtractor()
    try:
        extractor.feed(html_content)
    except Exception:
        pass
    # Remove exact match of source domain; keep subdomains (they need separate checks)
    return {d for d in extractor.domains if d != source_domain and not _is_cdn_hostname(d)}


# ── /proc/net/tcp parsing ─────────────────────────────────────────────────────

def _parse_proc_net(path: str) -> set[tuple[str, int]]:
    """Return (remote_ip, port) pairs for ESTABLISHED connections on port 80 or 443."""
    pairs: set[tuple[str, int]] = set()
    try:
        with open(path) as f:
            next(f)
            for line in f:
                cols = line.split()
                if len(cols) < 4:
                    continue
                if cols[3] != "01":
                    continue
                remote = cols[2]
                try:
                    hex_addr, hex_port = remote.rsplit(":", 1)
                except ValueError:
                    continue
                port = int(hex_port, 16)
                if port not in (80, 443):
                    continue
                if len(hex_addr) == 8:
                    raw = bytes.fromhex(hex_addr)[::-1]
                    pairs.add((socket.inet_ntoa(raw), port))
                elif len(hex_addr) == 32:
                    raw = b"".join(
                        bytes.fromhex(hex_addr[i : i + 8])[::-1]
                        for i in range(0, 32, 8)
                    )
                    pairs.add((socket.inet_ntop(socket.AF_INET6, raw), port))
    except (FileNotFoundError, PermissionError, ValueError):
        pass
    return pairs


# ── TLS cert domain extraction ────────────────────────────────────────────────

def _cert_domains(ip: str) -> tuple[list[str], list[str]]:
    """Return (usable_domains, all_raw_domains) from the TLS cert at *ip*:443.

    usable_domains: non-CDN domains suitable for classification.
    all_raw_domains: every SAN/CN entry (for logging when usable is empty).
    """
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    usable: list[str] = []
    raw_all: list[str] = []
    try:
        with socket.create_connection((ip, 443), timeout=2) as raw:
            with ctx.wrap_socket(raw) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return [], []
                cert = _x509.load_der_x509_certificate(der)
                try:
                    san_ext = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
                    for name in san_ext.value.get_values_for_type(_x509.DNSName):
                        d = name.lower().lstrip("*.")
                        if "." in d:
                            raw_all.append(d)
                            if not _is_cdn_hostname(d):
                                usable.append(d)
                except _x509.ExtensionNotFound:
                    pass
                if not usable:
                    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                        d = attr.value.lower().lstrip("*.")
                        if "." in d:
                            raw_all.append(d)
                            if not _is_cdn_hostname(d):
                                usable.append(d)
    except Exception:
        pass
    return usable, raw_all


def _is_cdn_hostname(hostname: str) -> bool:
    if hostname in _SKIP_DOMAINS:
        return True
    if any(hostname.endswith(f".{s}") or hostname == s for s in _CDN_SUFFIXES):
        return True
    tld = hostname.rsplit(".", 1)[-1]
    return tld in _BOGUS_TLDS


# ── HTTP fetch ────────────────────────────────────────────────────────────────

_HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


async def _fetch_html(domain: str) -> Optional[str]:
    """
    Fetch the homepage for *domain*, returning raw HTML or None.
    Tries HTTPS first then HTTP.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            async with httpx.AsyncClient(
                timeout=5.0,
                follow_redirects=True,
                verify=False,
                max_redirects=3,
            ) as client:
                resp = await client.get(url, headers=_HTTP_HEADERS)
                if resp.status_code < 400:
                    return resp.text
        except Exception:
            continue
    return None


# ── Scanner thread ────────────────────────────────────────────────────────────

class DomainScanner(threading.Thread):
    """
    Daemon thread that:
      • Continuously scans /proc/net/tcp{,6} for new HTTP/HTTPS connections
      • Resolves each IP → domain (TLS cert SANs or reverse DNS)
      • Temporarily blocks the IP while the LLM classifies the page
      • Auto-blocks adult domains; unblocks safe ones
      • Extracts all outbound links and pre-classifies them in the background
        so the user experiences zero delay when following links
    """

    def __init__(
        self,
        db,
        agent,
        provider_name: str,
        confidence_threshold: float,
        on_adult: Callable[[str, str, Optional[str]], None],
        scan_interval: float = 1.5,
        prescan_limit: int = 0,   # 0 = unlimited; >0 caps domains queued per page
        image_scanner_enabled: bool = False,
        image_confidence_threshold: float = 0.75,
        image_max_per_page: int = 5,
    ) -> None:
        super().__init__(daemon=True, name="llm-domain-scanner")
        self.db = db
        self.agent = agent
        self.provider_name = provider_name
        self.confidence_threshold = confidence_threshold
        self.on_adult = on_adult
        self.scan_interval = scan_interval
        self.prescan_limit = prescan_limit
        self._stop_event = threading.Event()
        self._seen_pairs: set[tuple[str, int]] = set()
        self._links_extracted: set[str] = set()
        self._links_expiry: float = 0.0
        self._safe_cache: dict[str, float] = {}
        self._in_flight: set[str] = set()
        self._llm_sem: Optional[asyncio.Semaphore] = None
        self._prescan_queue: Optional[asyncio.Queue] = None

        # Image scanner
        self._nsfw_classifier = None
        self._image_threshold = image_confidence_threshold
        self._image_max = image_max_per_page
        if image_scanner_enabled:
            try:
                from blocky.llm.image_scanner import NSFWClassifier
                self._nsfw_classifier = NSFWClassifier()
                logger.info("NSFW image scanner enabled (threshold=%.2f)", image_confidence_threshold)
            except Exception as e:
                logger.warning("Could not initialize NSFW image scanner: %s", e)

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        logger.info(
            "LLM domain scanner started (provider=%s, threshold=%.2f, prescan_depth=%d)",
            self.provider_name, self.confidence_threshold, PRESCAN_DEPTH,
        )
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._llm_sem = asyncio.Semaphore(8)
        self._prescan_queue = asyncio.Queue(maxsize=PRESCAN_QUEUE_MAX)
        try:
            loop.run_until_complete(self._scan_loop())
        finally:
            loop.close()
        logger.info("LLM domain scanner stopped")

    # ── Main scan loop ────────────────────────────────────────────────────────

    # Links-extracted TTL: prevents re-fetching HTML when a domain has many IPs.
    _LINKS_TTL = 120.0
    # Safe-domain re-check interval: how long before re-classifying a "safe" domain.
    _SAFE_TTL = 300.0
    # How often to clear _seen_pairs so closed+reopened connections are re-checked
    _SEEN_TTL = 30.0

    # Number of parallel prescan workers draining the link queue
    _PRESCAN_WORKERS = 4

    async def _scan_loop(self) -> None:
        import time
        # Start multiple pre-scan background workers for concurrent link classification
        prescan_tasks = [
            asyncio.ensure_future(self._prescan_worker())
            for _ in range(self._PRESCAN_WORKERS)
        ]
        seen_expiry = time.monotonic() + self._SEEN_TTL
        try:
            while not self._stop_event.is_set():
                try:
                    now = time.monotonic()
                    # Expire links cache
                    if now >= self._links_expiry:
                        self._links_extracted.clear()
                        self._links_expiry = now + self._LINKS_TTL
                    # Evict expired safe-cache entries
                    expired = [d for d, exp in self._safe_cache.items() if now >= exp]
                    for d in expired:
                        del self._safe_cache[d]
                    # Periodically clear seen pairs so re-visits are caught
                    if now >= seen_expiry:
                        self._seen_pairs.clear()
                        seen_expiry = now + self._SEEN_TTL

                    pairs: set[tuple[str, int]] = set()
                    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
                        pairs |= _parse_proc_net(path)

                    new_pairs = pairs - self._seen_pairs
                    self._seen_pairs |= new_pairs

                    if new_pairs:
                        await asyncio.gather(
                            *[self._process_pair(ip, port) for ip, port in new_pairs],
                            return_exceptions=True,
                        )
                except Exception as e:
                    logger.error("Scanner loop error: %s", e)

                await asyncio.sleep(self.scan_interval)
        finally:
            for t in prescan_tasks:
                t.cancel()

    # ── Per-connection handler (real-time, with temp block) ───────────────────

    async def _process_pair(self, ip: str, port: int) -> None:
        loop = asyncio.get_event_loop()

        # 1. Resolve domain ───────────────────────────────────────────────────
        domain: Optional[str] = None

        if port == 443:
            usable, raw_all = await loop.run_in_executor(None, _cert_domains, ip)
            if usable:
                domain = min(usable, key=len)
                logger.debug("SSL cert domain for %s: %s", ip, domain)
            elif raw_all:
                _log_scan(
                    raw_all[0], "skipped", "cdn-cert",
                    reason=f"ip={ip} cert SANs all CDN: {', '.join(raw_all[:5])}",
                )
                logger.debug("All cert SANs are CDN for %s: %s", ip, raw_all[:5])

        if domain is None:
            try:
                hostname = await loop.run_in_executor(
                    None, lambda: socket.gethostbyaddr(ip)[0]
                )
                hostname = hostname.lower()
                if hostname.startswith("www."):
                    hostname = hostname[4:]
                if "." in hostname and not _is_cdn_hostname(hostname):
                    domain = hostname
                else:
                    _log_scan(
                        hostname, "skipped", "cdn-rdns",
                        reason=f"ip={ip} reverse DNS is CDN: {hostname}",
                    )
                    return
            except (socket.herror, socket.gaierror, OSError):
                _log_scan(
                    ip, "skipped", "no-rdns",
                    reason=f"ip={ip} no reverse DNS and no cert domain",
                )
                return

        if not domain or "." not in domain:
            return

        # 2. Decide what work is needed ──────────────────────────────────────
        need_classify = self._needs_classification(domain)
        need_links    = domain not in self._links_extracted

        if not need_classify and not need_links:
            return

        if need_links:
            self._links_extracted.add(domain)
        if need_classify:
            self._in_flight.add(domain)

        logger.info(
            "LLM scanner: %s (ip=%s port=%d) classify=%s links=%s",
            domain, ip, port, need_classify, need_links,
        )

        html: Optional[str] = None
        temp_blocked = False
        is_adult = False
        confidence = 0.0
        reason = ""
        has_real_content = False

        try:
            from blocky.llm.keyword_filter import check_domain, check_content

            # 3. Keyword pre-filter on domain name (instant, no network) ───
            if need_classify and check_domain(domain):
                is_adult = True
                confidence = 0.95
                reason = f"Adult keyword in domain name: {domain}"
                _log_scan(domain, "blocked", "keyword-domain", confidence, reason, "live")
                logger.info("Keyword filter blocked domain: %s", domain)

            # 4. Immediately temp-block + kill connections while verifying ──
            if need_classify and not is_adult:
                try:
                    await loop.run_in_executor(
                        None, lambda: run_helper("iptables_temp_block", ip=ip)
                    )
                    temp_blocked = True
                    # Kill existing TCP connections so browser stops loading
                    try:
                        await loop.run_in_executor(
                            None, lambda: run_helper("kill_connections", ip=ip)
                        )
                    except Exception:
                        pass
                except Exception:
                    pass

            # 5. Fetch HTML ────────────────────────────────────────────────
            html = await _fetch_html(domain)
            page_text = _extract_text(html) if html else ""
            has_real_content = bool(page_text.strip())

            # 6. Run all checks concurrently ───────────────────────────────
            if need_classify and not is_adult and has_real_content:
                # Parse page text sections once
                title, meta, body = "", "", page_text
                for line in page_text.split("\n"):
                    if line.startswith("Title: "):
                        title = line[7:]
                    elif line.startswith("Meta: "):
                        meta = line[6:]
                    elif line.startswith("Content: "):
                        body = line[9:]

                async def _check_keywords() -> tuple[bool, float, str]:
                    kw_adult, kw_reason = check_content(title, meta, body)
                    if kw_adult:
                        _log_scan(domain, "blocked", "keyword-content", 0.92, kw_reason, "live", page_text)
                        return True, 0.92, kw_reason
                    return False, 0.0, ""

                async def _check_llm() -> tuple[bool, float, str]:
                    if not self.agent:
                        return False, 0.0, ""
                    text = f"Domain: {domain}\n{page_text}"[:2000]
                    try:
                        async with self._llm_sem:
                            result = await self.agent.run(text)
                        cls = result.output
                        if cls.is_adult and cls.confidence >= self.confidence_threshold:
                            _log_scan(domain, "blocked", "llm", cls.confidence, cls.reason, "live", page_text)
                            return True, cls.confidence, cls.reason
                        _log_scan(domain, "safe", "llm", cls.confidence, cls.reason, "live", page_text)
                    except Exception as e:
                        _log_scan(domain, "error", "llm", 0, str(e), "live")
                        logger.warning("LLM classification error for %s: %s", domain, e)
                    return False, 0.0, ""

                async def _check_image() -> tuple[bool, float, str]:
                    if not self._nsfw_classifier or not html:
                        return False, 0.0, ""
                    try:
                        from blocky.llm.image_scanner import classify_page_images
                        img_nsfw, img_score, img_reason = await classify_page_images(
                            domain, html, self._nsfw_classifier,
                            threshold=self._image_threshold,
                            max_images=self._image_max,
                        )
                        if img_nsfw:
                            _log_scan(domain, "blocked", "image", img_score, img_reason, "live")
                            return True, img_score, img_reason
                        _log_scan(domain, "safe", "image", img_score, "below threshold", "live")
                    except Exception as e:
                        _log_scan(domain, "error", "image", 0, str(e), "live")
                    return False, 0.0, ""

                # Fire all checks at once
                results = await asyncio.gather(
                    _check_keywords(), _check_llm(), _check_image(),
                    return_exceptions=True,
                )
                # Any positive result → block
                for r in results:
                    if isinstance(r, tuple) and r[0]:
                        is_adult, confidence, reason = r
                        break

            # Handle domain-only LLM check (no page content)
            elif need_classify and not is_adult and not has_real_content and self.agent:
                text = (
                    f"Domain: {domain}\n"
                    "No page content could be retrieved. Classify based on the domain name alone.\n"
                    "If the domain name clearly indicates adult content, classify accordingly."
                )
                try:
                    async with self._llm_sem:
                        result = await self.agent.run(text)
                    cls = result.output
                    if cls.is_adult and cls.confidence >= self.confidence_threshold:
                        is_adult = True
                        confidence = cls.confidence
                        reason = cls.reason
                        _log_scan(domain, "blocked", "llm", confidence, reason, "live")
                    else:
                        _log_scan(domain, "safe", "llm", cls.confidence, cls.reason, "live")
                except Exception as e:
                    _log_scan(domain, "error", "llm", 0, str(e), "live")

        except Exception as e:
            _log_scan(domain, "error", "scanner", 0, str(e), "live")
            logger.warning("Scanner error for %s: %s", domain, e)
            self._in_flight.discard(domain)
            if temp_blocked:
                try:
                    await loop.run_in_executor(
                        None, lambda: run_helper("iptables_temp_unblock", ip=ip)
                    )
                except Exception:
                    pass
            return

        # 7. Record result and act ─────────────────────────────────────────
        if need_classify:
            import time
            self._in_flight.discard(domain)
            if is_adult:
                self.db.set_llm_cache(domain, True, confidence, self.provider_name)
                logger.info(
                    "Blocked adult domain: %s (confidence=%.2f, reason=%s)",
                    domain, confidence, reason,
                )
                self.on_adult(domain, reason, ip)
            elif has_real_content:
                self.db.set_llm_cache(domain, False, confidence, self.provider_name)
                self._safe_cache[domain] = time.monotonic() + self._SAFE_TTL
                _log_scan(domain, "safe", "all-checks", confidence, "passed all filters", "live", page_text)
                if temp_blocked:
                    await self._temp_unblock(ip, loop)
            else:
                _log_scan(domain, "skipped", "no-content", 0, "no real page content", "live")
                logger.info("LLM scanner: %s — no real content, will retry on next visit", domain)
                self._links_extracted.discard(domain)
                if temp_blocked:
                    await self._temp_unblock(ip, loop)

        # 8. Extract links — always when we have HTML ─────────────────────
        if html and need_links:
            self._enqueue_links(html, domain, depth=PRESCAN_DEPTH)

    # ── Pre-scan worker (background, no temp block) ───────────────────────────

    async def _prescan_worker(self) -> None:
        """
        Drains _prescan_queue, classifying each domain without blocking the user.
        Shares the LLM semaphore with _process_pair so rate limits are respected.
        """
        while not self._stop_event.is_set():
            try:
                domain, depth = await asyncio.wait_for(
                    self._prescan_queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                return

            try:
                await self._prescan_domain(domain, depth)
            except Exception as e:
                logger.debug("Pre-scan error for %s: %s", domain, e)

    async def _prescan_domain(self, domain: str, depth: int) -> None:
        """Classify *domain* proactively. No temp-block — user hasn't visited yet."""
        if not self._needs_classification(domain):
            return
        self._in_flight.add(domain)

        from blocky.llm.keyword_filter import check_domain, check_content

        is_adult = False
        confidence = 0.0
        reason = ""
        has_real_content = False
        html: Optional[str] = None

        try:
            # Keyword check on domain name (instant)
            if check_domain(domain):
                is_adult = True
                confidence = 0.95
                reason = f"Adult keyword in domain: {domain}"
                _log_scan(domain, "blocked", "keyword-domain", confidence, reason, "prescan")

            html = await _fetch_html(domain)
            page_text = _extract_text(html) if html else ""
            has_real_content = bool(page_text.strip())

            # Run all checks concurrently
            if not is_adult and has_real_content:
                title, meta, body = "", "", page_text
                for line in page_text.split("\n"):
                    if line.startswith("Title: "):
                        title = line[7:]
                    elif line.startswith("Meta: "):
                        meta = line[6:]
                    elif line.startswith("Content: "):
                        body = line[9:]

                async def _kw() -> tuple[bool, float, str]:
                    kw_adult, kw_reason = check_content(title, meta, body)
                    if kw_adult:
                        _log_scan(domain, "blocked", "keyword-content", 0.92, kw_reason, "prescan", page_text)
                        return True, 0.92, kw_reason
                    return False, 0.0, ""

                async def _llm() -> tuple[bool, float, str]:
                    if not self.agent:
                        return False, 0.0, ""
                    text = f"Domain: {domain}\n{page_text}"[:2000]
                    try:
                        async with self._llm_sem:
                            result = await self.agent.run(text)
                        cls = result.output
                        if cls.is_adult and cls.confidence >= self.confidence_threshold:
                            _log_scan(domain, "blocked", "llm", cls.confidence, cls.reason, "prescan", page_text)
                            return True, cls.confidence, cls.reason
                        _log_scan(domain, "safe", "llm", cls.confidence, cls.reason, "prescan", page_text)
                    except Exception as e:
                        _log_scan(domain, "error", "llm", 0, str(e), "prescan")
                    return False, 0.0, ""

                async def _img() -> tuple[bool, float, str]:
                    if not self._nsfw_classifier or not html:
                        return False, 0.0, ""
                    try:
                        from blocky.llm.image_scanner import classify_page_images
                        img_nsfw, img_score, img_reason = await classify_page_images(
                            domain, html, self._nsfw_classifier,
                            threshold=self._image_threshold,
                            max_images=self._image_max,
                        )
                        if img_nsfw:
                            _log_scan(domain, "blocked", "image", img_score, img_reason, "prescan")
                            return True, img_score, img_reason
                        _log_scan(domain, "safe", "image", img_score, "below threshold", "prescan")
                    except Exception as e:
                        _log_scan(domain, "error", "image", 0, str(e), "prescan")
                    return False, 0.0, ""

                results = await asyncio.gather(_kw(), _llm(), _img(), return_exceptions=True)
                for r in results:
                    if isinstance(r, tuple) and r[0]:
                        is_adult, confidence, reason = r
                        break

            elif not is_adult and not has_real_content and self.agent:
                text = (
                    f"Domain: {domain}\n"
                    "No page content could be retrieved. Classify based on the domain name alone.\n"
                    "If the domain name clearly indicates adult content, classify accordingly."
                )
                try:
                    async with self._llm_sem:
                        result = await self.agent.run(text)
                    cls = result.output
                    if cls.is_adult and cls.confidence >= self.confidence_threshold:
                        is_adult, confidence, reason = True, cls.confidence, cls.reason
                        _log_scan(domain, "blocked", "llm", confidence, reason, "prescan")
                    else:
                        _log_scan(domain, "safe", "llm", cls.confidence, cls.reason, "prescan")
                except Exception as e:
                    _log_scan(domain, "error", "llm", 0, str(e), "prescan")

        except Exception as e:
            logger.debug("Pre-scan error for %s: %s", domain, e)
            self._in_flight.discard(domain)
            return

        import time
        self._in_flight.discard(domain)
        if is_adult:
            self.db.set_llm_cache(domain, True, confidence, self.provider_name)
            logger.info("Pre-scan blocked: %s (confidence=%.2f, reason=%s)", domain, confidence, reason)
            self.on_adult(domain, reason, None)
        elif has_real_content:
            self.db.set_llm_cache(domain, False, confidence, self.provider_name)
            self._safe_cache[domain] = time.monotonic() + self._SAFE_TTL
            _log_scan(domain, "safe", "all-checks", confidence, "passed all filters", "prescan", page_text)
            logger.info("Pre-scan: %s → safe (confidence=%.2f)", domain, confidence)
        else:
            _log_scan(domain, "skipped", "no-content", 0, "no real page content", "prescan")
            logger.debug("Pre-scan: %s — no real content, skipping cache", domain)

        if depth > 0 and html:
            self._enqueue_links(html, domain, depth=depth - 1)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _needs_classification(self, domain: str, log: bool = True) -> bool:
        """Return True if the domain still needs an LLM classification."""
        if domain in self._in_flight:
            return False

        # Infrastructure / CDN / known-safe → never classify
        if _is_cdn_hostname(domain):
            if log:
                _log_scan(domain, "skipped", "cdn", 0, "infrastructure/CDN domain")
            return False

        # Recently classified as safe (in-memory) → skip until TTL expires
        if domain in self._safe_cache:
            if log:
                _log_scan(domain, "skipped", "cached-safe", 0, "recently classified safe (memory)")
            return False

        # Already in DB cache (adult or safe) → skip
        cached = self.db.get_llm_cache(domain)
        if cached:
            if log:
                is_adult = cached.get("is_adult", False) if isinstance(cached, dict) else bool(cached)
                _log_scan(domain, "skipped", "cached-db", 0, f"in DB cache (adult={is_adult})")
            return False

        # Already blocked by a user rule
        from blocky.models.block_rule import BlockType
        blocked = {
            r.domain
            for r in self.db.get_all_rules()
            if r.block_type == BlockType.WEBSITE and r.domain
        }
        if domain in blocked:
            self.db.set_llm_cache(domain, True, 1.0, "already-blocked")
            if log:
                _log_scan(domain, "skipped", "already-blocked", 1.0, "user rule already blocks this")
            return False

        # In ANY category domain list (active or not) — skip to avoid wasting tokens
        from blocky.data.categories import CATEGORIES
        for cat_data in CATEGORIES.values():
            if domain in cat_data.get("domains", []):
                if log:
                    _log_scan(domain, "skipped", "category", 0, "in category domain list")
                return False

        return True

    def _enqueue_links(self, html: str, source_domain: str, depth: int) -> None:
        """
        Extract all outbound domains from *html* and add novel ones to the
        pre-scan queue at the given *depth*.
        """
        if self._prescan_queue is None or depth < 0:
            return

        linked = _extract_linked_domains(html, source_domain)
        logger.info(
            "LLM link scan: found %d external domains linked from %s",
            len(linked), source_domain,
        )
        queued = 0
        cap = self.prescan_limit if self.prescan_limit > 0 else len(linked)
        for d in linked:
            if queued >= cap:
                break
            if not self._needs_classification(d):
                continue
            try:
                self._prescan_queue.put_nowait((d, depth))
                queued += 1
            except asyncio.QueueFull:
                logger.warning("LLM pre-scan queue full — dropping remaining links from %s", source_domain)
                break

        if linked:
            logger.info(
                "LLM pre-scan: queued %d/%d linked domains from %s (depth=%d)",
                queued, len(linked), source_domain, depth,
            )

    async def _temp_unblock(self, ip: str, loop: asyncio.AbstractEventLoop) -> None:
        try:
            await loop.run_in_executor(
                None, lambda: run_helper("iptables_temp_unblock", ip=ip)
            )
            logger.debug("LLM scanner: temp-unblocked %s", ip)
        except Exception:
            pass
