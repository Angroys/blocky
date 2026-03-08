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
import logging
import socket
import ssl
import threading
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

from blocky.engine.helper_client import HelperError, run_helper

logger = logging.getLogger(__name__)

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
)

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
    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
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
                    self._parts.append(content)

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        elif t == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title or self._skip_depth == 0:
            s = data.strip()
            if s:
                self._parts.append(s)

    def result(self) -> str:
        return " ".join(self._parts)


def _extract_text(html_content: str, max_chars: int = 1000) -> str:
    extractor = _HTMLTextExtractor()
    try:
        extractor.feed(html_content)
    except Exception:
        pass
    return extractor.result()[:max_chars]


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

def _cert_domains(ip: str) -> list[str]:
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    domains: list[str] = []
    try:
        with socket.create_connection((ip, 443), timeout=2) as raw:
            with ctx.wrap_socket(raw) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return []
                cert = _x509.load_der_x509_certificate(der)
                try:
                    san_ext = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
                    for name in san_ext.value.get_values_for_type(_x509.DNSName):
                        d = name.lower().lstrip("*.")
                        if "." in d and not _is_cdn_hostname(d):
                            domains.append(d)
                except _x509.ExtensionNotFound:
                    pass
                if not domains:
                    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                        d = attr.value.lower().lstrip("*.")
                        if "." in d and not _is_cdn_hostname(d):
                            domains.append(d)
    except Exception:
        pass
    return domains


def _is_cdn_hostname(hostname: str) -> bool:
    if any(hostname.endswith(s) for s in _CDN_SUFFIXES):
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
        scan_interval: float = 3.0,
        prescan_limit: int = 0,   # 0 = unlimited; >0 caps domains queued per page
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
        self._seen_pairs: set[tuple[str, int]] = set()   # cleared every scan cycle
        self._links_extracted: set[str] = set()           # cleared every _LINKS_TTL
        self._links_expiry: float = 0.0
        self._safe_cache: dict[str, float] = {}           # domain → expiry (monotonic)
        self._in_flight: set[str] = set()
        self._llm_sem: Optional[asyncio.Semaphore] = None
        self._prescan_queue: Optional[asyncio.Queue] = None

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        logger.info(
            "LLM domain scanner started (provider=%s, threshold=%.2f, prescan_depth=%d)",
            self.provider_name, self.confidence_threshold, PRESCAN_DEPTH,
        )
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._llm_sem = asyncio.Semaphore(1)
        self._prescan_queue = asyncio.Queue(maxsize=PRESCAN_QUEUE_MAX)
        try:
            loop.run_until_complete(self._scan_loop())
        finally:
            loop.close()
        logger.info("LLM domain scanner stopped")

    # ── Main scan loop ────────────────────────────────────────────────────────

    # Seconds before _seen_pairs is cleared so navigating to a new page
    # Links-extracted TTL: prevents re-fetching HTML when a domain has many IPs.
    _LINKS_TTL = 120.0
    # Safe-domain re-check interval: how long before re-classifying a "safe" domain.
    _SAFE_TTL = 60.0

    async def _scan_loop(self) -> None:
        import time
        # Start pre-scan background worker
        prescan_task = asyncio.ensure_future(self._prescan_worker())
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

                    # Clear _seen_pairs every cycle so every new TCP connection
                    # (new page open) is always processed afresh.
                    self._seen_pairs.clear()

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
            prescan_task.cancel()

    # ── Per-connection handler (real-time, with temp block) ───────────────────

    async def _process_pair(self, ip: str, port: int) -> None:
        loop = asyncio.get_event_loop()

        # 1. Resolve domain ───────────────────────────────────────────────────
        domain: Optional[str] = None

        if port == 443:
            cert_domains = await loop.run_in_executor(None, _cert_domains, ip)
            if cert_domains:
                domain = min(cert_domains, key=len)
                logger.debug("SSL cert domain for %s: %s", ip, domain)

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
                    logger.debug("Skipping CDN/unresolvable host for %s: %s", ip, hostname)
                    return
            except (socket.herror, socket.gaierror, OSError):
                return

        if not domain or "." not in domain:
            return

        # 2. Decide what work is needed ──────────────────────────────────────
        need_classify = self._needs_classification(domain)
        need_links    = domain not in self._links_extracted

        # Nothing to do at all
        if not need_classify and not need_links:
            return

        # Claim the domain immediately so concurrent IPs for the same domain
        # don't duplicate HTML fetches while this coroutine is awaiting.
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
        cls = None
        try:
            # 3. Fetch HTML FIRST — before the temp block so our own httpx
            #    connection isn't caught by the DROP rule ─────────────────────
            html = await _fetch_html(domain)

            if need_classify:
                text = _extract_text(html) if html else None
                has_real_content = bool(text)
                if not text:
                    logger.info("LLM scanner: no page text for %s, classifying domain name only", domain)
                    text = f"Domain: {domain}"
                text = text[:1000]

                # 4. Temp DROP the browser NOW (while LLM call is in-flight) ──
                try:
                    await loop.run_in_executor(
                        None, lambda: run_helper("iptables_temp_block", ip=ip)
                    )
                    temp_blocked = True
                except Exception:
                    pass

                # 5. Classify ─────────────────────────────────────────────────
                async with self._llm_sem:
                    result = await self.agent.run(text)
                cls = result.output

        except Exception as e:
            logger.warning("LLM classification error for %s: %s", domain, e)
            self._in_flight.discard(domain)
            if temp_blocked:
                try:
                    await loop.run_in_executor(
                        None, lambda: run_helper("iptables_temp_unblock", ip=ip)
                    )
                except Exception:
                    pass
            return

        if need_classify and cls is not None:
            import time
            self._in_flight.discard(domain)
            is_adult = cls.is_adult and cls.confidence >= self.confidence_threshold
            if is_adult:
                # Permanent DB record — domain stays blocked across restarts
                self.db.set_llm_cache(domain, True, cls.confidence, self.provider_name)
            elif has_real_content:
                # Safe with real content: short in-memory TTL, re-check after _SAFE_TTL
                self._safe_cache[domain] = time.monotonic() + self._SAFE_TTL
            else:
                # No real content (CloudFlare/403): don't cache at all — retry next visit
                logger.info("LLM scanner: %s — no real content, will retry on next visit", domain)
                self._links_extracted.discard(domain)

        # 6. Extract links — always when we have HTML ─────────────────────────
        if html and need_links:
            self._enqueue_links(html, domain, depth=PRESCAN_DEPTH)

        if need_classify and cls is not None:
            is_adult = cls.is_adult and cls.confidence >= self.confidence_threshold
            if is_adult:
                logger.info(
                    "LLM detected adult domain: %s (confidence=%.2f, reason=%s)",
                    domain, cls.confidence, cls.reason,
                )
                # Permanent block supersedes the temp DROP — no need to unblock
                self.on_adult(domain, cls.reason, ip)
            else:
                logger.debug("LLM classified %s as safe (confidence=%.2f)", domain, cls.confidence)
                if temp_blocked:
                    await self._temp_unblock(ip, loop)

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

        logger.debug("LLM pre-scan: classifying %s (depth=%d remaining)", domain, depth)

        html: Optional[str] = None
        try:
            html = await _fetch_html(domain)
            text = _extract_text(html) if html else None
            has_real_content = bool(text)
            if not text:
                text = f"Domain: {domain}"
            text = text[:1000]

            async with self._llm_sem:
                result = await self.agent.run(text)
            cls = result.output

        except Exception as e:
            logger.debug("LLM pre-scan classification error for %s: %s", domain, e)
            self._in_flight.discard(domain)
            return

        import time
        self._in_flight.discard(domain)
        is_adult = cls.is_adult and cls.confidence >= self.confidence_threshold
        if is_adult:
            self.db.set_llm_cache(domain, True, cls.confidence, self.provider_name)
        elif has_real_content:
            self._safe_cache[domain] = time.monotonic() + self._SAFE_TTL
        else:
            logger.debug("LLM pre-scan: %s — no real content, skipping cache", domain)

        # Always enqueue links regardless of classification — adult sites link
        # to sister sites that also need blocking; safe sites link to sites the
        # user might visit next.
        if depth > 0 and html:
            self._enqueue_links(html, domain, depth=depth - 1)

        if is_adult:
            logger.info(
                "LLM pre-scan blocked: %s (confidence=%.2f) — proactively blocking before user visits",
                domain, cls.confidence,
            )
            self.on_adult(domain, cls.reason, None)
        else:
            logger.info("LLM pre-scan: %s → safe (confidence=%.2f)", domain, cls.confidence)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _needs_classification(self, domain: str) -> bool:
        """Return True if the domain still needs an LLM classification."""
        import time

        if domain in self._in_flight:
            return False

        # Adult/blocked result in DB → permanently skip (already blocked)
        cached = self.db.get_llm_cache(domain)
        if cached and cached.get("is_adult"):
            return False

        # Recently classified as safe → skip until TTL expires
        if domain in self._safe_cache:
            return False

        from blocky.models.block_rule import BlockType
        blocked = {
            r.domain
            for r in self.db.get_all_rules()
            if r.block_type == BlockType.WEBSITE and r.domain
        }
        if domain in blocked:
            self.db.set_llm_cache(domain, True, 1.0, "already-blocked")
            return False

        from blocky.data.categories import CATEGORIES
        for cat in (self.db.get_active_categories() or []):
            cat_data = CATEGORIES.get(cat["category_id"], {})
            if domain in cat_data.get("domains", []):
                self.db.set_llm_cache(domain, True, 1.0, "in-category-list")
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
