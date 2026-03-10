"""
Local NSFW image detection using ONNX runtime.

Uses GantMan's nsfw_model (MobileNet v2, ~10MB ONNX) to classify images
into: drawings, hentai, neutral, porn, sexy.

The model is downloaded on first use to ~/.local/share/blocky/models/.
No API key required — runs entirely locally on CPU.

Detection strategy (in order):
  1. Headless Chrome screenshot — captures the actual rendered page
  2. Image download fallback — downloads images from HTML src/srcset/og:image
"""

import asyncio
import html.parser
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# ── Model config ─────────────────────────────────────────────────────────────

MODEL_DIR = Path.home() / ".local" / "share" / "blocky" / "models"
MODEL_FILE = "nsfw_mobilenet_v2.onnx"
MODEL_PATH = MODEL_DIR / MODEL_FILE

# GantMan/nsfw_model — MobileNet v2, 5 classes, ~10MB
MODEL_URL = (
    "https://raw.githubusercontent.com/nicenemo/noisy-nsfw-model/"
    "main/mobilenet_v2_140_224/saved_model.onnx"
)

# The 5 output classes in order
CLASS_NAMES = ["drawings", "hentai", "neutral", "porn", "sexy"]

# ── Headless browser detection ───────────────────────────────────────────────

_CHROME_CANDIDATES = [
    "google-chrome-stable",
    "google-chrome",
    "chromium-browser",
    "chromium",
    "brave-browser",
]

_chrome_path: Optional[str] = None


def _find_chrome() -> Optional[str]:
    """Find a Chromium-based browser for headless screenshots."""
    global _chrome_path
    if _chrome_path is not None:
        return _chrome_path if _chrome_path else None
    for name in _CHROME_CANDIDATES:
        p = shutil.which(name)
        if p:
            _chrome_path = p
            logger.info("Headless browser for screenshots: %s", p)
            return p
    _chrome_path = ""  # cache the negative result
    logger.warning("No Chromium-based browser found for screenshots")
    return None


async def _take_screenshot(domain: str) -> Optional[bytes]:
    """Take a headless Chrome screenshot of a domain. Returns PNG bytes or None."""
    chrome = _find_chrome()
    if not chrome:
        return None

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp_path = tmp.name

    url = f"https://{domain}"
    cmd = [
        chrome,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--disable-extensions",
        "--disable-dev-shm-usage",
        "--window-size=1280,900",
        f"--screenshot={tmp_path}",
        "--hide-scrollbars",
        "--virtual-time-budget=5000",  # wait up to 5s for JS rendering
        url,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=15.0)

        path = Path(tmp_path)
        if path.exists() and path.stat().st_size > 1000:
            data = path.read_bytes()
            path.unlink(missing_ok=True)
            logger.debug("Screenshot taken for %s (%d bytes)", domain, len(data))
            return data
        path.unlink(missing_ok=True)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        Path(tmp_path).unlink(missing_ok=True)
        logger.debug("Screenshot timeout for %s", domain)
    except Exception as e:
        Path(tmp_path).unlink(missing_ok=True)
        logger.debug("Screenshot error for %s: %s", domain, e)
    return None


# ── Image URL extractor (fallback) ───────────────────────────────────────────

_SKIP_IMG_PATTERNS = frozenset({
    "logo", "icon", "favicon", "sprite", "avatar", "pixel",
    "tracking", "beacon", "1x1", "spacer", "blank", "badge",
    "button", "arrow", "spinner", "loading",
})


class _ImageExtractor(html.parser.HTMLParser):
    """Extract image URLs from HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.urls: list[str] = []
        self._base = base_url
        self._seen: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list) -> None:
        d = dict(attrs)
        t = tag.lower()

        if t == "img" and d.get("src"):
            self._add(d["src"])
        elif t == "source" and d.get("srcset"):
            for part in d["srcset"].split(","):
                url = part.strip().split()[0]
                if url:
                    self._add(url)
        elif t == "meta":
            prop = (d.get("property") or "").lower()
            if prop in ("og:image", "twitter:image") and d.get("content"):
                self._add(d["content"])
        elif t == "video" and d.get("poster"):
            self._add(d["poster"])

    def _add(self, url: str) -> None:
        if not url or url.startswith("data:"):
            return
        if url.endswith(".svg") or url.endswith(".gif"):
            return

        # Resolve relative URLs
        if url.startswith("//"):
            url = "https:" + url
        elif not url.startswith("http"):
            url = urljoin(self._base, url)

        # Skip known UI/tracking assets
        url_lower = url.lower()
        if any(p in url_lower for p in _SKIP_IMG_PATTERNS):
            return

        if url not in self._seen:
            self._seen.add(url)
            self.urls.append(url)


def extract_image_urls(html_content: str, domain: str, max_images: int = 5) -> list[str]:
    """Extract the most representative image URLs from HTML."""
    base_url = f"https://{domain}"
    extractor = _ImageExtractor(base_url)
    try:
        extractor.feed(html_content)
    except Exception:
        pass

    urls = extractor.urls

    def _score(u: str) -> int:
        ul = u.lower()
        score = 0
        if "og:image" in ul or "og_image" in ul:
            score += 10
        for hint in ("large", "full", "original", "1200", "1080", "800", "600"):
            if hint in ul:
                score += 5
                break
        for hint in ("thumb", "small", "tiny", "mini", "100x", "50x", "32x"):
            if hint in ul:
                score -= 5
                break
        return score

    urls.sort(key=_score, reverse=True)
    return urls[:max_images]


# ── ONNX classifier ─────────────────────────────────────────────────────────

class NSFWClassifier:
    """ONNX-based NSFW image classifier."""

    def __init__(self) -> None:
        self._session = None

    def _ensure_model(self) -> bool:
        """Download model if not present. Returns True if model is ready."""
        if MODEL_PATH.exists():
            return True

        logger.info("Downloading NSFW model to %s ...", MODEL_PATH)
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        try:
            with httpx.stream("GET", MODEL_URL, follow_redirects=True, timeout=60.0) as resp:
                resp.raise_for_status()
                tmp = MODEL_PATH.with_suffix(".tmp")
                with open(tmp, "wb") as f:
                    for chunk in resp.iter_bytes(chunk_size=8192):
                        f.write(chunk)
                shutil.move(str(tmp), str(MODEL_PATH))
            logger.info("NSFW model downloaded (%d MB)", MODEL_PATH.stat().st_size // (1024 * 1024))
            return True
        except Exception as e:
            logger.error("Failed to download NSFW model: %s", e)
            tmp = MODEL_PATH.with_suffix(".tmp")
            if tmp.exists():
                tmp.unlink()
            return False

    def _load_session(self) -> bool:
        """Load the ONNX inference session."""
        if self._session is not None:
            return True
        if not self._ensure_model():
            return False
        try:
            import onnxruntime as ort
            self._session = ort.InferenceSession(
                str(MODEL_PATH),
                providers=["CPUExecutionProvider"],
            )
            logger.info("NSFW classifier loaded")
            return True
        except Exception as e:
            logger.error("Failed to load NSFW model: %s", e)
            return False

    def classify(self, image_bytes: bytes) -> Optional[dict[str, float]]:
        """
        Classify an image. Returns dict of {class_name: score} or None on error.
        """
        if not self._load_session():
            return None

        try:
            from PIL import Image
            import numpy as np
            import io

            img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            img = img.resize((224, 224))
            arr = np.array(img, dtype=np.float32) / 255.0
            # NHWC → NCHW is NOT needed for this model (it expects NHWC)
            arr = np.expand_dims(arr, axis=0)

            input_name = self._session.get_inputs()[0].name
            output_name = self._session.get_outputs()[0].name
            result = self._session.run([output_name], {input_name: arr})
            scores = result[0][0]

            return {name: float(scores[i]) for i, name in enumerate(CLASS_NAMES)}
        except Exception as e:
            logger.debug("Image classification error: %s", e)
            return None

    def is_nsfw(self, scores: dict[str, float], threshold: float = 0.75) -> bool:
        """Return True if porn + hentai score exceeds threshold."""
        return (scores.get("porn", 0) + scores.get("hentai", 0)) > threshold


# ── Async page scanner ────────────────────────────────────────────────────

_HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
}


async def classify_page_images(
    domain: str,
    html_content: str,
    classifier: NSFWClassifier,
    threshold: float = 0.75,
    max_images: int = 5,
) -> tuple[bool, float, str]:
    """
    Classify a page for NSFW content.

    Strategy:
      1. Take a headless Chrome screenshot and classify it
      2. Fallback: download individual images from the HTML and classify each

    Returns (is_nsfw, max_score, reason).
    """
    loop = asyncio.get_event_loop()

    # ── Strategy 1: Screenshot ────────────────────────────────────────────
    screenshot = await _take_screenshot(domain)
    if screenshot:
        scores = await loop.run_in_executor(None, classifier.classify, screenshot)
        if scores:
            nsfw_score = scores.get("porn", 0) + scores.get("hentai", 0)
            logger.debug(
                "Screenshot NSFW scores for %s: porn=%.3f hentai=%.3f sexy=%.3f",
                domain, scores.get("porn", 0), scores.get("hentai", 0), scores.get("sexy", 0),
            )
            if nsfw_score >= threshold:
                return True, nsfw_score, f"NSFW screenshot (score={nsfw_score:.2f})"
            # If screenshot is clearly safe, skip image downloads
            if nsfw_score < 0.2:
                return False, nsfw_score, ""

    # ── Strategy 2: Individual images ─────────────────────────────────────
    urls = extract_image_urls(html_content, domain, max_images)
    if not urls:
        ss_score = 0.0
        if screenshot:
            scores = await loop.run_in_executor(None, classifier.classify, screenshot)
            if scores:
                ss_score = scores.get("porn", 0) + scores.get("hentai", 0)
        return False, ss_score, ""

    max_score = 0.0
    nsfw_url = ""

    sem = asyncio.Semaphore(3)

    async def _check_image(url: str) -> Optional[tuple[float, str]]:
        async with sem:
            try:
                async with httpx.AsyncClient(
                    timeout=8.0, follow_redirects=True, verify=False,
                ) as client:
                    resp = await client.get(url, headers=_HTTP_HEADERS)
                    if resp.status_code >= 400:
                        return None
                    ct = resp.headers.get("content-type", "")
                    if not ct.startswith("image/"):
                        return None
                    if len(resp.content) < 5000:
                        return None

                scores = await loop.run_in_executor(None, classifier.classify, resp.content)
                if scores is None:
                    return None
                nsfw_score = scores.get("porn", 0) + scores.get("hentai", 0)
                return nsfw_score, url
            except Exception:
                return None

    results = await asyncio.gather(*[_check_image(u) for u in urls], return_exceptions=True)

    for r in results:
        if isinstance(r, tuple) and r is not None:
            score, url = r
            if score > max_score:
                max_score = score
                nsfw_url = url

    if max_score >= threshold:
        short_url = nsfw_url.split("?")[0][-80:]
        return True, max_score, f"NSFW image detected (score={max_score:.2f}): ...{short_url}"

    return False, max_score, ""
