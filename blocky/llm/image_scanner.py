"""
Local NSFW image detection using ONNX runtime.

Uses Falconsai/nsfw_image_detection ViT model (~87MB ONNX, quantized) to
classify images as normal or nsfw.

The model is downloaded on first use to ~/.local/share/blocky/models/.
No API key required — runs entirely locally on CPU.

Detection strategy (in order):
  1. Active window screenshot via maim + xdotool — captures what the user sees
  2. Image download fallback — downloads images from HTML src/srcset/og:image
"""

import asyncio
import html.parser
import logging
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# ── Model config ─────────────────────────────────────────────────────────────

MODEL_DIR = Path.home() / ".local" / "share" / "blocky" / "models"
MODEL_FILE = "nsfw_vit_quantized.onnx"
MODEL_PATH = MODEL_DIR / MODEL_FILE

# Falconsai/nsfw_image_detection — ViT binary classifier (ONNX, quantized, ~87MB)
# Hosted on HuggingFace (GitHub CDN IPs may be blocked by our own SNI rules)
MODEL_URL = (
    "https://huggingface.co/onnx-community/nsfw_image_detection-ONNX/"
    "resolve/main/onnx/model_quantized.onnx"
)

# Binary classifier: normal (0) vs nsfw (1)
CLASS_NAMES = ["normal", "nsfw"]

# ImageNet normalization (ViT expects normalized input)
_IMAGENET_MEAN = (0.485, 0.456, 0.406)
_IMAGENET_STD = (0.229, 0.224, 0.225)

# Detection threshold
NSFW_THRESHOLD = 0.70

# ── Screenshot tools ─────────────────────────────────────────────────────────
# Captures the active window to classify what the user is viewing.
# Supports multiple backends for X11 and Wayland:
#   X11:     maim + xdotool (preferred), scrot (fallback)
#   Wayland: grim (preferred), hyprshot (Hyprland)

_screenshot_backend: Optional[str] = None  # cached backend name or ""


def _detect_screenshot_backend() -> Optional[str]:
    """Detect the best available screenshot tool. Returns backend name or None."""
    global _screenshot_backend
    if _screenshot_backend is not None:
        return _screenshot_backend if _screenshot_backend else None

    session_type = os.environ.get("XDG_SESSION_TYPE", "").lower()
    is_wayland = session_type == "wayland"

    if is_wayland:
        if shutil.which("grim"):
            _screenshot_backend = "grim"
            logger.info("Screenshot backend: grim (Wayland)")
            return _screenshot_backend
        if shutil.which("hyprshot"):
            _screenshot_backend = "hyprshot"
            logger.info("Screenshot backend: hyprshot (Hyprland)")
            return _screenshot_backend
    else:
        # X11
        if shutil.which("maim") and shutil.which("xdotool"):
            _screenshot_backend = "maim"
            logger.info("Screenshot backend: maim + xdotool (X11)")
            return _screenshot_backend
        if shutil.which("scrot"):
            _screenshot_backend = "scrot"
            logger.info("Screenshot backend: scrot (X11)")
            return _screenshot_backend

    # Cross-session fallbacks (try X11 tools on Wayland too, XWayland may work)
    if shutil.which("maim") and shutil.which("xdotool"):
        _screenshot_backend = "maim"
        logger.info("Screenshot backend: maim + xdotool (XWayland fallback)")
        return _screenshot_backend

    _screenshot_backend = ""
    logger.warning(
        "No screenshot tools found. Install one of: "
        "maim+xdotool (X11), scrot (X11), grim (Wayland), hyprshot (Hyprland)"
    )
    return None


# Browser WM_CLASS names to search for with xdotool
_BROWSER_CLASSES = [
    "google-chrome", "Google-chrome",
    "chromium", "Chromium", "chromium-browser",
    "brave-browser", "Brave-browser",
    "firefox", "Firefox", "Navigator",
    "Arc",
    "vivaldi", "Vivaldi",
    "opera", "Opera",
    "microsoft-edge", "Microsoft-edge",
]


async def _find_browser_windows() -> list[str]:
    """Find all browser window IDs using xdotool search --class."""
    window_ids: list[str] = []
    for cls in _BROWSER_CLASSES:
        try:
            proc = await asyncio.create_subprocess_exec(
                "xdotool", "search", "--class", cls,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            if proc.returncode == 0 and stdout.strip():
                for wid in stdout.decode().strip().split("\n"):
                    wid = wid.strip()
                    if wid and wid not in window_ids:
                        window_ids.append(wid)
                if window_ids:
                    logger.info("Found %d browser window(s) for class '%s'", len(window_ids), cls)
                    return window_ids  # found a match, use this browser
        except (asyncio.TimeoutError, Exception):
            continue
    return window_ids


async def _screenshot_maim(tmp_path: str) -> bool:
    """Capture browser window with maim + xdotool."""
    logger.info("Searching for browser windows with xdotool...")

    # Try to find a browser window first
    window_ids = await _find_browser_windows()

    if not window_ids:
        # Fallback to active window
        logger.info("No browser windows found, falling back to active window")
        proc = await asyncio.create_subprocess_exec(
            "xdotool", "getactivewindow",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        if proc.returncode != 0 or not stdout.strip():
            logger.warning("xdotool getactivewindow failed (rc=%d): %s",
                           proc.returncode, stderr.decode().strip())
            return False
        window_ids = [stdout.decode().strip()]

    # Capture the first (most recent / focused) browser window
    window_id = window_ids[0]
    logger.info("Capturing browser window ID %s with maim → %s", window_id, tmp_path)
    proc = await asyncio.create_subprocess_exec(
        "maim", "-i", window_id, tmp_path,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
    if proc.returncode != 0:
        logger.warning("maim failed (rc=%d): %s", proc.returncode, stderr.decode().strip())
    return proc.returncode == 0


async def _screenshot_scrot(tmp_path: str) -> bool:
    """Capture focused window with scrot. Falls back to full screen."""
    # Try focused window first (-u), fall back to full screen
    for flags in (["-u", tmp_path], [tmp_path]):
        logger.info("Taking screenshot with scrot %s → %s",
                    " ".join(flags[:-1]) or "(fullscreen)", tmp_path)
        proc = await asyncio.create_subprocess_exec(
            "scrot", *flags,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        if proc.returncode == 0:
            return True
        logger.warning("scrot failed (rc=%d): %s", proc.returncode, stderr.decode().strip())
    return False


async def _find_hyprland_browser_window() -> tuple[str, list[int], list[int]] | None:
    """Find a browser window via hyprctl clients -j on Hyprland.

    Returns (title, [x, y], [w, h]) or None if no browser window found.
    """
    import json as _json

    _BROWSER_HYPR = {"brave", "chromium", "chrome", "firefox", "vivaldi", "opera", "edge", "arc"}

    proc = await asyncio.create_subprocess_exec(
        "hyprctl", "clients", "-j",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
    if proc.returncode != 0 or not stdout.strip():
        return None

    clients = _json.loads(stdout.decode())
    for client in clients:
        cls = client.get("class", "").lower()
        title = client.get("title", "")
        at = client.get("at", [0, 0])
        size = client.get("size", [0, 0])
        # Match any browser class
        if any(b in cls for b in _BROWSER_HYPR) and size[0] > 100 and size[1] > 100:
            logger.info("Found Hyprland browser window: class=%s at=%s size=%s title='%s'",
                       cls, at, size, title[:60])
            return title, at, size
    return None


async def _screenshot_grim(tmp_path: str) -> bool:
    """Capture browser window with grim (Wayland).

    On Hyprland: finds browser windows via hyprctl clients -j and captures
    that window's geometry with grim -g. Falls back to active window, then
    full screen.
    """
    # Try Hyprland browser window capture first
    if os.environ.get("HYPRLAND_INSTANCE_SIGNATURE"):
        import json as _json
        try:
            # Strategy 1: Find browser window specifically
            browser = await _find_hyprland_browser_window()
            if browser:
                title, at, size = browser
                geom = f"{at[0]},{at[1]} {size[0]}x{size[1]}"
                logger.info("Taking grim screenshot of browser window: %s", geom)
                proc = await asyncio.create_subprocess_exec(
                    "grim", "-g", geom, tmp_path,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                if proc.returncode == 0:
                    return True
                logger.warning("grim -g (browser) failed (rc=%d): %s",
                              proc.returncode, stderr.decode().strip())

            # Strategy 2: Active window (may be non-browser)
            proc = await asyncio.create_subprocess_exec(
                "hyprctl", "activewindow", "-j",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            if proc.returncode == 0 and stdout.strip():
                win = _json.loads(stdout.decode())
                at = win.get("at", [0, 0])
                size = win.get("size", [0, 0])
                if size[0] > 100 and size[1] > 100:
                    geom = f"{at[0]},{at[1]} {size[0]}x{size[1]}"
                    logger.info("Taking grim screenshot of active window: %s", geom)
                    proc = await asyncio.create_subprocess_exec(
                        "grim", "-g", geom, tmp_path,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                    if proc.returncode == 0:
                        return True
                    logger.warning("grim -g (active) failed (rc=%d): %s",
                                  proc.returncode, stderr.decode().strip())
        except Exception as e:
            logger.debug("hyprctl window capture failed: %s", e)

    # Fallback: full screen capture
    logger.info("Taking grim full-screen screenshot → %s", tmp_path)
    proc = await asyncio.create_subprocess_exec(
        "grim", tmp_path,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
    if proc.returncode != 0:
        logger.warning("grim failed (rc=%d): %s", proc.returncode, stderr.decode().strip())
    return proc.returncode == 0


async def _screenshot_hyprshot(tmp_path: str) -> bool:
    """Capture active window with hyprshot (Hyprland)."""
    logger.info("Taking screenshot with hyprshot → %s", tmp_path)
    proc = await asyncio.create_subprocess_exec(
        "hyprshot", "-m", "window", "-o", str(Path(tmp_path).parent),
        "-f", Path(tmp_path).name,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
    if proc.returncode != 0:
        logger.warning("hyprshot failed (rc=%d): %s", proc.returncode, stderr.decode().strip())
    return proc.returncode == 0


_SCREENSHOT_FNS = {
    "maim": _screenshot_maim,
    "scrot": _screenshot_scrot,
    "grim": _screenshot_grim,
    "hyprshot": _screenshot_hyprshot,
}


async def _take_screenshot(domain: str) -> Optional[bytes]:
    """Capture the active window. Returns PNG bytes or None."""
    backend = _detect_screenshot_backend()
    if not backend:
        logger.warning("Screenshot skipped for %s — no backend available", domain)
        return None

    logger.info("Taking screenshot for %s using %s", domain, backend)

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        fn = _SCREENSHOT_FNS[backend]
        ok = await fn(tmp_path)

        path = Path(tmp_path)
        if ok and path.exists() and path.stat().st_size > 1000:
            data = path.read_bytes()
            path.unlink(missing_ok=True)
            logger.info("Screenshot captured [%s] for %s (%d bytes)", backend, domain, len(data))
            return data
        size = path.stat().st_size if path.exists() else 0
        logger.warning("Screenshot too small or failed [%s] for %s (ok=%s, size=%d)",
                       backend, domain, ok, size)
        path.unlink(missing_ok=True)
    except asyncio.TimeoutError:
        Path(tmp_path).unlink(missing_ok=True)
        logger.warning("Screenshot timeout [%s] for %s", backend, domain)
    except Exception as e:
        Path(tmp_path).unlink(missing_ok=True)
        logger.warning("Screenshot error [%s] for %s: %s", backend, domain, e)
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

    _download_lock = threading.Lock()
    _download_failed = False  # skip retries within the same session

    def __init__(self) -> None:
        self._session = None

    def _ensure_model(self) -> bool:
        """Download model if not present. Returns True if model is ready."""
        if MODEL_PATH.exists():
            return True
        if NSFWClassifier._download_failed:
            return False

        with NSFWClassifier._download_lock:
            # Re-check after acquiring lock (another thread may have downloaded)
            if MODEL_PATH.exists():
                return True
            if NSFWClassifier._download_failed:
                return False

            logger.info("Downloading NSFW model to %s ...", MODEL_PATH)
            MODEL_DIR.mkdir(parents=True, exist_ok=True)
            try:
                with httpx.stream("GET", MODEL_URL, follow_redirects=True, timeout=120.0) as resp:
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
                NSFWClassifier._download_failed = True
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
        Classify an image. Returns dict of {class_name: probability} or None on error.
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

            # ImageNet normalization
            mean = np.array(_IMAGENET_MEAN, dtype=np.float32)
            std = np.array(_IMAGENET_STD, dtype=np.float32)
            arr = (arr - mean) / std

            # HWC → CHW → NCHW (ViT expects channel-first)
            arr = np.transpose(arr, (2, 0, 1))
            arr = np.expand_dims(arr, axis=0).astype(np.float32)

            input_name = self._session.get_inputs()[0].name
            output_name = self._session.get_outputs()[0].name
            logits = self._session.run([output_name], {input_name: arr})[0][0]

            # Softmax to get probabilities
            exp = np.exp(logits - np.max(logits))
            probs = exp / exp.sum()

            return {name: float(probs[i]) for i, name in enumerate(CLASS_NAMES)}
        except Exception as e:
            logger.debug("Image classification error: %s", e)
            return None

    @staticmethod
    def nsfw_score(scores: dict[str, float]) -> float:
        """NSFW probability score."""
        return scores.get("nsfw", 0)

    def is_nsfw(self, scores: dict[str, float], threshold: float = 0.70) -> bool:
        """Return True if NSFW probability exceeds threshold."""
        return scores.get("nsfw", 0) >= threshold


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
    threshold: float = 0.70,
    max_images: int = 5,
) -> tuple[bool, float, str]:
    """
    Classify a page for NSFW content.

    Strategy:
      1. Active window screenshot via maim/grim/scrot — classify what user sees
      2. Fallback: download individual images from the HTML and classify each

    Returns (is_nsfw, nsfw_score, reason).
    """
    loop = asyncio.get_event_loop()
    logger.info("Classifying page images for %s (threshold=%.2f, max_images=%d)",
                domain, threshold, max_images)

    # ── Strategy 1: Screenshot ────────────────────────────────────────────
    screenshot = await _take_screenshot(domain)
    if screenshot:
        logger.info("Running NSFW model on screenshot for %s (%d bytes)...", domain, len(screenshot))
        scores = await loop.run_in_executor(None, classifier.classify, screenshot)
        if scores:
            nsfw_prob = scores.get("nsfw", 0)
            logger.info(
                "Screenshot NSFW result for %s: nsfw=%.3f normal=%.3f",
                domain, nsfw_prob, scores.get("normal", 0),
            )
            if nsfw_prob >= threshold:
                logger.info("BLOCKED by screenshot: %s (nsfw=%.3f >= %.2f)",
                           domain, nsfw_prob, threshold)
                return True, nsfw_prob, f"NSFW screenshot (score={nsfw_prob:.2f})"
            # If screenshot is clearly safe, skip image downloads
            if nsfw_prob < 0.2:
                logger.info("Screenshot safe for %s — skipping image downloads", domain)
                return False, nsfw_prob, ""

    # ── Strategy 2: Individual images ─────────────────────────────────────
    urls = extract_image_urls(html_content, domain, max_images)
    if not urls:
        logger.info("No image URLs extracted from %s HTML — skipping image check", domain)
        ss_score = 0.0
        if screenshot:
            scores = await loop.run_in_executor(None, classifier.classify, screenshot)
            if scores:
                ss_score = scores.get("nsfw", 0)
        return False, ss_score, ""

    logger.info("Checking %d images from %s: %s", len(urls), domain,
                [u.split("/")[-1][:40] for u in urls])

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
                nsfw_prob = scores.get("nsfw", 0)
                logger.info("Image NSFW score for %s: %.3f (%s)",
                           url.split("/")[-1][:50], nsfw_prob, domain)
                return nsfw_prob, url
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
        logger.info("BLOCKED by image: %s (score=%.3f >= %.2f) url=%s",
                    domain, max_score, threshold, short_url)
        return True, max_score, f"NSFW image (score={max_score:.2f}): ...{short_url}"

    return False, max_score, ""
