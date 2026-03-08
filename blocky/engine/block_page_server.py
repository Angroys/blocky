"""
Local HTTP server that serves a "site blocked" page.
Runs on 127.0.0.1:7878 in a daemon thread.
Blocked domains resolve to 127.0.0.1 via /etc/hosts; iptables NAT redirects
port 80 → 7878 so the browser lands here instead of getting a connection error.
"""
import http.server
import logging
import threading
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

BLOCK_PORT = 7878

_BLOCK_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blocked by Blocky</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: linear-gradient(135deg,
      #0a0a0f 0%, #12121a 40%, #0f0f1a 100%);
    color: #e2e2f0;
  }

  .card {
    text-align: center;
    padding: 56px 64px;
    background: rgba(18, 18, 26, 0.90);
    border: 1px solid rgba(255, 51, 102, 0.35);
    border-radius: 24px;
    box-shadow:
      0 0 0 1px rgba(255, 51, 102, 0.10) inset,
      0 0 60px rgba(255, 51, 102, 0.12),
      0 24px 64px rgba(0, 0, 0, 0.60);
    max-width: 520px;
    width: 90vw;
  }

  .icon {
    font-size: 64px;
    margin-bottom: 20px;
    display: block;
    filter: drop-shadow(0 0 20px rgba(255, 51, 102, 0.60));
  }

  h1 {
    font-size: 28px;
    font-weight: 800;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #ff3366;
    text-shadow: 0 0 24px rgba(255, 51, 102, 0.50);
    margin-bottom: 12px;
  }

  .domain {
    font-family: monospace;
    font-size: 15px;
    color: #00d4ff;
    background: rgba(0, 212, 255, 0.08);
    border: 1px solid rgba(0, 212, 255, 0.20);
    border-radius: 8px;
    padding: 6px 16px;
    display: inline-block;
    margin-bottom: 20px;
    word-break: break-all;
  }

  p {
    color: #6b6b8a;
    font-size: 14px;
    line-height: 1.7;
    margin-bottom: 32px;
  }

  .badge {
    display: inline-block;
    background: rgba(255, 51, 102, 0.12);
    border: 1px solid rgba(255, 51, 102, 0.30);
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: #ff3366;
  }

  .wordmark {
    margin-top: 36px;
    font-size: 11px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: #3a3a5a;
  }
  .wordmark span { color: #00d4ff; }
</style>
</head>
<body>
<div class="card">
  <span class="icon">🛡️</span>
  <h1>Site Blocked</h1>
  <div class="domain">{domain}</div>
  <p>
    This website has been blocked because it was detected as adult content
    by Blocky's AI content filter. If you believe this is a mistake, you
    can remove the block from the Blocky app.
  </p>
  <span class="badge">Adult Content</span>
  <div class="wordmark">Blocked by <span>BLOCKY</span></div>
</div>
</body>
</html>
"""


class _BlockPageHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        host = self.headers.get("Host", "").split(":")[0]
        html = _BLOCK_HTML.replace("{domain}", host or "this site").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def log_message(self, *_) -> None:
        pass  # suppress access log noise


_server: http.server.HTTPServer | None = None
_lock = threading.Lock()


def start() -> None:
    """Start the block page server in a daemon thread (idempotent)."""
    global _server
    with _lock:
        if _server is not None:
            return
        try:
            _server = http.server.HTTPServer(("127.0.0.1", BLOCK_PORT), _BlockPageHandler)
            t = threading.Thread(target=_server.serve_forever, daemon=True, name="blocky-block-page")
            t.start()
            logger.info("Block page server started on http://127.0.0.1:%d", BLOCK_PORT)
        except OSError as e:
            logger.warning("Could not start block page server: %s", e)


def stop() -> None:
    global _server
    with _lock:
        if _server:
            _server.shutdown()
            _server = None
