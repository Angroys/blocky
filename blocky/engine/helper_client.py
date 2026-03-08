import json
import subprocess
from pathlib import Path
from typing import Any

HELPER_PATH = "/usr/local/lib/blocky/blocky-apply.py"


class HelperError(Exception):
    pass


def run_helper(action: str, **kwargs: Any) -> dict:
    """
    Call the privileged helper via sudo.
    Returns parsed JSON response. Raises HelperError on failure.
    """
    if not Path(HELPER_PATH).exists():
        raise HelperError(
            f"Helper not found at {HELPER_PATH}. Run install.sh first."
        )
    cmd = ["sudo", HELPER_PATH, f"--action={action}", f"--data={json.dumps(kwargs)}"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        raise HelperError(f"Helper timed out for action {action!r}")
    except Exception as e:
        raise HelperError(f"Failed to run helper: {e}")

    if result.returncode != 0:
        # Helper writes error JSON to stdout; stderr is for system-level failures
        try:
            response = json.loads(result.stdout)
            error_msg = response.get("error") or result.stderr.strip()
        except (json.JSONDecodeError, AttributeError):
            error_msg = result.stderr.strip()
        raise HelperError(f"Helper exited {result.returncode}: {error_msg}")

    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise HelperError(f"Helper returned invalid JSON: {result.stdout!r}")

    if not response.get("ok"):
        raise HelperError(response.get("error", "Unknown helper error"))

    return response


def is_helper_available() -> bool:
    return Path(HELPER_PATH).exists()
