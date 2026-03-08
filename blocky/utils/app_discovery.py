import os
import configparser
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DESKTOP_DIRS = [
    Path("/usr/share/applications"),
    Path("/usr/local/share/applications"),
    Path.home() / ".local" / "share" / "applications",
]


@dataclass
class AppProfile:
    display_name: str
    exe_path: str
    process_name: str
    icon_name: str
    desktop_file: str
    categories: list[str]


def _parse_exec(exec_str: str) -> str:
    """Strip field codes (%u %F etc.) and return the bare executable."""
    parts = exec_str.split()
    clean = [p for p in parts if not p.startswith("%")]
    return clean[0] if clean else exec_str


def _resolve_exe(cmd: str) -> Optional[str]:
    """Try to resolve command to absolute path."""
    if os.path.isabs(cmd) and os.path.isfile(cmd):
        return cmd
    # Search PATH
    for directory in os.environ.get("PATH", "").split(":"):
        candidate = Path(directory) / cmd
        if candidate.is_file():
            return str(candidate)
    return None


def discover_apps() -> list[AppProfile]:
    apps: list[AppProfile] = []
    seen_exes: set[str] = set()

    for desktop_dir in DESKTOP_DIRS:
        if not desktop_dir.exists():
            continue
        for desktop_file in sorted(desktop_dir.glob("*.desktop")):
            try:
                cfg = configparser.ConfigParser(interpolation=None)
                cfg.read(str(desktop_file), encoding="utf-8")

                if "Desktop Entry" not in cfg:
                    continue
                entry = cfg["Desktop Entry"]

                if entry.get("Type") != "Application":
                    continue
                if entry.get("NoDisplay", "false").lower() == "true":
                    continue
                if entry.get("Hidden", "false").lower() == "true":
                    continue

                name = entry.get("Name", "")
                exec_str = entry.get("Exec", "")
                if not name or not exec_str:
                    continue

                cmd = _parse_exec(exec_str)
                exe_path = _resolve_exe(cmd)
                if not exe_path or exe_path in seen_exes:
                    continue

                seen_exes.add(exe_path)
                process_name = Path(exe_path).name
                icon = entry.get("Icon", "application-x-executable")
                categories_str = entry.get("Categories", "")
                categories = [c for c in categories_str.split(";") if c]

                apps.append(AppProfile(
                    display_name=name,
                    exe_path=exe_path,
                    process_name=process_name,
                    icon_name=icon,
                    desktop_file=str(desktop_file),
                    categories=categories,
                ))
            except Exception:
                continue

    apps.sort(key=lambda a: a.display_name.lower())
    return apps
