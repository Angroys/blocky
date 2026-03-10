# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Tool Usage

**Always use CodeGraph tools** (codegraph_search, codegraph_node, codegraph_context, codegraph_callers, codegraph_callees, codegraph_impact) for code exploration and reading source files. The `.codegraph/` index is available — prefer it over grep/glob/read for finding symbols, tracing call chains, and reading implementations.

## Commands

```bash
# Run the GUI app
uv run python -m blocky

# Run the CLI
uv run blocky-cli

# Run tests
uv run pytest

# First-time setup (installs sudo helper + sudoers drop-in)
bash install.sh
```

### Venv setup (if recreating)

```bash
uv venv --python python3.14 --system-site-packages
uv sync
```

`--system-site-packages` is **required** — gi/GTK4 bindings are only available from system Python 3.14.

## Architecture

**Blocky** is a GTK4 + libadwaita website/app blocker for Linux with optional AI content detection.

### Core layers

- **UI** (`blocky/ui/`): `Adw.Application` → `Adw.OverlaySplitView` (responsive sidebar + content stack). Six pages: Dashboard, Categories, Websites, Apps, Schedules, Settings. Each page has a `refresh()` method called on navigation and status changes.
- **Engine** (`blocky/engine/`): `BlockManager` is the central orchestrator — activates/deactivates rules, manages hosts file + iptables + cgroups via the privileged helper. `ProcessWatcher` is a daemon thread polling `/proc/` via psutil every 1–2s. `BlockPageServer` serves a "Site Blocked" page on localhost:7878.
- **Helper** (`helper/blocky-apply.py`): Runs as root via sudo. Manages `/etc/hosts` (atomic writes), iptables chains, cgroup v2 (`/sys/fs/cgroup/blocky/blocked`), and DNS redirect. JSON request/response protocol.
- **Database** (`blocky/db/database.py`): SQLite at `~/.local/share/blocky/blocky.db`. Tables: `block_rules`, `schedules`, `category_blocks`, `llm_domain_cache`, `settings`, `activity_log`. Raw sqlite3 with dataclass deserialization (`_rule_from_row()`, `_schedule_from_row()`).
- **Scheduler** (`blocky/scheduler/`): APScheduler background thread with `CronTrigger` — creates activate/deactivate job pairs per rule.
- **LLM** (`blocky/llm/`): `DomainScanner` monitors `/proc/net/tcp` for active connections, resolves IPs to domains, fetches pages, classifies via AI. Multi-provider: Anthropic, Groq, Gemini, Grok. Uses `pydantic_ai.Agent` (custom wrappers for Groq/Grok).
- **Models** (`blocky/models/`): `BlockRule` and `Schedule` dataclasses with enums (`BlockType`, `BlockStatus`, `RecurrenceType`).

### Key patterns

- **Thread-safe UI updates**: Background threads use `GLib.idle_add()` to touch GTK widgets.
- **Status callback**: `BlockManager.set_status_callback()` notifies the UI when blocking state changes; pages refresh automatically.
- **Privilege escalation**: `helper_client.run_helper(action, **kwargs)` serializes to JSON, calls sudo helper, parses JSON response. 15-second timeout. Raises `HelperError` on failure.
- **Tray mode**: `app.hold()` keeps the app alive when window is hidden; close-request hides to tray instead of quitting.
- **CSS theming**: Two themes — `main.css` (dark neon, default) and `glass.css` (light). Hot-swappable at runtime via `app.apply_theme()`.

### Website blocking flow

1. `BlockManager.activate_rule()` → `_apply_website()` → `helper_client.run_helper("hosts_add", domain=…)`
2. Helper atomically writes `/etc/hosts` inside `# BLOCKY:BEGIN … # BLOCKY:END` markers
3. Optional IP layer: DNS resolve → `iptables_add_ip` DROP rules

### App blocking modes

- **network**: cgroup v2 isolation — add PIDs to `blocky/blocked` cgroup, iptables REJECT via `xt_cgroup`
- **kill**: `ProcessWatcher` terminates matching processes on sight
- **strict**: kill entire process tree + cgroup network isolation
