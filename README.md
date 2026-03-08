# Blocky

A futuristic GTK4 app and website blocker for Linux with optional AI-powered adult content detection.

## Features

- **Website blocking** — `/etc/hosts` entries + optional iptables IP-layer rules
- **App blocking** — cgroup v2 network isolation or process kill (strict mode kills the whole tree)
- **Category blocking** — one-click block lists for Adult, Gambling, Social, Gaming, Streaming, News
- **Smart Detection** — DNS redirect to Cloudflare for Families (1.1.1.3) to catch unlisted adult sites
- **LLM Detection** *(experimental)* — AI scans live HTTP/HTTPS traffic and auto-blocks adult domains
- **Scheduling** — APScheduler cron jobs to automatically enable/disable rules on a timetable
- **Dark neon UI** — GTK4 + libadwaita with a custom CSS theme (cyan/purple/green/red palette)

## Requirements

- Linux with cgroup v2 (`/sys/fs/cgroup/`)
- Python 3.14 (system-installed)
- GTK 4 + libadwaita (`python-gobject` system package)
- `sudo` access for the privileged helper

## Installation

```bash
# Clone and enter the repo
git clone <repo-url>
cd blocky

# Create venv (must use --system-site-packages for gi/GTK access)
uv venv --python python3.14 --system-site-packages
uv sync

# Install the privileged helper and sudoers drop-in (needs sudo)
bash install.sh
```

## Running

```bash
uv run python -m blocky
```

## LLM Content Detection

The LLM detection layer monitors active TCP connections to ports 80/443, reverse-resolves IPs to domain names, fetches each homepage, and asks an AI model whether the content is adult material. Detected domains are auto-blocked and logged.

**Supported providers:**

| Provider | Model | API key env |
|---|---|---|
| Anthropic | `claude-haiku-4-5-20251001` | `ANTHROPIC_API_KEY` |
| Groq | `llama-3.1-8b-instant` | `GROQ_API_KEY` |
| Gemini | `gemini-2.0-flash-lite` | `GEMINI_API_KEY` |
| Grok (xAI) | `grok-3-mini` | set in UI |

**Setup:**
1. Open Settings → LLM Content Detection
2. Choose a provider and enter your API key
3. Adjust confidence threshold (default 0.85)
4. Click "Test" to verify the connection
5. Go to Categories → Adult → enable "LLM Detection"

**Verify the cache:**
```bash
sqlite3 ~/.local/share/blocky/blocky.db "SELECT * FROM llm_domain_cache LIMIT 10;"
```

## Architecture

```
blocky/
├── models/          BlockRule, Schedule dataclasses
├── db/              SQLite CRUD (blocky.db)
├── engine/
│   ├── block_manager.py    central orchestrator
│   ├── helper_client.py    calls sudo helper
│   └── process_watcher.py  psutil background thread
├── llm/
│   ├── providers.py        provider configs (Anthropic, Groq, Gemini, Grok)
│   ├── models.py           PydanticAI agent + ContentClassification
│   └── scanner.py          /proc/net/tcp scanner → fetch → classify → block
├── scheduler/       APScheduler cron jobs
├── utils/           domain_utils, app_discovery
└── ui/
    ├── application.py
    ├── main_window.py      OverlaySplitView + Stack navigation
    ├── style/main.css      dark neon CSS theme
    └── pages/              dashboard, categories, websites, apps, schedules, settings
helper/
└── blocky-apply.py  privileged helper (runs as root via sudo)
```

## How Blocking Works

### Websites
1. UI calls `block_manager.activate_rule(rule)`
2. Helper atomically writes `/etc/hosts` inside `# BLOCKY:BEGIN … # BLOCKY:END`
3. Optional IP layer: DNS resolution → iptables DROP rules

### Apps — Network mode
1. Helper creates `/sys/fs/cgroup/blocky/blocked/`
2. iptables rule: `BLOCKY_OUTPUT -m cgroup --path blocky/blocked -j REJECT`
3. Current PIDs added to `cgroup.procs`; `ProcessWatcher` monitors new launches

### Apps — Kill / Strict mode
- Kill: `ProcessWatcher` calls `proc.kill()` on matching processes
- Strict: cgroup isolation + kill entire process tree immediately

## Data

Database at `~/.local/share/blocky/blocky.db`:

| Table | Purpose |
|---|---|
| `block_rules` | website and app rules |
| `schedules` | time windows for rules |
| `category_blocks` | active category state |
| `llm_domain_cache` | LLM classification results |
| `settings` | key-value config |
| `activity_log` | audit trail |
