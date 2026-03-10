import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

from blocky.models.block_rule import BlockRule, BlockType, BlockStatus
from blocky.models.schedule import Schedule, RecurrenceType


DB_DIR = Path.home() / ".local" / "share" / "blocky"
DB_PATH = DB_DIR / "blocky.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    recurrence TEXT NOT NULL,
    weekday_mask INTEGER DEFAULT 0,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    active INTEGER DEFAULT 1,
    strict INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS block_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    block_type TEXT NOT NULL,
    domain TEXT,
    extra_domains TEXT DEFAULT '[]',
    block_ip_layer INTEGER DEFAULT 0,
    exe_path TEXT,
    process_name TEXT,
    block_mode TEXT DEFAULT 'network',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    schedule_id INTEGER REFERENCES schedules(id),
    notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule_id INTEGER,
    rule_name TEXT NOT NULL,
    action TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS category_blocks (
    category_id TEXT PRIMARY KEY,
    active INTEGER DEFAULT 1,
    smart_detect INTEGER DEFAULT 0,
    enabled_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_domain_cache (
    domain TEXT PRIMARY KEY,
    is_adult INTEGER NOT NULL,
    confidence REAL NOT NULL,
    provider TEXT NOT NULL,
    classified_at TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path = DB_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        # Migrations for existing databases
        try:
            self._conn.execute("ALTER TABLE schedules ADD COLUMN strict INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists
        self._conn.commit()

    def _rule_from_row(self, row: sqlite3.Row) -> BlockRule:
        return BlockRule(
            id=row["id"],
            name=row["name"],
            block_type=BlockType(row["block_type"]),
            domain=row["domain"],
            extra_domains=json.loads(row["extra_domains"] or "[]"),
            block_ip_layer=bool(row["block_ip_layer"]),
            exe_path=row["exe_path"],
            process_name=row["process_name"],
            block_mode=row["block_mode"] or "network",
            status=BlockStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            schedule_id=row["schedule_id"],
            notes=row["notes"] or "",
        )

    def _schedule_from_row(self, row: sqlite3.Row) -> Schedule:
        return Schedule(
            id=row["id"],
            name=row["name"],
            recurrence=RecurrenceType(row["recurrence"]),
            weekday_mask=row["weekday_mask"],
            start_time=row["start_time"],
            end_time=row["end_time"],
            active=bool(row["active"]),
            strict=bool(row["strict"]),
        )

    # --- Block Rules ---

    def get_all_rules(self) -> list[BlockRule]:
        rows = self._conn.execute("SELECT * FROM block_rules ORDER BY id").fetchall()
        return [self._rule_from_row(r) for r in rows]

    def get_active_rules(self) -> list[BlockRule]:
        rows = self._conn.execute(
            "SELECT * FROM block_rules WHERE status = 'active' ORDER BY id"
        ).fetchall()
        return [self._rule_from_row(r) for r in rows]

    def get_rule(self, rule_id: int) -> Optional[BlockRule]:
        row = self._conn.execute(
            "SELECT * FROM block_rules WHERE id = ?", (rule_id,)
        ).fetchone()
        return self._rule_from_row(row) if row else None

    def add_rule(self, rule: BlockRule) -> int:
        cur = self._conn.execute(
            """INSERT INTO block_rules
               (name, block_type, domain, extra_domains, block_ip_layer,
                exe_path, process_name, block_mode, status, created_at, schedule_id, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rule.name,
                rule.block_type.value,
                rule.domain,
                json.dumps(rule.extra_domains),
                int(rule.block_ip_layer),
                rule.exe_path,
                rule.process_name,
                rule.block_mode,
                rule.status.value,
                rule.created_at.isoformat(),
                rule.schedule_id,
                rule.notes,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def update_rule(self, rule: BlockRule) -> None:
        self._conn.execute(
            """UPDATE block_rules SET
               name=?, block_type=?, domain=?, extra_domains=?, block_ip_layer=?,
               exe_path=?, process_name=?, block_mode=?, status=?, schedule_id=?, notes=?
               WHERE id=?""",
            (
                rule.name,
                rule.block_type.value,
                rule.domain,
                json.dumps(rule.extra_domains),
                int(rule.block_ip_layer),
                rule.exe_path,
                rule.process_name,
                rule.block_mode,
                rule.status.value,
                rule.schedule_id,
                rule.notes,
                rule.id,
            ),
        )
        self._conn.commit()

    def delete_rule(self, rule_id: int) -> None:
        self._conn.execute("DELETE FROM block_rules WHERE id = ?", (rule_id,))
        self._conn.commit()

    def set_rule_status(self, rule_id: int, status: BlockStatus) -> None:
        self._conn.execute(
            "UPDATE block_rules SET status = ? WHERE id = ?",
            (status.value, rule_id),
        )
        self._conn.commit()

    # --- Schedules ---

    def get_schedules(self) -> list[Schedule]:
        rows = self._conn.execute("SELECT * FROM schedules ORDER BY id").fetchall()
        return [self._schedule_from_row(r) for r in rows]

    def get_schedule(self, schedule_id: int) -> Optional[Schedule]:
        row = self._conn.execute(
            "SELECT * FROM schedules WHERE id = ?", (schedule_id,)
        ).fetchone()
        return self._schedule_from_row(row) if row else None

    def add_schedule(self, schedule: Schedule) -> int:
        cur = self._conn.execute(
            """INSERT INTO schedules (name, recurrence, weekday_mask, start_time, end_time, active, strict)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                schedule.name,
                schedule.recurrence.value,
                schedule.weekday_mask,
                schedule.start_time,
                schedule.end_time,
                int(schedule.active),
                int(schedule.strict),
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def update_schedule(self, schedule: Schedule) -> None:
        self._conn.execute(
            """UPDATE schedules SET name=?, recurrence=?, weekday_mask=?,
               start_time=?, end_time=?, active=?, strict=? WHERE id=?""",
            (
                schedule.name,
                schedule.recurrence.value,
                schedule.weekday_mask,
                schedule.start_time,
                schedule.end_time,
                int(schedule.active),
                int(schedule.strict),
                schedule.id,
            ),
        )
        self._conn.commit()

    def delete_schedule(self, schedule_id: int) -> None:
        self._conn.execute(
            "UPDATE block_rules SET schedule_id = NULL WHERE schedule_id = ?",
            (schedule_id,),
        )
        self._conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        self._conn.commit()

    # --- Settings ---

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=?",
            (key, value, value),
        )
        self._conn.commit()

    # --- Activity Log ---

    def log_activity(self, rule_id: Optional[int], rule_name: str, action: str) -> None:
        self._conn.execute(
            "INSERT INTO activity_log (timestamp, rule_id, rule_name, action) VALUES (?, ?, ?, ?)",
            (datetime.now().isoformat(), rule_id, rule_name, action),
        )
        self._conn.commit()

    def get_recent_activity(self, limit: int = 20) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM activity_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Category Blocks ---

    def get_active_categories(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM category_blocks WHERE active = 1"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_category(self, category_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM category_blocks WHERE category_id = ?", (category_id,)
        ).fetchone()
        return dict(row) if row else None

    def set_category_active(self, category_id: str, active: bool, smart_detect: bool = False) -> None:
        from datetime import datetime
        self._conn.execute(
            """INSERT INTO category_blocks (category_id, active, smart_detect, enabled_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(category_id) DO UPDATE SET active=?, smart_detect=?, enabled_at=?""",
            (
                category_id, int(active), int(smart_detect), datetime.now().isoformat(),
                int(active), int(smart_detect), datetime.now().isoformat(),
            ),
        )
        self._conn.commit()

    # --- LLM Domain Cache ---

    def get_llm_cache(self, domain: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM llm_domain_cache WHERE domain = ?", (domain,)
        ).fetchone()
        return dict(row) if row else None

    def set_llm_cache(
        self, domain: str, is_adult: bool, confidence: float, provider: str
    ) -> None:
        now = datetime.now().isoformat()
        self._conn.execute(
            """INSERT INTO llm_domain_cache (domain, is_adult, confidence, provider, classified_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(domain) DO UPDATE SET
                   is_adult=excluded.is_adult,
                   confidence=excluded.confidence,
                   provider=excluded.provider,
                   classified_at=excluded.classified_at""",
            (domain, int(is_adult), confidence, provider, now),
        )
        self._conn.commit()

    def clear_llm_cache(self) -> int:
        """Delete all cached LLM classifications. Returns number of rows deleted."""
        cur = self._conn.execute("DELETE FROM llm_domain_cache")
        self._conn.commit()
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()
