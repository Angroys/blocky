"""
Blocky CLI — manage block rules without opening the GUI.

Usage examples:
  blocky-cli status
  blocky-cli block website reddit.com
  blocky-cli block website reddit.com --deep
  blocky-cli block app /opt/zen-browser-bin/zen-bin --mode strict
  blocky-cli unblock website reddit.com
  blocky-cli unblock app zen-bin
  blocky-cli category block adult
  blocky-cli category block adult --smart
  blocky-cli category unblock adult
  blocky-cli list
  blocky-cli list categories
  blocky-cli schedule list
  blocky-cli schedule add "Work hours" 09:00 17:00 --days mon-fri
"""

import argparse
import sys

from blocky.data.categories import CATEGORIES
from blocky.db.database import Database
from blocky.engine.block_manager import BlockManager
from blocky.engine.helper_client import is_helper_available
from blocky.models.block_rule import BlockRule, BlockStatus, BlockType
from blocky.models.schedule import RecurrenceType, Schedule
from blocky.utils.domain_utils import is_valid_domain, normalize_domain


def _get_backend() -> tuple[Database, BlockManager]:
    db = Database()
    bm = BlockManager(db)
    if is_helper_available():
        bm.start()
    return db, bm


def _rule_row(rule: BlockRule) -> str:
    status = "●" if rule.status == BlockStatus.ACTIVE else "○"
    kind = f"[{rule.block_type.value}]"
    detail = rule.domain or rule.exe_path or ""
    mode = f"({rule.block_mode})" if rule.block_type == BlockType.APP else ""
    sched = f" [sched:{rule.schedule_id}]" if rule.schedule_id else ""
    return f"  {status} {rule.id:>3}  {kind:<9} {rule.name:<25} {detail:<35} {mode}{sched}"


# ── Subcommands ──────────────────────────────────────────────────────────────

def cmd_status(args, db: Database, bm: BlockManager) -> None:
    active = db.get_active_rules()
    all_rules = db.get_all_rules()
    cats = db.get_active_categories()

    print(f"\n  BLOCKY STATUS")
    print(f"  Helper installed : {'yes' if is_helper_available() else 'NO — run install.sh'}")
    print(f"  Active rules     : {len(active)}/{len(all_rules)}")
    print(f"  Active categories: {len(cats)}")
    if cats:
        for c in cats:
            smart = " [smart]" if c.get("smart_detect") else ""
            print(f"    • {c['category_id']}{smart}")
    print()


def cmd_list(args, db: Database, bm: BlockManager) -> None:
    if getattr(args, "target", None) == "categories":
        print("\n  CATEGORIES")
        for cat_id, cat in CATEGORIES.items():
            active = bm.is_category_active(cat_id)
            smart = bm.is_smart_detect_active(cat_id)
            status = "●" if active else "○"
            smart_tag = " [smart]" if smart else ""
            print(f"  {status}  {cat_id:<15} {cat['name']:<22} {len(cat['domains'])} domains{smart_tag}")
        print()
        return

    rules = db.get_all_rules()
    if not rules:
        print("  No block rules.")
        return
    print(f"\n  {'ID':>3}  {'TYPE':<9} {'NAME':<25} {'DOMAIN/EXE':<35} MODE")
    print("  " + "─" * 85)
    for rule in rules:
        print(_rule_row(rule))
    print()


def cmd_block_website(args, db: Database, bm: BlockManager) -> None:
    domain = normalize_domain(args.domain)
    if not is_valid_domain(domain):
        print(f"  Error: invalid domain '{domain}'")
        sys.exit(1)

    rule = BlockRule(
        name=domain,
        block_type=BlockType.WEBSITE,
        domain=domain,
        block_ip_layer=getattr(args, "deep", False),
        status=BlockStatus.ACTIVE,
    )
    rule_id = db.add_rule(rule)
    rule.id = rule_id

    if is_helper_available():
        bm.activate_rule(rule)
        print(f"  Blocked: {domain} (id={rule_id})")
    else:
        print(f"  Saved: {domain} (id={rule_id}) — helper not installed, rule not applied yet")


def cmd_block_app(args, db: Database, bm: BlockManager) -> None:
    process_name = args.process_name
    mode = getattr(args, "mode", "strict")
    if mode not in ("network", "kill", "strict"):
        print(f"  Error: unknown mode '{mode}' — use network, kill, or strict")
        sys.exit(1)

    # Verify the process name exists (or warn)
    import psutil
    running = [p.name() for p in psutil.process_iter(["name"])
               if p.info.get("name") == process_name]
    if not running:
        print(f"  Warning: no running process named '{process_name}' — rule saved anyway")

    rule = BlockRule(
        name=getattr(args, "name", None) or process_name,
        block_type=BlockType.APP,
        process_name=process_name,
        block_mode=mode,
        status=BlockStatus.ACTIVE,
    )
    rule_id = db.add_rule(rule)
    rule.id = rule_id

    if is_helper_available():
        bm.activate_rule(rule)
        print(f"  Blocking app: {rule.name} [{mode}] (id={rule_id})")
    else:
        print(f"  Saved: {rule.name} (id={rule_id}) — helper not installed")


def cmd_unblock(args, db: Database, bm: BlockManager) -> None:
    target = args.target  # domain name, process name, or rule id
    rules = db.get_all_rules()

    matched = [
        r for r in rules
        if str(r.id) == target
        or r.domain == target
        or r.process_name == target
        or r.name == target
    ]

    if not matched:
        print(f"  No rule matching '{target}'")
        sys.exit(1)

    for rule in matched:
        bm.delete_rule(rule)
        print(f"  Unblocked: {rule.name} (id={rule.id})")


def cmd_category(args, db: Database, bm: BlockManager) -> None:
    action = args.cat_action
    cat_id = getattr(args, "category_id", None)

    if action == "list" or cat_id is None:
        cmd_list(type("A", (), {"target": "categories"})(), db, bm)
        return

    if cat_id not in CATEGORIES:
        print(f"  Unknown category '{cat_id}'. Valid: {', '.join(CATEGORIES)}")
        sys.exit(1)

    if action == "block":
        smart = getattr(args, "smart", False)
        if not is_helper_available():
            print("  Error: helper not installed — run install.sh")
            sys.exit(1)
        bm.activate_category(cat_id, smart_detect=smart)
        smart_msg = " with Smart Detection (DNS redirect)" if smart else ""
        print(f"  Category blocked: {CATEGORIES[cat_id]['name']}{smart_msg}")
        print(f"  Domains blocked: {len(CATEGORIES[cat_id]['domains'])}")

    elif action == "unblock":
        bm.deactivate_category(cat_id)
        print(f"  Category unblocked: {CATEGORIES[cat_id]['name']}")


def cmd_schedule_list(args, db: Database, bm: BlockManager) -> None:
    schedules = db.get_schedules()
    if not schedules:
        print("  No schedules.")
        return
    print(f"\n  {'ID':>3}  {'NAME':<20} {'TIME':<15} {'RECURRENCE'}")
    print("  " + "─" * 55)
    for s in schedules:
        status = "●" if s.active else "○"
        print(f"  {status} {s.id:>3}  {s.name:<20} {s.start_time}-{s.end_time:<9} {s.recurrence.value}")
    print()


def cmd_schedule_add(args, db: Database, bm: BlockManager) -> None:
    days_arg = getattr(args, "days", "weekdays")
    if days_arg in ("mon-fri", "weekdays"):
        recurrence = RecurrenceType.WEEKDAYS
        mask = 0b0011111
    elif days_arg in ("sat-sun", "weekends"):
        recurrence = RecurrenceType.WEEKENDS
        mask = 0b1100000
    elif days_arg == "daily":
        recurrence = RecurrenceType.DAILY
        mask = 0b1111111
    else:
        recurrence = RecurrenceType.CUSTOM
        day_map = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
        mask = 0
        for day in days_arg.split(","):
            idx = day_map.get(day.strip().lower())
            if idx is not None:
                mask |= (1 << idx)

    schedule = Schedule(
        name=args.name,
        recurrence=recurrence,
        weekday_mask=mask,
        start_time=args.start,
        end_time=args.end,
    )
    sched_id = db.add_schedule(schedule)
    print(f"  Schedule created: '{args.name}' {args.start}-{args.end} {days_arg} (id={sched_id})")


# ── Main entry point ─────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="blocky-cli",
        description="Blocky — block apps and websites from the command line",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # status
    sub.add_parser("status", help="Show current blocking status")

    # list [categories]
    list_p = sub.add_parser("list", help="List block rules or categories")
    list_p.add_argument("target", nargs="?", choices=["categories"], help="What to list")

    # block website <domain>
    block_p = sub.add_parser("block", help="Add a block rule")
    block_sub = block_p.add_subparsers(dest="block_type", required=True)

    web_p = block_sub.add_parser("website", help="Block a website")
    web_p.add_argument("domain", help="Domain to block (e.g. reddit.com)")
    web_p.add_argument("--deep", action="store_true", help="Also add iptables IP block")

    app_p = block_sub.add_parser("app", help="Block an application")
    app_p.add_argument("process_name", help="Process name to block (e.g. zen-bin, firefox)")
    app_p.add_argument("--mode", choices=["network", "kill", "strict"],
                       default="strict", help="Block mode (default: strict)")
    app_p.add_argument("--name", help="Display name for the rule")

    # unblock <target>
    unblock_p = sub.add_parser("unblock", help="Remove a block rule")
    unblock_p.add_argument("target", help="Domain, process name, rule name, or rule id")

    # category block/unblock <id>
    cat_p = sub.add_parser("category", help="Manage category blocks")
    cat_sub = cat_p.add_subparsers(dest="cat_action", required=True)

    cat_list = cat_sub.add_parser("list", help="List all categories")

    cat_block = cat_sub.add_parser("block", help="Block a category")
    cat_block.add_argument("category_id", choices=list(CATEGORIES.keys()))
    cat_block.add_argument("--smart", action="store_true",
                           help="Enable Smart Detection (DNS redirect, adult only)")

    cat_unblock = cat_sub.add_parser("unblock", help="Unblock a category")
    cat_unblock.add_argument("category_id", choices=list(CATEGORIES.keys()))

    # schedule list / add
    sched_p = sub.add_parser("schedule", help="Manage schedules")
    sched_sub = sched_p.add_subparsers(dest="sched_action", required=True)
    sched_sub.add_parser("list", help="List schedules")
    sched_add = sched_sub.add_parser("add", help="Create a schedule")
    sched_add.add_argument("name", help="Schedule name")
    sched_add.add_argument("start", help="Start time HH:MM")
    sched_add.add_argument("end", help="End time HH:MM")
    sched_add.add_argument("--days", default="weekdays",
                           help="Days: weekdays, weekends, daily, or mon,tue,wed,...  (default: weekdays)")

    args = parser.parse_args()
    db, bm = _get_backend()

    try:
        if args.command == "status":
            cmd_status(args, db, bm)
        elif args.command == "list":
            cmd_list(args, db, bm)
        elif args.command == "block":
            if args.block_type == "website":
                cmd_block_website(args, db, bm)
            elif args.block_type == "app":
                cmd_block_app(args, db, bm)
        elif args.command == "unblock":
            cmd_unblock(args, db, bm)
        elif args.command == "category":
            cmd_category(args, db, bm)
        elif args.command == "schedule":
            if args.sched_action == "list":
                cmd_schedule_list(args, db, bm)
            elif args.sched_action == "add":
                cmd_schedule_add(args, db, bm)
    finally:
        bm.stop()
        db.close()


if __name__ == "__main__":
    main()
