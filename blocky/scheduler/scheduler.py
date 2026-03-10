import logging
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from blocky.models.block_rule import BlockRule, BlockStatus
from blocky.models.schedule import RecurrenceType, Schedule

logger = logging.getLogger(__name__)

# Bitmask: bit 0 = Monday, bit 6 = Sunday
_DOW_MAP = {0: "mon", 1: "tue", 2: "wed", 3: "thu", 4: "fri", 5: "sat", 6: "sun"}


def _mask_to_dow(mask: int) -> str:
    days = [_DOW_MAP[i] for i in range(7) if mask & (1 << i)]
    return ",".join(days) if days else "mon-sun"


def _recurrence_to_dow(recurrence: RecurrenceType, mask: int) -> str:
    if recurrence == RecurrenceType.DAILY:
        return "mon-sun"
    if recurrence == RecurrenceType.WEEKDAYS:
        return "mon-fri"
    if recurrence == RecurrenceType.WEEKENDS:
        return "sat,sun"
    if recurrence == RecurrenceType.CUSTOM:
        return _mask_to_dow(mask)
    return "mon-sun"


def is_schedule_in_window(schedule: Schedule) -> bool:
    """Check if the current time falls within a schedule's active window."""
    if not schedule.active:
        return False
    now = datetime.now()
    current_dow = now.strftime("%a").lower()[:3]
    dow = _recurrence_to_dow(schedule.recurrence, schedule.weekday_mask)
    if current_dow not in dow:
        return False
    start_h, start_m = (int(x) for x in schedule.start_time.split(":"))
    end_h, end_m = (int(x) for x in schedule.end_time.split(":"))
    start_mins = start_h * 60 + start_m
    end_mins = end_h * 60 + end_m
    now_mins = now.hour * 60 + now.minute
    return start_mins <= now_mins < end_mins


class BlockScheduler:
    def __init__(self) -> None:
        self._scheduler = BackgroundScheduler(
            job_defaults={"misfire_grace_time": 60}
        )
        self._block_manager = None

    def set_block_manager(self, bm) -> None:
        self._block_manager = bm

    def start(self) -> None:
        self._scheduler.start()
        logger.info("BlockScheduler started")

    def stop(self) -> None:
        self._scheduler.shutdown(wait=False)

    def add_schedule(self, rule: BlockRule, schedule: Schedule) -> None:
        if not schedule.active:
            return
        dow = _recurrence_to_dow(schedule.recurrence, schedule.weekday_mask)
        start_h, start_m = schedule.start_time.split(":")
        end_h, end_m = schedule.end_time.split(":")

        self._scheduler.add_job(
            self._activate,
            CronTrigger(day_of_week=dow, hour=int(start_h), minute=int(start_m)),
            args=[rule.id],
            id=f"on_{rule.id}",
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._deactivate,
            CronTrigger(day_of_week=dow, hour=int(end_h), minute=int(end_m)),
            args=[rule.id],
            id=f"off_{rule.id}",
            replace_existing=True,
        )
        logger.info(
            "Scheduled rule %d: %s %s-%s on %s",
            rule.id, rule.name, schedule.start_time, schedule.end_time, dow,
        )

        # Check if we're currently within the window and should activate now
        self._maybe_activate_now(rule, schedule, dow)

    def remove_schedule(self, rule_id: int) -> None:
        for job_id in (f"on_{rule_id}", f"off_{rule_id}"):
            try:
                self._scheduler.remove_job(job_id)
            except Exception:
                pass

    def _activate(self, rule_id: int) -> None:
        if not self._block_manager:
            return
        rule = self._block_manager.db.get_rule(rule_id)
        if rule:
            logger.info("Schedule: activating rule %d (%s)", rule_id, rule.name)
            self._block_manager.activate_rule(rule)

    def _deactivate(self, rule_id: int) -> None:
        if not self._block_manager:
            return
        rule = self._block_manager.db.get_rule(rule_id)
        if rule:
            logger.info("Schedule: deactivating rule %d (%s)", rule_id, rule.name)
            self._block_manager.deactivate_rule(rule)

    def _maybe_activate_now(
        self, rule: BlockRule, schedule: Schedule, dow: str
    ) -> None:
        """Activate the rule immediately if we're currently within its window."""
        if is_schedule_in_window(schedule):
            self._activate(rule.id)

    def reload_schedules(self, rules: list[BlockRule], schedules: list[Schedule]) -> None:
        """Clear all scheduled jobs and re-register from DB."""
        self._scheduler.remove_all_jobs()
        sched_map = {s.id: s for s in schedules}
        for rule in rules:
            if rule.schedule_id and rule.schedule_id in sched_map:
                self.add_schedule(rule, sched_map[rule.schedule_id])
