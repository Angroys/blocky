from dataclasses import dataclass
from enum import Enum
from typing import Optional


class RecurrenceType(Enum):
    ONCE = "once"
    DAILY = "daily"
    WEEKDAYS = "weekdays"
    WEEKENDS = "weekends"
    CUSTOM = "custom"


@dataclass
class Schedule:
    name: str
    recurrence: RecurrenceType
    start_time: str       # "HH:MM"
    end_time: str         # "HH:MM"
    id: Optional[int] = None
    weekday_mask: int = 0b0111110  # Mon-Fri default (bits 1-5)
    active: bool = True
    strict: bool = False
