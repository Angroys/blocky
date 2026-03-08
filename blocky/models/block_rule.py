from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Optional


class BlockType(Enum):
    WEBSITE = "website"
    APP = "app"


class BlockStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    SCHEDULED = "scheduled"


@dataclass
class BlockRule:
    name: str
    block_type: BlockType
    id: Optional[int] = None
    # Website fields
    domain: Optional[str] = None
    extra_domains: list[str] = field(default_factory=list)
    block_ip_layer: bool = False
    # App fields
    exe_path: Optional[str] = None
    process_name: Optional[str] = None
    block_mode: str = "network"   # "network" | "kill"
    # Common
    status: BlockStatus = BlockStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.now)
    schedule_id: Optional[int] = None
    notes: str = ""
