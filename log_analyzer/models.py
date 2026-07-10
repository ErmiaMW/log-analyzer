from dataclasses import dataclass
from datetime import datetime


@dataclass()
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    endpoint: str
    protocol: str
    status: int
    response_size: int | None
    referrer: str
    user_agent: str