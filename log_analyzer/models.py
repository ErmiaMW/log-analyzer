from dataclasses import dataclass
from datetime import datetime
from collections import Counter


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
   
    
@dataclass(slots=True)
class AnalysisResult:
    total_lines: int
    total_requests: int
    malformed_lines: int
    unique_ip_count: int

    endpoint_counts: Counter[str]
    ip_counts: Counter[str]
    hourly_requests: Counter[datetime]

    client_error_count: int
    server_error_count: int

    @property
    def error_count(self) -> int:
        return (
            self.client_error_count
            + self.server_error_count
        )

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0

        return (
            self.error_count
            / self.total_requests
            * 100
        )