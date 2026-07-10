from collections import Counter
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from log_analyzer.models import AnalysisResult,LogEntry
from log_analyzer.parser import parse_log_line
from log_analyzer.reader import open_log_file


class LogAnalyzer:

    def __init__(self) -> None:
        self._total_lines = 0
        self._total_requests = 0
        self._malformed_lines = 0
        self._filtered_requests = 0

        self._unique_ips: set[str] = set()

        self._endpoint_counts: Counter[str] = Counter()
        self._ip_counts: Counter[str] = Counter()
        self._hourly_requests: Counter[datetime] = Counter()

        self._client_error_count = 0
        self._server_error_count = 0
        
        self._login_401_counts: Counter[str] = Counter()
        self._hourly_5xx_counts: Counter[datetime] = Counter()

    def add_entry(self, entry: LogEntry) -> None:

        self._total_lines += 1
        self._total_requests += 1

        self._unique_ips.add(entry.ip)

        self._endpoint_counts[entry.endpoint] += 1
        self._ip_counts[entry.ip] += 1

        hour = entry.timestamp.replace(minute=0,second=0,microsecond=0,)

        self._hourly_requests[hour] += 1

        if (entry.status == 401 and entry.endpoint == "/login"):
            self._login_401_counts[entry.ip] += 1
        
        if 400 <= entry.status < 500:
            self._client_error_count += 1

        elif 500 <= entry.status < 600:
            self._server_error_count += 1
            self._hourly_5xx_counts[hour] += 1

    def add_malformed_line(self) -> None:

        self._total_lines += 1
        self._malformed_lines += 1

    def add_filtered_request(self) -> None:

        self._total_lines += 1
        self._filtered_requests += 1

    def build_result(self) -> AnalysisResult:

        return AnalysisResult(
            total_lines=self._total_lines,
            total_requests=self._total_requests,
            malformed_lines=self._malformed_lines,
            unique_ip_count=len(self._unique_ips),
            endpoint_counts=Counter(
                self._endpoint_counts
            ),
            ip_counts=Counter(
                self._ip_counts
            ),
            hourly_requests=Counter(
                self._hourly_requests
            ),
            client_error_count=(
                self._client_error_count
            ),
            server_error_count=(
                self._server_error_count
            ),
            filtered_requests=(
                self._filtered_requests
            ),
            login_401_counts=Counter(
                self._login_401_counts
            ),
            hourly_5xx_counts=Counter(
                self._hourly_5xx_counts
            ),
        )


def _is_in_time_range(timestamp: datetime,start_time: datetime | None,end_time: datetime | None,) -> bool:

    if (start_time is not None and timestamp < start_time):
        return False

    if (end_time is not None and timestamp >= end_time):
        return False

    return True


def analyze_lines(lines: Iterable[str],start_time: datetime | None = None,end_time: datetime | None = None,) -> AnalysisResult:

    analyzer = LogAnalyzer()

    for line in lines:
        entry = parse_log_line(line)

        if entry is None:
            analyzer.add_malformed_line()
            continue

        if not _is_in_time_range(entry.timestamp,start_time,end_time,):
            analyzer.add_filtered_request()
            continue

        analyzer.add_entry(entry)

    return analyzer.build_result()


def analyze_file(path: Path,start_time: datetime | None = None,end_time: datetime | None = None,) -> AnalysisResult:

    with open_log_file(path) as log_file:
        return analyze_lines(
            log_file,
            start_time=start_time,
            end_time=end_time,
        )