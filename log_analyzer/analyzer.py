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

        self._unique_ips: set[str] = set()

        self._endpoint_counts: Counter[str] = Counter()
        self._ip_counts: Counter[str] = Counter()
        self._hourly_requests: Counter[datetime] = Counter()

        self._client_error_count = 0
        self._server_error_count = 0

    def add_entry(self, entry: LogEntry) -> None:

        self._total_lines += 1
        self._total_requests += 1

        self._unique_ips.add(entry.ip)

        self._endpoint_counts[entry.endpoint] += 1
        self._ip_counts[entry.ip] += 1

        hour = entry.timestamp.replace(
            minute=0,
            second=0,
            microsecond=0,
        )

        self._hourly_requests[hour] += 1

        if 400 <= entry.status < 500:
            self._client_error_count += 1

        elif 500 <= entry.status < 600:
            self._server_error_count += 1

    def add_malformed_line(self) -> None:

        self._total_lines += 1
        self._malformed_lines += 1

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
        )


def analyze_lines(
    lines: Iterable[str],
) -> AnalysisResult:

    analyzer = LogAnalyzer()

    for line in lines:
        entry = parse_log_line(line)

        if entry is None:
            analyzer.add_malformed_line()
            continue

        analyzer.add_entry(entry)

    return analyzer.build_result()


def analyze_file(path: Path) -> AnalysisResult:

    with open_log_file(path) as log_file:
        return analyze_lines(log_file)