import re
from datetime import datetime

from log_analyzer.models import LogEntry


LOG_PATTERN = re.compile(
    r'^'
    r'(?P<ip>\S+) '
    r'\S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) '
    r'(?P<endpoint>\S+) '
    r'(?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\d+|-) '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
    r'$'
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def normalize_endpoint(endpoint: str) -> str:
    """Remove query parameters from an endpoint to group requests to the same resource
    under one endpoint during traffic analysis.
    
    For example /products?page=1 and /products?page=2 are both normalized to /products
    """

    return endpoint.split("?", maxsplit=1)[0]


def parse_log_line(line: str) -> LogEntry | None:

    match = LOG_PATTERN.fullmatch(line.strip())

    if match is None:
        return None

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"),
            TIMESTAMP_FORMAT,
        )

        size_value = match.group("size")
        response_size = None if size_value == "-" else int(size_value)

        return LogEntry(
            ip=match.group("ip"),
            timestamp=timestamp,
            method=match.group("method"),
            endpoint=normalize_endpoint(match.group("endpoint")),
            protocol=match.group("protocol"),
            status=int(match.group("status")),
            response_size=response_size,
            referrer=match.group("referrer"),
            user_agent=match.group("user_agent"),
        )

    except ValueError:
        return None