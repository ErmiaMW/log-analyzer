from collections import Counter
from datetime import datetime
import json

from log_analyzer.models import AnalysisResult
from log_analyzer.detector import DetectionResult

HISTOGRAM_WIDTH = 40


def _top_items(counts: Counter[str],limit: int,) -> list[tuple[str, int]]:

    return sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0]),
    )[:limit]


def _build_ranked_section(title: str,counts: Counter[str],limit: int,) -> list[str]:

    lines = [title, "-" * len(title),]

    items = _top_items(counts, limit)

    if not items:
        lines.append("No data.")
        return lines

    for rank, (name, count) in enumerate(items, start=1,):
        lines.append(
            f"{rank:>2}. {name:<35} {count:>10,}"
        )

    return lines


def _format_hour(hour: datetime) -> str:
    return hour.strftime("%Y-%m-%d %H:00 %z")


def _aggregate_by_hour(hourly_requests: Counter[datetime],) -> Counter[int]:

    hourly_counts: Counter[int] = Counter({hour: 0 for hour in range(24)})

    for timestamp, count in (hourly_requests.items()):
        hourly_counts[timestamp.hour] += count

    return hourly_counts


def _build_hourly_section(hourly_requests: Counter[datetime],) -> list[str]:

    lines = [
        "Hourly Traffic",
        "--------------",
    ]

    if not hourly_requests:
        lines.append("No data.")
        return lines

    hourly_counts = (
        _aggregate_by_hour(
            hourly_requests
        )
    )

    maximum = max(
        hourly_counts.values()
    )

    for hour in range(24):
        count = hourly_counts[hour]

        bar_length = (
            round(
                count
                / maximum
                * HISTOGRAM_WIDTH
            )
            if count > 0
            else 0
        )

        bar = "█" * bar_length

        lines.append(
            f"{hour:02d} - "
            f"{bar:<{HISTOGRAM_WIDTH}} "
            f"{count:>10,}"
        )

    return lines


def _find_peak_hour(hourly_requests: Counter[datetime],) -> tuple[datetime, int] | None:
    if not hourly_requests:
        return None

    return min(hourly_requests.items(), key=lambda item: (-item[1], item[0], ), )


def _find_quiet_hour(hourly_requests: Counter[datetime],) -> tuple[datetime, int] | None:
    if not hourly_requests:
        return None

    return min(hourly_requests.items(), key=lambda item: (item[1], item[0], ),)


def _build_security_section(detections: DetectionResult,) -> list[str]:

    lines = [
        "Security Findings",
        "-----------------",
        "Suspicious Login Activity",
    ]

    if detections.suspicious_logins:
        for finding in (
            detections.suspicious_logins
        ):
            lines.append(
                f"- {finding.ip}: "
                f"{finding.failed_attempts:,} "
                "failed /login attempts "
                "(401)"
            )
    else:
        lines.append(
            "No suspicious login "
            "activity detected."
        )

    lines.extend(
        [
            "",
            "5xx Error Spikes",
        ]
    )

    if detections.server_error_spikes:
        for spike in (
            detections.server_error_spikes
        ):
            lines.append(
                f"- {_format_hour(spike.hour)}: "
                f"{spike.error_count:,}/"
                f"{spike.total_requests:,} "
                "requests "
                f"({spike.error_rate_percent:.2f}%)"
            )
    else:
        lines.append(
            "No 5xx error spikes detected."
        )

    return lines


def build_text_report(
    result: AnalysisResult,
    top_n: int = 10,
    execution_time: float = 0.0,
    detections: DetectionResult | None = None,
) -> str:
    
    lines = [
        "Log Analysis Report",
        "===================",
        (
        f"{'Execution Time:':<25}"
        f"{execution_time:>10.3f} s"
        ),
        "",
        "Summary",
        "-------",
        (
            f"{'Total Lines:':<25}"
            f"{result.total_lines:>12,}"
        ),
        (
            f"{'Total Requests:':<25}"
            f"{result.total_requests:>12,}"
        ),
        (
        f"{'Filtered Requests:':<25}"
        f"{result.filtered_requests:>12,}"
        ),
        (
            f"{'Malformed Lines:':<25}"
            f"{result.malformed_lines:>12,}"
        ),
        (
            f"{'Unique IPs:':<25}"
            f"{result.unique_ip_count:>12,}"
        ),
        (
            f"{'4xx Responses:':<25}"
            f"{result.client_error_count:>12,}"
        ),
        (
            f"{'5xx Responses:':<25}"
            f"{result.server_error_count:>12,}"
        ),
        (
            f"{'Error Rate:':<25}"
            f"{result.error_rate:>11.2f}%"
        ),
        "",
    ]

    lines.extend(
        _build_ranked_section(
            f"Top {top_n} Endpoints",
            result.endpoint_counts,
            top_n,
        )
    )

    lines.append("")

    lines.extend(
        _build_ranked_section(
            f"Top {top_n} IPs",
            result.ip_counts,
            top_n,
        )
    )

    lines.append("")

    lines.extend(
        _build_hourly_section(
            result.hourly_requests
        )
    )

    peak = _find_peak_hour(
        result.hourly_requests
    )

    quiet = _find_quiet_hour(
        result.hourly_requests
    )

    if peak is not None and quiet is not None:
        lines.extend(
            [
                "",
                (
                    "Peak Hour: "
                    f"{_format_hour(peak[0])} "
                    f"({peak[1]:,} requests)"
                ),
                (
                    "Quiet Hour: "
                    f"{_format_hour(quiet[0])} "
                    f"({quiet[1]:,} requests)"
                ),
            ]
        )

    if detections is not None:
        lines.append("")

        lines.extend(
            _build_security_section(
                detections
            )
        )
    
    return "\n".join(lines)

def build_json_report(
    result: AnalysisResult,
    top_n: int = 10,
    execution_time: float = 0.0,
    detections: DetectionResult | None = None,
) -> str:
    
    hourly_counts = _aggregate_by_hour(
        result.hourly_requests
    )

    peak = _find_peak_hour(
        result.hourly_requests
    )

    quiet = _find_quiet_hour(
        result.hourly_requests
    )
    
    if detections is None:
        detections = DetectionResult()

    payload = {
        "summary": {
            "total_lines": result.total_lines,
            "total_requests": result.total_requests,
            "filtered_requests": (
                result.filtered_requests
            ),
            "malformed_lines": (
                result.malformed_lines
            ),
            "unique_ips": (
                result.unique_ip_count
            ),
            "client_errors_4xx": (
                result.client_error_count
            ),
            "server_errors_5xx": (
                result.server_error_count
            ),
            "error_count": result.error_count,
            "error_rate_percent": round(
                result.error_rate,
                2,
            ),
            "execution_time_seconds": round(
                execution_time,
                6,
            ),
        },
        "top_endpoints": [
            {
                "endpoint": endpoint,
                "requests": count,
            }
            for endpoint, count in _top_items(
                result.endpoint_counts,
                top_n,
            )
        ],
        "top_ips": [
            {
                "ip": ip,
                "requests": count,
            }
            for ip, count in _top_items(
                result.ip_counts,
                top_n,
            )
        ],
        "hourly_traffic": {
            f"{hour:02d}": hourly_counts[hour]
            for hour in range(24)
        },
        "peak_hour": (
            None
            if peak is None
            else {
                "timestamp": (
                    peak[0].isoformat()
                ),
                "requests": peak[1],
            }
        ),
        "quiet_hour": (
            None
            if quiet is None
            else {
                "timestamp": (
                    quiet[0].isoformat()
                ),
                "requests": quiet[1],
            }
        ),
        "security_findings": {
            "suspicious_logins": [
                {
                    "ip": finding.ip,
                    "failed_attempts": (
                        finding.failed_attempts
                    ),
                }
                for finding
                in detections.suspicious_logins
            ],
            "server_error_spikes": [
                {
                    "timestamp": (
                        spike.hour.isoformat()
                    ),
                    "total_requests": (
                        spike.total_requests
                    ),
                    "server_errors_5xx": (
                        spike.error_count
                    ),
                    "error_rate_percent": round(
                        spike.error_rate_percent,
                        2,
                    ),
                    "baseline_rate_percent": round(
                        spike.baseline_rate_percent,
                        2,
                    ),
                }
                for spike
                in detections.server_error_spikes
            ],
        },
    }

    return json.dumps(
        payload,
        indent=2,
        ensure_ascii=False,
    )
