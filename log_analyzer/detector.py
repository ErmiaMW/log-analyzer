from dataclasses import dataclass
from datetime import datetime
from statistics import median

from log_analyzer.models import AnalysisResult


DEFAULT_LOGIN_FAILURE_THRESHOLD = 20

MIN_REQUESTS_PER_HOUR = 100
MIN_5XX_ERRORS = 10
MIN_5XX_RATE_PERCENT = 5.0
SPIKE_MULTIPLIER = 2.0


@dataclass()
class SuspiciousLoginFinding:
    ip: str
    failed_attempts: int


@dataclass()
class ServerErrorSpike:
    hour: datetime
    total_requests: int
    error_count: int
    error_rate_percent: float
    baseline_rate_percent: float


@dataclass()
class DetectionResult:
    suspicious_logins: tuple[SuspiciousLoginFinding, ...] = ()

    server_error_spikes: tuple[ServerErrorSpike, ...] = ()


def detect_suspicious_logins(
    result: AnalysisResult,
    threshold: int = (DEFAULT_LOGIN_FAILURE_THRESHOLD),) -> tuple[SuspiciousLoginFinding, ...]:

    suspicious_items = [
        (ip, count)
        for ip, count
        in result.login_401_counts.items()
        if count >= threshold
    ]

    suspicious_items.sort(
        key=lambda item: (
            -item[1],
            item[0],
        )
    )

    return tuple(
        SuspiciousLoginFinding(ip=ip, failed_attempts=count,)
        for ip, count in suspicious_items
    )


def detect_5xx_spikes(result: AnalysisResult,) -> tuple[ServerErrorSpike, ...]:

    eligible_hours = [
        (hour, request_count)
        for hour, request_count
        in result.hourly_requests.items()
        if (request_count>= MIN_REQUESTS_PER_HOUR)
    ]

    if len(eligible_hours) < 2:
        return ()

    hourly_rates = [
        (result.hourly_5xx_counts[hour] / request_count* 100)
        for hour, request_count
        in eligible_hours
    ]

    baseline_rate = median(
        hourly_rates
    )

    spike_rate = max(
        MIN_5XX_RATE_PERCENT, baseline_rate * SPIKE_MULTIPLIER,)

    spikes: list[ServerErrorSpike] = []

    for hour, request_count in sorted(eligible_hours):
        error_count = (result.hourly_5xx_counts[hour])

        error_rate = (error_count / request_count* 100)
        
        if (error_count >= MIN_5XX_ERRORS and error_rate >= spike_rate):
            
            spikes.append(
                ServerErrorSpike(
                    hour=hour,total_requests=(request_count),
                    error_count=(error_count),
                    error_rate_percent=(error_rate),
                    baseline_rate_percent=(baseline_rate),
                )
            )

    return tuple(spikes)


def detect_anomalies(result: AnalysisResult, login_failure_threshold: int = (DEFAULT_LOGIN_FAILURE_THRESHOLD),) -> DetectionResult:

    return DetectionResult(
        suspicious_logins=(
            detect_suspicious_logins(
                result,
                threshold=(
                    login_failure_threshold
                ),
            )
        ),
        server_error_spikes=(
            detect_5xx_spikes(result)
        ),
    )