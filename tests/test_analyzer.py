import unittest
from datetime import datetime, timezone

from log_analyzer.analyzer import analyze_lines


def make_log_line(
    *,
    ip: str,
    timestamp: str,
    endpoint: str,
    status: int,
) -> str:
    return (
        f'{ip} - - '
        f'[{timestamp}] '
        f'"GET {endpoint} HTTP/1.1" '
        f'{status} 100 "-" "test-agent"'
    )


class AnalyzeLinesTests(unittest.TestCase):

    def test_aggregates_log_statistics(self) -> None:
        lines = [
            make_log_line(
                ip="203.0.113.1",
                timestamp=(
                    "01/Jun/2026:"
                    "09:15:00 +0000"
                ),
                endpoint="/products?page=1",
                status=200,
            ),
            make_log_line(
                ip="203.0.113.1",
                timestamp=(
                    "01/Jun/2026:"
                    "09:45:00 +0000"
                ),
                endpoint="/products?page=2",
                status=404,
            ),
            make_log_line(
                ip="203.0.113.2",
                timestamp=(
                    "01/Jun/2026:"
                    "10:05:00 +0000"
                ),
                endpoint="/health",
                status=500,
            ),
            "malformed log line",
        ]

        result = analyze_lines(lines)

        self.assertEqual(
            result.total_lines,
            4,
        )

        self.assertEqual(
            result.total_requests,
            3,
        )

        self.assertEqual(
            result.malformed_lines,
            1,
        )

        self.assertEqual(
            result.unique_ip_count,
            2,
        )

        self.assertEqual(
            result.endpoint_counts["/products"],
            2,
        )

        self.assertEqual(
            result.ip_counts["203.0.113.1"],
            2,
        )

        self.assertEqual(
            result.client_error_count,
            1,
        )

        self.assertEqual(
            result.server_error_count,
            1,
        )

        self.assertAlmostEqual(
            result.error_rate,
            66.67,
            places=2,
        )

        hour = datetime(
            2026,
            6,
            1,
            9,
            tzinfo=timezone.utc,
        )

        self.assertEqual(
            result.hourly_requests[hour],
            2,
        )

    def test_handles_empty_input(self) -> None:
        result = analyze_lines([])

        self.assertEqual(
            result.total_requests,
            0,
        )

        self.assertEqual(
            result.error_rate,
            0.0,
        )


if __name__ == "__main__":
    unittest.main()