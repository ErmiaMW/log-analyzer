import unittest
from datetime import datetime, timezone

from log_analyzer.parser import parse_log_line


class ParseLogLineTests(unittest.TestCase):
    def test_parses_valid_log_line(self) -> None:
        line = (
            '203.0.113.42 - - '
            '[01/Jun/2026:09:14:22 +0000] '
            '"GET /products/1877 HTTP/1.1" '
            '200 5324 "-" "Mozilla/5.0"'
        )

        entry = parse_log_line(line)

        self.assertIsNotNone(entry)

        assert entry is not None

        self.assertEqual(entry.ip, "203.0.113.42")
        self.assertEqual(
            entry.timestamp,
            datetime(
                2026,
                6,
                1,
                9,
                14,
                22,
                tzinfo=timezone.utc,
            ),
        )
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.endpoint, "/products/1877")
        self.assertEqual(entry.protocol, "HTTP/1.1")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.response_size, 5324)
        self.assertEqual(entry.referrer, "-")
        self.assertEqual(entry.user_agent, "Mozilla/5.0")

    def test_returns_none_for_malformed_line(self) -> None:
        self.assertIsNone(
            parse_log_line(
                "salam"
            )
        )

    def test_removes_query_parameters(self) -> None:
        line = (
            '203.0.113.42 - - '
            '[01/Jun/2026:09:14:22 +0000] '
            '"GET /products?page=2 HTTP/1.1" '
            '200 100 "-" "curl/8.4.0"'
        )

        entry = parse_log_line(line)

        self.assertIsNotNone(entry)

        assert entry is not None

        self.assertEqual(
            entry.endpoint,
            "/products",
        )

if __name__ == "__main__":
    unittest.main()