import argparse
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter

from log_analyzer.analyzer import analyze_file
from log_analyzer.reporter import (
    build_text_report,
)


def positive_integer(value: str) -> int:

    number = int(value)

    if number <= 0:
        raise argparse.ArgumentTypeError(
            "value must be greater than zero"
        )

    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
    )

    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to log file.",
    )

    parser.add_argument(
        "--top",
        type=positive_integer,
        default=10,
        metavar="N",
        help=(
            "Number of top endpoints and "
            "IPs in report. Default: 10."
        ),
    )

    return parser


def main(
    argv: Sequence[str] | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    start_time = perf_counter()

    result = analyze_file(
        args.log_file
    )

    execution_time = (
        perf_counter() - start_time
    )

    report = build_text_report(
        result,
        top_n=args.top,
        execution_time=execution_time,
    )

    print(report)

    return 0