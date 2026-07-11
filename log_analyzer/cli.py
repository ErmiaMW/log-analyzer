import argparse
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from time import perf_counter

from log_analyzer.analyzer import analyze_file
from log_analyzer.reporter import build_text_report, build_json_report
from log_analyzer.detector import detect_anomalies


def positive_integer(value: str) -> int:

    number = int(value)

    if number <= 0:
        raise argparse.ArgumentTypeError(
            "value must be greater than zero"
        )

    return number


def parse_iso_datetime(value: str) -> datetime:

    normalized_value = (
        f"{value[:-1]}+00:00"
        if value.endswith("Z")
        else value
    )

    try:
        parsed_value = datetime.fromisoformat(normalized_value)

    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "use ISO 8601 format, for example: "
            "2026-06-01T09:00:00+00:00"
        ) from error

    if (parsed_value.tzinfo is None or parsed_value.utcoffset() is None):
        raise argparse.ArgumentTypeError(
            "datetime must include a timezone"
        )

    return parsed_value


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
        help="Number of top results. Default: 10.",
    )

    parser.add_argument(
        "--from",
        dest="start_time",
        type=parse_iso_datetime,
        metavar="DATETIME",
        help="Include requests from this datetime.",
    )

    parser.add_argument(
        "--to",
        dest="end_time",
        type=parse_iso_datetime,
        metavar="DATETIME",
        help="Exclude requests  from this datetime onward.",
    )
    
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Save  a JSON report to  report.json",
        )
    
    parser.add_argument(
        "--login-threshold",
        type=positive_integer,
        default=20,
        metavar="N",
        help=(
            "Minimum failed /login and attempts for suspicious activity. Default: 20."),
    )

    return parser


def main(argv: Sequence[str] | None = None,) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if (args.start_time is not None and args.end_time is not None and args.start_time >= args.end_time):
        parser.error(
            "--from must be earlier than --to"
        )

    start = perf_counter()

    result = analyze_file(args.log_file, start_time=args.start_time, end_time=args.end_time, )
    
    detections = detect_anomalies(result, login_failure_threshold=(args.login_threshold),)

    execution_time = perf_counter() - start

    report = build_text_report(result, top_n=args.top, execution_time=execution_time, detections=detections,)

    if args.json_output:
        json_report = build_json_report(result, top_n=args.top, execution_time=execution_time, detections=detections,)

        output_path = Path("report.json")

        output_path.write_text(json_report + "\n", encoding="utf-8",)

        print(
            f"\nJSON report saved to: "
            f"{output_path.resolve()}"
        )

    print(report)    
    
    return 0