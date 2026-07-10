import argparse
from collections.abc import Sequence
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="log-analyzer",
    )

    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to the log file.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:

    parser = build_parser()
    args = parser.parse_args(argv)

    return 0