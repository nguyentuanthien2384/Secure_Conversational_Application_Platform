"""Dedicated offline practice process: python -m scripts.practice_lab."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.app.practice_runner import STAGE_IDS, run_practice


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Thực hành SCAP cục bộ, SQLite tạm và PCAP tổng hợp")
    parser.add_argument("--stage", action="append", choices=["all", *STAGE_IDS], help="Chọn giai đoạn; có thể lặp, mặc định all")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/practice-lab"))
    args = parser.parse_args(argv)
    try:
        summary = run_practice(args.stage, args.output_dir)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"Practice lab: {summary['passed_scenarios']}/{summary['total_scenarios']} passed")
    for stage in summary["stages"]:
        print(f"  {stage['status'].upper()}: {stage['id']}")
    print(f"HTML: {args.output_dir / 'practice-report.html'}")
    print("PCAP: synthetic DNS/TCP/HTTP fixture; no live capture, no TLS")
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
