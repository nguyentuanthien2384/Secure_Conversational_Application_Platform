"""Run the offline security feedback loop: python -m scripts.validate_security."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.app.security_validation import SCENARIOS, run_validation, write_reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate SCAP controls against isolated local scenarios (no remote targets)")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/security-validation"))
    parser.add_argument("--scenario", action="append", choices=[item.identifier for item in SCENARIOS], help="Run only this scenario; may be repeated")
    args = parser.parse_args(argv)
    report = run_validation(args.scenario)
    json_path, junit_path = write_reports(report, args.output_dir)
    print(f"Security validation: {report['passed_scenarios']}/{report['total_scenarios']} passed")
    for item in report["scenarios"]:
        print(f"  {item['status'].upper()}: {item['id']}")
    print(f"JSON: {json_path}\nJUnit: {junit_path}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
