
from pathlib import Path

from src.version_detector import detect_php_version
from src.advisory_matcher import (
    load_advisories,
    match_advisories,
    check_advisory_freshness
)
from src.report_generator import generate_report
import json

def display_findings(findings):
    """Display potential advisory matches and remediation guidance."""

    if not findings:
        print("\nNo matching advisory ranges were found.")
        print("This does not prove the installation is secure.")
        return

    print("\nPotential vulnerability matches:")

    for finding in findings:
        print(f"\n  Advisory: {finding['id']}")
        print(f"  Title: {finding['title']}")
        print(f"  Severity: {finding['severity']}")
        print(f"  Fixed version: {finding['fixed_version']}")
        print(f"  Status: {finding['status']}")
        print(f"  Remediation: {finding['remediation']}")
        print(f"  Source: {finding['source']}")

    print("\nAssessment: Matching advisory ranges found.")
    print("Review the official advisories and deployment details.")



def main():
    project_root = Path(__file__).resolve().parent
    advisory_file = project_root / "data" / "sample_advisories.json"

    print("=" * 55)
    print("PHPShield - PHP Vulnerability Assessment")
    print("=" * 55)

    detection = detect_php_version()

    if not detection["installed"] or not detection["version"]:
        print("\nPHP version detection failed.")
        print(detection["message"])
        return

    version = detection["version"]

    print(f"\nDetected PHP version: {version}")

    try:
        advisories = load_advisories(advisory_file)
    except FileNotFoundError:
        print("\nERROR: Advisory database file was not found.")
        print(f"Expected location: {advisory_file}")
        return
    except json.JSONDecodeError:
        print("\nERROR: Advisory database contains invalid JSON.")
        print("Check the JSON syntax in the advisory database.")
        return
    except (ValueError, OSError) as exc:
        print(f"\nERROR: Could not load advisory database: {exc}")
        return

    freshness_warnings = check_advisory_freshness(advisories)

    if freshness_warnings:
        print("\nAdvisory data freshness warnings:")

        for warning in freshness_warnings:
            print(f"  WARNING: {warning}")
    else:
        print("\nAdvisory data freshness: All entries are within the 30-day threshold.")

    findings = match_advisories(version, advisories)    

    display_findings(findings)

    # Generate and save the assessment report
    report_file = generate_report(
    detection,
    findings,
    project_root / "reports",
    freshness_warnings=freshness_warnings
)

    print(f"\nJSON report saved to: {report_file}")
    print("=" * 55)


if __name__ == "__main__":
    main()
