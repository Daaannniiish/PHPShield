
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_report(detection, findings, output_dir, freshness_warnings=None):
    """Save a PHPShield assessment as a JSON report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report = {
        "tool": "PHPShield",
        "generated_at": datetime.now(timezone.utc).isoformat(),

        "assessment": {
            "type": "PHP version advisory matching",
            "detected_version": detection.get("version"),
            "detection_message": detection.get("message"),
            "advisories_checked": [
                "CVE-2026-109618",
                "CVE-2026-109619"
            ],
            "coverage_limitations": [
                "The database currently checks only the two listed advisories.",
                "Other PHP vulnerabilities may not be covered.",
                "PHP runtimes used by web servers may differ from the detected CLI version.",
                "Vendor backported fixes are not independently verified."
            ]
        },

        "finding_count": len(findings),
        "findings": findings,
        "freshness_warnings": freshness_warnings or [],

        "assessment_note": (
            "No matching advisory ranges were found. "
            "This does not prove the installation is secure. "
            "The assessment is limited to the configured advisory data."
            if not findings
            else
            "Potential advisory matches were found. Verify the official "
            "advisories, installed build, vendor patches, and affected deployment."
        )
    }

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    report_file = output_path / f"php_shield_report_{timestamp}.json"

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report_file
