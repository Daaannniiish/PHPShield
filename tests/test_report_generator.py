
import json
import tempfile
import unittest
from pathlib import Path

from src.report_generator import generate_report


class ReportGeneratorTests(unittest.TestCase):

    def test_report_includes_assessment_scope_and_limitations(self):
        detection = {
            "installed": True,
            "version": "8.5.12",
            "message": "PHP version detected successfully."
        }

        findings = []

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = generate_report(
                detection,
                findings,
                temp_dir
            )

            with report_path.open("r", encoding="utf-8") as file:
                report = json.load(file)

        self.assertEqual(report["tool"], "PHPShield")
        self.assertEqual(report["assessment"]["detected_version"], "8.5.12")

        self.assertEqual(
            report["assessment"]["advisories_checked"],
            ["CVE-2026-109618", "CVE-2026-109619"]
        )

        limitations = report["assessment"]["coverage_limitations"]

        self.assertTrue(limitations)
        self.assertTrue(
            any("Other PHP vulnerabilities" in item for item in limitations)
        )
        self.assertTrue(
            any("web servers" in item for item in limitations)
        )
        self.assertTrue(
            any("backported fixes" in item for item in limitations)
        )

        self.assertEqual(report["finding_count"], 0)
        self.assertIn(
            "does not prove the installation is secure",
            report["assessment_note"]
        )
    
    def test_report_saves_freshness_warnings(self):
        detection = {
            "installed": True,
            "version": "8.5.12",
            "message": "PHP version detected successfully."
        }

        warnings = [
            "CVE-TEST-001: advisory data is 45 days old."
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = generate_report(
                detection,
                [],
                temp_dir,
                freshness_warnings=warnings
            )

            with report_path.open("r", encoding="utf-8") as file:
                report = json.load(file)

        self.assertEqual(report["freshness_warnings"], warnings)



if __name__ == "__main__":
    unittest.main()
