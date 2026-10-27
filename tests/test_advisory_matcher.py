
import json
import tempfile
import unittest
from pathlib import Path
from datetime import date
from src.advisory_matcher import load_advisories, match_advisories,check_advisory_freshness
from main import display_findings
from unittest.mock import patch
from main import main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "sample_advisories.json"


class PHP2ShellAdvisoryTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.advisories = load_advisories(DATA_FILE)

    def test_versions_before_fix_match_both_cves(self):
        cases = {
            "8.2.34": "8.2.35",
            "8.3.35": "8.3.36",
            "8.4.26": "8.4.27",
            "8.5.11": "8.5.12",
        }

        for version, fixed in cases.items():
            with self.subTest(version=version):
                matches = match_advisories(version, self.advisories)
                ids = {item["id"] for item in matches}

                self.assertEqual(
                    ids,
                    {"CVE-2026-109618", "CVE-2026-109619"}
                )
                self.assertTrue(
                    all(item["fixed_version"] == fixed for item in matches)
                )

    def test_fixed_boundaries_do_not_match(self):
        for version in ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]:
            with self.subTest(version=version):
                self.assertEqual(
                    match_advisories(version, self.advisories),
                    []
                )

    def test_findings_include_source_and_severity(self):
        matches = match_advisories("8.5.11", self.advisories)

        self.assertEqual(len(matches), 2)

        for item in matches:
            self.assertEqual(item["severity"], "Critical")
            self.assertTrue(item["source"])
            self.assertNotIn("verified", item)
    def test_findings_include_remediation_and_status(self):
            matches = match_advisories("8.5.11", self.advisories)
    
            self.assertTrue(matches)
    
            for finding in matches:
                self.assertEqual(finding["installed_version"], "8.5.11")
                self.assertIn("Upgrade to version", finding["remediation"])
                self.assertIn("Verify the official advisory", finding["remediation"])
                self.assertEqual(
                    finding["status"],
                    "Potential match - verification required"
                )
                self.assertTrue(finding["fixed_version"])

class AdvisoryDataValidationTests(unittest.TestCase):

    def load_test_data(self, advisories):
        """Write test advisories to a temporary JSON file."""
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            encoding="utf-8",
            delete=False
        )
        with temp_file:
            json.dump({"advisories": advisories}, temp_file)

        self.addCleanup(Path(temp_file.name).unlink, missing_ok=True)
        return load_advisories(temp_file.name)


    def valid_advisory(self, advisory_id="CVE-TEST-001"):
        return {
            "id": advisory_id,
            "title": "Test advisory",
            "severity": "High",
            "source": "https://example.com/advisory",
            "last_checked": "2026-10-24",
            "affected_ranges": [
                {"introduced": "8.2.0", "fixed": "8.2.5"}
            ]
        }


    def test_duplicate_ids_are_rejected(self):
        advisory = self.valid_advisory()
        with self.assertRaisesRegex(ValueError, "Duplicate advisory ID"):
            self.load_test_data([advisory, advisory.copy()])

    def test_missing_id_is_rejected(self):
        advisory = self.valid_advisory()
        del advisory["id"]
        with self.assertRaisesRegex(ValueError, "missing its ID"):
            self.load_test_data([advisory])

    def test_invalid_severity_is_rejected(self):
        advisory = self.valid_advisory()
        advisory["severity"] = "Super Critical"
        with self.assertRaisesRegex(ValueError, "Invalid severity"):
            self.load_test_data([advisory])

    def test_missing_source_is_rejected(self):
        advisory = self.valid_advisory()
        advisory["source"] = ""
        with self.assertRaisesRegex(ValueError, "missing its source"):
            self.load_test_data([advisory])

    def test_missing_affected_ranges_is_rejected(self):
        advisory = self.valid_advisory()
        del advisory["affected_ranges"]
        with self.assertRaisesRegex(ValueError, "invalid affected ranges"):
            self.load_test_data([advisory])
    
    def test_missing_fixed_version_is_rejected(self):
        advisory = self.valid_advisory()
        del advisory["affected_ranges"][0]["fixed"]

        with self.assertRaisesRegex(ValueError, "missing or invalid version"):
            self.load_test_data([advisory])

    def test_invalid_version_format_is_rejected(self):
        advisory = self.valid_advisory()
        advisory["affected_ranges"][0]["introduced"] = "eight.five.12"

        with self.assertRaisesRegex(ValueError, "missing or invalid version"):
            self.load_test_data([advisory])

    def test_reversed_version_range_is_rejected(self):
        advisory = self.valid_advisory()
        advisory["affected_ranges"][0]["introduced"] = "8.5.20"
        advisory["affected_ranges"][0]["fixed"] = "8.5.12"

        with self.assertRaisesRegex(ValueError, "introduced.*older than.*fixed"):
            self.load_test_data([advisory])
    
    def test_missing_last_checked_date_is_rejected(self):
        advisory = self.valid_advisory()
        del advisory["last_checked"]

        with self.assertRaisesRegex(ValueError, "last_checked"):
            self.load_test_data([advisory])

    def test_invalid_last_checked_date_is_rejected(self):
        advisory = self.valid_advisory()
        advisory["last_checked"] = "2026-02-30"

        with self.assertRaisesRegex(ValueError, "invalid last_checked date"):
            self.load_test_data([advisory])


class AdvisoryFreshnessTests(unittest.TestCase):

    def test_recent_advisory_has_no_warning(self):
        advisory = {
            "id": "CVE-TEST-001",
            "last_checked": date.today().isoformat()
        }

        self.assertEqual(check_advisory_freshness([advisory]), [])

    def test_old_advisory_generates_warning(self):
        from datetime import timedelta

        old_date = (date.today() - timedelta(days=45)).isoformat()
        advisory = {
            "id": "CVE-TEST-002",
            "last_checked": old_date
        }

        warnings = check_advisory_freshness([advisory])

        self.assertEqual(len(warnings), 1)
        self.assertIn("CVE-TEST-002", warnings[0])
        self.assertIn("45 days old", warnings[0])

    def test_future_date_generates_warning(self):
        from datetime import timedelta

        future_date = (date.today() + timedelta(days=1)).isoformat()
        advisory = {
            "id": "CVE-TEST-003",
            "last_checked": future_date
        }

        warnings = check_advisory_freshness([advisory])

        self.assertEqual(len(warnings), 1)
        self.assertIn("future", warnings[0])

    def test_negative_threshold_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "cannot be negative"):
            check_advisory_freshness([], max_age_days=-1)


class FindingDisplayTests(unittest.TestCase):

    def test_display_shows_remediation_and_source(self):
        findings = [{
            "id": "CVE-TEST-001",
            "title": "Test vulnerability",
            "severity": "High",
            "fixed_version": "8.5.12",
            "status": "Potential match - verification required",
            "remediation": "Upgrade to version 8.5.12 and verify the official advisory.",
            "source": "https://example.com/advisory"
        }]

        with patch("builtins.print") as mock_print:
            display_findings(findings)

        output = "\n".join(
            " ".join(str(arg) for arg in call.args)
            for call in mock_print.call_args_list
        )

        self.assertIn("CVE-TEST-001", output)
        self.assertIn("Potential match - verification required", output)
        self.assertIn("8.5.12", output)
        self.assertIn("Upgrade to version", output)
        self.assertIn("https://example.com/advisory", output)


class MainErrorHandlingTests(unittest.TestCase):

    
    def test_invalid_advisory_record_stops_assessment(self):
        with patch("main.Path.resolve") as mock_resolve, \
             patch("main.detect_php_version") as mock_detect, \
             patch("main.load_advisories") as mock_load, \
             patch("builtins.print") as mock_print:

            mock_resolve.return_value.parent = Path(
                "Z:/PHPShield_Invalid_Record_Test"
            )

            mock_detect.return_value = {
                "installed": True,
                "version": "8.5.12",
                "message": "PHP version detected successfully."
            }

            mock_load.side_effect = ValueError(
                "Invalid severity for advisory CVE-TEST-001."
            )

            main()

        output = "\n".join(
            " ".join(str(arg) for arg in call.args)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            "ERROR: Could not load advisory database:",
            output
        )
        self.assertIn("Invalid severity", output)
        self.assertNotIn("JSON report saved to:", output)

    
    def test_invalid_json_stops_assessment(self):
        with patch("main.Path.resolve") as mock_resolve, \
             patch("main.detect_php_version") as mock_detect, \
             patch("main.load_advisories") as mock_load, \
             patch("builtins.print") as mock_print:

            mock_resolve.return_value.parent = Path(
                "Z:/PHPShield_Invalid_Test"
            )

            mock_detect.return_value = {
                "installed": True,
                "version": "8.5.12",
                "message": "PHP version detected successfully."
            }

            import json
            mock_load.side_effect = json.JSONDecodeError(
                "Invalid JSON", "{", 1
            )

            main()

        output = "\n".join(
            " ".join(str(arg) for arg in call.args)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            "ERROR: Advisory database contains invalid JSON.",
            output
        )
        self.assertNotIn("JSON report saved to:", output)


    def test_missing_advisory_file_stops_assessment(self):
        with patch("main.Path.resolve") as mock_resolve, \
             patch("main.detect_php_version") as mock_detect, \
             patch("builtins.print") as mock_print:

            mock_resolve.return_value.parent = Path(
                "Z:/PHPShield_Missing_Test"
            )

            mock_detect.return_value = {
                "installed": True,
                "version": "8.5.12",
                "message": "PHP version detected successfully."
            }

            main()

        output = "\n".join(
            " ".join(str(arg) for arg in call.args)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            "ERROR: Advisory database file was not found.",
            output
        )
        self.assertNotIn("JSON report saved to:", output)

    
    





if __name__ == "__main__":
    unittest.main()
