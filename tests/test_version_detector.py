
import unittest
from src.advisory_matcher import parse_version


class VersionComparisonTests(unittest.TestCase):

    def test_versions_compare_numerically(self):
        self.assertLess(
            parse_version("8.5.9"),
            parse_version("8.5.12")
        )

    def test_equal_versions(self):
        self.assertEqual(
            parse_version("8.5.12"),
            parse_version("8.5.12")
        )

    def test_invalid_version_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_version("not-a-version")


if __name__ == "__main__":
    unittest.main()
