
import json
import re
from pathlib import Path
from datetime import date


def parse_version(version):
    if not isinstance(version, str):
        raise ValueError("Version must be a string.")

    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"Unsupported version format: {version}")

    return tuple(int(part) for part in version.split("."))



def load_advisories(file_path):
    with Path(file_path).open("r", encoding="utf-8") as file:
        data = json.load(file)

    advisories = data.get("advisories")

    if not isinstance(advisories, list):
        raise ValueError("Advisory data must contain an 'advisories' list.")

    seen_ids = set()

    for advisory in advisories:
        advisory_id = advisory.get("id")

        if not advisory_id:
            raise ValueError("An advisory is missing its ID.")

        if advisory_id in seen_ids:
            raise ValueError(f"Duplicate advisory ID: {advisory_id}")

        seen_ids.add(advisory_id)

        if advisory.get("severity") not in {
            "Critical", "High", "Medium", "Low", "Unknown"
        }:
            raise ValueError(
                f"Invalid severity for advisory {advisory_id}."
            )

        if not advisory.get("source"):
            raise ValueError(
                f"Advisory {advisory_id} is missing its source."
            )
        last_checked = advisory.get("last_checked")

        if not isinstance(last_checked, str):
            raise ValueError(
                f"Advisory {advisory_id} is missing its last_checked date."
             )

        try:
            date.fromisoformat(last_checked)
        except ValueError as exc:
            raise ValueError(
                f"Advisory {advisory_id} has an invalid last_checked date. "
                "Use YYYY-MM-DD format."
            ) from exc
        

        if not isinstance(advisory.get("affected_ranges"), list):
            raise ValueError(
                f"Advisory {advisory_id} has invalid affected ranges."
            )
        
        affected_ranges = advisory["affected_ranges"]

        if not affected_ranges:
            raise ValueError(
                f"Advisory {advisory_id} has no affected version ranges."
            )

        for version_range in affected_ranges:
            if not isinstance(version_range, dict):
                raise ValueError(
                    f"Advisory {advisory_id} contains an invalid version range."
                )

            try:
                introduced = parse_version(version_range["introduced"])
                fixed = parse_version(version_range["fixed"])
            except (KeyError, ValueError) as exc:
                raise ValueError(
                    f"Advisory {advisory_id} has a missing or invalid version."
                ) from exc

            if introduced >= fixed:
                raise ValueError(
                    f"Advisory {advisory_id} has an invalid range: "
                    "'introduced' must be older than 'fixed'."
                )


    return advisories


def check_advisory_freshness(advisories, max_age_days=30):
    """Return warnings for advisories whose review dates are too old."""

    if max_age_days < 0:
        raise ValueError("max_age_days cannot be negative.")

    today = date.today()
    warnings = []

    for advisory in advisories:
        last_checked = date.fromisoformat(advisory["last_checked"])
        age_days = (today - last_checked).days

        if age_days < 0:
            warnings.append(
                f"{advisory['id']}: last_checked date is in the future."
            )
        elif age_days > max_age_days:
            warnings.append(
                f"{advisory['id']}: advisory data is {age_days} days old "
                f"(last checked {last_checked.isoformat()}). Review the source."
            )

    return warnings




def match_advisories(installed_version, advisories):
    installed = parse_version(installed_version)
    matches = []

    for advisory in advisories:
        for version_range in advisory.get("affected_ranges", []):
            try:
                introduced = parse_version(version_range["introduced"])
                fixed = parse_version(version_range["fixed"])
            except (KeyError, ValueError):
                continue

            if introduced >= fixed:
                continue

            if introduced <= installed < fixed:

                matches.append({
                    "id": advisory.get("id", "Unknown"),
                    "title": advisory.get("title", "Untitled"),
                    "severity": advisory.get("severity", "Unknown"),
                    "installed_version": installed_version,
                    "fixed_version": version_range["fixed"],
                    "remediation": (
                        f"Upgrade to version {version_range['fixed']} or a later "
                        "supported, patched release in the same PHP branch. "
                        "Verify the official advisory and vendor patch status."
                    ),
                    "source": advisory.get("source", ""),
                    "status": "Potential match - verification required"
                })

                break

    return matches


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    advisories = load_advisories(root / "data" / "sample_advisories.json")

    for version in [
        "8.2.34", "8.2.35",
        "8.3.35", "8.3.36",
        "8.4.26", "8.4.27",
        "8.5.11", "8.5.12"
    ]:
        matches = match_advisories(version, advisories)
        print(f"\nPHP {version}")

        if matches:
            for match in matches:
                print(f"  Affected: {match['id']}")
                print(f"  Severity: {match['severity']}")
                print(f"  Fixed in: {match['fixed_version']}")
        else:
            print("  No matching advisory in the configured ranges.")
