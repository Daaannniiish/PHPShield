
import json
import sys
from pathlib import Path

import streamlit as st

# Make the project root available for imports
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.version_detector import detect_php_version
from src.advisory_matcher import (
    load_advisories,
    match_advisories,
    check_advisory_freshness,
)
from src.report_generator import generate_report


st.set_page_config(
    page_title="PHPShield | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# PHPShield dark SOC theme
st.markdown("""
<style>
/* Main application background */
.stApp {
    background: #0b1120;
    color: #e2e8f0;
}

/* Main content spacing */
.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1500px;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: #101827;
    border-right: 1px solid #263449;
}

/* Headings */
h1, h2, h3 {
    color: #f1f5f9 !important;
    letter-spacing: -0.4px;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: linear-gradient(145deg, #131f32, #101827);
    border: 1px solid #263b53;
    border-radius: 12px;
    padding: 18px;
}

/* Metric labels and values */
[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
}

[data-testid="stMetricValue"] {
    color: #38bdf8 !important;
}

/* Buttons */
.stButton > button,
.stDownloadButton > button {
    background: #087e8b;
    color: white;
    border: 1px solid #22d3ee;
    border-radius: 8px;
    font-weight: 600;
    transition: 0.2s ease;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    background: #0e7490;
    border-color: #67e8f9;
    color: white;
}

/* Expandable findings and report sections */
[data-testid="stExpander"] {
    background: #111c2e;
    border: 1px solid #263b53;
    border-radius: 10px;
}

/* Tables */
[data-testid="stDataFrame"] {
    border: 1px solid #263b53;
    border-radius: 10px;
}

/* Dividers */
hr {
    border-color: #263449;
}

/* Caption and supporting text */
[data-testid="stCaptionContainer"] {
    color: #94a3b8;
}

/* Links */
a {
    color: #38bdf8 !important;
}
</style>
""", unsafe_allow_html=True)


st.title("🛡️ PHPShield")
st.caption("PHP Vulnerability Assessment Dashboard")

st.warning(
    "PHPShield checks configured advisory records only. "
    "No findings does not prove that PHP is secure."
)

advisory_file = PROJECT_ROOT / "data" / "sample_advisories.json"
report_dir = PROJECT_ROOT / "reports"

st.sidebar.header("Assessment Controls")
st.sidebar.write("Target: Local PHP CLI")
st.sidebar.write("Database: Configured JSON advisories")

run_scan = st.sidebar.button(
    "Run Assessment",
    type="primary",
    use_container_width=True,
)

if run_scan:
    with st.spinner("Assessing local PHP installation..."):
        try:
            detection = detect_php_version()

            if not detection.get("installed") or not detection.get("version"):
                st.error(detection.get("message", "PHP version detection failed."))

            else:
                advisories = load_advisories(advisory_file)
                freshness_warnings = check_advisory_freshness(advisories)
                findings = match_advisories(
                    detection["version"],
                    advisories,
                )

                report_path = generate_report(
                    detection,
                    findings,
                    report_dir,
                    freshness_warnings=freshness_warnings,
                )

                st.session_state["assessment"] = {
                    "detection": detection,
                    "findings": findings,
                    "freshness_warnings": freshness_warnings,
                    "report_path": str(report_path),
                    "advisory_count": len(advisories),
                }

        except (OSError, ValueError, json.JSONDecodeError) as exc:
            st.error(f"Assessment could not be completed: {exc}")

        except Exception as exc:
            st.error(f"Unexpected error: {exc}")


assessment = st.session_state.get("assessment")

if assessment:
    detection = assessment["detection"]
    findings = assessment["findings"]
    warnings = assessment["freshness_warnings"]

    st.subheader("Assessment Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Detected PHP", detection["version"])
    col2.metric("Potential Matches", len(findings))
    col3.metric("Advisories Checked", assessment["advisory_count"])
    col4.metric("Freshness Warnings", len(warnings))

    st.caption(
        "Assessment target: local PHP command-line installation. "
        "A web server may use a different PHP runtime."
    )

    st.divider()
    st.subheader("Potential Findings")

    if findings:
        for finding in findings:
            with st.expander(
                f'{finding["severity"]} | {finding["id"]} | '
                f'{finding["title"]}'
            ):
                st.write("**Status:**", finding["status"])
                st.write("**Installed version:**", finding["installed_version"])
                st.write("**Fixed version:**", finding["fixed_version"])
                st.write("**Remediation:**", finding["remediation"])
                st.write("**Source:**", finding["source"])
    else:
        st.success("No matching advisory ranges were found.")
        st.info(
            "This result applies only to the configured advisory database. "
            "It is not a guarantee that the installation is secure."
        )

    if warnings:
        st.subheader("Advisory Freshness Warnings")
        for warning in warnings:
            st.warning(str(warning))
    else:
        st.success("All configured advisory records are within the freshness threshold.")

    st.divider()
    st.subheader("JSON Assessment Report")

    report_path = Path(assessment["report_path"])

    if report_path.exists():
        report_data = report_path.read_bytes()

        st.download_button(
            label="Download JSON Report",
            data=report_data,
            file_name=report_path.name,
            mime="application/json",
        )

        with st.expander("Preview JSON Report"):
            st.json(json.loads(report_data))

    else:
        st.error("The report file could not be found.")

else:
    st.info("Select **Run Assessment** in the sidebar to begin.")

# Assessment History
st.divider()
st.subheader("Assessment History")

report_files = sorted(
    report_dir.glob("*.json"),
    key=lambda path: path.stat().st_mtime,
    reverse=True,
)

if not report_files:
    st.info("No saved assessment reports found yet.")
else:
    st.caption(f"{len(report_files)} saved report(s) found.")

    for report_file in report_files:
        with st.expander(
            f"📄 {report_file.name} — "
            f"{__import__('datetime').datetime.fromtimestamp(report_file.stat().st_mtime):%d %b %Y, %H:%M}"
        ):
            try:
                with report_file.open("r", encoding="utf-8") as file:
                    historical_report = json.load(file)

                assessment_details = historical_report.get("assessment", {})
                findings_count = historical_report.get("finding_count", 0)

                col1, col2 = st.columns(2)
                col1.metric(
                    "PHP Version",
                    assessment_details.get("detected_version") or "Unknown",
                )
                col2.metric("Potential Matches", findings_count)

                st.download_button(
                    "Download This Report",
                    data=json.dumps(historical_report, indent=2),
                    file_name=report_file.name,
                    mime="application/json",
                    key=f"download_{report_file.name}",
                )

            except (OSError, json.JSONDecodeError) as exc:
                st.error(f"Could not read this report: {exc}")
