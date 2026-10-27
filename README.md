# PHPShield — PHP Vulnerability Assessment Tool

PHPShield is a Python-based security tool that detects the installed PHP CLI version and compares it against a locally configured database of security advisories. It identifies potential version-range matches, provides remediation guidance, checks advisory metadata freshness, and generates a JSON assessment report.

> **Important:** PHPShield is a prototype assessment tool, not a complete vulnerability scanner. A version-range match does not prove exploitability, and no matches do not guarantee that a system is secure.

## Features

- **PHP version detection:** Detects the installed PHP CLI version.
- **Advisory matching:** Compares the detected version against configured affected-version ranges.
- **Advisory validation:** Checks advisory IDs, severity, sources, dates, and version ranges.
- **Freshness checks:** Warns when advisory metadata is older than the configured 30-day threshold or contains a future date.
- **Remediation guidance:** Displays the configured fixed version and recommends verifying official advisories and vendor patches.
- **JSON reporting:** Saves findings, assessment scope, and freshness warnings.
- **Error handling:** Reports missing, malformed, or invalid advisory data.
- **Automated tests:** Includes tests for version comparison, advisory validation, matching, reporting, and error handling.


## Technology Stack

- Python 3.11
- PHP CLI
- Streamlit — web dashboard
- JSON — advisory database and assessment reports
- Python `unittest` — automated testing



## Project Structure

```text
PHPShield/
├── src/
│   ├── version_detector.py
│   ├── advisory_matcher.py
│   └── report_generator.py
├── data/
│   └── sample_advisories.json
├── tests/
│   ├── test_version_detector.py
│   ├── test_advisory_matcher.py
│   └── test_report_generator.py
├── reports/
│   └── php_shield_report_<timestamp>.json
├── app.py
├── main.py
└── README.md
```


## Requirements

- Python 3.11 or compatible Python 3 version
- PHP CLI installed and accessible through `PATH`
- Windows, macOS, or Linux with the required tools configured

## Setup and Usage

### 1. Clone or download the project

Open a terminal in the project directory.

### 2. Create a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Configure PHP

Install PHP CLI and ensure `php -v` works in the same terminal used to run PHPShield.

### 4. Run the assessment

```powershell
python main.py
```

PHPShield detects the PHP CLI version, loads the configured advisory database, checks its metadata freshness, matches version ranges, and saves a report.


### 5. Launch the Dashboard

Install Streamlit in your activated virtual environment:

```powershell
python -m pip install streamlit
```

Start the dashboard:

```powershell
python -m streamlit run app.py
```

The dashboard supports local PHP assessment, displays potential findings and advisory freshness warnings, and provides downloadable JSON reports and assessment history.

### 6. Run the Tests

```powershell
python -m unittest discover -s tests -v
```


## Output

Assessment reports are saved in the `reports/` directory using unique timestamped filenames, for example:

```text
reports/php_shield_report_20261027_090738_528170.json
```

Each new assessment creates a separate report so previous scans can be retained and reviewed through the dashboard's Assessment History section.

Reports include the detected PHP version, configured advisory IDs, potential findings, remediation guidance, freshness warnings, and assessment limitations.


## Assessment Logic

1. Detect the installed PHP CLI version.
2. Load and validate the configured advisory data.
3. Check advisory metadata freshness.
4. Compare the detected version against affected-version ranges.
5. Display potential matches and remediation guidance.
6. Generate a JSON report.

## Security Limitations

- The tool only checks advisories present in its configured database.
- Advisory dates are metadata; PHPShield does not independently verify that an official source was reviewed on that date.
- The detected CLI version may differ from the PHP runtime used by a web server.
- Vendor backported patches are not independently verified.
- A matching version range indicates a potential match, not confirmed exploitability.
- A clean result means only that no configured affected ranges matched.

Always verify findings against the official advisory and the relevant PHP distributor or vendor.

## Future Improvements

Possible future work includes automated advisory updates, broader advisory coverage, web-runtime detection, and more comprehensive integration testing.

## Author

Developed as a cybersecurity learning project focused on vulnerability assessment, version comparison, defensive security practices, and automated testing.
