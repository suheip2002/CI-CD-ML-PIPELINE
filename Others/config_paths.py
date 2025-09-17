from pathlib import Path

# Get the project root (parent of the "Others" folder)
BASE_DIR = Path(__file__).resolve().parent.parent  # go up one level to project root

# CSV folder in the project root
CSV_DIR = BASE_DIR / "Csv_data"

FEATURE_ENGINEERED_WITH_LABEL = CSV_DIR / "feature_engineered_vulnerabilities_with_label.csv"
CLEANED_VULNERABILITIES = CSV_DIR / "cleaned_vulnerabilities.csv"
COMBINED_VULNERABILITIES = CSV_DIR / "combined_vulnerabilities.csv"
DEPENDABOT_ALERTS = CSV_DIR / "dependabot_alerts.csv"
GITHUB_ADVISORIES = CSV_DIR / "github_advisories.csv"
MERGED_VULNERABILITIES = CSV_DIR / "merged_vulnerabilities.csv"
NVD_CVES = CSV_DIR / "nvd_cves.csv"
