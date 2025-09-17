import pandas as pd


def merge_vulnerability_data(cleaned_vulnerabilities_path, dependabot_alerts_path, output_path):
    print(f"Loading cleaned vulnerabilities from {cleaned_vulnerabilities_path}...")
    df_cleaned = pd.read_csv(cleaned_vulnerabilities_path)
    print(f"Loaded {len(df_cleaned)} entries from cleaned vulnerabilities.")

    print(f"Loading Dependabot alerts from {dependabot_alerts_path}...")
    df_dependabot = pd.read_csv(dependabot_alerts_path)
    print(f"Loaded {len(df_dependabot)} entries from Dependabot alerts.")

    # Rename 'CVE_ID' in df_cleaned to 'vulnerability_cve_id' to match df_dependabot for merging
    # Or, decide on a common key. For now, let's assume CVE_ID is the primary key for merging.
    # If Dependabot alerts have CVE_IDs, we can merge on that. If not, we might need to merge on repo_full_name and dependency_name.
    # For simplicity, let's assume we want to enrich existing vulnerabilities with Dependabot info.
    # A more robust merge strategy would involve understanding the exact relationship between the two datasets.

    # Let's try to merge based on CVE_ID if available in both, otherwise, keep them separate for now
    # and consider a different integration strategy.
    # For now, we'll do a simple concatenation and then deduplicate, prioritizing the more complete entry.

    # Standardize column names for merging/concatenation if necessary
    # Assuming 'CVE_ID' in cleaned_vulnerabilities.csv corresponds to 'vulnerability_cve_id' in dependabot_alerts.csv
    df_dependabot_renamed = df_dependabot.rename(columns={'vulnerability_cve_id': 'CVE_ID'})

    # Select relevant columns from dependabot_alerts for merging
    # We want to add information from dependabot alerts to our existing vulnerabilities
    # Let's pick some key columns from dependabot_alerts that might be useful
    dependabot_cols_to_merge = [
        'CVE_ID', 'repo_full_name', 'alert_number', 'state', 'created_at',
        'vulnerability_severity', 'vulnerability_advisory_ghsa_id',
        'vulnerability_advisory_summary', 'vulnerability_advisory_description',
        'first_patched_version', 'vulnerable_versions'
    ]

    # Filter dependabot_alerts to only include rows with a valid CVE_ID for merging
    df_dependabot_filtered = df_dependabot_renamed.dropna(subset=['CVE_ID'])

    # Perform a left merge from cleaned_vulnerabilities to dependabot_alerts
    # This will add Dependabot alert information to existing CVEs if a match is found
    # If a CVE has multiple Dependabot alerts, this will create duplicate rows for the CVE.
    # We might need to handle this by aggregating Dependabot info per CVE before merging.
    print("Merging dataframes based on CVE_ID...")
    merged_df = pd.merge(
        df_cleaned,
        df_dependabot_filtered[dependabot_cols_to_merge].drop_duplicates(subset=['CVE_ID']),
        on='CVE_ID',
        how='left',
        suffixes=('_cleaned', '_dependabot')
    )

    print(f"Merged dataframe has {len(merged_df)} entries and {len(merged_df.columns)} columns.")
    merged_df.to_csv(output_path, index=False)
    print(f"Merged data saved to {output_path}")


if __name__ == "__main__":
    CLEANED_VULNERABILITIES_CSV = "cleaned_vulnerabilities.csv"
    DEPENDABOT_ALERTS_CSV = "dependabot_alerts.csv"
    OUTPUT_CSV = "merged_vulnerabilities.csv"
    merge_vulnerability_data(CLEANED_VULNERABILITIES_CSV, DEPENDABOT_ALERTS_CSV, OUTPUT_CSV)