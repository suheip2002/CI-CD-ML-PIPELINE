from github import Github
import os
import pandas as pd


def get_github_vulnerability_data(token, org_name=None, repo_name=None):
    g = Github(token)

    all_alerts = []
    all_advisories = []

    print("Fetching Dependabot alerts...")
    if org_name:
        try:
            org = g.get_organization(org_name)
            repos = org.get_repos()
        except Exception as e:
            print(f"Error getting organization {org_name}: {e}")
            return [], []
    elif repo_name:
        try:
            repos = [g.get_user().get_repo(repo_name)]
        except Exception as e:
            print(f"Error getting repository {repo_name}: {e}")
            return [], []
    else:
        # If no org or repo specified, try to get alerts for all accessible repos of the authenticated user
        repos = g.get_user().get_repos()

    for repo in repos:
        try:
            # Dependabot alerts are per repository
            alerts = repo.get_dependabot_alerts()
            for alert in alerts:
                # Safely access nested attributes using .get() or checking for existence
                security_vulnerability = alert.security_vulnerability

                advisory = None
                if security_vulnerability and hasattr(security_vulnerability, 'advisory'):
                    advisory = security_vulnerability.advisory

                first_patched_version = None
                if security_vulnerability and hasattr(security_vulnerability, 'first_patched_version'):
                    first_patched_version = security_vulnerability.first_patched_version

                all_alerts.append({
                    "repo_full_name": repo.full_name,
                    "alert_number": alert.number,
                    "state": alert.state,
                    "created_at": alert.created_at,
                    "updated_at": alert.updated_at,
                    "dismissed_at": alert.dismissed_at,
                    "dismissed_reason": alert.dismissed_reason,
                    "dependency_name": alert.dependency.package.name if alert.dependency and alert.dependency.package else None,
                    "dependency_scope": alert.dependency.scope if alert.dependency else None,
                    "vulnerability_severity": security_vulnerability.severity if security_vulnerability and hasattr(
                        security_vulnerability, 'severity') else None,
                    "vulnerability_advisory_ghsa_id": advisory.ghsa_id if advisory and hasattr(advisory,
                                                                                               'ghsa_id') else None,
                    "vulnerability_advisory_summary": advisory.summary if advisory and hasattr(advisory,
                                                                                               'summary') else None,
                    "vulnerability_advisory_description": advisory.description if advisory and hasattr(advisory,
                                                                                                       'description') else None,
                    "vulnerability_cve_id": security_vulnerability.cve_id if security_vulnerability and hasattr(
                        security_vulnerability, 'cve_id') else None,
                    "first_patched_version": first_patched_version.identifier if first_patched_version and hasattr(
                        first_patched_version, 'identifier') else None,
                    "vulnerable_versions": security_vulnerability.vulnerable_version_range if security_vulnerability and hasattr(
                        security_vulnerability, 'vulnerable_version_range') else None,
                })
            print(f"Fetched {alerts.totalCount} Dependabot alerts for {repo.full_name}")
        except Exception as e:
            print(f"Could not retrieve Dependabot alerts for {repo.full_name}: {e}")

    print("Fetching GitHub Security Advisories...")
    # GitHub Security Advisories are global or per repository/organization
    # For simplicity, let's fetch a general set of advisories.
    # A more targeted approach would involve searching by package name or CVE ID.
    # The GitHub API for advisories is a bit more complex for bulk fetching without specific criteria.
    # For now, we'll rely on the advisories linked through Dependabot alerts.
    # If a broader set of advisories is needed, we'd use g.get_security_advisories() with filters.
    # Example: advisories = g.get_security_advisories(ecosystem='PIP', severity='CRITICAL')
    # For this project, the advisories linked to Dependabot alerts should be sufficient for contextual risk.

    # Convert to DataFrame and save
    alerts_df = pd.DataFrame(all_alerts)
    # advisories_df = pd.DataFrame(all_advisories) # Currently not populated directly

    return alerts_df, pd.DataFrame(all_advisories)  # Return empty advisories_df for now


if __name__ == "__main__":
    # Replace with your actual token or get it from environment variable
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

    if not GITHUB_TOKEN:
        print(
            "GitHub token not found. Please set the GITHUB_TOKEN environment variable or provide it directly in the script.")
    else:
        # Example usage: Fetch alerts for a specific organization or user's repositories
        # You might need to adjust org_name or repo_name based on your GitHub setup
        # For now, it will try to fetch for all repos accessible by the token's user.
        dependabot_alerts_df, github_advisories_df = get_github_vulnerability_data(GITHUB_TOKEN)

        if not dependabot_alerts_df.empty:
            dependabot_alerts_df.to_csv("dependabot_alerts.csv", index=False)
            print("Dependabot alerts saved to dependabot_alerts.csv")
        else:
            print("No Dependabot alerts fetched or an error occurred.")

        if not github_advisories_df.empty:
            github_advisories_df.to_csv("github_advisories_enhanced.csv", index=False)
            print("GitHub advisories saved to github_advisories_enhanced.csv")
        else:
            print("No additional GitHub advisories fetched directly.")
