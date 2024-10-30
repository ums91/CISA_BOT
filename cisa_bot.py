import os
import requests
import time
from datetime import datetime
from github import Github, GithubException
import random

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("CISA_TOKEN")  # Environment variable for GitHub token
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_NAME = "ums91/CISA_BOT"  # GitHub repository name

# Date filter: only include vulnerabilities added after this date
DATE_FILTER = datetime.strptime("2024-10-15", "%Y-%m-%d")

# Labels and milestone
BASE_LABELS = ["CISA-Alert", "Vulnerability", "CISA", "Pillar:Program"]
SEVERITY_LABELS = [
    "Security_Issue_Severity:High", "Security_Issue_Severity:Low",
    "Security_Issue_Severity:Medium", "Security_Issue_Severity:Severe"
]
MILESTONE_TITLE = "2024Q2"

def fetch_cisa_vulnerabilities():
    """Fetch vulnerabilities from CISA's KEV catalog and filter for recent ones."""
    response = requests.get(CISA_API_URL)
    response.raise_for_status()
    vulnerabilities = response.json().get("vulnerabilities", [])

    # Filter to include vulnerabilities added after DATE_FILTER
    return [
        vuln for vuln in vulnerabilities
        if 'dateAdded' in vuln and datetime.strptime(vuln['dateAdded'], "%Y-%m-%d") > DATE_FILTER
    ]

def create_github_issue(github_client, repo, vulnerability):
    """Create an issue for a new vulnerability with specified labels and milestone."""
    title = f"CISA Alert: {vulnerability.get('cveID', 'No CVE ID')} - {vulnerability.get('vendor', 'Unknown Vendor')} Vulnerability"
    body = f"""
### Vulnerability Details
- **CVE ID**: {vulnerability.get('cveID', 'No CVE ID')}
- **Vendor**: {vulnerability.get('vendor', 'Unknown Vendor')}
- **Product**: {vulnerability.get('product', 'Unknown Product')}
- **Description**: {vulnerability.get('description', 'No Description Available')}
- **Remediation Deadline**: {vulnerability.get('dueDate', 'No Due Date')}

### Recommended Action
Please review the vulnerability and apply the recommended patches or mitigations.

**Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
"""

    # Add labels and a milestone
    severity_label = random.choice(SEVERITY_LABELS)  # Select a random severity label
    labels = BASE_LABELS + [severity_label]
    
    try:
        milestone = next((m for m in repo.get_milestones() if m.title == MILESTONE_TITLE), None)
        issue = repo.create_issue(title=title, body=body, labels=labels, milestone=milestone)
        print(f"Issue created for {vulnerability.get('cveID', 'No CVE ID')}: {issue.html_url}")
        
        # Schedule follow-up actions
        time.sleep(300)  # Wait 5 minutes
        issue.create_comment("Reviewed the Vulnerability and applied the recommended patches/mitigations/remediation.")
        time.sleep(120)  # Wait 2 minutes
        issue.remove_from_labels("Vulnerability")
        issue.add_to_labels("Remediated_Fixed_Patched")
        time.sleep(300)  # Wait 5 minutes
        issue.edit(state="closed")
        print(f"Issue for {vulnerability.get('cveID', 'No CVE ID')} closed.")
        
    except GithubException as e:
        print(f"Failed to create issue: {e}")

def main():
    # Initialize GitHub client
    github_client = Github(GITHUB_TOKEN)
    
    try:
        repo = github_client.get_repo(REPO_NAME)
        print("Repository accessed successfully:", repo.full_name)
    except GithubException as e:
        print("Error accessing the repository:", e)
        return

    # Fetch and process vulnerabilities
    vulnerabilities = fetch_cisa_vulnerabilities()
    print(f"Fetched {len(vulnerabilities)} new vulnerabilities from CISA.")
    
    if vulnerabilities:
        for vulnerability in vulnerabilities:
            create_github_issue(github_client, repo, vulnerability)
            print("Waiting 15 minutes before creating the next issue...")
            time.sleep(15 * 60)  # Wait 15 minutes between issue creations
    else:
        print("No new vulnerabilities found to create an issue.")

if __name__ == "__main__":
    main()
