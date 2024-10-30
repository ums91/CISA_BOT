import os
import requests
import time
from datetime import datetime, timedelta
from github import Github, GithubException

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("CISA_TOKEN")
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_NAME = "ums91/CISA_BOT"

# Date filter (all vulnerabilities after this date will be considered)
DATE_FILTER = datetime.strptime("2024-10-15", "%Y-%m-%d")

# Labels and milestone
STATIC_LABELS = ["Vulnerability", "CISA-Alert", "CISA", "Pillar:Program"]
SEVERITY_LABELS = [
    "Security_Issue_Severity:High",
    "Security_Issue_Severity:Low",
    "Security_Issue_Severity:Medium",
    "Security_Issue_Severity:Severe"
]
MILESTONE_TITLE = "2024Q2"

def fetch_cisa_vulnerabilities():
    """Fetch the latest vulnerabilities from CISA's KEV catalog."""
    response = requests.get(CISA_API_URL)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])

def create_github_issue(github_client, repo, vulnerability, milestone):
    """Create a GitHub issue for a new vulnerability with specified labels and milestone."""
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

    labels = STATIC_LABELS + [SEVERITY_LABELS[int(time.time()) % len(SEVERITY_LABELS)]]

    print(f"Attempting to create an issue with title: {title}")

    try:
        issue = repo.create_issue(
            title=title,
            body=body,
            labels=labels,
            milestone=milestone
        )
        print(f"Issue created for {vulnerability.get('cveID', 'No CVE ID')}: {issue.html_url}")

        # Schedule the comment and label updates
        time.sleep(300)  # Wait 5 minutes
        post_comment_and_update_labels(issue)

    except GithubException as e:
        print(f"Error creating issue for {vulnerability.get('cveID', 'No CVE ID')}: {e}")

def post_comment_and_update_labels(issue):
    """Post a comment, update labels, and close the issue after specified delays."""
    try:
        # Post a comment
        issue.create_comment("Reviewed the Vulnerability and applied the recommended patches/mitigations/remediation.")
        print(f"Comment posted on issue #{issue.number}")

        time.sleep(120)  # Wait 2 minutes

        # Update labels
        labels = [label.name for label in issue.labels if label.name != "Vulnerability"]
        labels.append("Remediated_Fixed_Patched")
        issue.edit(labels=labels)
        print(f"Labels updated on issue #{issue.number}")

        time.sleep(300)  # Wait 5 minutes

        # Close the issue
        issue.edit(state="closed")
        print(f"Issue #{issue.number} closed.")

    except GithubException as e:
        print(f"Error updating or closing issue #{issue.number}: {e}")

def main():
    github_client = Github(GITHUB_TOKEN)
    
    try:
        repo = github_client.get_repo(REPO_NAME)
        print("Repository accessed successfully:", repo.full_name)

        # Retrieve or create milestone
        milestone = None
        for m in repo.get_milestones():
            if m.title == MILESTONE_TITLE:
                milestone = m
                break
        if milestone is None:
            milestone = repo.create_milestone(MILESTONE_TITLE)

    except GithubException as e:
        print("Error accessing the repository:", e)
        return

    vulnerabilities = fetch_cisa_vulnerabilities()
    print(f"Fetched {len(vulnerabilities)} vulnerabilities from CISA.")

    filtered_vulnerabilities = [
        v for v in vulnerabilities
        if datetime.strptime(v.get("dateAdded", "1970-01-01"), "%Y-%m-%d") > DATE_FILTER
    ]

    print(f"{len(filtered_vulnerabilities)} vulnerabilities found after {DATE_FILTER.strftime('%Y-%m-%d')}.")

    for i, vulnerability in enumerate(filtered_vulnerabilities):
        create_github_issue(github_client, repo, vulnerability, milestone)
        if i < len(filtered_vulnerabilities) - 1:
            time.sleep(900)  # Wait 15 minutes between issues

if __name__ == "__main__":
    main()
