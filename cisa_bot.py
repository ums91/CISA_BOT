import os
import requests
from github import Github

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("PERSONAL_GITHUB_TOKEN")
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_NAME = "ums91/CISA_BOT"  # Replace with your GitHub repository

def fetch_cisa_vulnerabilities():
    """Fetch the latest vulnerabilities from CISA's KEV catalog."""
    response = requests.get(CISA_API_URL)
    response.raise_for_status()
    return response.json()["vulnerabilities"]

def create_github_issue(repo, vulnerability):
    """Create a GitHub issue for a new vulnerability."""
    title = f"CISA Alert: {vulnerability['cveID']} - {vulnerability['vendor']} Vulnerability"
    body = f"""
### Vulnerability Details
- **CVE ID**: {vulnerability['cveID']}
- **Vendor**: {vulnerability['vendor']}
- **Product**: {vulnerability['product']}
- **Description**: {vulnerability['description']}
- **Remediation Deadline**: {vulnerability['dueDate']}

### Recommended Action
Please review the vulnerability and apply the recommended patches or mitigations.

**Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
"""
    issue = repo.create_issue(title=title, body=body, labels=["CISA-Alert", "Vulnerability"])
    print(f"Issue created for {vulnerability['cveID']}: {issue.html_url}")

def main():
    # Initialize GitHub client and repository
    github = Github(GITHUB_TOKEN)
    repo = github.get_repo(REPO_NAME)

    # Fetch vulnerabilities and create issues
    vulnerabilities = fetch_cisa_vulnerabilities()
    for vulnerability in vulnerabilities:
        create_github_issue(repo, vulnerability)

if __name__ == "__main__":
    main()
