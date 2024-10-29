import os
import requests
from github import Github

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("PERSONAL_GITHUB_TOKEN")  # Ensure this matches your GitHub Action secret name
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_NAME = "ums91/CISA_BOT"  # Replace with your actual GitHub repository name

def fetch_cisa_vulnerabilities():
    """Fetch the latest vulnerabilities from CISA's KEV catalog."""
    response = requests.get(CISA_API_URL)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])

def create_github_issue(repo, vulnerability):
    """Create a GitHub issue for a new vulnerability."""
    # Use `.get()` with default values to handle missing fields
    title = f"CISA Alert: {vulnerability.get('cveID', 'No CVE ID')} - {vulnerability.get('vendor', 'Unknown Vendor')} Vulnerability"
    body = f"""
### Vulnerability Details
- **CVE ID**: {vulnerability.get('cveID', 'N/A')}
- **Vendor**: {vulnerability.get('vendor', 'Unknown Vendor')}
- **Product**: {vulnerability.get('product', 'Unknown Product')}
- **Description**: {vulnerability.get('description', 'No description available.')}
- **Remediation Deadline**: {vulnerability.get('dueDate', 'N/A')}

### Recommended Action
Please review the vulnerability and apply the recommended patches or mitigations.

**Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
"""
    # Create GitHub issue with labels
    issue = repo.create_issue(title=title, body=body, labels=["CISA-Alert", "Vulnerability"])
    print(f"Issue created for {vulnerability.get('cveID', 'No CVE ID')}: {issue.html_url}")

def main():
    # Initialize GitHub client with the token
    github = Github(GITHUB_TOKEN)
    try:
        # Access the repository
        repo = github.get_repo(REPO_NAME)
        print("Repository accessed successfully:", repo.full_name)
    except Exception as e:
        print("Error accessing the repository:", e)
        return

    # Fetch vulnerabilities and create issues
    vulnerabilities = fetch_cisa_vulnerabilities()
    for vulnerability in vulnerabilities:
        try:
            create_github_issue(repo, vulnerability)
        except Exception as e:
            print(f"Error creating issue for {vulnerability.get('cveID', 'No CVE ID')}: {e}")

if __name__ == "__main__":
    main()
