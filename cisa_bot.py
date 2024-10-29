import os
import requests
import time
from github import Github, GithubException

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("PERSONAL_GITHUB_TOKEN")
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_NAME = "ums91/CISA_BOT"  # Replace with your GitHub repository

def fetch_cisa_vulnerabilities():
    """Fetch the latest vulnerabilities from CISA's KEV catalog."""
    response = requests.get(CISA_API_URL)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])

def create_github_issue(repo, vulnerability):
    """Create a GitHub issue for a new vulnerability."""
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

    # Debug logging
    print("Attempting to create issue with title:", title)
    print("Issue body:", body)

    try:
        issue = repo.create_issue(title=title, body=body, labels=["CISA-Alert", "Vulnerability"])
        print(f"Issue created for {vulnerability.get('cveID', 'No CVE ID')}: {issue.html_url}")
    except Exception as e:
        print(f"Error creating issue for {vulnerability.get('cveID', 'No CVE ID')}: {e}")


def main():
    # Initialize GitHub client and repository
    github = Github(GITHUB_TOKEN)

    # Check rate limit before proceeding
    rate_limit = github.get_rate_limit()
    print(f"Remaining requests: {rate_limit.core.remaining}, Resets at: {rate_limit.core.reset}")

    try:
        repo = github.get_repo(REPO_NAME)
        print("Repository accessed successfully:", repo.full_name)
    except Exception as e:
        print("Error accessing the repository:", e)
        return

    # Fetch vulnerabilities and create issues
    vulnerabilities = fetch_cisa_vulnerabilities()
    for vulnerability in vulnerabilities:
        retries = 0
        while True:
            rate_limit = github.get_rate_limit()  # Check rate limit before each attempt
            if rate_limit.core.remaining == 0:
                wait_time = (rate_limit.core.reset.timestamp() - time.time()) + 5  # Convert to timestamp
                print(f"Rate limit reached. Waiting for {wait_time:.2f} seconds...")
                time.sleep(wait_time)  # Sleep until the limit resets
                continue  # Check the rate limit again after waiting

            try:
                create_github_issue(repo, vulnerability)
                break  # Exit the retry loop if successful
            except GithubException as e:
                if e.status == 403 and "rate limit exceeded" in e.data["message"].lower():
                    retries += 1
                    wait_time = min(3600, 2 ** retries)  # Exponential backoff, capped at 1 hour
                    print(f"Rate limit exceeded. Waiting for {wait_time:.2f} seconds before retrying...")
                    time.sleep(wait_time)  # Sleep before retrying
                    # Check rate limit again
                    rate_limit = github.get_rate_limit()
                    print(f"Remaining requests after waiting: {rate_limit.core.remaining}, Resets at: {rate_limit.core.reset}")
                else:
                    print(f"Error creating issue for {vulnerability.get('cveID', 'No CVE ID')}: {e}")
                    break  # Exit the retry loop for other errors

if __name__ == "__main__":
    main()
