import os
import requests
import time
from datetime import datetime
from github import Github, GithubException

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("CISA_TOKEN")  # Replace with your actual GitHub token
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_NAME = "ums91/CISA_BOT"  # Replace with your GitHub repository

# Date filter (all vulnerabilities after this date will be considered)
DATE_FILTER = datetime.strptime("2024-10-15", "%Y-%m-%d")

def fetch_cisa_vulnerabilities():
    """Fetch the latest vulnerabilities from CISA's KEV catalog and filter for new ones."""
    response = requests.get(CISA_API_URL)
    response.raise_for_status()  # Raise an error for bad responses
    vulnerabilities = response.json().get("vulnerabilities", [])

    # Filter vulnerabilities found after DATE_FILTER
    new_vulnerabilities = [
        vuln for vuln in vulnerabilities
        if 'dateAdded' in vuln and datetime.strptime(vuln['dateAdded'], "%Y-%m-%d") > DATE_FILTER
    ]
    
    return new_vulnerabilities

def create_github_issue(github_client, repo, vulnerability):
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

    print(f"Attempting to create an issue with title: {title}")

    retries = 0
    while True:
        try:
            # Check remaining requests before trying to create an issue
            rate_limit = github_client.get_rate_limit().core
            if rate_limit.remaining < 5:  # Leave some buffer
                reset_time = rate_limit.reset.timestamp() - time.time() + 5
                print(f"Rate limit low. Waiting for {reset_time:.2f} seconds...")
                time.sleep(reset_time)

            # Create the issue
            issue = repo.create_issue(title=title, body=body, labels=["CISA-Alert", "Vulnerability"])
            print(f"Issue created for {vulnerability.get('cveID', 'No CVE ID')}: {issue.html_url}")
            break  # Exit the loop if successful
        except GithubException as e:
            print(f"GithubException: {e}")
            if e.status == 404:
                print(f"Error: Repository '{REPO_NAME}' not found or issue creation failed: {e.data}")
                print(f"Repository: {repo}, Title: {title}, Body: {body}")
            elif e.status == 401:
                print(f"Error: Bad credentials. Check your GitHub token and its permissions.")
            elif e.status == 403 and "rate limit exceeded" in e.data["message"].lower():
                retries += 1
                wait_time = min(3600, 2 ** retries)  # Exponential backoff, max 1 hour
                print(f"Rate limit exceeded. Waiting for {wait_time:.2f} seconds before retrying...")
                time.sleep(wait_time)
            else:
                print(f"Error creating issue for {vulnerability.get('cveID', 'No CVE ID')}: {e}")
            break  # Exit on other errors

def main():
    # Initialize GitHub client and repository
    github_client = Github(GITHUB_TOKEN)

    try:
        repo = github_client.get_repo(REPO_NAME)
        print("Repository accessed successfully:", repo.full_name)
    except GithubException as e:
        print("Error accessing the repository:", e)
        return

    # Fetch new vulnerabilities
    vulnerabilities = fetch_cisa_vulnerabilities()
    print(f"Fetched {len(vulnerabilities)} new vulnerabilities from CISA.")

    if vulnerabilities:
        # Loop over each vulnerability and create an issue with a delay
        for vulnerability in vulnerabilities:
            create_github_issue(github_client, repo, vulnerability)
            print("Waiting 15 minutes before creating the next issue...")
            time.sleep(15 * 60)  # Wait for 15 minutes before the next issue
    else:
        print("No new vulnerabilities found to create an issue.")

if __name__ == "__main__":
    main()
