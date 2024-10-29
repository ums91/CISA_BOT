import os
import requests
import time
from github import Github, GithubException
from concurrent.futures import ThreadPoolExecutor, as_completed

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("MY_TOKEN")
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_NAME = "ums91/CISA_BOT"  # Replace with your GitHub repository

def fetch_cisa_vulnerabilities():
    """Fetch the latest vulnerabilities from CISA's KEV catalog."""
    response = requests.get(CISA_API_URL)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])

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
            # Check for specific errors
            if e.status == 404:
                print(f"Error: Repository '{REPO_NAME}' not found or issue creation failed: {e.data}")
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
    except Exception as e:
        print("Error accessing the repository:", e)
        return

    # Fetch vulnerabilities
    vulnerabilities = fetch_cisa_vulnerabilities()

    # Create a ThreadPoolExecutor for concurrent execution with limited workers
    with ThreadPoolExecutor(max_workers=2) as executor:  # Fewer workers to limit API hits
        future_to_vulnerability = {
            executor.submit(create_github_issue, github_client, repo, vulnerability): vulnerability for vulnerability in vulnerabilities
        }

        for future in as_completed(future_to_vulnerability):
            vulnerability = future_to_vulnerability[future]
            try:
                future.result()  # Raise any exceptions from create_github_issue
            except Exception as e:
                print(f"Error processing vulnerability {vulnerability.get('cveID', 'No CVE ID')}: {e}")

if __name__ == "__main__":
    main()
