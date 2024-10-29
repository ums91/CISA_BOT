import os
import requests
import time
from github import Github, GithubException
from concurrent.futures import ThreadPoolExecutor, as_completed

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

    retries = 0
    while True:
        try:
            issue = repo.create_issue(title=title, body=body, labels=["CISA-Alert", "Vulnerability"])
            print(f"Issue created for {vulnerability.get('cveID', 'No CVE ID')}: {issue.html_url}")
            break  # Exit the loop if successful
        except GithubException as e:
            if e.status == 403 and "rate limit exceeded" in e.data["message"].lower():
                retries += 1
                wait_time = 2 ** retries  # Exponential backoff
                print(f"Rate limit exceeded. Waiting for {wait_time:.2f} seconds before retrying...")
                time.sleep(wait_time)
            else:
                print(f"Error creating issue for {vulnerability.get('cveID', 'No CVE ID')}: {e}")
                break  # Exit on other errors

def main():
    # Initialize GitHub client and repository
    github = Github(GITHUB_TOKEN)

    try:
        repo = github.get_repo(REPO_NAME)
        print("Repository accessed successfully:", repo.full_name)
    except Exception as e:
        print("Error accessing the repository:", e)
        return

    # Fetch vulnerabilities
    vulnerabilities = fetch_cisa_vulnerabilities()

    # Create a ThreadPoolExecutor for concurrent execution
    with ThreadPoolExecutor(max_workers=5) as executor:  # You can adjust the number of workers
        future_to_vulnerability = {executor.submit(create_github_issue, repo, vulnerability): vulnerability for vulnerability in vulnerabilities}

        for future in as_completed(future_to_vulnerability):
            vulnerability = future_to_vulnerability[future]
            try:
                future.result()  # This will raise an exception if the function raised one
            except Exception as e:
                print(f"Error processing vulnerability {vulnerability.get('cveID', 'No CVE ID')}: {e}")

if __name__ == "__main__":
    main()
