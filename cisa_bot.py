import os
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("PERSONAL_GITHUB_TOKEN")
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_NAME = "ums91/CISA_BOT"  # Replace with your GitHub repository
API_URL = f"https://api.github.com/repos/{REPO_NAME}/issues"

# Headers for GitHub API
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

def create_github_issue(vulnerability):
    """Direct API call to create a GitHub issue for a new vulnerability."""
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

    issue_data = {
        "title": title,
        "body": body,
        "labels": ["CISA-Alert", "Vulnerability"]
    }

    retries = 0
    while True:
        try:
            # Check rate limit and back off if necessary
            response = requests.post(API_URL, headers=HEADERS, json=issue_data)
            print("Response Status Code:", response.status_code)  # Added for debugging
            if response.status_code == 201:
                issue_url = response.json().get("html_url")
                print(f"Issue created for {vulnerability.get('cveID', 'No CVE ID')}: {issue_url}")
                break
            elif response.status_code == 403 and "rate limit" in response.text:
                reset_time = 60 * (2 ** retries)  # Exponential backoff
                print(f"Rate limit exceeded. Waiting for {reset_time:.2f} seconds...")
                time.sleep(reset_time)
                retries += 1
            elif response.status_code == 404:
                print(f"Repository not found or issues not enabled for repository: {REPO_NAME}")
                break
            elif response.status_code == 401:
                print(f"Unauthorized: Check your credentials. Response: {response.json()}")
                break
            else:
                print(f"Error creating issue for {vulnerability.get('cveID', 'No CVE ID')}: {response.status_code} {response.json()}")
                break
        except requests.RequestException as e:
            print(f"Error creating issue for {vulnerability.get('cveID', 'No CVE ID')}: {e}")
            break


def main():
    # Fetch vulnerabilities
    vulnerabilities = fetch_cisa_vulnerabilities()

    # Create a ThreadPoolExecutor for concurrent issue creation
    with ThreadPoolExecutor(max_workers=2) as executor:  # Reduced workers to avoid rate limiting
        future_to_vulnerability = {executor.submit(create_github_issue, vulnerability): vulnerability for vulnerability in vulnerabilities}

        for future in as_completed(future_to_vulnerability):
            vulnerability = future_to_vulnerability[future]
            try:
                future.result()  # This will raise an exception if the function raised one
            except Exception as e:
                print(f"Error processing vulnerability {vulnerability.get('cveID', 'No CVE ID')}: {e}")

if __name__ == "__main__":
    main()
