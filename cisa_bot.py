import os
import requests
import time
from datetime import datetime
from github import Github, GithubException

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("CISA_TOKEN")  # Replace with your actual GitHub token
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"  # NVD API base URL
REPO_NAME = "ums91/CISA_BOT"  # Replace with your GitHub repository
DATE_CUTOFF = datetime(2024, 10, 15)  # Only process vulnerabilities added after this date

def fetch_cisa_vulnerabilities():
    """Fetch the latest vulnerabilities from CISA's KEV catalog and filter by date."""
    response = requests.get(CISA_API_URL)
    response.raise_for_status()
    vulnerabilities = response.json().get("vulnerabilities", [])

    # Filter vulnerabilities by the cutoff date
    recent_vulnerabilities = [
        v for v in vulnerabilities 
        if 'dateAdded' in v and datetime.fromisoformat(v['dateAdded']) > DATE_CUTOFF
    ]
    return recent_vulnerabilities

def fetch_vulnerability_details(cve_id):
    """Fetch detailed vulnerability information using the CVE ID from an external API."""
    try:
        # Call NVD API for detailed CVE information
        response = requests.get(f"{NVD_API_URL}{cve_id}")
        response.raise_for_status()
        data = response.json()

        # Extract specific details from the response
        cve_item = data.get("result", {}).get("CVE_Items", [])[0]  # First item if exists
        if cve_item:
            return {
                "name": cve_item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "No Name"),
                "cvss_score": cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", "No CVSS Score"),
                "epss_score": cve_item.get("impact", {}).get("epss", {}).get("value", "No EPSS Score"),
                "weaknesses": cve_item.get("cve", {}).get("problemtype", {}).get("problemtype_data", [{}])[0].get("description", [{}])[0].get("value", "No Weaknesses"),
                "ghsa_id": "Fetch GHSA from appropriate source if available",
            }
        else:
            print(f"No details found for CVE ID: {cve_id}")
            return {}
    except Exception as e:
        print(f"Error fetching details for CVE ID {cve_id}: {e}")
        return {}

def create_github_issue(github_client, repo, vulnerability):
    """Create a GitHub issue for a new vulnerability with specified labels and a milestone."""
    cve_id = vulnerability.get('cveID', 'No CVE ID')
    detailed_info = fetch_vulnerability_details(cve_id)

    title = f"CISA Alert: {cve_id} - {detailed_info.get('name', 'Unnamed Vulnerability')} - {vulnerability.get('vendor', 'Unknown Vendor')}"
    body = f"""
### Vulnerability Details
- **Name**: {detailed_info.get('name', 'Unnamed Vulnerability')}
- **CVE ID**: {cve_id}
- **GHSA ID**: {detailed_info.get('ghsa_id', 'No GHSA ID')}
- **Vendor**: {vulnerability.get('vendor', 'Unknown Vendor')}
- **Product**: {vulnerability.get('product', 'Unknown Product')}
- **Description**: {vulnerability.get('description', 'No Description Available')}
- **Remediation Deadline**: {vulnerability.get('dueDate', 'No Due Date')}
- **CVSS Score**: {detailed_info.get('cvss_score', 'No CVSS Score')}
- **EPSS Score**: {detailed_info.get('epss_score', 'No EPSS Score')}
- **Weaknesses**: {detailed_info.get('weaknesses', 'No Weaknesses Provided')}

### Recommended Action
Please review the vulnerability and apply the recommended patches or mitigations.

**Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
"""

    # Remaining code to set up severity labels, create issue, etc., as before...
    print(f"Attempting to create an issue with title: {title}")

    # Define severity-based label
    severity_label = {
        "high": "Security_Issue_Severity_High",
        "low": "Security_Issue_Severity_Low",
        "medium": "Security_Issue_Severity_Medium",
        "severe": "Security_Issue_Severity_Severe"
    }.get(vulnerability.get('severity', 'Unknown').lower(), None)

    # Labels and milestone setup
    labels = ["CISA-Alert", "Vulnerability", "CISA", "Pillar:Program"]
    if severity_label:
        labels.append(severity_label)

    milestone = None
    try:
        milestones = repo.get_milestones()
        for m in milestones:
            if m.title == "2024Q2":
                milestone = m
                break
    except GithubException as e:
        print(f"Error retrieving milestone: {e}")

    retries = 0
    while True:
        try:
            rate_limit = github_client.get_rate_limit().core
            if rate_limit.remaining < 5:
                reset_time = rate_limit.reset.timestamp() - time.time() + 5
                print(f"Rate limit low. Waiting for {reset_time:.2f} seconds...")
                time.sleep(reset_time)

            issue = repo.create_issue(
                title=title, 
                body=body, 
                labels=labels, 
                milestone=milestone
            )
            print(f"Issue created for {cve_id}: {issue.html_url}")

            delayed_issue_actions(issue)
            break
        except GithubException as e:
            print(f"Error creating issue for {cve_id}: {e}")
            if e.status == 404:
                print(f"Repository '{REPO_NAME}' not found or issue creation failed.")
            elif e.status == 401:
                print("Bad credentials. Check your GitHub token and its permissions.")
            elif e.status == 403 and "rate limit exceeded" in e.data["message"].lower():
                retries += 1
                wait_time = min(3600, 2 ** retries)
                print(f"Rate limit exceeded. Waiting for {wait_time:.2f} seconds...")
                time.sleep(wait_time)
            else:
                break

def main():
    github_client = Github(GITHUB_TOKEN)
    try:
        repo = github_client.get_repo(REPO_NAME)
        print("Repository accessed successfully:", repo.full_name)
    except GithubException as e:
        print("Error accessing the repository:", e)
        return

    vulnerabilities = fetch_cisa_vulnerabilities()
    print(f"Fetched {len(vulnerabilities)} vulnerabilities from CISA.")

    if vulnerabilities:
        create_github_issue(github_client, repo, vulnerabilities[0])
    else:
        print("No vulnerabilities found to create an issue.")

if __name__ == "__main__":
    main()
