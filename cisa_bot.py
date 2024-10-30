import os
import requests
import time
from datetime import datetime
from github import Github, GithubException

# GitHub and CISA credentials
GITHUB_TOKEN = os.getenv("CISA_TOKEN")  # Replace with your actual GitHub token
CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REPO_NAME = "ums91/CISA_BOT"  # Replace with your GitHub repository
DATE_CUTOFF = datetime(2024, 10, 15)  # Only process vulnerabilities added after this date

def fetch_cisa_vulnerabilities():
    """Fetch the latest vulnerabilities from CISA's KEV catalog and filter by date."""
    response = requests.get(CISA_API_URL)
    response.raise_for_status()  # Raise an error for bad responses
    vulnerabilities = response.json().get("vulnerabilities", [])

    # Filter vulnerabilities by the cutoff date
    recent_vulnerabilities = [
        v for v in vulnerabilities 
        if 'dateAdded' in v and datetime.fromisoformat(v['dateAdded']) > DATE_CUTOFF
    ]
    return recent_vulnerabilities

def delayed_issue_actions(issue):
    """Perform delayed actions on an issue with status updates."""
    try:
        print("Issue created, waiting 5 minutes to post review comment...")
        time.sleep(300)  # 5 minutes
        comment = "Reviewed the Vulnerability and applied the recommended patches/mitigations/remediation."
        issue.create_comment(comment)
        print("Comment posted on issue. Waiting 2 minutes to update labels...")

        # Wait for 2 minutes, then update labels
        time.sleep(120)  # 2 minutes
        issue.remove_from_labels("Vulnerability")
        issue.add_to_labels("Remediated_Fixed_Patched")
        print("Labels updated. Waiting 5 minutes to close the issue...")

        # Wait for 5 more minutes, then close the issue
        time.sleep(300)  # 5 minutes
        issue.edit(state="closed")
        print(f"Issue {issue.number} closed.")

    except GithubException as e:
        print(f"Error during delayed actions for issue {issue.number}: {e}")

def create_github_issue(github_client, repo, vulnerability):
    """Create a GitHub issue for a new vulnerability with specified labels and a milestone."""
    # Extract vulnerability details with a fallback to 'Unknown' if missing
    cve_id = vulnerability.get('cveID', 'No CVE ID')
    name = vulnerability.get('name', 'Unnamed Vulnerability')
    vendor = vulnerability.get('vendor', 'Unknown Vendor')
    product = vulnerability.get('product', 'Unknown Product')
    description = vulnerability.get('description', 'No Description Available')
    due_date = vulnerability.get('dueDate', 'No Due Date')
    cvss_score = vulnerability.get('cvss', 'No CVSS Score')
    epss_score = vulnerability.get('epss', 'No EPSS Score')
    weaknesses = vulnerability.get('weaknesses', 'No Weaknesses Provided')
    ghsa_id = vulnerability.get('ghsaID', 'No GHSA ID')
    
    title = f"CISA Alert: {cve_id} - {name} - {vendor} Vulnerability"
    
    # Build the issue body with detailed information
    body = f"""
### Vulnerability Details
- **Name**: {name}
- **CVE ID**: {cve_id}
- **GHSA ID**: {ghsa_id}
- **Vendor**: {vendor}
- **Product**: {product}
- **Description**: {description}
- **Remediation Deadline**: {due_date}
- **CVSS Score**: {cvss_score}
- **EPSS Score**: {epss_score}
- **Weaknesses**: {weaknesses}

### Recommended Action
Please review the vulnerability and apply the recommended patches or mitigations.

**Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
"""

    print(f"Attempting to create an issue with title: {title}")

    # Determine severity-based label
    severity = vulnerability.get('severity', 'Unknown').lower()
    severity_label = {
        "high": "Security_Issue_Severity_High",
        "low": "Security_Issue_Severity_Low",
        "medium": "Security_Issue_Severity_Medium",
        "severe": "Security_Issue_Severity_Severe"
    }.get(severity, None)  # Default if severity not specified

    # Default labels
    labels = ["CISA-Alert", "Vulnerability", "CISA", "Pillar:Program"]
    if severity_label:
        labels.append(severity_label)

    # Retrieve or create the milestone "2024Q2"
    milestone = None
    try:
        milestones = repo.get_milestones()
        for m in milestones:
            if m.title == "2024Q2":
                milestone = m
                break
        if not milestone:
            print("Milestone '2024Q2' not found in repository.")
    except GithubException as e:
        print(f"Error retrieving milestone: {e}")

    retries = 0
    while True:
        try:
            # Check remaining requests before trying to create an issue
            rate_limit = github_client.get_rate_limit().core
            if rate_limit.remaining < 5:  # Leave some buffer
                reset_time = rate_limit.reset.timestamp() - time.time() + 5
                print(f"Rate limit low. Waiting for {reset_time:.2f} seconds...")
                time.sleep(reset_time)

            # Create the issue with labels and milestone
            issue = repo.create_issue(
                title=title, 
                body=body, 
                labels=labels, 
                milestone=milestone
            )
            print(f"Issue created for {cve_id}: {issue.html_url}")

            # Start delayed actions on the issue
            delayed_issue_actions(issue)
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
                print(f"Error creating issue for {cve_id}: {e}")
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

    # Fetch vulnerabilities
    vulnerabilities = fetch_cisa_vulnerabilities()
    print(f"Fetched {len(vulnerabilities)} vulnerabilities from CISA.")

    if vulnerabilities:
        # Take only the first vulnerability and create an issue
        first_vulnerability = vulnerabilities[0]
        create_github_issue(github_client, repo, first_vulnerability)
    else:
        print("No vulnerabilities found to create an issue.")

if __name__ == "__main__":
    main()
