import http.client
import json
import time

# GitLab project and API configuration
GITLAB_BASE_URL = "gitlab.com"
GITLAB_PROJECT_ID = "YOUR_PROJECT_ID"  # Replace with your GitLab project ID
GITLAB_ACCESS_TOKEN = "YOUR_ACCESS_TOKEN"  # Replace with your GitLab access token

# CISA API configuration
CISA_API_URL = "/api/v1/known_exploited_vulnerabilities"  # Replace with actual endpoint path if different
CISA_API_HOST = "www.cisa.gov"  # Adjust the host if CISA uses a different domain

def fetch_cisa_vulnerabilities():
    """Fetch the latest vulnerabilities from the CISA API."""
    connection = http.client.HTTPSConnection(CISA_API_HOST)
    connection.request("GET", CISA_API_URL)
    response = connection.getresponse()
    if response.status == 200:
        data = response.read()
        connection.close()
        return json.loads(data)
    else:
        print("Error fetching data from CISA API:", response.status)
        connection.close()
        return []

def create_gitlab_issue(title, description):
    """Create a new issue in GitLab."""
    connection = http.client.HTTPSConnection(GITLAB_BASE_URL)
    headers = {
        "Authorization": f"Bearer {GITLAB_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    issue_data = json.dumps({
        "title": title,
        "description": description
    })
    connection.request("POST", f"/api/v4/projects/{GITLAB_PROJECT_ID}/issues", body=issue_data, headers=headers)
    response = connection.getresponse()
    if response.status == 201:
        print(f"Issue created: {title}")
    else:
        print(f"Failed to create issue: {title}, Status code: {response.status}")
    connection.close()

def process_vulnerabilities():
    """Fetch vulnerabilities from CISA and create GitLab issues for each."""
    vulnerabilities = fetch_cisa_vulnerabilities()
    
    # Create GitLab issues for each vulnerability
    for vulnerability in vulnerabilities:
        title = f"New Vulnerability: {vulnerability.get('cveID', 'Unknown ID')}"
        description = (
            f"**CVE ID**: {vulnerability.get('cveID')}\n"
            f"**Description**: {vulnerability.get('description', 'No description provided')}\n"
            f"**Published Date**: {vulnerability.get('publishedDate', 'N/A')}\n"
            f"**Vendor**: {vulnerability.get('vendor', 'N/A')}\n"
            f"**Product**: {vulnerability.get('product', 'N/A')}\n"
            f"**Advisory**: {vulnerability.get('advisoryURL', 'No advisory URL')}\n"
        )
        create_gitlab_issue(title, description)

if __name__ == "__main__":
    # Schedule this script to run periodically, for example every day
    while True:
        print("Creating tickets for each CISA vulnerability...")
        process_vulnerabilities()
        print("Waiting for the next scheduled check...")
        time.sleep(86400)  # Run once a day (86400 seconds)
