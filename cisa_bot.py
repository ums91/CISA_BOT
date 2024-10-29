from github import Github
import time
import requests

# Function to fetch vulnerabilities from a CISA source
def fetch_vulnerabilities():
    """Fetch vulnerabilities from a CISA source (placeholder function)."""
    # Replace this with the actual API or method to fetch vulnerabilities
    # Example data format returned from CISA
    return [
        {
            'cve_id': 'CVE-2024-37383',
            'vendor': 'Unknown Vendor',
            'product': 'Webmail',
            'description': '',  # Empty for testing
            'remediation_deadline': '2024-11-14',
        },
        {
            'cve_id': 'CVE-2021-31196',
            'vendor': 'Unknown Vendor',
            'product': 'Exchange Server',
            'description': '',  # Empty for testing
            'remediation_deadline': '2024-09-11',
        }
        # Add more vulnerabilities as needed
    ]

# Function to create an issue on GitHub
def create_github_issue(repo, vulnerability):
    """Create a GitHub issue for a given vulnerability."""
    title = f"CISA Alert: {vulnerability['cve_id']} - {vulnerability['vendor']} Vulnerability"
    body = (
        f"### Vulnerability Details\n"
        f"- **CVE ID**: {vulnerability['cve_id']}\n"
        f"- **Vendor**: {vulnerability['vendor']}\n"
        f"- **Product**: {vulnerability['product']}\n"
        f"- **Description**: {vulnerability.get('description', 'No Description Available')}\n"
        f"- **Remediation Deadline**: {vulnerability['remediation_deadline']}\n"
        f"### Recommended Action\n"
        f"Please review the vulnerability and apply the recommended patches or mitigations.\n"
        f"**Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"
    )

    # Check rate limit before creating an issue
    rate_limit = github.get_rate_limit()
    print(f"Remaining requests: {rate_limit.core.remaining}, Resets at: {rate_limit.core.reset}")

    if rate_limit.core.remaining == 0:
        wait_time = (rate_limit.core.reset - time.time()) + 5  # Add some buffer time
        print(f"Rate limit exceeded. Waiting for {wait_time} seconds.")
        time.sleep(wait_time)

    try:
        issue = repo.create_issue(title=title, body=body)
        print(f"Issue created: {issue.html_url}")
    except Exception as e:
        print(f"Error creating issue for {vulnerability['cve_id']}: {e}")

# Main function to run the bot
def main():
    # GitHub token and repository info
    GITHUB_TOKEN = os.getenv("PERSONAL_GITHUB_TOKEN")  # Replace with your GitHub token
    REPO_NAME = "ums91/CISA_BOT"  # Replace with your repository name

    # Initialize GitHub client
    global github
    github = Github(GITHUB_TOKEN)

    # Access the specified repository
    try:
        repo = github.get_repo(REPO_NAME)
        print(f"Repository accessed successfully: {REPO_NAME}")

        # Fetch vulnerabilities from CISA
        vulnerabilities = fetch_vulnerabilities()

        # Loop through vulnerabilities and create issues one by one
        for vulnerability in vulnerabilities:
            create_github_issue(repo, vulnerability)

    except Exception as e:
        print(f"Error accessing repository: {e}")

# Run the main function
if __name__ == "__main__":
    main()
