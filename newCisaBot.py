
import os
import sys
import time
from datetime import date, datetime
import logging
from jsonpath_ng.ext import parse as jsonpath_parse
from github import Github
import requests
from ratelimit import limits, sleep_and_retry

os.environ["GITHUB_TOKEN"] = os.getenv("CISA_TOKEN")

REQUEST_TIMEOUT = 60

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

def log_message(message, result=""):
    """ log a message to the screen """
    message = message + " "
    message = f"{message.expandtabs(4).ljust(95, '.')} {result}"
    logging.info(message)

def log_blank():
    """ log a blank line to the screen """
    logging.info("")

def log_complete(message):
    """ log a message as complete """
    log_message(message, "complete")

class Constants:
    """ constants """
    GITHUB_REPO = "ums91/CISA_BOT"
    CISA_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveID="
    NVD_API_TOKEN = "dededdac-a990-43bc-bce6-306b49c66971"
    RATE = 25
    MINUTE = 60
    MILESTONE_NAME = "2024Q2"
    LABEL_REMEDIATED = "Remediated_Fixed_Patched"
    README_FILE = "README.md"

class Main:
    """ main """

    def __init__(self):
        self.github = Github(os.getenv("GITHUB_TOKEN"))
        self.repo = self.github.get_repo(Constants.GITHUB_REPO)

    def download_cisa_list(self):
        """ download issues from CISA """
        log_message("\tDownloading CISA feed")
        response = requests.get(Constants.CISA_FEED_URL, timeout=REQUEST_TIMEOUT)

        if response.ok:
            cisa_list = response.json()
            log_message("\t\tNumber of CISA issues", len(cisa_list["vulnerabilities"]))
            log_complete("\tDownloading CISA feed")

            for cisa_item in cisa_list["vulnerabilities"]:
                cisa_item["cisa_item_in_github_list"] = False

            return cisa_list

        log_message("ERROR: Unable to get CISA feed", "exiting")
        sys.exit(os.EX_DATAERR)

    def main(self):
        """ main """
        log_message("Looking for new CISA issues to report")
        cisa_list = self.download_cisa_list()
        
        cutoff_date = datetime.strptime("2024-10-26", "%Y-%m-%d")
        cisa_list["vulnerabilities"] = [
            item for item in cisa_list["vulnerabilities"]
            if datetime.strptime(item["dateAdded"], "%Y-%m-%d") > cutoff_date
        ]
        
        cisa_list["vulnerabilities"] = sorted(cisa_list["vulnerabilities"], key=lambda k: k["dateAdded"], reverse=True)
        log_blank()

        github_list = self.download_github_list()
        log_blank()

        log_message("\tComparing CISA and GitHub lists")
        for github_item in github_list:
            for cisa_item in cisa_list["vulnerabilities"]:
                if "Internal-CISA".lower() in github_item.title.lower() and cisa_item["cveID"].lower() in github_item.title:
                    cisa_item["cisa_item_in_github_list"] = True
                    break

        new_items = [item for item in cisa_list["vulnerabilities"] if not item["cisa_item_in_github_list"]]
        log_message("\t\tNumber of new CISA issues", len(new_items))

        self.create_github_issues(new_items)
        log_complete("Completed processing CISA issues")    

    def download_github_list(self):
        """ download the GitHub issues list """
        log_message("\tDownloading GitHub issue list")
        github_list = self.repo.get_issues(state="all", labels=["security-issue-source::internally-reported-cisa","security-issue-type::vulnerability", "CISA-Alert"])
        log_message("\t\tNumber of GitHub issues", github_list.totalCount)
        log_complete("\tDownloading GitHub issue list")
        return github_list

    @sleep_and_retry
    @limits(calls=Constants.RATE, period=Constants.MINUTE)
    def get_nvd_data(self, cve):
        """ get the NVD data for a CVE """
        headers = {
            "apiKey": Constants.NVD_API_TOKEN
        }
        response = requests.get(f"{Constants.NVD_API_URL}{cve}", headers=headers, timeout=REQUEST_TIMEOUT)

        if response.ok:
            return response.json()
        else:
            log_message(f"Non-OK return code from NVD database: {response.reason} ({response.status_code})")

        log_message("ERROR: Unable to get NVD data for", cve)
        sys.exit(os.EX_DATAERR)

    def get_cvss_data(self, nvd_data):
        """ parse out the NVD data """
        cvss_version = "TBD"
        cvss_severity = "UNKNOWN"
        cvss_score = ""
        cvss_vector = "No NVD record available at time of creation"

        # Ensure that there is data in the 'metrics' field
        try:
            impact = jsonpath_parse("$.vulnerabilities[0].cve.metrics").find(nvd_data)[0].value
            if impact is not None:
                if "cvssMetricV31" in impact:
                    cvss_version = "3.1"
                    cvss_severity = jsonpath_parse("$.cvssMetricV31[0].cvssData.baseSeverity").find(impact)[0].value
                    cvss_vector = jsonpath_parse("$.cvssMetricV31[0].cvssData.vectorString").find(impact)[0].value
                elif "cvssMetricV30" in impact:
                    cvss_version = "3.0"
                    cvss_severity = jsonpath_parse("$.cvssMetricV30[0].cvssData.baseSeverity").find(impact)[0].value
                    cvss_vector = jsonpath_parse("$.cvssMetricV30[0].cvssData.vectorString").find(impact)[0].value
                elif "cvssMetricV2" in impact:
                    cvss_version = "2"
                    cvss_severity = jsonpath_parse("$.cvssMetricV2[0].baseSeverity").find(impact)[0].value
                    cvss_vector = jsonpath_parse("$.cvssMetricV2[0].cvssData.vectorString").find(impact)[0].value
        except (IndexError, KeyError) as e:
            log_message(f"Error processing CVSS data: {e}. Falling back to default values.")
        
        return cvss_version, cvss_severity, cvss_score, cvss_vector

    def generate_description_and_labels(self, cisa_item, nvd_data):
        """ generate the ticket markdown """
        try:
            nvd_description = jsonpath_parse("$.vulnerabilities[0].cve.descriptions[0].value").find(nvd_data)[0].value
        except IndexError:
            nvd_description = "No description available at the time of issue creation."

        cvss_version, cvss_severity, cvss_score, cvss_vector = self.get_cvss_data(nvd_data)

        description = f'''## Summary
### Vulnerability Name: {cisa_item["vulnerabilityName"]}     
Confirm if {cisa_item["vendorProject"]} {cisa_item["product"]} impacted with {cisa_item["vulnerabilityName"]} - below is applicable to any systems.

## Reference

From CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

[{cisa_item["cveID"]}](https://nvd.nist.gov/vuln/detail/{cisa_item["cveID"]})

## Severity

{cvss_severity} - CVSS v{cvss_version} {cvss_score} - ({cvss_vector})

## Detailed description of the vulnerability

{nvd_description}

## Reporter

CISA - CYBERSECURITY & INFRASTRUCTURE SECURITY AGENCY
'''

        labels = ["security-issue-source::internally-reported-cisa","security-issue-type::vulnerability", "CISA-Alert", f"security-issue-severity::{cvss_severity}".lower()]
        return description, labels

    def create_github_issues(self, new_items):
        """ create GitHub issues for new items """
        log_message("Creating GitHub issues for CISA vulnerabilities")
    
        # Get the current month and year
        current_month_year = datetime.now().strftime("%Y/%m")
        log_message(f"Current month and year: {current_month_year}")
    
        # Get the milestone by name
        milestone = None
        log_message(f"Fetching milestone '{Constants.MILESTONE_NAME}'...")
        for m in self.repo.get_milestones(state='open'):
            if m.title == Constants.MILESTONE_NAME:
                milestone = m
                log_message(f"Milestone '{Constants.MILESTONE_NAME}' found.")
                break
    
        if not milestone:
            log_message(f"ERROR: Milestone '{Constants.MILESTONE_NAME}' not found!", "exiting")
            sys.exit(os.EX_DATAERR)
    
        # Process each CISA item
        log_message(f"Found {len(new_items)} new CISA issues to create.")
        for cisa_item in new_items:
            # Modify the title to include the current month and year, followed by "Internal-CISA"
            issue_title = f"{current_month_year} : Internal-CISA - {cisa_item['vendorProject']} {cisa_item['product']} - {cisa_item['cveID']}"
            log_message(f"Checking if issue '{issue_title}' already exists...")
    
            # Check if an issue with the same title exists (open or closed)
            existing_issues = self.repo.get_issues(state="all", labels=["security-issue-source::internally-reported-cisa","security-issue-type::vulnerability", "CISA-Alert"])
            if any(issue.title == issue_title for issue in existing_issues):
                log_message(f"Issue '{issue_title}' already exists. Skipping creation.")
                continue
    
            log_message(f"Creating issue for CISA item: {cisa_item['cveID']}")
    
            description, labels = self.generate_description_and_labels(cisa_item, self.get_nvd_data(cisa_item["cveID"]))
    
            # Create the issue with the modified title
            try:
                issue = self.repo.create_issue(
                    title=issue_title,
                    body=description,
                    labels=labels
                )
                log_message(f"Issue '{issue_title}' created successfully.")
            except Exception as e:
                log_message(f"ERROR: Failed to create issue '{issue_title}': {str(e)}")
                continue
    
            # Wait for 1 minute, then add milestone
            log_message(f"Waiting 1 minute before adding milestone...")
            time.sleep(60)  # Wait for 1 minute
            try:
                issue.edit(milestone=milestone)
                log_message(f"Milestone '{Constants.MILESTONE_NAME}' added to issue '{issue_title}'.")
            except Exception as e:
                log_message(f"ERROR: Failed to add milestone to issue '{issue_title}': {str(e)}")
    
            # Add comment, label, and close issue with delays
            log_message(f"Waiting 2 minutes before Adding comment to issue '{issue_title}'...")
            time.sleep(120)  # Wait for 2 minute
            try:
                issue.create_comment("This vulnerability is not applicable to any systems.")
                log_message(f"Comment added to issue '{issue_title}'.")
            except Exception as e:
                log_message(f"ERROR: Failed to add comment to issue '{issue_title}': {str(e)}")
    
            log_message(f"Waiting 1 minute before Adding Label to issue '{issue_title}'...")
            time.sleep(60)  # Wait for 1 minute
            try:
                issue.add_to_labels(Constants.LABEL_REMEDIATED)
                log_message(f"Label '{Constants.LABEL_REMEDIATED}' added to issue '{issue_title}'.")
            except Exception as e:
                log_message(f"ERROR: Failed to add label to issue '{issue_title}': {str(e)}")
    
            log_message(f"Waiting 1 minute before closing the issue '{issue_title}'...")
            time.sleep(60)  # Wait for 1 minute
            try:
                issue.edit(state="closed")
                log_message(f"Issue '{issue_title}' closed.")
            except Exception as e:
                log_message(f"ERROR: Failed to close issue '{issue_title}': {str(e)}")
    
        log_complete("GitHub issues creation completed")
        # Update the README file after all issues have been created
        self.update_readme(new_items)


    def update_readme(self, new_items):
        """ update README file with the latest vulnerabilities """
        log_message("Updating README with latest vulnerabilities")
        readme = self.repo.get_contents(Constants.README_FILE)
        readme_content = readme.decoded_content.decode("utf-8")

        # Filter out vulnerabilities that are already in the README
        new_vulnerabilities = []
        for item in new_items:
            vulnerability_entry = f"- **{item['cveID']}**: ({item['vulnerabilityName']}) -\nVendor Project: {item.get('title', f'{item.get('vendorProject', 'Unknown Vendor')} - \nProduct: {item.get('product', 'Unknown Product')}')}"
            if vulnerability_entry not in readme_content:
                new_vulnerabilities.append(vulnerability_entry)

        # If there are no new vulnerabilities to add, skip the update
        if not new_vulnerabilities:
            log_message("No new vulnerabilities to update in README.")
            return

        # Append the filtered new vulnerabilities to the README content
        new_vulnerabilities_content = "\n".join(new_vulnerabilities[:6])
        updated_readme_content = readme_content.replace("## New Vulnerabilities", f"## New Vulnerabilities\n{new_vulnerabilities_content}")

        # Commit the updated README content
        self.repo.update_file(readme.path, "Updating README with new vulnerabilities", updated_readme_content, readme.sha)
        log_complete("README file updated")


if __name__ == "__main__":
    Main().main()
