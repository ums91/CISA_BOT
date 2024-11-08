#! /usr/bin/env python3

""" collect issues published by CISA and create GitHub issues for them """

# pylint: disable=trailing-whitespace
# pylint: disable=line-too-long

import os
import sys
import time
from datetime import date
from datetime import datetime
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
    NVD_API_TOKEN = "8ecc1512-a5f6-4b94-a9ae-b20d0467680f"
    RATE = 25
    MINUTE = 60
    MILESTONE_NAME = "2024Q2"

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
        github_list = self.repo.get_issues(state="all", labels=["Vulnerability", "CISA-Alert"])
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
Confirm if {cisa_item["vendorProject"]} {cisa_item["product"]} vulnerability below is applicable to any systems.

## Reference

From CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

[{cisa_item["cveID"]}](https://nvd.nist.gov/vuln/detail/{cisa_item["cveID"]})

## Severity

{cvss_severity} - CVSS v{cvss_version} {cvss_score} - ({cvss_vector})

## Detailed description of the vulnerability

{nvd_description}

## Reporter

CISA
'''

        labels = ["Vulnerability", "CISA-Alert", f"security-issue-severity::{cvss_severity}".lower()]
        return description, labels

def create_github_issue(self, cisa_item):
    """ create the issue in GitHub """
    today = date.today()
    title = f'{today.year}/{today.strftime("%m")} : Internal-CISA : {cisa_item["vendorProject"]} : {cisa_item["product"]} : {cisa_item["cveID"]}'
    nvd_data = self.get_nvd_data(cisa_item["cveID"])

    description, labels = self.generate_description_and_labels(cisa_item, nvd_data)

    issue = self.repo.create_issue(
        title=title,
        body=description,
        labels=labels
    )
    log_message("\t\tCreated GitHub issue", title)

    # Wait 1 minute and add the issue to the milestone "2024Q2"
    time.sleep(60)

    # Get all milestones and find the one with the correct title
    milestones = self.repo.get_milestones(state="open")  # You can also use 'state="all"' if you want to include closed milestones
    milestone = next((m for m in milestones if m.title == Constants.MILESTONE_NAME), None)

    if milestone:
        issue.edit(milestone=milestone)
        log_message("\t\tAdded issue to milestone", Constants.MILESTONE_NAME)
    else:
        log_message(f"\t\tMilestone '{Constants.MILESTONE_NAME}' not found.", "error")

    # Wait 2 minutes and add a comment
    time.sleep(120)
    issue.create_comment("This vulnerability is not applicable to the product/application, so closing this issue.")

    # Wait another 2 minutes and add the "Remediated_Fixed_Patched" label
    time.sleep(120)
    issue.add_labels("Remediated_Fixed_Patched")

    # Wait 3 more minutes and close the issue
    time.sleep(180)
    issue.edit(state="closed")

    log_complete("Issue closed and updated with comment and label")


    def create_github_issues(self, new_items):
        """ create new GitHub issues from the list of new CISA items """
        for cisa_item in new_items:
            self.create_github_issue(cisa_item)

if __name__ == "__main__":
    Main().main()
