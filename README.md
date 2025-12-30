Automated Threat Intelligence & Firewall Triage

Overview

This tool automates the daily SOC task of analyzing suspicious IP addresses. It ingests a list of IPs (e.g., from a SIEM export like Splunk or Wazuh), enriches them with real-time reputation data from AbuseIPDB, and generates a structured blocklist for the Network Security team.

Business Value:

Reduces manual lookup time by 90%.

Eliminates human error in copy-pasting IP addresses.

Creates a standardized audit trail (automation.log).

Features

Automated Enrichment: Queries AbuseIPDB API for confidence scores and country of origin.

Smart Thresholding: Automatically categorizes IPs as BLOCK or MONITOR based on a configurable risk score (Default: >50).

Enterprise Logging: Records all actions and errors to automation.log for auditing.

Error Handling: Resilient against network timeouts and API rate limits.

Prerequisites

Python 3.x

An AbuseIPDB API Key (Free tier is sufficient for testing).

Installation

Clone or Download the script.

Install dependencies:

pip install requests


Configure your API Key:
Security Note: Never hardcode API keys in the script.

Windows (PowerShell):

$env:ABUSEIPDB_KEY="your_api_key_here"


Mac/Linux:

export ABUSEIPDB_KEY="your_api_key_here"


Usage

Place your list of suspicious IPs in a file named suspicious_ips.csv.
Note: If the file doesn't exist, the script will create a dummy one for testing.

Run the automation:

python threat_intel_bot.py


Check the results:

Report: Open firewall_blocklist.csv to see the decision matrix.

Logs: Open automation.log to troubleshoot any issues.

Configuration

You can adjust the blocking threshold in threat_intel_bot.py:

BLOCK_THRESHOLD = 50  # Lower this to be more aggressive, raise it to reduce false positives


Disclaimer

This tool is intended for defensive security purposes. Always verify high-impact blocks before applying them to production firewalls.
