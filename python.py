import requests
import csv
import os
import time
import logging

# --- CONFIGURATION ---
# In a real company, these thresholds usually come from a config file.
BLOCK_THRESHOLD = 50
INPUT_FILE = 'suspicious_ips.csv'
OUTPUT_FILE = 'firewall_blocklist.csv'
LOG_FILE = 'automation.log'

# --- SETUP LOGGING ---
# Real tools log to a file so you can debug what happened yesterday.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Get API Key securely from Environment Variable
# If not found, it warns the user but doesn't crash immediately (unless you try to run it).
API_KEY = os.getenv('ABUSEIPDB_KEY')

def check_ip_reputation(ip):
    """
    Queries AbuseIPDB for the given IP address.
    Returns: (score, country_code) or (None, None) on error.
    """
    if not API_KEY:
        logging.error("API Key missing! Set 'ABUSEIPDB_KEY' in your environment variables.")
        return None, None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {'ipAddress': ip, 'maxAgeInDays': 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        # Check for specific HTTP errors
        if response.status_code == 401:
            logging.error("Unauthorized: Check your API Key.")
            return None, None
        if response.status_code == 429:
            logging.warning("Rate limit exceeded. Slowing down...")
            time.sleep(5)
            return None, None
            
        response.raise_for_status()
        data = response.json()['data']
        return data['abuseConfidenceScore'], data['countryCode']

    except requests.exceptions.RequestException as e:
        logging.error(f"Network error checking {ip}: {e}")
        return None, None

def create_dummy_input():
    """Creates a dummy CSV if one doesn't exist, just for testing purposes."""
    if not os.path.exists(INPUT_FILE):
        logging.info(f"Input file not found. Creating a dummy {INPUT_FILE} for testing...")
        with open(INPUT_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP_Address']) # Header
            writer.writerow(['118.25.6.39']) # Known bad IP
            writer.writerow(['8.8.8.8'])     # Google DNS (Clean)
            writer.writerow(['192.168.1.1']) # Local IP
        logging.info("Dummy data created.")

def main():
    logging.info("--- Starting Threat Intel Enrichment Process ---")
    
    # 1. Ensure we have data to process
    create_dummy_input()

    # 2. Process the file
    try:
        with open(INPUT_FILE, 'r') as infile, open(OUTPUT_FILE, 'w', newline='') as outfile:
            reader = csv.reader(infile)
            writer = csv.writer(outfile)
            
            # Write headers for the output report
            writer.writerow(['IP_Address', 'Risk_Score', 'Country', 'Action', 'Timestamp'])

            # Handle case where input file might handle headers differently
            header = next(reader, None)
            if header and "IP" not in header[0] and "." in header[0]:
                 # If the first row looks like an IP, reset cursor (no header in file)
                 infile.seek(0)
            
            count = 0
            for row in reader:
                if not row: continue # Skip empty rows
                
                ip = row[0].strip()
                logging.info(f"Analyzing: {ip}")
                
                score, country = check_ip_reputation(ip)
                
                if score is not None:
                    action = "BLOCK" if score > BLOCK_THRESHOLD else "MONITOR"
                    writer.writerow([ip, score, country, action, time.strftime("%Y-%m-%d %H:%M:%S")])
                    
                    if action == "BLOCK":
                        logging.warning(f"HIGH RISK DETECTED: {ip} (Score: {score}) -> Added to Blocklist")
                    else:
                        logging.info(f"Low Risk: {ip} (Score: {score})")
                
                count += 1
                # Respect API limits (Free tier usually allows limited reqs/min)
                time.sleep(1)

        logging.info(f"--- Completed. Processed {count} IPs. Results in {OUTPUT_FILE} ---")

    except FileNotFoundError:
        logging.critical(f"Critical Error: Could not handle file operations.")
    except Exception as e:
        logging.critical(f"Unexpected crash: {e}")

if __name__ == "__main__":
    main()
