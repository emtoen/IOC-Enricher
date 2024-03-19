import warnings
warnings.filterwarnings('ignore')
import requests
import json
import csv
import argparse
from tqdm import tqdm

# Create the argument parser
parser = argparse.ArgumentParser(description="IP Reputation Lookup")
parser.add_argument("input_file", help="Path to the input file")
# Add any additional arguments you need

# Parse the command-line arguments
args = parser.parse_args()

input_file = args.input_file


# Your VirusTotal API key
api_key = "xxxxxxxxxxxxxxxxxxxxxxxxxx"

# Virustotal Endpoint for retrieving ip address lookups
endpoint = "https://www.virustotal.com/api/v3/ip_addresses/"

headers = {"accept": "application/json"}

# file where the results gets saved
csv_filename = "results.csv"

# Read the IP addresses from the file
with open(input_file, "r") as file:
    ip_addresses = [line.strip() for line in file]  

with open(csv_filename, "w", newline="") as file:
    writer = csv.writer(file)

    # Write header row
    writer.writerow(["IP Address", "Country", "Response Data"])
    with tqdm(total=len(ip_addresses), desc="Progress") as pbar:
        for ip_address in ip_addresses:
            # Make a GET request to the endpoint with the IP address
            response = requests.get(f"{endpoint}/{ip_address}", headers={"x-apikey": api_key})

            if response.status_code == 200:
                # Do something with the response data
                data = response.json()
                verdict = (data["data"]["attributes"]["last_analysis_stats"]["malicious"])
                if verdict > 0:
                    status =  "Malicious"
                    try:
                        country = data["data"]["attributes"]["country"]
                    except KeyError:
                        country = 'NA'
                    writer.writerow([ip_address, country, status])
                else:
                    status =  "Undetected"
                    try:
                        country = data["data"]["attributes"]["country"]
                    except KeyError:
                        country = 'N.A'
                    writer.writerow([ip_address, country, status])
            else:
                writer.writerow([ip_address, "", "", f"Error occurred: {response.status_code}"])
                print("Error occurred:", response.status_code)
            pbar.update(1)
print("Scan Completed!")


