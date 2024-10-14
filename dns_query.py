import requests
import json
import os
import csv
import time
from datetime import datetime
from requests.exceptions import ConnectionError, RequestException

# Script to find 'keywords' from DNS logs. 
# Using logs from Bind9 stored in Elastic, leveraging the Elastic API to query the DNS logs from a list of known adult content websites. 



# ElasticSearch configuration
# Index Containing DNS logs 
INDEX_PATTERN = "logs-cph-bind9*"   


# Get ElasticSearch credentials and URL from environment variables
CLIENT_IP = os.getenv("CLIENT_IP")
ELASTIC_URL = os.getenv("ELASTIC_URL")
USERNAME = os.getenv("ELASTIC_USERNAME")
PASSWORD = os.getenv("ELASTIC_PASSWORD")

if not USERNAME or not PASSWORD or not ELASTIC_URL or not CLIENT_IP:
    print("Error: ELASTIC_USERNAME or ELASTIC_PASSWORD or ELASTIC_URL or CLIENT_IP environment variables are not set.")
    exit(1)

# Disable warnings for insecure requests (due to self-signed certificates)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

current_time = datetime.now().strftime("%b_%d_%Y_%H%M%S")

# Initialize CSV file
csv_file = f"dns_results_{current_time}_{CLIENT_IP}.csv"
csv_headers = ["URL", "Timestamp"]

# Create CSV file and write the header if it doesn't exist
if not os.path.exists(csv_file):
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)

def query_elastic(url):
    # ElasticSearch Query
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"client.ip": CLIENT_IP}},
                    {"wildcard": {"destination.address": f"*{url}*"}}
                ]
            }
        },
        "_source": ["@timestamp", "client.ip", "destination.address", "message"]  # Fetch the timestamp and other fields
    }

    # ElasticSearch API URL for querying
    query_url = f"{ELASTIC_URL}/{INDEX_PATTERN}/_search"

    retries = 5  # Number of retries for DNS resolution
    wait_time = 10  # Time to wait between retries (in seconds)
    
    for attempt in range(retries):
        try:
            # Perform the request, ignoring SSL certificate warnings
            response = requests.post(
                query_url,
                auth=(USERNAME, PASSWORD),
                headers={"Content-Type": "application/json"},
                data=json.dumps(query),
                verify=False
            )

            # Check if the response is valid
            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                if hits:
                    for hit in hits:
                        timestamp = hit['_source']['@timestamp']
                        message = hit['_source']['message']
                        print(f"Hit found for URL '{url}' at timestamp: {timestamp}")

                        # Append to CSV
                        with open(csv_file, 'a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([url, timestamp, message])

                    return True
                else:
                    return False
            else:
                print(f"Failed to query ElasticSearch. Status Code: {response.status_code}")
                print(response.text)
                time.sleep(5)
                return False
        
        except (ConnectionError, RequestException) as e:
            # If DNS resolution error occurs, wait and retry
            print(f"DNS resolution error or network issue encountered: {e}")
            print(f"Retrying in {wait_time} seconds... (Attempt {attempt + 1}/{retries})")
            time.sleep(wait_time)

    # If all retries fail, exit the function
    print("Max retries reached. Exiting query.")
    return False

def main():
    # Use a relative path to refer to the file in the current directory
    url_list_file = "pi_blocklist_porn_top1m"

    # Open the file containing the list of URLs
    try:
        with open(url_list_file, 'r') as file:
            urls = file.read().splitlines()

        # Query ElasticSearch for each URL in the file
        for url in urls:
            if query_elastic(url):
                pass  # Only show results for URLs that had hits

    except FileNotFoundError:
        print(f"Error: File '{url_list_file}' not found.")

if __name__ == "__main__":
    main()
