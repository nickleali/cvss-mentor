# set of steps to set up the application

import json
import os

# helper library imports
from cvsscomparers import *
from cvssscrapers import *

# 0. load database connection parameters from config file
## 

postgresConf = 'postgres.conf'

try:
    with open(postgresConf, 'r', encoding='utf-8') as file:
        postgresConfLoaded = json.load(file)
        if isinstance(postgresConfLoaded, list):
            print (f"Loaded JSON list from '{postgresConfLoaded}':")
        else:
            print("Error: The file does not contain a top-level JSON list.")
except FileNotFoundError:
    print(f"Error: The file '{postgresConf}' was not found.")
except json.JSONDecodeError:
    print("Error: Failed to decode JSON from the file. Check for invalid JSON syntax.")

# 0.1 get JSON from NVD, store locally

# 1. create the database
## call database-build.py functions

# 2. scrape files in the source directory, return JSON list
## call source-scraper.py functions
## ensure we load all the json files from the directory

# define the local directory where the files exist

localFolder = '/data'

# file_name = "/workspaces/mycvss/cve/nvd/2023/nvdcve-2.0-2023.json"

# Define the input JSON file name
input_json_file = "./data/2025.json"
# Define the output CSV file name based on the input JSON file name
output_csv_file = os.path.splitext(input_json_file)[0] + ".csv"

# Process the JSON file to extract and compare vectors
extracted_comparisons = process_cve_json(input_json_file)

# Save the results to a CSV file
save_to_csv(extracted_comparisons, output_csv_file)

if extracted_comparisons:
    print("\n--- Console Output of Extracted Comparisons ---")
    for entry in extracted_comparisons:
        print(f"CVE ID: {entry['cve_id']}")
        print(f"  NVD Vector: {entry['nvd_vector']}")
        print(f"  PSIRT Vector: {entry['psirt_vector']}")
        print(f"  Comparison Result: {entry['comparison_result']}")
        if entry['detailed_differences']:
            print(f"  Detailed Differences: {entry['detailed_differences']}")
        print("-" * 30)
else:
    print("No CVSS vector pairs found with both NVD and PSIRT sources for comparison.")

# 2.1 for testing, also output JSON into text and CSV

# 3. store the JSON list in the database
## create new module database-store.py with functions to store data

# 4. create complimentary stats tables