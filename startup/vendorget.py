# parse the NVD JSON and get a list of all the vendors present

import json
import os

def extract_vendors(json_data, output_file="found_vendors.txt"):
    """
    Parses JSON data to find unique sourceIdentifiers, saves them to a file,
    and returns them as a list.
    """
    # If the input is a string, parse it into a dictionary
    if isinstance(json_data, str):
        data = json.loads(json_data)
    else:
        data = json_data

    unique_identifiers = set()

    # Navigate the JSON structure: vulnerabilities -> cve -> sourceIdentifier
    vulnerabilities = data.get("vulnerabilities", [])
    
    for entry in vulnerabilities:
        cve_data = entry.get("cve", {})
        source_id = cve_data.get("sourceIdentifier")
        
        if source_id:
            unique_identifiers.add(source_id)

    # Convert set to a sorted list for consistent output
    result_list = sorted(list(unique_identifiers))

    # Store the values to a file
    try:
        with open(output_file, "w") as f:
            for identifier in result_list:
                f.write(f"{identifier}\n")
        print(f"Successfully saved {len(result_list)} unique identifiers to {output_file}")
    except IOError as e:
        print(f"Error writing to file: {e}")

    return result_list

# Example Usage:
'''
file_path = "/workspaces/python-2/cvss-mentor/data/report_2026.json"

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        unique_ids = extract_vendors(data, output_file="found_vendors.txt")
        print(unique_ids)
except FileNotFoundError:
    print(f"Error: The file '{file_path}' was not found.")
except json.JSONDecodeError:
    print(f"Error: Could not decode JSON from '{file_path}'. Please check file format.")
'''