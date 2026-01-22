# parse the NVD JSON and get a list of all the vendors present

import json

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
# raw_json = """{ ... your json string ... }"""
# unique_ids = extract_unique_source_identifiers(raw_json)
# print(unique_ids)