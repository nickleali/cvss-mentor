# stats script after basic data is pulled out of the json

# go through each of the CSVs found and do stats and finally summarize them

# adjust functions so we can get running totals per year returned and we can summarize everything found

# for each CSV, do stats
# sum the stats per year in other tracking values
# give a big report at the end with differences

# system imports

import os
import json

# local imports

from cvssstats import *

# Set this value to the local folder path where the CSV files reside
localFolder = str("./data")

def export_results_to_json(data_object, output_filename="cvss_master_report.json"):
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            # indent=4 makes the file human-readable
            json.dump(data_object, f, indent=4)
        print(f"Successfully exported data to {output_filename}")
    except Exception as e:
        print(f"Error exporting JSON: {e}")

def process_directory(directory_path):
    # Initialize master object to hold aggregated data
    master_results = {
        "files_processed": 0,
        "total_processed": 0,
        "total_identical": 0,
        "total_different": 0,
        "metric_frequencies": {},  # Will sum counts here
        "value_swaps": {}           # Use dict for easy merging: {(m, n, p): count}
    }

    # Iterate through all files in the directory
    for filename in os.listdir(directory_path):
        if filename.endswith(".csv"):
            file_path = os.path.join(directory_path, filename)
            
            # Call the previous function
            file_data = analyze_cvss_discrepancies(file_path)
            
            if "error" in file_data:
                print(f"Skipping {filename}: {file_data['error']}")
                continue

            # Update high-level counters
            master_results["files_processed"] += 1
            master_results["total_processed"] += file_data["total_processed"]
            master_results["total_identical"] += file_data["total_identical"]
            master_results["total_different"] += file_data["total_different"]

            # Merge metric frequencies
            for metric, count in file_data["metric_frequencies"].items():
                master_results["metric_frequencies"][metric] = \
                    master_results["metric_frequencies"].get(metric, 0) + count

            # Merge value swaps
            for swap in file_data["value_swaps"]:
                # Create a unique key for the specific swap
                key = (swap["metric"], swap["nvd_value"], swap["psirt_value"])
                master_results["value_swaps"][key] = \
                    master_results["value_swaps"].get(key, 0) + swap["occurrence_count"]

    # Convert value_swaps back to the list-of-dicts format for consistency
    final_swaps = []
    for (m, vn, vp), count in sorted(master_results["value_swaps"].items(), key=lambda x: x[1], reverse=True):
        final_swaps.append({
            "metric": m,
            "nvd_value": vn,
            "psirt_value": vp,
            "occurrence_count": count
        })
    
    master_results["value_swaps"] = final_swaps
    return master_results

# Example execution:
final_report = process_directory('./data')
print(f"Successfully analyzed {final_report['files_processed']} files.")

# --- Execution Example ---
# 1. Process the directory
master_data = process_directory('./data')

# 2. Export the resulting object
export_results_to_json(master_data)