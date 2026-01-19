# functions for performing stats and comparisons on sets of CVSS vector data

# prepare a function that reads a CSV file of vectors, diffs them, and finds a count of the differences
# 

import csv
from collections import Counter

def process_cve_stats(fileCSV):
    '''
    This function will check for the differences in pairs of CVSS strings in a provided document.

    The function will maintain a count of all of the observed differences and maintain an index of the different metrics.

    At the end, the function will return statistics about the set: the total number of same vector pairs, total different, and percentages. 
    Then, the function will return the total count of all different metrics in the set as a function of percentages.

    For example, in the 100 records, impact metrics are observed to be different a certain percent of the time.
    '''

def analyze_cvss_discrepancies(file_path):
    analysis_results = {
        "total_processed": 0,
        "total_identical": 0,
        "total_different": 0,
        "metric_frequencies": {},
        "value_swaps": []
    }
    
    metric_counts = Counter()
    swap_counts = Counter()

    try:
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                analysis_results["total_processed"] += 1
                nvd_str = row['nvd_vector']
                psirt_str = row['psirt_vector']

                if nvd_str == psirt_str:
                    analysis_results["total_identical"] += 1
                    continue
                
                analysis_results["total_different"] += 1
                
                # Parse strings into dicts (e.g., {"AV": "N", "AC": "L", ...})
                nvd_m = {item.split(':')[0]: item.split(':')[1] for item in nvd_str.split('/') if ':' in item}
                psirt_m = {item.split(':')[0]: item.split(':')[1] for item in psirt_str.split('/') if ':' in item}

                all_metrics = set(nvd_m.keys()).union(psirt_m.keys())
                
                for m in all_metrics:
                    val_n = nvd_m.get(m)
                    val_p = psirt_m.get(m)
                    
                    if val_n != val_p:
                        metric_counts[m] += 1
                        swap_counts[(m, val_n, val_p)] += 1

        # Format metric frequencies for the return object
        analysis_results["metric_frequencies"] = dict(metric_counts.most_common())

        # Format specific swaps into a list of dictionaries
        for (metric, nvd_val, psirt_val), count in swap_counts.most_common():
            analysis_results["value_swaps"].append({
                "metric": metric,
                "nvd_value": nvd_val,
                "psirt_value": psirt_val,
                "occurrence_count": count
            })

    except FileNotFoundError:
        return {"error": f"File not found at {file_path}"}

    return analysis_results

# Example usage:
# data_object = analyze_cvss_discrepancies('cvss_data.csv')
# print(data_object["metric_frequencies"])

def analyze_cvss_differences(file_path):
    '''
    A simple python function that will parse a file that contains lines of CVSS data and compare them 
    The function expects a file with pairs of CVSS:3.1 vector strings to determine what metrics are different.
    The function should maintain a count of each of the total vector strings that are different 
    and maintain a count of the individual differences in the metrics of each vector string. 
    '''
    total_vectors = 0
    total_different_vectors = 0
    metric_diff_counts = Counter()

    with open(file_path, mode='r', encoding='utf-8') as f:
        # Use csv.DictReader to automatically handle headers and quoted fields
        reader = csv.DictReader(f)
        
        for row in reader:
            total_vectors = total_vectors + 1
            nvd_str = row['nvd_vector']
            psirt_str = row['psirt_vector']

            if nvd_str == psirt_str:
                continue
            
            # Increment count for vectors that don't match exactly
            total_different_vectors += 1
            
            # Convert "CVSS:3.1/AV:N/AC:L..." into {'AV': 'N', 'AC': 'L', ...}
            nvd_metrics = dict(item.split(':') for item in nvd_str.split('/') if ':' in item)
            psirt_metrics = dict(item.split(':') for item in psirt_str.split('/') if ':' in item)

            # Compare individual metrics
            # Common CVSS 3.1 metrics: AV, AC, PR, UI, S, C, I, A
            all_keys = set(nvd_metrics.keys()).union(psirt_metrics.keys())
            
            for key in all_keys:
                if nvd_metrics.get(key) != psirt_metrics.get(key):
                    metric_diff_counts[key] += 1

    # Output Results
    print(f"--- Analysis Report ---")
    print(f"Total Vector Strings Found: {total_vectors}")
    print(f"Total Vector Strings with Differences: {total_different_vectors}")
    print(f"\nFrequency of Metric Discrepancies:")
    for metric, count in metric_diff_counts.most_common():
        print(f"- {metric}: {count} occurrences")

# Example usage:
# analyze_cvss_differences('./data/2023.csv')