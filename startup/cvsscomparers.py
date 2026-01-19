# functions that do CVSS vector comparison

def compare_cvss_vectors(vector1, vector2):
    """
    Compares two CVSS v3.1 vector strings and returns a list of values of True or False for each metric compared.
    """
    def parse_vector(vector):
        # Remove the "CVSS:3.1/" prefix
        if vector.startswith("CVSS:3.1/"):
            vector = vector.replace("CVSS:3.1/", "")
        # Split into components
        components = vector.split('/')
        metrics = {}
        for comp in components:
            if ':' in comp:
                k, v = comp.split(':', 1)
                metrics[k] = v
        return metrics

    metrics1 = parse_vector(vector1)
    metrics2 = parse_vector(vector2)

    # Union of all metric keys (in case one vector is missing a metric)
    all_keys = set(metrics1.keys()) | set(metrics2.keys())
    diffs = {}
    for key in all_keys:
        diffs[key] = metrics1.get(key) == metrics2.get(key)

    # If all are True, return None (vectors are identical)
    if all(diffs.values()):
        return None
    return diffs

def compare_cvss_vectors_detail(nvd_vector_str, psirt_vector_str):
    """
    Compares two CVSS v3.1 vector strings and returns a string detailing differences.
    """
    nvd_metrics = parse_cvss_vector(nvd_vector_str)
    psirt_metrics = parse_cvss_vector(psirt_vector_str)

    differences = []
    
    # Get all unique metric keys from both dictionaries
    all_metric_keys = sorted(list(set(nvd_metrics.keys()) | set(psirt_metrics.keys())))

    for key in all_metric_keys:
        nvd_val = nvd_metrics.get(key, "N/A") # Use "N/A" if metric is missing from one
        psirt_val = psirt_metrics.get(key, "N/A")

        if nvd_val != psirt_val:
            differences.append(f"{key}: NVD={nvd_val}, PSIRT={psirt_val}")
    
    if differences:
        return "; ".join(differences)
    else:
        return "No specific differences found (should not happen if overall vectors are different)"

def parse_cvss_vector(vector_string):
    """
    Parses a CVSS v3.1 vector string into a dictionary of metric-value pairs.
    Example: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
    Returns: {'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'R', 'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N'}
    """
    metrics = {}
    if not vector_string or not vector_string.startswith("CVSS:3.1/"):
        return metrics

    parts = vector_string.split('/')[1:] # Skip "CVSS:3.1"
    for part in parts:
        if ':' in part:
            key, value = part.split(':', 1)
            metrics[key] = value
    return metrics