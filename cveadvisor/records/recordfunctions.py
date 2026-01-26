import json

def find_cve_data(json_filepath, cve_id):
    with open(json_filepath, 'r', encoding='utf-8') as f:
        cve_list = json.load(f)

    for record in cve_list:
        cve = record.get('cve', {})

        # Check CVE ID
        if cve.get('id') != cve_id:
            continue

        # 1. Description (first English description)
        description = None
        for desc in cve.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value')
                break

        # 2. Vendor CVSS v4.0 metric string
        vendor_cvss_v40 = None
        for metric in cve.get('metrics', {}).get('cvssMetricV40', []):
            if (metric.get('source') == cve.get('sourceIdentifier') and
                metric.get('type', '').lower() == 'secondary'):
                vendor_cvss_v40 = metric.get('cvssData', {}).get('vectorString')
                break

        # 3. Vendor CVSS v3.1 metric string
        vendor_cvss_v31 = None
        for metric in cve.get('metrics', {}).get('cvssMetricV31', []):
            if (metric.get('source') == cve.get('sourceIdentifier') and
                metric.get('type', '').lower() == 'secondary'):
                vendor_cvss_v31 = metric.get('cvssData', {}).get('vectorString')
                break

        # 4. NVD CVSS v3.1 metric string (source NVD, type Primary)
        nvd_cvss_v31 = None
        for metric in cve.get('metrics', {}).get('cvssMetricV31', []):
            if (metric.get('source', '').lower() == 'nvd@nist.gov' and
                metric.get('type', '').lower() == 'primary'):
                nvd_cvss_v31 = metric.get('cvssData', {}).get('vectorString')
                break

        # 5. CWE value (first English weakness description)
        cwe_value = None
        for weakness in cve.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en' and desc.get('value', '').startswith('CWE-'):
                    cwe_value = desc.get('value')
                    break
            if cwe_value:
                break

        return {
            'description': description,
            'vendor_cvss_v40': vendor_cvss_v40,
            'vendor_cvss_v31': vendor_cvss_v31,
            'nvd_cvss_v31': nvd_cvss_v31,
            'cwe_value': cwe_value
        }

    return None  # If not found