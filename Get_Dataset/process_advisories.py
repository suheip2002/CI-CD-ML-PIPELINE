import os
import json
import csv


def extract_advisory_data(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        advisory = json.load(f)

    # Extracting required fields
    cve_id = advisory.get('id', '')
    description = advisory.get('details', '')

    # Severity (CVSS or GitHub rating)
    severity = None
    if 'severity' in advisory.get('database_specific', {}):
        severity = advisory['database_specific']['severity']
    elif 'severity' in advisory.get('severity', []):
        # Assuming the first severity entry is the primary one
        severity = advisory['severity'][0].get('score')

        # CWE IDs
    cwe_ids = []
    if 'cwe_ids' in advisory.get('database_specific', {}):
        cwe_ids = advisory['database_specific']['cwe_ids']
    elif 'weaknesses' in advisory:
        for weakness in advisory['weaknesses']:
            if 'cweId' in weakness:
                cwe_ids.append(weakness['cweId'])

    # Affected versions
    affected_versions = []
    if 'affected' in advisory:
        for affected_item in advisory['affected']:
            if 'versions' in affected_item:
                affected_versions.extend(affected_item['versions'])
            if 'ranges' in affected_item:
                for r in affected_item['ranges']:
                    for event in r['events']:
                        if 'introduced' in event:
                            affected_versions.append(f"introduced:{event['introduced']}")
                        if 'fixed' in event:
                            affected_versions.append(f"fixed:{event['fixed']}")

    return {
        'cve_id': cve_id,
        'description': description,
        'severity': severity,
        'cwe_ids': ', '.join(cwe_ids),
        'affected_versions': ', '.join(affected_versions)
    }


def process_advisories(advisory_db_path, output_csv_path):
    data = []
    # Walk through the advisory database directory
    for root, _, files in os.walk(advisory_db_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    advisory_data = extract_advisory_data(file_path)
                    data.append(advisory_data)
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")

    # Write to CSV
    if data:
        keys = data[0].keys()
        with open(output_csv_path, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(data)
        print(f"Successfully processed {len(data)} advisories and saved to {output_csv_path}")
    else:
        print("No advisories found or processed.")


if __name__ == '__main__':
    # This script assumes you have cloned the GitHub Advisory Database
    # into a directory named 'advisory-database' in the same location as this script.
    # Adjust the path if your setup is different.
    ADVISORY_DB_PATH = 'advisory-database/advisories'
    OUTPUT_CSV_PATH = 'github_advisories.csv'
    process_advisories(ADVISORY_DB_PATH, OUTPUT_CSV_PATH)

