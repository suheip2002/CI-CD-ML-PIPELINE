import os
import json
import csv


def extract_nvd_cve_data(cve_entry):
    cve_id = cve_entry["cve"]["CVE_data_meta"]["ID"]
    description = cve_entry["cve"]["description"]["description_data"][0]["value"]

    # Extract CVSS v3 severity if available, otherwise v2
    severity = None
    cvss_v3_score = None
    cvss_v2_score = None

    if "impact" in cve_entry and "baseMetricV3" in cve_entry["impact"]:
        cvss_v3_score = cve_entry["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        severity = cve_entry["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
    elif "impact" in cve_entry and "baseMetricV2" in cve_entry["impact"]:
        cvss_v2_score = cve_entry["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
        severity = cve_entry["impact"]["baseMetricV2"]["severity"]

    # Extract CWE IDs
    cwe_ids = []
    if "problemtype" in cve_entry["cve"] and "problemtype_data" in cve_entry["cve"]["problemtype"]:
        for problem_type in cve_entry["cve"]["problemtype"]["problemtype_data"]:
            for description_item in problem_type["description"]:
                if "value" in description_item and description_item["value"].startswith("CWE-"):
                    cwe_ids.append(description_item["value"])

    # Affected versions (simplified for now, can be expanded later)
    affected_versions = []
    if "configurations" in cve_entry and "nodes" in cve_entry["configurations"]:
        for node in cve_entry["configurations"]["nodes"]:
            if "cpe_match" in node:
                for cpe_match in node["cpe_match"]:
                    if "cpe23Uri" in cpe_match:
                        affected_versions.append(cpe_match["cpe23Uri"])

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "cvss_v3_score": cvss_v3_score,
        "cvss_v2_score": cvss_v2_score,
        "cwe_ids": ", ".join(cwe_ids),
        "affected_versions": ", ".join(affected_versions)
    }


def process_nvd_data(nvd_data_path, output_csv_path):
    all_cve_data = []
    for filename in os.listdir(nvd_data_path):
        if filename.endswith(".json"):
            file_path = os.path.join(nvd_data_path, filename)
            print(f"Processing {filename}...")
            with open(file_path, "r", encoding="utf-8") as f:
                nvd_json = json.load(f)
                if "CVE_Items" in nvd_json:
                    for cve_entry in nvd_json["CVE_Items"]:
                        try:
                            cve_data = extract_nvd_cve_data(cve_entry)
                            all_cve_data.append(cve_data)
                        except Exception as e:
                            print(f"Error processing CVE entry in {filename}: {e}")

    if all_cve_data:
        keys = all_cve_data[0].keys()
        with open(output_csv_path, "w", newline="", encoding="utf-8") as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(all_cve_data)
        print(f"Successfully processed {len(all_cve_data)} NVD CVEs and saved to {output_csv_path}")
    else:
        print("No NVD CVEs found or processed.")


if __name__ == "__main__":
    NVD_DATA_PATH = "nvd_data"
    OUTPUT_CSV_PATH = "nvd_cves.csv"
    process_nvd_data(NVD_DATA_PATH, OUTPUT_CSV_PATH)
