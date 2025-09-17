import requests
import os
import gzip
import shutil

NVD_FEEDS_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"


def get_nvd_json_feed_urls():
    # This function would typically parse the NVD page to find the latest JSON feed URLs.
    # For simplicity, we'll assume we know the format for recent years.
    # In a real-world scenario, you might use BeautifulSoup to parse https://nvd.nist.gov/vuln/data-feeds#CVE_FEED
    # to get the exact file names and hashes.

    # Example for a few recent years and the \'modified\' feed
    urls = []
    current_year = 2025  # Assuming current year for the project
    for year in range(2002, current_year + 1):
        urls.append(f"{NVD_FEEDS_URL}nvdcve-1.1-{year}.json.gz")
    urls.append(f"{NVD_FEEDS_URL}nvdcve-1.1-modified.json.gz")
    return urls


def download_and_extract_nvd_feed(url, output_dir="nvd_data"):
    os.makedirs(output_dir, exist_ok=True)

    file_name_gz = os.path.basename(url)
    file_path_gz = os.path.join(output_dir, file_name_gz)
    file_name_json = file_name_gz.replace(".gz", "")
    file_path_json = os.path.join(output_dir, file_name_json)

    print(f"Downloading {url}...")
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(file_path_gz, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"Downloaded {file_name_gz}. Extracting...")
        with gzip.open(file_path_gz, "rb") as f_in:
            with open(file_path_json, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        print(f"Extracted to {file_path_json}")
        os.remove(file_path_gz)  # Clean up .gz file
    except requests.exceptions.RequestException as e:
        print(f"Error downloading or extracting {url}: {e}")


if __name__ == "__main__":
    feed_urls = get_nvd_json_feed_urls()
    for url in feed_urls:
        download_and_extract_nvd_feed(url)

