import requests


SERVER_URL = "http://127.0.0.1:8000"


def scan_file(file_path, server_url=SERVER_URL):

    try:
        with open(file_path, "rb") as f:
            response = requests.post(
                f"{server_url}/scan-file",
                files={"file": (file_path, f)}
            )
        if response.status_code == 200:
            print(f"✅ File scanned successfully: {file_path}")
            print(response.json())
        else:
            print(f"❌ Error ({response.status_code}): {response.text}")
    except FileNotFoundError:
        print(f"❌ Error: File not found: {file_path}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error while scanning file: {e}")


def scan_url(url, server_url=SERVER_URL):

    try:
        response = requests.post(
            f"{server_url}/scan-url",
            data={"url_to_scan": url}
        )
        if response.status_code != 200:
            print(f"❌ Error ({response.status_code}): {response.text}")
            return

        print(f"✅ URL scanned successfully: {url}")
        data = response.json()

  
        if "data" not in data or "attributes" not in data["data"]:
            print("⚠️ Warning: Scan result format unexpected.")
            print(data)
            return

        stats = data["data"]["attributes"]["last_analysis_stats"]

        print("\n🔎 Scan Results Summary:")
        print(f"Malicious  : {stats.get('malicious', 0)}")
        print(f"Suspicious : {stats.get('suspicious', 0)}")
        print(f"Harmless   : {stats.get('harmless', 0)}")
        print(f"Undetected : {stats.get('undetected', 0)}")

        if stats.get("malicious", 0) > 0:
            print("\n⚠️ WARNING: This URL is flagged as malicious by some engines!")
        else:
            print("\n✅ This URL appears safe based on current scans.")

    except requests.exceptions.RequestException as e:
        print(f"❌ Network error while scanning URL: {e}")
