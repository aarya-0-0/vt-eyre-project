# server.py
import os
import requests
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="VT-Eyre Server",
    description="API server for vt-eyre CLI tool",
)

# Allow all origins (optional, allows CLI from anywhere)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Read your VirusTotal API key from environment variable
VT_API_KEY = os.environ.get("5ca6f006544e46c5dd85b10def7d5fc0bb5dd0c91e02e01b43c77894dc0ad6e7")
if not VT_API_KEY:
    raise ValueError("Please set the VT_API_KEY environment variable!")

HEADERS = {"x-apikey": VT_API_KEY}

VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_FILE_SCAN = "https://www.virustotal.com/api/v3/files"

@app.post("/scan-url")
async def scan_url(url_to_scan: str = Form(...)):
    """Scan a URL using VirusTotal API"""
    # VirusTotal expects URL encoded in base64
    import base64
    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
    
    # Submit URL for scanning
    resp = requests.post(VT_URL_SCAN, data={"url": url_to_scan}, headers=HEADERS)
    if resp.status_code != 200:
        return {"error": resp.text, "status_code": resp.status_code}
    
    # Fetch analysis result
    result = requests.get(f"{VT_URL_SCAN}/{url_id}", headers=HEADERS)
    return result.json()

@app.post("/scan-file")
async def scan_file(file: UploadFile = File(...)):
    """Scan a file using VirusTotal API"""
    files = {"file": (file.filename, await file.read())}
    resp = requests.post(VT_FILE_SCAN, files=files, headers=HEADERS)
    if resp.status_code != 200:
        return {"error": resp.text, "status_code": resp.status_code}
    
    file_id = resp.json().get("data", {}).get("id")
    if file_id:
        result = requests.get(f"{VT_FILE_SCAN}/{file_id}", headers=HEADERS)
        return result.json()
    else:
        return {"error": "Failed to get file scan ID", "response": resp.json()}
