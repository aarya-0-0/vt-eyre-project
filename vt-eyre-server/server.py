from fastapi import FastAPI, UploadFile, Form
import requests
import uvicorn

app = FastAPI()

VT_API_KEY = "5ca6f006544e46c5dd85b10def7d5fc0bb5dd0c91e02e01b43c77894dc0ad6e7       "  # Keep your VirusTotal API key here

@app.post("/scan-file")
async def scan_file(file: UploadFile):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.post(url, headers=headers, files={"file": (file.filename, await file.read())})
    return response.json()

@app.post("/scan-url")
async def scan_url(url_to_scan: str = Form(...)):
    import base64
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).rstrip(b"=").decode()
    response = requests.get(f"{api_url}/{url_id}", headers=headers)
    return response.json()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)  
