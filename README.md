# VT-Eyre

**VT-Eyre** is a lightweight Python CLI tool for scanning URLs and files for malware using a local FastAPI backend server and the VirusTotal API. It is designed to be beginner-friendly while following professional Python packaging practices.

---

## Features

- Scan URLs or files for potential malware
- CLI-based tool for simple usage
- Local FastAPI server handles communication with VirusTotal API
- Clear scan summary including:
  - Malicious
  - Suspicious
  - Harmless
  - Undetected

---

## Installation

Install VT-Eyre via pip:

'''bash
pip install vt-eyre==0.8.0

### Run VT-Eyre CLI

Scan a URL:

``bash
vt-eyre --url example.com

Scan a file:
vt-eyre --file malicious.txt


