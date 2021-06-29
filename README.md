# VirusTotal V3 API Tool

### This tool utilizes the VirusTotal V3 API.
https://developers.virustotal.com/v3.0/reference

I have used this python library to communicate with the API. 
https://virustotalapi3.readthedocs.io/en/latest/

### Features:
- Fetch indiactor report from VirusTotal
- Automatically determine indicator type
- - Types accepted: [File Hash(md5, sha-1, sha-256), IPv4 Address, Domain/URL]
- Store apikey in a dotfile (.apikey) or keep it in memory during execution.

### Usage:
You need Python3 in order to run this.

1. python3 -m pip install requirements.txt (or pip install -r requirements.txt)
2. python3 vt3.py

### TODO:
- Implement file upload and analysis
- Implement API rate checking

## Disclaimer:
### Use this tool at your own risk, while this tool has been tested and it works, I assume no responsibility or liability.