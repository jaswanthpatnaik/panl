import requests
import time
import os

def check_virustotal(sha256, md5, api_key):
    if not api_key:
        return None
        
    # Try SHA256 first
    results = _query_vt(sha256, api_key)
    
    # Fallback to MD5 if SHA256 is not found (sometimes helps with indexing)
    if results and results.get("error") == "File not found on VirusTotal":
        results_md5 = _query_vt(md5, api_key)
        if results_md5 and not results_md5.get("error"):
            return results_md5
            
    return results

def upload_to_virustotal(file_path, api_key):
    if not api_key:
        return {"error": "API Key required for upload", "status": "error"}
        
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(url, headers=headers, files=files, timeout=60)
            
        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            return {
                "status": "success",
                "analysis_id": analysis_id,
                "message": "File successfully submitted for scanning."
            }
        else:
            return {"error": f"Upload failed: {response.status_code}", "status": "error"}
    except Exception as e:
        return {"error": f"Upload error: {str(e)}", "status": "error"}

def _query_vt(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        # Base link is always deterministic for a hash
        vt_link = f"https://www.virustotal.com/gui/file/{file_hash}"
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()) if stats else 0,
                "link": vt_link,
                "status": "found"
            }
        elif response.status_code == 404:
            return {"error": "File not found on VirusTotal", "status": "not_found", "link": vt_link}
        elif response.status_code == 401:
            return {"error": "Invalid VirusTotal API Key", "status": "error", "link": vt_link}
        elif response.status_code == 429:
            return {"error": "VirusTotal API Rate Limit Exceeded", "status": "error", "link": vt_link}
        else:
            return {"error": f"VT API Error: {response.status_code}", "status": "error", "link": vt_link}
    except Exception as e:
        return {"error": f"Connection Error: {str(e)}", "status": "error", "link": f"https://www.virustotal.com/gui/file/{file_hash}"}
