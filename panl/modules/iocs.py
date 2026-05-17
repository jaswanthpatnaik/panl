import re
import subprocess
import os

def extract_iocs(filepath):
    result = {
        "urls": [],
        "ips": [],
        "emails": [],
        "domains": []
    }
    
    patterns = {
        "urls": r"https?://[^\s/$.?#].[^\s]*",
        "ips": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "domains": r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\b"
    }
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            # Native Python 'strings' implementation
            import string
            printable = set(string.printable.encode())
            raw_text = "".join(chr(b) if b in printable else " " for b in content)
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, raw_text)
            for m in set(matches):
                # Clean trailing punctuation from URLs/domains
                m = m.rstrip(').,;:"\'')
                result[key].append({"value": m, "type": key.rstrip("s").upper()})
                
    except Exception as e:
        print(f"[!] IOC Extraction Error: {e}")
        
    return result
