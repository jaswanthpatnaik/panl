import shutil
import re
import os
from typing import List, Dict, Any
from panl.modules.utils import safe_run

def scan_keywords(filepath: str) -> Dict[str, Any]:
    result = {
        "counts": {},
        "suspicious_found": [],
        "raw_detections": [],
        "error": None
    }
    
    # 1. Structural PDF Analysis (if applicable)
    if filepath.lower().endswith('.pdf'):
        suspicious_pdf_keywords = [
            "/JavaScript", "/JS", "/OpenAction", "/AA", "/EmbeddedFile", 
            "/Launch", "/RichMedia", "/XFA", "/AcroForm", "/ObjStm", "/Encrypt"
        ]
        cmd = "pdfid" if shutil.which("pdfid") else "pdfid.py"
        ret, stdout, stderr = safe_run([cmd, filepath])
        if ret == 0:
            for line in stdout.splitlines():
                for kw in suspicious_pdf_keywords:
                    if kw in line:
                        match = re.search(rf"{kw}\s+(\d+)", line)
                        if match:
                            count = int(match.group(1))
                            if count > 0:
                                result["counts"][kw] = count
                                result["suspicious_found"].append(kw)

    # 2. Raw Binary String Analysis (Heuristics)
    # This detects PowerShell, WScript, and shellcode patterns in ANY file type
    heuristic_patterns = {
        "PowerShell Execution": [rb"powershell", rb"Invoke-Expression", rb"IEX", rb"-ExecutionPolicy", rb"-EncodedCommand"],
        "WScript/CScript Shell": [rb"WScript.Shell", rb"CreateObject", rb"cscript.exe", rb"wscript.exe"],
        "Base64 Executable Header": [rb"TVqQAAMAAAAEAAAA"],
        "Suspicious API Call": [rb"VirtualAlloc", rb"CreateRemoteThread", rb"WriteProcessMemory", rb"ShellExecute"],
        "Network Callback": [rb"http://", rb"https://", rb"ftp://", rb"socket.connect"]
    }
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            for category, patterns in heuristic_patterns.items():
                found_in_cat = []
                for p in patterns:
                    if re.search(p, content, re.IGNORECASE):
                        found_in_cat.append(p.decode(errors='ignore'))
                if found_in_cat:
                    result["raw_detections"].append({"category": category, "matches": found_in_cat})
    except Exception as e:
        result["error"] = str(e)
                        
    return result
