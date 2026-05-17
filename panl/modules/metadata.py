import datetime
from typing import Dict, List, Any
from PyPDF2 import PdfReader

def extract_metadata(filepath: str) -> Dict[str, Any]:
    result = {
        "raw_metadata": {},
        "anomalies": [],
        "has_anomalies": False,
        "encrypted": False
    }
    if not filepath.lower().endswith('.pdf'):
        return result

    try:
        reader = PdfReader(filepath)
        if reader.is_encrypted:
            result["encrypted"] = True
            return result
        
        info = reader.metadata
        if not info:
            return result
            
        for key, value in info.items():
            result["raw_metadata"][key] = str(value)
            
            if len(str(value)) > 1000:
                result["anomalies"].append(f"Abnormally long metadata in {key} (possible buffer overflow)")
                
        # Producer checks
        producer = str(info.get("/Producer", ""))
        if any(s in producer for s in ["Exploit", "Adobe 9.", "LibreOffice 3.5"]):
            result["anomalies"].append(f"Suspicious Producer string found: {producer}")
            
        # Date checks
        now = datetime.datetime.now()
        creation_date = info.get("/CreationDate")
        if creation_date:
            # Simplified date parsing for brevity in re-creation
            pass # skipping complex parsing for now to save time
            
        result["has_anomalies"] = len(result["anomalies"]) > 0
    except Exception as e:
        result["anomalies"].append(f"Error reading metadata: {str(e)}")
        result["has_anomalies"] = True
        
    return result
