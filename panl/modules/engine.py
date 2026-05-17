import os
import json
from panl.modules.metadata import extract_metadata
from panl.modules.keywords import scan_keywords
from panl.modules.javascript import analyze_javascript
from panl.modules.iocs import extract_iocs
from panl.modules.behavior import get_behavioral_profile
from panl.modules.risk_score import calculate_risk_score
from panl.modules.utils import compute_file_hashes
from panl.modules.offline_scan import run_offline_scan
from panl.modules.vt_check import check_virustotal
from panl.modules.office import analyze_office_doc
from panl.modules.expert_system import generate_expert_summary

def get_config():
    from panl.modules.utils import get_user_path
    config_path = get_user_path('config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except: pass
    return {"vt_api_key": ""}

def analyze_file(filepath, vt_api_key=None, progress_callback=None):
    if not os.path.exists(filepath):
        return None

    results = {"filename": os.path.basename(filepath), "filesize": os.path.getsize(filepath)}
    results.update(compute_file_hashes(filepath))
    ext = os.path.splitext(filepath)[1].lower()

    def run_step(desc, func, *args):
        if progress_callback: progress_callback(desc)
        return func(*args)

    from panl.modules.ocr import audit_images
    image_audit = audit_images(filepath)
    results["image_audit"] = image_audit
    results["metadata"] = run_step("Extracting Metadata", extract_metadata, filepath)
    results["keyword_scan"] = run_step("Scanning Keywords", scan_keywords, filepath)
    
    if ext == '.pdf':
        results["js_analysis"] = run_step("Analyzing JavaScript", analyze_javascript, filepath)
    elif ext in ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt']:
        results["office_analysis"] = run_step("Performing Surgical Office Audit", analyze_office_doc, filepath)
    
    results["iocs"] = run_step("Extracting IOCs", extract_iocs, filepath)
    results["offline_scan"] = run_step("Performing Offline Malware Scan", run_offline_scan, filepath)
    
    config = get_config()
    key = vt_api_key or config.get("vt_api_key")
    if key:
        results["vt_results"] = run_step("Querying VirusTotal Intel", check_virustotal, results["sha256"], results["md5"], key)
    
    results["behavior"] = get_behavioral_profile(results)
    results["risk_score"] = calculate_risk_score(results)
    results["ai_summary"] = generate_expert_summary(results)

    return results
