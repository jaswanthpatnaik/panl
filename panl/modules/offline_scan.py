import os
import yara
import subprocess

def run_offline_scan(filepath):
    results = {
        "yara_matches": [],
        "clamav_results": None,
        "threat_found": False
    }
    
    # 1. YARA Scanning (Safe Loading)
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'rules')
    if os.path.exists(rules_dir):
        for f in os.listdir(rules_dir):
            if f.endswith('.yar'):
                rule_path = os.path.join(rules_dir, f)
                try:
                    # Verify if the file is a valid YARA rule (not a 404 page)
                    with open(rule_path, 'r') as rf:
                        content = rf.read(100)
                        if "Not Found" in content or "404" in content:
                            continue
                    
                    # Compile and match individually to prevent one bad rule from stopping the scan
                    rules = yara.compile(rule_path)
                    matches = rules.match(filepath)
                    for m in matches:
                        results["yara_matches"].append({
                            "rule": m.rule,
                            "tags": m.tags,
                            "meta": m.meta
                        })
                        results["threat_found"] = True
                except Exception as e:
                    # Log error but continue scanning with other rules
                    print(f"[!] Warning: Skipping corrupted rule {f}: {e}")

    # 2. ClamAV Scanning
    try:
        process = subprocess.Popen(['clamscan', '--no-summary', filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode('utf-8', errors='ignore').strip()
        
        if "FOUND" in output:
            virus_name = output.split("FOUND")[-1].strip()
            results["clamav_results"] = f"Detected: {virus_name}"
            results["threat_found"] = True
        elif "OK" in output:
            results["clamav_results"] = "Clean"
    except Exception as e:
        results["clamav_results"] = f"ClamAV Unavailable"
        
    return results
