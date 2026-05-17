BEHAVIOR_MAP = {
    "/JavaScript": {
        "why": "Executable script content detected within the document structure.",
        "actions": ["Remote code execution", "Data exfiltration via network", "Phishing redirection"]
    },
    "/JS": {
        "why": "Embedded JavaScript found, indicating active content.",
        "actions": ["Browser exploit delivery", "Automated form submission"]
    },
    "/OpenAction": {
        "why": "Document is configured to execute a command automatically upon opening.",
        "actions": ["Immediate malware execution", "Forced user interaction"]
    },
    "/AA": {
        "why": "Additional Actions detected which trigger on specific user events.",
        "actions": ["Anti-analysis/Anti-tamper checks", "Persistence via event triggers"]
    },
    "/Launch": {
        "why": "The document contains instructions to launch external system applications.",
        "actions": ["Direct system command execution", "PowerShell/CMD spawning"]
    },
    "/EmbeddedFile": {
        "why": "One or more secondary files are hidden inside the PDF wrapper.",
        "actions": ["Dropping secondary malware payloads", "Credential harvesting"]
    },
    "eval_unescape": {
        "why": "Advanced obfuscation (eval/unescape) is used to hide script logic.",
        "actions": ["Exploit code obfuscation", "Bypassing static security filters"]
    },
    "shellcode_pattern": {
        "why": "Binary patterns resembling shellcode or NOP sleds were identified.",
        "actions": ["Buffer overflow exploitation", "Direct CPU instruction injection"]
    },
    "metadata_anomaly": {
        "why": "Anomalous metadata (e.g., extreme string lengths) suggests an exploit attempt.",
        "actions": ["Denial of Service (DoS)", "Memory corruption exploit"]
    }
}

def get_behavioral_profile(findings):
    profile = {
        "detailed_findings": []
    }
    
    # Check Keywords
    kw_found = findings.get("keyword_scan", {}).get("suspicious_found", [])
    for kw in kw_found:
        if kw in BEHAVIOR_MAP:
            profile["detailed_findings"].append({
                "why": BEHAVIOR_MAP[kw]["why"],
                "actions": BEHAVIOR_MAP[kw]["actions"]
            })
            
    # Check JS Analysis
    js_summary = findings.get("js_analysis", {}).get("summary", {})
    if js_summary.get("total_flagged", 0) > 0:
        profile["detailed_findings"].append({
            "why": BEHAVIOR_MAP["eval_unescape"]["why"],
            "actions": BEHAVIOR_MAP["eval_unescape"]["actions"]
        })
        
    if js_summary.get("highest_obfuscation_score", 0) >= 8:
        profile["detailed_findings"].append({
            "why": BEHAVIOR_MAP["shellcode_pattern"]["why"],
            "actions": BEHAVIOR_MAP["shellcode_pattern"]["actions"]
        })
        
    # Check Metadata
    if findings.get("metadata", {}).get("has_anomalies"):
        profile["detailed_findings"].append({
            "why": BEHAVIOR_MAP["metadata_anomaly"]["why"],
            "actions": BEHAVIOR_MAP["metadata_anomaly"]["actions"]
        })

    # Check Raw Heuristic Detections
    raw_detections = findings.get("keyword_scan", {}).get("raw_detections", [])
    for det in raw_detections:
        cat = det.get("category")
        if cat == "PowerShell Execution":
            profile["detailed_findings"].append({
                "why": "PowerShell command patterns detected in binary stream.",
                "actions": ["Bypassing execution policies", "Memory-only malware staging", "Remote server callback"]
            })
        elif cat == "WScript/CScript Shell":
            profile["detailed_findings"].append({
                "why": "Windows Script Host (WSH) shell triggers identified.",
                "actions": ["Spawning system shells", "Executing external binaries", "Persistence via Scheduled Tasks"]
            })
        elif cat == "Suspicious API Call":
            profile["detailed_findings"].append({
                "why": f"Direct invocation of sensitive system APIs detected: {', '.join(det.get('matches', []))}",
                "actions": ["Process injection (Process Hollowing)", "Direct memory manipulation", "Anti-forensic evasion"]
            })
        elif cat == "Base64 Executable Header":
            profile["detailed_findings"].append({
                "why": "Base64 encoded binary/PE header found.",
                "actions": ["Dropping secondary executable payloads", "Payload concealment", "Living off the Land (LotL) execution"]
            })
        elif cat == "Network Callback":
            profile["detailed_findings"].append({
                "why": "Suspicious network URLs or socket connections found in raw content.",
                "actions": ["C2 (Command & Control) communication", "Downloading second-stage malware", "Exfiltrating harvested data"]
            })
        
    # Check Office Analysis
    office = findings.get("office_analysis", {})
    if office:
        if office.get("vba_macros"):
            profile["detailed_findings"].append({
                "why": "Embedded VBA Macros found in Office document.",
                "actions": ["Automated code execution", "System persistence"]
            })
        for indicator in office.get("risk_indicators", []):
            if "Auto-Execution" in indicator:
                profile["detailed_findings"].append({
                    "why": f"Office Auto-Exec trigger: {indicator}",
                    "actions": ["Immediate payload delivery", "Process injection"]
                })
            elif "Structural" in indicator or "ZIP Audit" in indicator:
                profile["detailed_findings"].append({
                    "why": f"Suspicious Office Structure: {indicator}",
                    "actions": ["Hidden object storage", "Advanced malware evasion", "Payload concealment"]
                })
            elif "Template Injection" in indicator:
                profile["detailed_findings"].append({
                    "why": "External Template Injection technique detected.",
                    "actions": ["Bypassing local macro security", "Remote payload execution"]
                })
        
    # Check Image Audit
    image_audit = findings.get("image_audit", {})
    for indicator in image_audit.get("risk_indicators", []):
        profile["detailed_findings"].append({
            "why": f"Image Weaponization: {indicator}",
            "actions": ["Bypassing text-only scanners", "Steganographic data exfiltration", "Client-side script execution"]
        })
        
    return profile
