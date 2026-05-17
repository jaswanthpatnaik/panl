def calculate_risk_score(findings, config=None):
    score = 0
    breakdown = {}
    strict_mode = config.get("strict_mode", False) if config else False
    
    # 1. Keyword Scan Analysis
    kw_scan = findings.get("keyword_scan", {})
    suspicious_keywords = kw_scan.get("suspicious_found", [])
    raw_detections = kw_scan.get("raw_detections", [])
    
    # Priority Keywords (Structural)
    has_js = False
    if "/JavaScript" in suspicious_keywords:
        score += 5
        breakdown["Embedded JavaScript"] = 5
        has_js = True
    if "/JS" in suspicious_keywords:
        score += 5
        breakdown["Active Scripting (JS)"] = 5
        has_js = True
    if "/OpenAction" in suspicious_keywords:
        score += 4
        breakdown["Automatic Execution (OpenAction)"] = 4
        has_js = True
    if "/Launch" in suspicious_keywords:
        score += 8
        breakdown["External Command Launch"] = 8
        has_js = True
    if "/EmbeddedFile" in suspicious_keywords:
        score += 6
        breakdown["Secondary Payload (EmbeddedFile)"] = 6
        
    # Heuristic Raw Detections (Behavioral)
    for det in raw_detections:
        category = det.get("category")
        pts = 7 if category in ["PowerShell Execution", "WScript/CScript Shell", "Suspicious API Call"] else 4
        score += pts
        breakdown[f"Heuristic: {category}"] = pts

    # 2. JavaScript Heuristics
    js_analysis = findings.get("js_analysis", {}).get("summary", {})
    if js_analysis.get("total_flagged", 0) > 0:
        pts = min(js_analysis["total_flagged"] * 2, 10)
        score += pts
        breakdown["Malicious JS Patterns"] = pts
        has_js = True
        
    if js_analysis.get("highest_obfuscation_score", 0) >= 7:
        score += 5
        breakdown["Advanced JS Obfuscation"] = 5
        
    # 3. Metadata & Structure
    metadata = findings.get("metadata", {})
    if metadata.get("has_anomalies"):
        score += 3
        breakdown["Structural Anomalies"] = 3
        
    # 4. OFFLINE SCAN INTEGRATION (YARA & CLAMAV)
    offline = findings.get("offline_scan", {})
    yara_matches = offline.get("yara_matches", [])
    if yara_matches:
        yara_pts = min(len(yara_matches) * 5, 20)
        score += yara_pts
        breakdown[f"YARA Signatures ({len(yara_matches)})"] = yara_pts
        
    clamav = offline.get("clamav_results", "")
    if clamav and "Detected" in clamav:
        score += 20
        breakdown["ClamAV Local Detection"] = 20

    # 5. OFFICE ANALYSIS INTEGRATION
    office = findings.get("office_analysis", {})
    if office:
        indicators = office.get("risk_indicators", [])
        if indicators:
            pts = min(len(indicators) * 5, 25)
            score += pts
            breakdown[f"Office Behavioral Risks ({len(indicators)})"] = pts
        
        if office.get("vba_macros"):
            score += 10
            breakdown["Embedded VBA Macros"] = 10

    # 6. IOC INTEGRATION
    iocs = findings.get("iocs", {})
    if iocs.get("urls") or iocs.get("ips"):
        ioc_count = len(iocs.get("urls", [])) + len(iocs.get("ips", []))
        pts = min(ioc_count * 10, 40)
        score += pts
        breakdown[f"Extracted IOCs ({ioc_count})"] = pts

    # 7. VIRUSTOTAL INTEGRATION
    vt = findings.get("vt_results")
    if vt and not vt.get("error"):
        vt_malicious = vt.get("malicious", 0)
        if vt_malicious > 0:
            vt_points = min(vt_malicious * 2, 20)
            score += vt_points
            breakdown[f"VirusTotal Detections ({vt_malicious})"] = vt_points

    # Determine Severity Classification
    severity = "Low"
    if score >= 20:
        severity = "Unsafe"
    elif score >= 12:
        severity = "High"
    elif score >= 6:
        severity = "Medium"
        
    # APPLY STRICT MODE OVERRIDE
    if strict_mode and has_js:
        severity = "Unsafe"
        score = max(score, 15)
        breakdown["STRICT MODE OVERRIDE"] = "Any JS flagged as Unsafe"
        
    return {
        "score": score,
        "severity": severity,
        "score_breakdown": breakdown
    }
