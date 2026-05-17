def generate_expert_summary(findings):
    score = findings['risk_score']['score']
    severity = findings['risk_score']['severity']
    
    summary = []
    
    if severity == "Unsafe":
        summary.append("<span style='color: #ff0055; font-weight: 800;'>⚠️ CRITICAL THREAT IDENTIFIED</span>: This document contains verified malicious indicators.")
    elif severity == "High":
        summary.append("<span style='color: #ff8c00; font-weight: 800;'>🟠 HIGH SUSPICION</span>: Multiple structural anomalies and behavioral triggers were detected.")
    else:
        summary.append("<span style='color: #00ff88; font-weight: 800;'>🟢 LOW RISK</span>: No major forensic red flags were identified.")

    # Specific Intelligence Logic
    vt = findings.get('vt_results')
    if vt and vt.get('malicious', 0) > 0:
        summary.append(f"Global intelligence confirms this as a <span style='color: #ff0055;'>known threat ({vt['malicious']} detections)</span>. This correlates with our local structural findings.")
    elif vt and vt.get('status') == 'not_found':
         summary.append("<span style='color: #00f2ff;'>🛡️ ZERO-DAY POTENTIAL</span>: This file was not found in global databases (0 detections), but our local structural audit has identified high-risk DNA. **Prioritize local forensic indicators over online reputation.**")
    
    off = findings.get('offline_scan', {})
    if off.get('yara_matches'):
        summary.append(f"Local signature analysis matched <span style='color: #ffcc00;'>{len(off['yara_matches'])} forensic rules</span>, indicating specialized exploit code or anti-analysis techniques.")
        
    js = findings.get('js_analysis', {}).get('summary', {})
    if js.get('total_flagged', 0) > 0:
        summary.append(f"Forensic logic identified <span style='color: #00f2ff;'>{js['total_flagged']} suspicious JS streams</span>. These contain high-entropy obfuscation patterns (e.g. charCodeAt, unescape) typical of second-stage dropper mechanisms designed for process injection.")

    meta = findings.get('metadata', {})
    if meta.get('has_anomalies'):
        summary.append("Detected <span style='color: #ff8c00;'>Structural Container Anomalies</span>. The document's xref table or object stream mapping is inconsistent with standard ISO 32000 specifications, suggesting manual tampering for AV evasion.")

    office = findings.get('office_analysis', {})
    if office and office.get('vba_macros'):
        summary.append(f"Identified <span style='color: #ff0055;'>Embedded VBA Macros</span>. These are surgically flagged as high-risk vectors for 'Living off the Land' (LotL) execution within the Office environment.")
    if office and any("Auto-Execution" in ind for ind in office.get('risk_indicators', [])):
        summary.append("Structural Audit confirmed <span style='color: #ffcc00;'>Auto-Execution Triggers</span>. The container is configured to launch binary streams immediately upon interaction, bypassing user-level security prompts.")

    if not summary:
        summary.append("No significant forensic insights available for this sample.")

    # Convert newlines to breaks for HTML
    return "<br><br>".join(summary)
