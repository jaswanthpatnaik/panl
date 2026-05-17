import os
from oletools.olevba import VBA_Parser
from oletools.oleid import OleID

def analyze_office_doc(filepath):
    """
    Analyzes Microsoft Office documents for malicious macros, OLE objects, and metadata anomalies.
    """
    findings = {
        "vba_macros": [],
        "ole_objects": [],
        "risk_indicators": [],
        "summary": "No suspicious Office-specific patterns detected."
    }

    try:
        # 1. Macro Analysis (Optional, might fail on non-OLE docs)
        try:
            vba_parser = VBA_Parser(filepath)
            if vba_parser.detect_vba_macros():
                findings["risk_indicators"].append("VBA Macros Detected")
                for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    findings["vba_macros"].append({
                        "stream": stream_path,
                        "filename": vba_filename,
                        "code_snippet": vba_code[:500] + "..." if len(vba_code) > 500 else vba_code
                    })
                
                auto_exec = vba_parser.analyze_macros()
                for kw_type, keyword, description in auto_exec:
                    if kw_type == 'AutoExec':
                        findings["risk_indicators"].append(f"Auto-Execution Macro: {keyword}")
        except: pass

        # 2. OLE Structure Analysis
        try:
            oid = OleID(filepath)
            indicators = oid.check()
            for i in indicators:
                # Ensure i and i.name exist to prevent NoneType error
                if i and hasattr(i, 'value') and i.value is True:
                    name = getattr(i, 'name', str(i.id))
                    if i.id in ['ole_objects', 'encrypted', 'ext_rels']:
                        findings["risk_indicators"].append(f"Structural Indicator: {name}")
        except: pass

        # 3. Direct ZIP Structure Audit (ALWAYS RUNS)
        import zipfile
        if zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath, 'r') as z:
                members = z.namelist()
                for m in members:
                    m_lower = m.lower()
                    # 3.1 Known Malicious/Suspicious Member Names
                    if 'vbaProject' in m:
                        findings["risk_indicators"].append("Hidden VBA Project Detected (ZIP Audit)")
                    if 'embeddings' in m:
                        findings["risk_indicators"].append("Embedded Binary Object Detected (ZIP Audit)")
                    if 'attachedTemplate' in m or 'External' in m:
                        findings["risk_indicators"].append("External Template Injection Indicator")
                    
                    # 3.2 Suspicious Extensions inside ZIP & Active Carving
                    if any(ext in m_lower for ext in ['.rtf', '.exe', '.dll', '.bin', '.bat', '.vbs', '.ps1', '.hta', '.sh']):
                        import hashlib
                        try:
                            obj_data = z.read(m)
                            obj_sha = hashlib.sha256(obj_data).hexdigest()
                            findings["ole_objects"].append({
                                "name": os.path.basename(m),
                                "sha256": obj_sha,
                                "size": len(obj_data),
                                "path": m
                            })
                            findings["risk_indicators"].append(f"Carved Payload: {os.path.basename(m)} ({obj_sha[:8]}...)")
                        except: pass
                        
                        findings["risk_indicators"].append(f"Suspicious Embedded Filetype: {os.path.basename(m)} (ZIP Audit)")
                        
                    # 3.3 Heuristic: Abnormally Large Members (Compression Evasion)
                    try:
                        info = z.getinfo(m)
                        if info.file_size > 1024 * 1024: # > 1MB
                            findings["risk_indicators"].append(f"Heuristic Alert: Abnormally Large Member ({os.path.basename(m)} - {info.file_size} bytes)")
                    except: pass

        if findings["risk_indicators"]:
            findings["risk_indicators"] = list(set(findings["risk_indicators"]))
            findings["summary"] = f"Suspicious activity detected: {', '.join(findings['risk_indicators'])}"

    except Exception as e:
        findings["summary"] = f"Office Parse Error: {str(e)}"

    return findings
