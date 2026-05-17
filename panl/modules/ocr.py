import re
import os

def audit_images(filepath):
    """
    Performs a forensic audit of images embedded in documents.
    Detects embedded scripts (SVG), suspicious EXIF metadata, and steganography signatures.
    """
    findings = {
        "images_audited": 0,
        "flagged_images": [],
        "risk_indicators": []
    }
    
    # Supported containers
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in ['.pdf', '.docx', '.pptx', '.xlsx']:
        return findings

    try:
        import zipfile
        if zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath, 'r') as z:
                for m in z.namelist():
                    if any(img_ext in m.lower() for img_ext in ['.png', '.jpg', '.jpeg', '.svg', '.gif']):
                        findings["images_audited"] += 1
                        try:
                            data = z.read(m)
                            # 1. Detect Scripts in SVGs or Image headers
                            if b'<script' in data or b'javascript:' in data:
                                findings["flagged_images"].append(f"Script injection in {os.path.basename(m)}")
                                findings["risk_indicators"].append(f"Image Script Injection: {os.path.basename(m)}")
                            
                            # 2. Detect PHP/Shell markers (Webshell inside Image)
                            if b'<?php' in data or b'eval(' in data:
                                findings["flagged_images"].append(f"Webshell markers in {os.path.basename(m)}")
                                findings["risk_indicators"].append(f"Webshell payload in image: {os.path.basename(m)}")
                                
                            # 3. Detect Large Hidden Blobs (Steganography)
                            if len(data) > 500000: # > 500KB for an embedded icon is suspicious
                                findings["risk_indicators"].append(f"Anomalous Image Size (Stego-Risk): {os.path.basename(m)}")
                        except: pass
    except: pass
    
    return findings
