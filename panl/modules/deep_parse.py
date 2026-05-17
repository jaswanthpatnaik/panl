import os
import re
import shutil
from typing import List, Dict, Any
from panl.modules.utils import safe_run

def parse_structure(filepath: str) -> List[Dict[str, Any]]:
    results = []
    suspicious_types = ["/JavaScript", "/JS", "/EmbeddedFile", "/Launch"]
    
    cmd = "pdf-parser" if shutil.which("pdf-parser") else "pdf-parser.py"
    
    for stype in suspicious_types:
        ret, stdout, stderr = safe_run([cmd, "--raw", "--search", stype, filepath])
        if ret == 0:
            # More robust object splitting
            objs = re.split(r"obj\s+\d+\s+\d+", stdout)
            ids = re.findall(r"obj\s+(\d+)\s+\d+", stdout)
            for i, content in enumerate(objs[1:]):
                obj_id = ids[i] if i < len(ids) else "?"
                
                # Unescape PDF octal/hex sequences if possible
                clean_content = content
                # Simple octal unescape: \050 -> (
                clean_content = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), clean_content)
                # Simple escape: \\ -> \
                clean_content = clean_content.replace("\\\\", "\\")
                
                results.append({
                    "object_id": obj_id,
                    "type": stype,
                    "raw_content": clean_content[:5000],
                    "decompressed_content": None,
                    "sha256": None
                })
                    
    return results
