import re
import subprocess
import os

def analyze_javascript(filepath):
    """Extracts and analyzes JavaScript from a PDF file."""
    result = {
        "snippets": [],
        "summary": {
            "total_snippets": 0,
            "total_flagged": 0,
            "highest_obfuscation_score": 0
        }
    }
    
    js_snippets = []
    
    try:
        # Use qpdf to extract all streams which might contain JS
        # This is more reliable than raw regex on binary
        process = subprocess.Popen(['qpdf', '--qdf', filepath, '-'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = process.communicate()
        content = stdout.decode('utf-8', errors='ignore')
        
        # Look for JS content between /JS and endstream
        # This is a simplified extractor for forensic purposes
        js_blocks = re.findall(r"/JS\s*\((.*?)\)", content, re.DOTALL)
        js_blocks += re.findall(r"/JS\s*<<(.*?)>>", content, re.DOTALL)
        
        for block in js_blocks:
            if block.strip():
                js_snippets.append(block.strip())
                
    except Exception as e:
        print(f"[!] JS Extraction Warning: {e}")

    result["summary"]["total_snippets"] = len(js_snippets)
    
    for code in js_snippets:
        flags = []
        score = 0
        
        # Heuristic Analysis
        if "eval(" in code: 
            flags.append("eval() execution")
            score += 3
        if "unescape(" in code:
            flags.append("unescape() decoding")
            score += 2
        if "String.fromCharCode" in code:
            flags.append("Dynamic character generation")
            score += 2
        if "%u" in code:
            flags.append("Shellcode-like encoding")
            score += 3
        if "\\x" in code:
            flags.append("Hexadecimal obfuscation")
            score += 1
            
        if len(code) > 1000: score += 2
        
        snippet_result = {
            "code_snippet_preview": code[:200] + ("..." if len(code) > 200 else ""),
            "flags": flags,
            "obfuscation_score": min(score, 10)
        }
        
        result["snippets"].append(snippet_result)
        if flags or score >= 5:
            result["summary"]["total_flagged"] += 1
        result["summary"]["highest_obfuscation_score"] = max(result["summary"]["highest_obfuscation_score"], score)
        
    return result
