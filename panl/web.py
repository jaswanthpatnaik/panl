import os
import time
import json
import re
import requests
import subprocess
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, flash, Response
from panl.modules.engine import analyze_file
from panl.modules.javascript import analyze_javascript
from panl.modules.iocs import extract_iocs
from panl.modules.behavior import get_behavioral_profile
from panl.modules.risk_score import calculate_risk_score
from panl.modules.utils import compute_file_hashes
from panl.modules.offline_scan import run_offline_scan
from panl.modules.vt_check import check_virustotal, upload_to_virustotal
from panl.modules.office import analyze_office_doc
from panl.modules.expert_system import generate_expert_summary
from panl.database import init_db, save_scan, get_all_scans, get_scan_by_hash

app = Flask(__name__)
app.secret_key = 'panl_nextgen_secure_key'

# Initialization
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, 'uploads')
CONFIG_FILE = os.path.join(PROJECT_ROOT, 'config.json')
RULES_DIR = os.path.join(PROJECT_ROOT, 'rules')

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

init_db()

def get_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except: pass
    return {"vt_api_key": "", "deep_scan": True, "analyst_name": "Senior Analyst", "accent_color": "#00f2ff"}

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except: return False

def check_system_status():
    status = {
        "vt": {"active": False, "msg": "No API Key"},
        "yara": {"active": False, "msg": "Rules Missing"},
        "clamav": {"active": False, "msg": "Service Unavailable"}
    }
    
    config = get_config()
    # 1. Check VT
    if config.get("vt_api_key"):
        try:
            # Quick ping to VT API to verify key
            r = requests.get(f"https://www.virustotal.com/api/v3/users/{config['vt_api_key']}", 
                             headers={"x-apikey": config['vt_api_key']}, timeout=3)
            if r.status_code == 200:
                status["vt"] = {"active": True, "msg": "Connected (Live Feed)"}
            else:
                status["vt"] = {"active": False, "msg": "Invalid API Key"}
        except:
            status["vt"] = {"active": False, "msg": "Network Error"}
            
    # 2. Check YARA
    if os.path.exists(RULES_DIR):
        rule_files = [f for f in os.listdir(RULES_DIR) if f.endswith('.yar')]
        if rule_files:
            status["yara"] = {"active": True, "msg": f"{len(rule_files)} Signatures Active"}
            
    # 3. Check ClamAV
    try:
        p = subprocess.run(['clamscan', '--version'], capture_output=True, text=True)
        if p.returncode == 0:
            status["clamav"] = {"active": True, "msg": "Engine Online"}
    except: pass
    
    return status

@app.route('/')
def index():
    scans = get_all_scans()
    config = get_config()
    return render_template('dashboard.html', recent_scans=scans, config=config)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files: return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '': return redirect(url_for('index'))
    
    if file:
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        
        try:
            findings = {
                "filename": file.filename,
                "filesize": os.path.getsize(filepath),
                "keyword_scan": {"suspicious_found": []},
                "js_analysis": {"summary": {"total_flagged": 0}},
                "metadata": {}
            }
            # Use unified forensic engine
            findings = analyze_file(filepath)
            
            save_scan(file.filename, findings["sha256"], 
                      findings["risk_score"]["score"], 
                      findings["risk_score"]["severity"], 
                      findings)
            
            return redirect(url_for('report', sha256=findings["sha256"]))
        except Exception as e:
            flash(f"Analysis failed: {str(e)}", "error")
            return redirect(url_for('index'))

@app.route('/report/<sha256>')
def report(sha256):
    findings = get_scan_by_hash(sha256)
    config = get_config()
    if not findings: return redirect(url_for('index'))
    return render_template('report_view.html', data=findings, config=config)

@app.route('/download_safe/<sha256>')
def download_safe(sha256):
    findings = get_scan_by_hash(sha256)
    if not findings: return "Not Found", 404
    filename = findings["filename"]
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath): return "Original file missing", 404
    
    ext = os.path.splitext(filename)[1].lower()
    
    if ext == '.pdf':
        with open(filepath, 'rb') as f: data = f.read()
        safe_data = data.replace(b'/JS', b'/XX').replace(b'/JavaScript', b'/NoScript').replace(b'/OpenAction', b'/NoAction')
        return Response(safe_data, mimetype='application/pdf', headers={"Content-Disposition": f"attachment; filename=CLEANED_{filename}"})
    
    elif ext in ['.docx', '.xlsx', '.pptx']:
        import zipfile
        import io
        output = io.BytesIO()
        try:
            with zipfile.ZipFile(filepath, 'r') as zin:
                with zipfile.ZipFile(output, 'w') as zout:
                    for item in zin.infolist():
                        buffer = zin.read(item.filename)
                        # Strip Macros
                        if 'vbaProject.bin' in item.filename: continue
                        # Strip External Relationships in XML files
                        if item.filename.endswith('.rels') or item.filename.endswith('.xml'):
                            # Neutralize URLs
                            buffer = buffer.replace(b'Target="http', b'Target="OFFLINE_SANATIZED_')
                        zout.writestr(item, buffer)
            output.seek(0)
            return Response(output.read(), mimetype='application/vnd.openxmlformats-officedocument', headers={"Content-Disposition": f"attachment; filename=CLEANED_{filename}"})
        except:
            return "Sanitization Failed", 500
            
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/preview/<path:filename>')
def preview(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath): return "Not found", 404
    
    ext = os.path.splitext(filename)[1].lower()
    
    if ext == '.pdf':
        with open(filepath, 'rb') as f: data = f.read()
        resp = Response(data.replace(b'/JS', b'/XX'), mimetype='application/pdf')
        # ZERO-TRUST POLICY: Total script ban, but allow native object rendering
        resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'; object-src 'self'; frame-ancestors 'self';"
        return resp
    
    elif ext in ['.docx', '.xlsx', '.pptx']:
        import zipfile
        import re
        text = ""
        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                # Extract text from main document components
                targets = ['word/document.xml', 'xl/sharedStrings.xml', 'ppt/slides/slide1.xml']
                for target in targets:
                    if target in z.namelist():
                        xml_content = z.read(target).decode('utf-8', errors='ignore')
                        # Simple regex to strip XML tags
                        clean_text = re.sub('<[^<]+?>', ' ', xml_content)
                        text += f"--- CONTENT FROM {target} ---\n\n" + clean_text + "\n\n"
            
            if not text: text = "No readable text content identified in forensic extraction."
            
            html_preview = f"<html><body style='background: #fff; color: #333; font-family: sans-serif; padding: 2rem; line-height: 1.6; white-space: pre-wrap;'><h2>FORENSIC TEXT EXTRACTION</h2><hr>{text}</body></html>"
            resp = Response(html_preview, mimetype='text/html')
            resp.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline';"
            return resp
        except:
            return "Forensic Extraction Failed", 500
            
    return "Format not supported for safe preview", 400

@app.route('/sandbox/<path:filename>')
def sandbox(filename):
    return render_template('sandbox.html', filename=filename)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    config = get_config()
    if request.method == 'POST':
        new_config = {
            "vt_api_key": request.form.get("vt_api_key", "").strip(),
            "analyst_name": request.form.get("analyst_name", "").strip(),
            "accent_color": request.form.get("accent_color", "#00f2ff"),
            "strict_mode": request.form.get("strict_mode") == "true"
        }
        save_config(new_config)
        flash("Settings updated.", "success")
        return redirect(url_for('settings'))
    
    status = check_system_status()
    return render_template('settings.html', config=config, status=status)

@app.route('/vt_upload/<sha256>', methods=['POST'])
def vt_upload(sha256):
    findings = get_scan_by_hash(sha256)
    if not findings: return jsonify({"error": "Scan not found"}), 404
    
    config = get_config()
    if not config.get("vt_api_key"):
        return jsonify({"error": "VT API Key not configured"}), 400
        
    filepath = os.path.join(UPLOAD_FOLDER, findings["filename"])
    if not os.path.exists(filepath):
        return jsonify({"error": "Original file missing in vault"}), 404
        
    result = upload_to_virustotal(filepath, config["vt_api_key"])
    return jsonify(result)

@app.route('/clear_history', methods=['POST'])
def clear_history():
    from panl.database import clear_all_scans
    clear_all_scans()
    flash("Intelligence Archive has been purged.", "success")
    return redirect(url_for('settings'))

@app.route('/purge_uploads', methods=['POST'])
def purge_uploads():
    try:
        files = os.listdir(UPLOAD_FOLDER)
        for f in files:
            os.remove(os.path.join(UPLOAD_FOLDER, f))
        flash("Forensic Vault has been cleared. All document samples deleted.", "success")
    except Exception as e:
        flash(f"Purge failed: {str(e)}", "error")
    return redirect(url_for('settings'))

def start_web(port=5000):
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == "__main__":
    start_web()
