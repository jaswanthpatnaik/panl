# 🛡️ PANL (Pdf ANaLysis Toolkit)
### **Technical Specification & Forensic Laboratory Manual**

## 📖 Executive Summary
Document-based malware vectors (PDFs, Microsoft Office files) remain the primary initial access vector for Advanced Persistent Threats (APTs) globally. Attackers routinely design weaponized files that evade traditional, signature-based antivirus solutions using dynamic obfuscation, steganography, and zero-day execution paths.

**PANL (Pdf ANaLysis Toolkit)** is a self-contained, offline-first forensic triage engine designed to audit, dissect, and identify document-based threats in air-gapped or high-security tactical environments. Rather than relying on historical reputation databases, PANL performs a deep **structural DNA audit** to capture malicious intent prior to document execution.

---

## ⚙️ Architectural Overview & Pipeline
PANL utilizes a completely decoupled, modular pipeline designed to parse untrusted binary containers safely. The engine avoids circular imports and enforces a sequential data flow, visualized in our **Engine Data Flow Diagram**:

1. **Ingestion & Parsing**: The file container is dissected at the binary level (e.g., zip-member structures for Office documents, xref/object streams for PDFs).
2. **Metadata Audit**: Creation stamps, modifications, and software signatures are parsed to spot manipulation.
3. **Forensic Image Audit**: Embedded visual structures (SVG/JPG/PNG) are examined for scripts and steganography.
4. **Static & Signature Auditing**: Custom YARA signatures are loaded to scan the binary streams offline.
5. **Active Payload Carving**: Suspicious `.bin` and OLE objects are carved out and parsed independently.
6. **Reputation Assessment**: Optional VirusTotal lookup is engaged to correlate offline findings with global intelligence.
7. **Zero-Trust Visual Triage**: The analyst inspects the document in a secure sandbox isolated via cryptographic Content Security Policies (CSP).

---

## 🛠️ Deep Dive: Core Forensic Capabilities

### 1. 🔍 Active Payload Carving (OLE / Stream Extraction)
Attackers frequently conceal secondary payloads (e.g., shellcode, PE executables, scripts) inside Office documents via OLE (Object Linking and Embedding) containers. PANL surgically audits ZIP container files:
* Automatically identifies embedded binary files (`.bin`, `.exe`, `.dll`, `.vbs`, etc.).
* Extracts the raw byte stream and computes its unique **SHA256 fingerprint**.
* Exposes the carved payload directly to the analyst in the Behavioral Matrix for forensic pivoting.

### 2. 🧪 Zero-Trust Sandbox & Isolation
Opening an untrusted PDF or Office document in a standard viewer poses severe client-side exploit risks. PANL implements a **digital blast shield**:
* **Cryptographic CSP**: Outbound network requests and dynamic inline scripts are blocked using strict HTTP Content-Security-Policy headers (`script-src 'none'`, `object-src 'self'`).
* **Surgical Stripping**: Active triggers (like `/JS` or `/OpenAction` in PDFs) are neutralized at the byte-level before the preview is rendered.
* **Safe Text Extraction**: Office documents are parsed to raw, human-readable text directly from their internal XML components, bypassing dangerous rendering paths completely.

### 3. 🖼️ Forensic Image Audit (Visual Evasion Vectors)
Modern threat groups often leverage embedded images to bypass text-based security filters:
* **SVG Script Audit**: Scans vector graphics for `<script>` or `javascript:` directives.
* **Webshell Marker Audit**: Scans image binary streams for PHP tags or execution statements (e.g., `<?php`, `eval()`).
* **Steganography Checks**: Flags anomalously large embedded icon or image assets (>500KB) representing high-risk steganographic stowing.

---

## 📖 Step-by-Step Triage & TTP Detection

### **Step 1: System Installation & Setup**
Execute the unified, offline-friendly installer:
```bash
sudo bash install.sh
```
This prepares the isolated virtual environment and compiles specialized PDF and Office YARA signatures.

### **Step 2: Command Line (CLI) Forensic Analysis**
To quickly audit a file and export the raw JSON report or print a pretty terminal layout:
```bash
panl analyze malware_sample.pdf --json
```

### **Step 3: Interactive Dashboard Triage**
Start the Web Hub to access visual charts and interactive sandboxing:
```bash
panl dashboard
```

---

## 📊 Conclusion & Strategic Value
PANL successfully bridges the gap between passive antivirus scanners and highly complex, slow-running sandbox systems. By offering high-speed structural audits, active payload carving, and bulletproof web-isolated previews, PANL equips forensic analysts with an instant, air-gappable first line of defense.
