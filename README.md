# 🛡️ PANL: Pdf ANaLysis toolkit

**PANL** is an autonomous, high-fidelity forensic intelligence suite designed to audit and neutralize document-based threats (PDF & Office) in air-gapped or high-security environments.

Unlike traditional scanners that rely on historical signatures, PNAL performs a deep **DNA Audit** of file structures to identify zero-day exploits, hidden droppers, and behavioral anomalies.

## 🚀 Key Forensic Features

*   **🔍 Active Payload Carving**: Surgically extracts OLE objects and binary streams from Office documents for independent forensic hashing.
*   **🧪 Zero-Trust Sandbox**: Visualizes documents through a digital blast shield using **Cryptographic CSP Isolation**—blocking all script execution and network callbacks.
*   **🖼️ Forensic Image Audit**: Deep binary inspection of embedded images (SVG/PNG/JPG) for script injections and steganography.
*   **🧠 Expert Behavioral Matrix**: Generates high-fidelity triage reports explaining the *why* and *how* behind suspicious file structures.
*   **🔗 Intelligence Correlation**: Integrated VirusTotal API support for historical reputation checks alongside local structural audit.

## 🛠️ Installation

PANL is designed to be self-contained and portable.

```bash
# Clone the repository
git clone https://github.com/jaswanthpatnaik/panl.git
cd panl

# Run the hardened installer (Requires sudo for global commands)
sudo bash install.sh
```

## 🖥️ Usage

### Interactive Intelligence Hub (Web Dashboard)
Launch the professional triage dashboard:
```bash
panl dashboard
```

### Forensic CLI Analysis
Perform a surgical scan directly from the terminal:
```bash
panl analyze <file_location>
```

## ⚖️ License
Distributed under the MIT License. See `LICENSE` for more information.

---
**Disclaimer**: PANL is a forensic tool for security professionals. Always handle suspicious samples within isolated environments.
