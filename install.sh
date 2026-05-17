#!/bin/bash

echo "------------------------------------------------"
echo "  PANL - Pdf ANaLyzer Toolkit Installer         "
echo "------------------------------------------------"

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo ./install.sh)"
  exit
fi

# Detect Package Manager
if [ -f /etc/debian_version ]; then
    echo "[*] Installing system dependencies..."
    apt-get update
    apt-get install -y qpdf binutils python3-pip python3-full python3-venv clamav yara curl
elif [ -f /etc/redhat-release ]; then
    echo "[*] Installing system dependencies..."
    yum install -y qpdf binutils python3-pip python3-venv clamav yara curl
fi

# Create a transparent virtual environment inside the project folder
echo "[*] Creating internal isolated environment (Safe Mode)..."
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
echo "[*] Installing forensic modules..."
pip3 install --upgrade pip
pip3 install yara-python clamd requests jinja2 Flask rich PyPDF2 oletools

# PDF YARA Rules
echo "[*] Downloading specialized PDF YARA signatures..."
mkdir -p rules
rm -f rules/*.yar
curl -L https://raw.githubusercontent.com/Yara-Rules/rules/master/Antidebug_Antivm/Antidebug_Antivm.yar -o rules/antidebug.yar
curl -L https://raw.githubusercontent.com/Yara-Rules/rules/master/Exploits/Exploit-PDF.yar -o rules/pdf_exploits.yar
curl -L https://raw.githubusercontent.com/Yara-Rules/rules/master/Malware/Malicious_Documents.yar -o rules/mal_docs.yar

# Fix permissions
chmod -R 755 rules/
chown -R $SUDO_USER:$SUDO_USER rules/ 2>/dev/null || chmod -R 777 rules/

# Create the global wrapper scripts
echo "[*] Setting up global 'panl' command..."
PROJECT_DIR=$(pwd)
WRAPPER_CONTENT=$(cat <<EOF
#!/bin/bash
# PNAL Transparent Wrapper
source $PROJECT_DIR/.venv/bin/activate
export PYTHONPATH=$PROJECT_DIR
python3 $PROJECT_DIR/panl/cli.py "\$@"
EOF
)

echo "$WRAPPER_CONTENT" > /usr/local/bin/panl

chmod +x /usr/local/bin/panl

echo "------------------------------------------------"
echo "[SUCCESS] PNAL is now installed!"
echo "[*] Use: 'panl dashboard' or 'panl analyze <file>'"
echo "[*] All forensic signatures verified."
echo "------------------------------------------------"
