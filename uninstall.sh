#!/bin/bash

echo "------------------------------------------------"
echo "  PNAL - Pdf ANaLyzer Toolkit Uninstaller       "
echo "------------------------------------------------"

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo ./uninstall.sh)"
  exit
fi

# Remove global wrappers
echo "[*] Removing global 'pnal' and 'panl' commands..."
rm -f /usr/local/bin/pnal
rm -f /usr/local/bin/panl

# Clean up virtual environment
if [ -d ".venv" ]; then
    echo "[*] Removing isolated Python environment..."
    rm -rf .venv
fi

# Optional: Clean up temporary uploads and database
read -p "[?] Would you like to remove the forensic database and uploads? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Purging database and uploads..."
    rm -f panl.db
    rm -rf uploads/*
fi

echo "------------------------------------------------"
echo "[SUCCESS] PNAL has been uninstalled from the system."
echo "[*] Note: The project folder and YARA rules were preserved."
echo "------------------------------------------------"
