import os
import shutil
import hashlib
import zlib
import codecs
import subprocess
import tempfile
import logging
from contextlib import contextmanager
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

def get_resource_path(relative_path: str) -> str:
    """ Get absolute path to resource, works for dev and for PyInstaller """
    import sys
    if hasattr(sys, '_MEIPASS'):
        return os.path.abspath(os.path.join(sys._MEIPASS, relative_path))
    base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.abspath(os.path.join(base_path, relative_path))

def get_user_path(relative_path: str) -> str:
    """ Get absolute path to user-writable files (db, uploads, config), works for dev and for PyInstaller """
    import sys
    if hasattr(sys, '_MEIPASS'):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.abspath(os.path.join(base_path, relative_path))

REQUIRED_TOOLS = {
    "pdfid":          "pdfid (pip install pdfid)",
    "pdf-parser.py":  "pdf-parser.py (pip install pdf-parser)",
    "peepdf":         "peepdf (pip install peepdf)",
    "qpdf":           "qpdf (apt install qpdf)",
    "strings":        "strings",
}

def check_tool(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def check_all_tools() -> Dict[str, bool]:
    status = {}
    for cmd, desc in REQUIRED_TOOLS.items():
        present = check_tool(cmd)
        status[cmd] = present
        if not present:
            logger.warning(f"Missing tool: {desc}")
    return status

def check_dependencies() -> List[str]:
    return [cmd for cmd, present in check_all_tools().items() if not present]

def compute_hashes(filepath: str) -> Dict[str, Optional[str]]:
    result = {"md5": None, "sha256": None}
    if not os.path.isfile(filepath):
        return result
    try:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha256.update(chunk)
        result["md5"] = md5.hexdigest()
        result["sha256"] = sha256.hexdigest()
    except Exception:
        pass
    return result

compute_file_hashes = compute_hashes

@contextmanager
def temp_dir(prefix: str = "pmal_"):
    path = tempfile.mkdtemp(prefix=prefix)
    try:
        yield path
    finally:
        shutil.rmtree(path)

def decompress_stream(compressed_bytes: bytes, filter_type: str) -> Optional[bytes]:
    ft = filter_type.lstrip("/").strip()
    try:
        if ft == "FlateDecode":
            return zlib.decompress(compressed_bytes)
        if ft == "ASCIIHexDecode":
            hex_str = compressed_bytes.decode("ascii", errors="ignore").replace(" ", "").rstrip(">")
            if len(hex_str) % 2 != 0: hex_str += "0"
            return bytes.fromhex(hex_str)
        return None
    except Exception:
        return None

def safe_run(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        return (proc.returncode, proc.stdout, proc.stderr)
    except Exception as e:
        return (-1, "", str(e))
