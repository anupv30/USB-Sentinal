"""
USB Sentinel AI - Local Heuristic & Forensic Scanning Engine
Performs real dynamic inspection of physical USB storage devices:
- Extension & Deceptive Double Extension analysis
- Magic Byte / Header Mismatch Detection
- Autorun & Windows Shortcut (.lnk) Forensics
- Cryptographic Hashes (MD5 & SHA-256)
- Shannon Entropy & Obfuscated String Extraction
- MACB Filesystem Timestamps
"""

import os
import re
import math
import struct
import hashlib
from datetime import datetime
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal


# Suspicious and High-Risk Extensions
HIGH_RISK_EXTENSIONS = {
    ".exe", ".vbs", ".ps1", ".bat", ".cmd", ".lnk", ".scr", 
    ".hta", ".dll", ".jar", ".iso", ".vbe", ".wsf", ".cpl", 
    ".reg", ".com", ".pif", ".msi", ".sys", ".inf"
}

DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".txt", ".rtf", ".mp3", 
    ".mp4", ".zip", ".rar", ".csv"
}

# Known Magic Byte Signatures
MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE / Executable (MZ)", "pe"),
    (b"%PDF", "Adobe Portable Document Format", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "Portable Network Graphics (PNG)", "png"),
    (b"\xff\xd8\xff", "JPEG Image", "jpg"),
    (b"GIF87a", "Graphics Interchange Format (GIF87a)", "gif"),
    (b"GIF89a", "Graphics Interchange Format (GIF89a)", "gif"),
    (b"PK\x03\x04", "ZIP Archive / OpenXML Document", "zip"),
    (b"PK\x05\x06", "Empty ZIP Archive", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Compound Binary Document (MS Office)", "ole"),
    (b"\x7fELF", "Linux ELF Executable", "elf"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", "7z"),
    (b"Rar!\x1a\x07", "RAR Archive", "rar"),
    (b"MSCF", "Microsoft Cabinet File", "cab"),
    (b"{\\rtf", "Rich Text Format", "rtf")
]

# Obfuscation Regex Patterns
REGEX_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
REGEX_URL = re.compile(r"https?://[a-zA-Z0-9\.\-/_%#?&=~]+")
REGEX_BASE64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
REGEX_POWERSHELL = re.compile(r"(?i)(?:-enc(?:odedcommand)?|-windowstyle\s+hidden|-exec(?:utionpolicy)?\s+bypass|invoke-expression|\biex\b|downloadstring|net\.webclient|frombase64string)")
REGEX_REGISTRY = re.compile(r"(?i)\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\]+")
REGEX_CMD_INJECT = re.compile(r"(?i)(?:cmd(?:\.exe)?\s*/c|mshta(?:\.exe)?|rundll32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|certutil(?:\.exe)?\s+-urlcache|vssadmin(?:\.exe)?\s+delete\s+shadows)")


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy (0.0 - 8.0) of given byte array."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p_i = count / length
            entropy -= p_i * math.log2(p_i)
    return round(entropy, 4)


def extract_strings(data: bytes, min_len: int = 4) -> list:
    """Extracts ASCII and UTF-16LE strings from binary buffer."""
    results = []
    # ASCII search
    ascii_pattern = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
    for match in ascii_pattern.finditer(data):
        try:
            results.append(match.group().decode("latin1"))
        except Exception:
            pass
            
    # UTF-16LE search
    utf16_pattern = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_len).encode() + rb",}")
    for match in utf16_pattern.finditer(data):
        try:
            results.append(match.group().decode("utf-16le"))
        except Exception:
            pass
            
    return results


def parse_lnk_file(file_path: str) -> dict:
    """
    Parses a Windows Shell Link (.lnk) file dynamically to extract target binary,
    arguments, relative path, and flags.
    """
    info = {
        "is_lnk": True,
        "target_path": "",
        "arguments": "",
        "relative_path": "",
        "icon_location": "",
        "flags": [],
        "suspicious_indicators": []
    }
    try:
        with open(file_path, "rb") as f:
            header = f.read(76)
            if len(header) < 76:
                return info
            # Check LinkCLSID
            link_flags = struct.unpack("<I", header[20:24])[0]
            
            # LinkFlags bitmasks
            has_target_id = bool(link_flags & 0x01)
            has_link_info = bool(link_flags & 0x02)
            has_name = bool(link_flags & 0x04)
            has_rel_path = bool(link_flags & 0x08)
            has_working_dir = bool(link_flags & 0x10)
            has_arguments = bool(link_flags & 0x20)
            has_icon = bool(link_flags & 0x40)
            is_unicode = bool(link_flags & 0x80)

            # Skip LinkTargetIDList
            if has_target_id:
                id_list_size_data = f.read(2)
                if len(id_list_size_data) == 2:
                    id_list_size = struct.unpack("<H", id_list_size_data)[0]
                    f.seek(id_list_size, os.SEEK_CUR)

            # LinkInfo structure
            if has_link_info:
                info_size_data = f.read(4)
                if len(info_size_data) == 4:
                    info_size = struct.unpack("<I", info_size_data)[0]
                    if info_size > 4:
                        f.seek(info_size - 4, os.SEEK_CUR)

            # Read StringData sections
            def read_string(f, is_unicode):
                cch_data = f.read(2)
                if len(cch_data) < 2:
                    return ""
                cch = struct.unpack("<H", cch_data)[0]
                byte_len = cch * 2 if is_unicode else cch
                str_bytes = f.read(byte_len)
                try:
                    return str_bytes.decode("utf-16le" if is_unicode else "latin1").strip("\x00")
                except Exception:
                    return ""

            if has_name:
                read_string(f, is_unicode)
            if has_rel_path:
                info["relative_path"] = read_string(f, is_unicode)
            if has_working_dir:
                read_string(f, is_unicode)
            if has_arguments:
                info["arguments"] = read_string(f, is_unicode)
            if has_icon:
                info["icon_location"] = read_string(f, is_unicode)

            # Check for suspicious arguments/targets
            combined = f"{info['relative_path']} {info['arguments']} {info['icon_location']}"
            if re.search(r"(?i)(powershell|cmd\.exe|mshta|rundll32|cscript|wscript|certutil|bitsadmin)", combined):
                info["suspicious_indicators"].append("Invokes Windows LOLBin / Script Engine")
            if re.search(r"(?i)(-enc|-encodedcommand|-windowstyle\s+hidden|-w\s+hidden)", combined):
                info["suspicious_indicators"].append("PowerShell Obfuscated/Hidden Execution Flag")
            if re.search(r"(?i)(\.\.\\|\.vbs|\.bat|\.ps1|\.scr)", combined):
                info["suspicious_indicators"].append("Traverses relative paths to script/payload")

    except Exception as e:
        info["parse_error"] = str(e)
    return info


def parse_autorun_inf(file_path: str) -> dict:
    """Inspects autorun.inf files for execution targets and actions."""
    info = {
        "is_autorun": True,
        "open_target": "",
        "shellexecute": "",
        "action": "",
        "icon": "",
        "raw_lines": [],
        "suspicious_indicators": []
    }
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith(";"):
                    continue
                info["raw_lines"].append(stripped)
                lower = stripped.lower()
                if lower.startswith("open="):
                    info["open_target"] = stripped[5:].strip()
                elif lower.startswith("shellexecute="):
                    info["shellexecute"] = stripped[13:].strip()
                elif lower.startswith("action="):
                    info["action"] = stripped[7:].strip()
                elif lower.startswith("icon="):
                    info["icon"] = stripped[5:].strip()

        target = info["open_target"] or info["shellexecute"]
        if target:
            ext = Path(target).suffix.lower()
            if ext in HIGH_RISK_EXTENSIONS or ".exe" in target.lower():
                info["suspicious_indicators"].append(f"Auto-executes binary payload: {target}")
            if any(k in target.lower() for k in ["cmd", "powershell", "wscript", "rundll32"]):
                info["suspicious_indicators"].append(f"Auto-executes command interpreter: {target}")
    except Exception as e:
        info["parse_error"] = str(e)
    return info


def scan_single_file(file_path: str, entropy_threshold: float = 7.2) -> dict:
    """
    Performs comprehensive heuristic, magic byte, entropy, and cryptographic analysis
    on a physical file.
    """
    path = Path(file_path).resolve()
    result = {
        "path": str(path),
        "name": path.name,
        "extension": path.suffix.lower(),
        "size_bytes": 0,
        "md5": "",
        "sha256": "",
        "entropy": 0.0,
        "magic_desc": "Unknown / Text",
        "magic_category": "unknown",
        "is_hidden": False,
        "macb": {},
        "rules_triggered": [],
        "risk_level": "CLEAN",  # CLEAN, SUSPICIOUS, MALICIOUS
        "threat_score": 0,
        "extracted_strings_sample": [],
        "matched_indicators": {
            "ips": [],
            "urls": [],
            "base64": [],
            "powershell": [],
            "registry": [],
            "cmd_inject": []
        },
        "forensic_details": {}
    }

    try:
        st = path.stat()
        result["size_bytes"] = st.st_size
        result["macb"] = {
            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(st.st_atime).isoformat(),
            "created": datetime.fromtimestamp(st.st_ctime).isoformat()
        }
        
        # Check Windows hidden attribute
        if os.name == "nt":
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs != -1 and (attrs & 2):  # FILE_ATTRIBUTE_HIDDEN = 2
                result["is_hidden"] = True
                result["rules_triggered"].append("Hidden File Attribute Active")
                result["threat_score"] += 15
        elif path.name.startswith("."):
            result["is_hidden"] = True

    except Exception as e:
        result["rules_triggered"].append(f"Stat read failure: {e}")
        return result

    # 1. Extension & Double Extension Analysis
    ext = result["extension"]
    name_lower = path.name.lower()
    
    # Check deceptive double extensions (e.g. invoice.pdf.exe)
    parts = name_lower.split(".")
    if len(parts) >= 3:
        second_last_ext = f".{parts[-2]}"
        last_ext = f".{parts[-1]}"
        if last_ext in HIGH_RISK_EXTENSIONS and second_last_ext in DECOY_EXTENSIONS:
            result["rules_triggered"].append(f"CRITICAL: Deceptive Double Extension ({second_last_ext}{last_ext})")
            result["threat_score"] += 45

    if ext in HIGH_RISK_EXTENSIONS:
        result["rules_triggered"].append(f"High-Risk Executable/Script Extension ({ext})")
        result["threat_score"] += 20

    # 2. Cryptographic Hashes & Header / Magic Byte Analysis
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    # Read first 8KB for header & entropy sample, then stream the rest
    first_chunk = b""
    full_data_sample = b""
    try:
        with open(path, "rb") as f:
            chunk = f.read(65536)
            first_chunk = chunk[:4096]
            full_data_sample = chunk
            while chunk:
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
                chunk = f.read(65536)

        result["md5"] = md5_hash.hexdigest()
        result["sha256"] = sha256_hash.hexdigest()
    except Exception as e:
        result["rules_triggered"].append(f"Read error: {e}")
        return result

    # Identify Magic Bytes
    detected_cat = "unknown"
    for signature, desc, cat in MAGIC_SIGNATURES:
        if first_chunk.startswith(signature):
            result["magic_desc"] = desc
            result["magic_category"] = cat
            detected_cat = cat
            break

    # Magic Byte Mismatch Check
    if detected_cat == "pe":
        if ext in DECOY_EXTENSIONS or ext in [".txt", ".log", ".dat", ".csv"]:
            result["rules_triggered"].append(f"CRITICAL: Header Mismatch! PE Executable disguised as {ext}")
            result["threat_score"] += 60

    if ext == ".pdf" and detected_cat != "pdf" and result["size_bytes"] > 0:
        result["rules_triggered"].append("Spoofed PDF: File lacks %PDF header signature")
        result["threat_score"] += 35

    # 3. Special Forensic Parsers (.lnk and autorun.inf)
    if ext == ".lnk":
        lnk_info = parse_lnk_file(str(path))
        result["forensic_details"]["lnk"] = lnk_info
        if lnk_info.get("suspicious_indicators"):
            for ind in lnk_info["suspicious_indicators"]:
                result["rules_triggered"].append(f"LNK Exploit: {ind}")
            result["threat_score"] += 35

    if path.name.lower() == "autorun.inf":
        autorun_info = parse_autorun_inf(str(path))
        result["forensic_details"]["autorun"] = autorun_info
        if autorun_info.get("suspicious_indicators"):
            for ind in autorun_info["suspicious_indicators"]:
                result["rules_triggered"].append(f"Autorun Payload: {ind}")
            result["threat_score"] += 50

    # 4. Entropy Calculation
    file_entropy = calculate_shannon_entropy(full_data_sample)
    result["entropy"] = file_entropy
    if file_entropy >= entropy_threshold and result["size_bytes"] > 512:
        result["rules_triggered"].append(f"High Entropy ({file_entropy:.2f}): Likely Packed/Encrypted Payload")
        result["threat_score"] += 25

    # 5. String Extraction & Obfuscation Scan
    extracted_strings = extract_strings(full_data_sample[:131072], min_len=4)
    result["extracted_strings_sample"] = extracted_strings[:50]

    # Regex matches across extracted text
    combined_text = " \n ".join(extracted_strings)
    
    ips = set(REGEX_IPV4.findall(combined_text))
    # Exclude standard loopback/broadcast
    real_ips = [ip for ip in ips if not ip.startswith(("127.", "0.", "255."))]
    if real_ips:
        result["matched_indicators"]["ips"] = real_ips[:10]
        result["rules_triggered"].append(f"Hardcoded External IP(s): {', '.join(real_ips[:3])}")
        result["threat_score"] += 15

    urls = set(REGEX_URL.findall(combined_text))
    if urls:
        result["matched_indicators"]["urls"] = list(urls)[:10]
        result["rules_triggered"].append(f"Hardcoded URL(s) detected ({len(urls)})")
        result["threat_score"] += 15

    b64_matches = REGEX_BASE64.findall(combined_text)
    if b64_matches and (ext in HIGH_RISK_EXTENSIONS or detected_cat in ["pe", "unknown"]):
        result["matched_indicators"]["base64"] = b64_matches[:5]
        result["rules_triggered"].append("Large Base64 Obfuscated Blob detected")
        result["threat_score"] += 20

    ps_matches = set(REGEX_POWERSHELL.findall(combined_text))
    if ps_matches:
        result["matched_indicators"]["powershell"] = list(ps_matches)
        result["rules_triggered"].append(f"PowerShell Malicious Flags: {', '.join(list(ps_matches)[:3])}")
        result["threat_score"] += 30

    reg_matches = set(REGEX_REGISTRY.findall(combined_text))
    if reg_matches:
        result["matched_indicators"]["registry"] = list(reg_matches)[:10]
        result["rules_triggered"].append("Registry Persistence / Tampering Paths referenced")
        result["threat_score"] += 20

    cmd_matches = set(REGEX_CMD_INJECT.findall(combined_text))
    if cmd_matches:
        result["matched_indicators"]["cmd_inject"] = list(cmd_matches)
        result["rules_triggered"].append(f"Command Injection / Shadow Deletion artifact: {list(cmd_matches)[0]}")
        result["threat_score"] += 35

    # Determine Overall Risk Level
    result["threat_score"] = min(100, result["threat_score"])
    if result["threat_score"] >= 60:
        result["risk_level"] = "MALICIOUS"
    elif result["threat_score"] >= 25:
        result["risk_level"] = "SUSPICIOUS"
    else:
        result["risk_level"] = "CLEAN"

    return result


class ScannerWorker(QThread):
    """
    Background worker thread to recursively scan real physical USB drive volumes
    without freezing the main PyQt UI.
    """
    progress = pyqtSignal(int, int, str)       # current, total, current_file_path
    file_scanned = pyqtSignal(dict)           # scan_result dict
    scan_finished = pyqtSignal(list, dict)    # all_results, summary_dict
    scan_error = pyqtSignal(str)

    def __init__(self, root_path: str, entropy_threshold: float = 7.2):
        super().__init__()
        self.root_path = root_path
        self.entropy_threshold = entropy_threshold
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        try:
            target = Path(self.root_path).resolve()
            if not target.exists():
                self.scan_error.emit(f"Drive root does not exist: {self.root_path}")
                return

            # Discover all files on the physical volume
            file_list = []
            for root, dirs, files in os.walk(target):
                if self._is_cancelled:
                    break
                for f in files:
                    full_p = os.path.join(root, f)
                    file_list.append(full_p)

            total_files = len(file_list)
            if total_files == 0:
                summary = {
                    "total_scanned": 0,
                    "clean": 0,
                    "suspicious": 0,
                    "malicious": 0,
                    "root_path": str(target),
                    "completed_at": datetime.now().isoformat()
                }
                self.scan_finished.emit([], summary)
                return

            results = []
            clean_count = 0
            suspicious_count = 0
            malicious_count = 0

            for i, file_p in enumerate(file_list):
                if self._is_cancelled:
                    break

                self.progress.emit(i + 1, total_files, file_p)
                res = scan_single_file(file_p, self.entropy_threshold)
                results.append(res)
                self.file_scanned.emit(res)

                if res["risk_level"] == "MALICIOUS":
                    malicious_count += 1
                elif res["risk_level"] == "SUSPICIOUS":
                    suspicious_count += 1
                else:
                    clean_count += 1

            summary = {
                "total_scanned": len(results),
                "clean": clean_count,
                "suspicious": suspicious_count,
                "malicious": malicious_count,
                "root_path": str(target),
                "completed_at": datetime.now().isoformat()
            }
            self.scan_finished.emit(results, summary)

        except Exception as e:
            self.scan_error.emit(f"Scan failed with error: {str(e)}")
