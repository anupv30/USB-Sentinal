# USB Sentinel AI // USB Forensics & Threat Intelligence

**USB Sentinel AI** is an advanced, full-stack cyber-forensics desktop application designed to detect, analyze, de-obfuscate, and remediate threats originating from real physical USB storage devices.

Built with Python, PyQt6, Win32 API / WMI / psutil, and powered by Groq's `llama-3.3-70b-versatile` (with intelligent model fallback), the application performs live hardware monitoring, heuristic analysis, entropy calculation, string extraction, cryptographic hashing, and automated AI threat assessment without hardcoded sample data or static mocks.

---

## Key Capabilities

### 1. Physical USB Detection & Hardware Monitoring (`usb_monitor.py`)
- Background hardware listener thread tracking Windows `WM_DEVICECHANGE` OS events and dynamic block device polling.
- Extracts volume metadata dynamically:
  - Mount Point / Drive Letter (e.g. `E:\`, `F:\`)
  - Volume Label & File System type (FAT32, NTFS, exFAT)
  - Volume Serial Number (formatted as `XXXX-XXXX`)
  - Total, Free, and Used capacity
- Automatic scan trigger on device insertion.
- Manual drive / directory selection for custom forensic examinations.

### 2. Local Heuristic & Forensic Scanning Engine (`scanner.py`)
- Multi-threaded scanner (`ScannerWorker`) operating recursively on the physical volume:
  - **Extension & Double Extension Analyzer:** Flags deceptive double extensions (e.g., `invoice.pdf.exe`, `photo.jpg.scr`).
  - **Magic Byte / Header Mismatch Detector:** Compares binary headers against magic byte signatures (`MZ`, `%PDF`, PNG, JPEG, ZIP, OLE compound documents, ELF, etc.) to expose spoofed file extensions.
  - **Autorun & Shortcut (.lnk) Forensics:** Parses `autorun.inf` execution directives and Windows Shell Link (`.lnk`) binary structures to extract targets, arguments (e.g., `powershell.exe -enc ...`), and LOLBin invocations.
  - **Cryptographic Integrity:** Computes streaming real MD5 and SHA-256 hashes for every file.
  - **Entropy & Obfuscation Scanner:** Calculates Shannon Entropy ($0.0 - 8.0$) to detect packed or encrypted payloads (>7.2). Extracts ASCII/Unicode strings, capturing IP addresses, URLs, Base64 blobs, PowerShell `-Enc` flags, and registry persistence keys.
  - **MACB Timeline:** Retrieves Modified, Accessed, and Created filesystem timestamps.

### 3. Groq AI Threat Intelligence & Intent Assistant (`groq_analyzer.py`)
- **Automated Deep Forensic Analysis:** Bundles file metadata, hashes, entropy, and extracted strings into structured JSON queries to Groq (`response_format={"type": "json_object"}`).
  - Returns Threat Verdict & Score (0–100)
  - Malware Category & MITRE ATT&CK TTP classifications (e.g. `T1059.001 - PowerShell`, `T1036.005 - Masquerading`)
  - Plain-English De-obfuscation Summary
  - Recommended Remediation (Quarantine, Delete, Allow, Sandbox)
- **Natural Language Intent Assistant with Tool Calling:**
  - Investigators can chat or command actions in plain English:
    - *"Quarantine all double-extension files found on the USB."*
    - *"Find all hidden scripts and explain their purpose."*
    - *"Generate an executive forensic summary of this USB session."*
  - Automatically executes backend tools (`quarantine_file`, `quarantine_matching`, `calculate_entropy`, `list_hidden_artifacts`, `export_pdf_report`).

### 4. Forensic Remediation & Quarantine Vault (`quarantine.py`)
- Isolated `.sentinel_quarantine/` local vault.
- AES-256-GCM authenticated encryption for quarantined files to prevent accidental execution.
- JSON metadata database tracking original file paths, SHA-256 hashes, timestamps, and threat justifications.
- Safe restoration or permanent purging of quarantined artifacts.

### 5. ReportLab PDF Forensic Report Generator (`report_gen.py`)
- Generates professional, multi-page forensic reports formatted for incident response:
  - Physical USB Hardware details & Serial Numbers
  - Scanned vs. Suspicious metrics
  - Flagged files with full cryptographic hashes (SHA-256, MD5) and entropy scores
  - Groq AI Threat Intelligence & MITRE ATT&CK matrix excerpts
  - Filesystem event audit log

---

## Architecture & Code Structure

```
USB SENTINEL/
├── main.py            # Main application entrypoint & Qt event loop
├── gui.py             # Cyberpunk Dark-Mode PyQt6 interface with 6 tab views
├── usb_monitor.py     # Real-time hardware listener & drive metadata extractor
├── scanner.py         # Multi-threaded heuristic, magic byte, entropy, and hash engine
├── groq_analyzer.py   # Groq LLM client (llama-3.3-70b-versatile & tool calling)
├── quarantine.py      # AES-256-GCM encrypted isolation vault & restorer
├── report_gen.py      # ReportLab forensic PDF report generator
└── requirements.txt   # Core Python dependencies
```

---

## Installation & Running

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Launch Application:**
   ```bash
   python main.py
   ```

3. **Insert any physical USB flash drive:**
   - USB Sentinel AI will automatically detect the device, display volume info, and initiate heuristic scanning.
