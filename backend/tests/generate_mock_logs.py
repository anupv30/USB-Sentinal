"""Mock Sample Log and Test File Generator for USB Forensics & Artifact Parser.

Generates:
1. Windows setupapi.dev.log with realistic USB mass storage and suspicious device history.
2. Linux dmesg and /var/log/syslog USB connection records.
3. Harmless sample files (.pdf, .bat, .vbs, .exe dummy headers, .inf) for forensic inspection testing.
"""

import os
import hashlib
from pathlib import Path

# Paths
TESTS_DIR = Path(__file__).resolve().parent
SAMPLE_DATA_DIR = TESTS_DIR / "sample_data"
MOCK_FILES_DIR = TESTS_DIR / "mock_files"


SETUPAPI_LOG_CONTENT = """[Device Install Log]
     OS Version = 10.0.19045
     Service Pack = 0.0
     Suite = 0x0100
     ProductType = 1
     Architecture = amd64

[Begin Device Install - USB Mass Storage Class]
>>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5581\\4C530001250912117462]
>>>  Section start 2026/09/20 14:22:10.125
     dvi: Device Status: 0x0180200a [DN_DRIVER_LOADED|DN_STARTED|DN_DISABLEABLE|DN_REMOVABLE]
     dvi: Parent Device: USB\\ROOT_HUB30\\4&1a75c12&0
     inf: Opened INF: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\usbstor.inf_amd64_d3a8276f7b1\\usbstor.inf' [Default]
     dvi: Selected driver: usbstor.inf:Generic.Install
     dvi: Install Device: USBSTOR\\DiskSanDisk_Ultra___________1.00\\4C530001250912117462&0
     dvi: Disk Name: SanDisk Ultra USB Device
     dvi: Assigned Drive Letter: E:
<<<  Section end 2026/09/20 14:22:12.890
<<<  [Exit status: SUCCESS]

>>>  [Device Install (Hardware initiated) - USB\\VID_0951&PID_1666\\0018F12B4F83EC21191E002B]
>>>  Section start 2026/09/28 09:15:02.430
     dvi: Device Status: 0x0180200a [DN_DRIVER_LOADED|DN_STARTED|DN_DISABLEABLE|DN_REMOVABLE]
     inf: Opened INF: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\usbstor.inf_amd64_d3a8276f7b1\\usbstor.inf' [Default]
     dvi: Selected driver: usbstor.inf:Generic.Install
     dvi: Install Device: USBSTOR\\DiskKingstonDataTraveler_3.0PMAP\\0018F12B4F83EC21191E002B&0
     dvi: Disk Name: Kingston DataTraveler 3.0 USB Device
     dvi: Assigned Drive Letter: F:
<<<  Section end 2026/09/28 09:15:04.110
<<<  [Exit status: SUCCESS]

>>>  [Device Install (Hardware initiated) - USB\\VID_1FC9&PID_0004\\DUCKY_KBD_PAYLOAD_99]
>>>  Section start 2026/10/02 23:41:19.502
     dvi: Device Status: 0x0180200a [DN_DRIVER_LOADED|DN_STARTED|DN_DISABLEABLE|DN_REMOVABLE]
     inf: Opened INF: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\keyboard.inf_amd64_f1208a994\\keyboard.inf'
     dvi: Hardware ID Match: HID\\VID_1FC9&PID_0004&REV_0100
     dvi: Warning: Device presents composite HID Keyboard and Virtual Mass Storage endpoint
     dvi: Device Description: Composite Keystroke Injector / Virtual Storage
<<<  Section end 2026/10/02 23:41:20.108
<<<  [Exit status: SUCCESS]
"""

DMESG_LOG_CONTENT = """[ 1245.892011] usb 1-1.2: new high-speed USB device number 5 using xhci_hcd
[ 1245.993412] usb 1-1.2: New USB device found, idVendor=0781, idProduct=5581, bcdDevice= 1.00
[ 1245.993418] usb 1-1.2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[ 1245.993420] usb 1-1.2: Product: Ultra
[ 1245.993423] usb 1-1.2: Manufacturer: SanDisk
[ 1245.993425] usb 1-1.2: SerialNumber: 4C530001250912117462
[ 1246.002199] usb-storage 1-1.2:1.0: USB Mass Storage device detected
[ 1246.003512] scsi host4: usb-storage 1-1.2:1.0
[ 1247.019441] scsi 4:0:0:0: Direct-Access     SanDisk  Ultra            1.00 PQ: 0 ANSI: 6
[ 1247.021002] sd 4:0:0:0: Attached scsi generic sg2 type 0
[ 1247.022301] sd 4:0:0:0: [sdb] 60063744 512-byte logical blocks: (30.8 GB/28.6 GiB)
[ 1247.023190] sd 4:0:0:0: [sdb] Write Protect is off
[ 1247.023193] sd 4:0:0:0: [sdb] Mode Sense: 43 00 00 00
[ 1247.024011] sd 4:0:0:0: [sdb] Write cache: disabled, read cache: enabled, doesn't support DPO or FUA
[ 1247.028910]  sdb: sdb1
[ 1247.031200] sd 4:0:0:0: [sdb] Attached SCSI removable disk
[ 3890.114002] usb 2-2: new SuperSpeed USB device number 3 using xhci_hcd
[ 3890.134901] usb 2-2: New USB device found, idVendor=0951, idProduct=1666, bcdDevice= 1.10
[ 3890.134905] usb 2-2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[ 3890.134908] usb 2-2: Product: DataTraveler 3.0
[ 3890.134910] usb 2-2: Manufacturer: Kingston
[ 3890.134912] usb 2-2: SerialNumber: 0018F12B4F83EC21191E002B
[ 3890.137882] usb-storage 2-2:1.0: USB Mass Storage device detected
[ 3890.138200] scsi host5: usb-storage 2-2:1.0
[ 3891.140220] scsi 5:0:0:0: Direct-Access     Kingston DataTraveler 3.0 PMAP PQ: 0 ANSI: 6
[ 3891.141501] sd 5:0:0:0: [sdc] 121044992 512-byte logical blocks: (62.0 GB/57.7 GiB)
[ 3891.142010] sd 5:0:0:0: [sdc] Write Protect is off
[ 3891.145100]  sdc: sdc1 sdc2
[ 3891.148000] sd 5:0:0:0: [sdc] Attached SCSI removable disk
"""

SYSLOG_USB_CONTENT = """Oct 05 10:14:22 forensic-station kernel: [ 1245.892011] usb 1-1.2: new high-speed USB device number 5 using xhci_hcd
Oct 05 10:14:22 forensic-station kernel: [ 1245.993412] usb 1-1.2: New USB device found, idVendor=0781, idProduct=5581, bcdDevice= 1.00
Oct 05 10:14:22 forensic-station kernel: [ 1245.993423] usb 1-1.2: Manufacturer: SanDisk
Oct 05 10:14:22 forensic-station kernel: [ 1245.993425] usb 1-1.2: SerialNumber: 4C530001250912117462
Oct 05 10:14:23 forensic-station kernel: [ 1246.002199] usb-storage 1-1.2:1.0: USB Mass Storage device detected
Oct 05 10:14:24 forensic-station kernel: [ 1247.031200] sd 4:0:0:0: [sdb] Attached SCSI removable disk
Oct 05 10:14:25 forensic-station udisksd[812]: Mounted /dev/sdb1 at /media/investigator/SANDISK_32G on behalf of uid 1000
Oct 06 18:30:11 forensic-station kernel: [ 3890.114002] usb 2-2: new SuperSpeed USB device number 3 using xhci_hcd
Oct 06 18:30:11 forensic-station kernel: [ 3890.134901] usb 2-2: New USB device found, idVendor=0951, idProduct=1666, bcdDevice= 1.10
Oct 06 18:30:11 forensic-station kernel: [ 3890.134910] usb 2-2: Manufacturer: Kingston
Oct 06 18:30:11 forensic-station kernel: [ 3890.134912] usb 2-2: SerialNumber: 0018F12B4F83EC21191E002B
Oct 06 18:30:12 forensic-station udisksd[812]: Mounted /dev/sdc1 at /media/investigator/KINGSTON_64 on behalf of uid 1000
"""


def generate_mock_logs():
    """Generates mock forensic logs into sample_data directory."""
    SAMPLE_DATA_DIR.mkdir(parents=True, exist_ok=True)

    files = {
        "setupapi.dev.log": SETUPAPI_LOG_CONTENT,
        "dmesg_usb.log": DMESG_LOG_CONTENT,
        "syslog_usb.log": SYSLOG_USB_CONTENT,
    }

    created = []
    for filename, content in files.items():
        file_path = SAMPLE_DATA_DIR / filename
        file_path.write_text(content.strip() + "\n", encoding="utf-8")
        created.append(str(file_path))
        print(f"[+] Generated mock log: {file_path}")

    return created


def generate_mock_test_files():
    """Generates benign sample files (.pdf, .bat, .vbs, harmless dummy .exe, .inf)."""
    MOCK_FILES_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Normal Innocent PDF (Minimal valid PDF structure)
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000101 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
    )

    # 2. Suspicious Batch file (.bat)
    bat_content = (
        "@echo off\r\n"
        ":: Harmless Forensic Testing Script\r\n"
        "echo [USB Artifact Test] Emulating suspicious persistence check...\r\n"
        "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run > nul 2>&1\r\n"
        "echo Execution complete.\r\n"
    ).encode("utf-8")

    # 3. Suspicious VBScript (.vbs)
    vbs_content = (
        "' Harmless USB Forensic Test VBScript\r\n"
        "Dim wshShell\r\n"
        "Set wshShell = CreateObject(\"WScript.Shell\")\r\n"
        "WScript.Echo \"USB Test Script Executed: Forensic Flag Verification\"\r\n"
    ).encode("utf-8")

    # 4. Harmless Dummy PE Executable (.exe) with standard MZ header & DOS stub
    # Does not contain any executable payload code, but exhibits MZ header signature
    dos_stub = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00"
        b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$"
        + (b"\x00" * 32)
        + b"PE\x00\x00"  # PE Signature
    )

    # 5. USB Autorun configuration (.inf)
    autorun_content = (
        "[autorun]\r\n"
        "open=sample_payload.exe\r\n"
        "action=Open USB Flash Drive\r\n"
        "icon=sample_payload.exe,0\r\n"
        "label=Test Volume\r\n"
    ).encode("utf-8")

    # 6. Double Extension decoy file (.pdf.exe)
    double_ext_content = dos_stub + b"\n:: Decoy double extension payload for inspection testing"

    mock_files = {
        "innocent_document.pdf": pdf_content,
        "cleanup_script.bat": bat_content,
        "update_tool.vbs": vbs_content,
        "sample_payload.exe": dos_stub,
        "autorun.inf": autorun_content,
        "confidential_report.pdf.exe": double_ext_content,
    }

    manifest = []
    for filename, raw_bytes in mock_files.items():
        file_path = MOCK_FILES_DIR / filename
        file_path.write_bytes(raw_bytes)
        md5 = hashlib.md5(raw_bytes).hexdigest()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        manifest.append({
            "name": filename,
            "path": str(file_path),
            "size": len(raw_bytes),
            "md5": md5,
            "sha256": sha256
        })
        print(f"[+] Created mock test file: {filename} ({len(raw_bytes)} bytes, SHA256: {sha256[:12]}...)")

    return manifest


if __name__ == "__main__":
    print("[*] Generating USB Forensics Mock Datasets...")
    logs = generate_mock_logs()
    files = generate_mock_test_files()
    print(f"[OK] Successfully generated {len(logs)} log files and {len(files)} test inspection files.")
