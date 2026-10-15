"""Verify live backend ingestion and forensic logs API."""

import json
import uuid
import urllib.request
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"
SAMPLE_DIR = Path(__file__).resolve().parent / "sample_data"

def test_live_workflow():
    # 1. Check health
    with urllib.request.urlopen(f"{BASE_URL}/api/health") as res:
        health = json.loads(res.read().decode())
        print(f"[1] Health Check: {health['status']} ({health['service']})")

    # 2. Check forensic logs before upload
    with urllib.request.urlopen(f"{BASE_URL}/api/forensic-logs") as res:
        logs_before = json.loads(res.read().decode())
        print(f"[2] Initial Ingested Forensic Logs Count: {len(logs_before)}")

    # 3. Helper for multipart upload
    def upload_file(filename: str, filepath: Path):
        boundary = uuid.uuid4().hex
        with open(filepath, "rb") as f:
            file_bytes = f.read()
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
        ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}/api/upload-log?save_to_db=true",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())

    # Ingest Windows SetupAPI Log
    win_res = upload_file("setupapi.dev.log", SAMPLE_DIR / "setupapi.dev.log")
    print(f"[3] Windows SetupAPI Ingested: {len(win_res)} devices returned")

    # Ingest Linux Syslog
    lin_res = upload_file("syslog_usb.log", SAMPLE_DIR / "syslog_usb.log")
    print(f"[4] Linux Syslog Ingested: {len(lin_res)} devices returned")

    # 4. Fetch forensic logs
    with urllib.request.urlopen(f"{BASE_URL}/api/forensic-logs") as res:
        logs = json.loads(res.read().decode())
        print(f"[5] Total Ingested Forensic Logs in DB: {len(logs)}")
        for l in logs:
            print(f"    - ID: {l['id']} | Type: {l['log_type']} | Source: {l['source_name']} | Devices: {l['parsed_devices_count']}")
            print(f"      Ingested At: {l['ingested_at']} | Raw Lines Count: {len(l['raw_content'].splitlines())}")
            for r in l["parsed_records"]:
                print(f"        * Device: VID={r['vendor_id']} PID={r['product_id']} SN={r['serial_number']}")
                print(f"          Label: {r['volume_label']} | First: {r['first_connected']} | Last: {r['last_connected']}")
                has_raw_snippet = bool(r.get("raw_lines"))
                print(f"          Raw Evidence Snippet Captured: {has_raw_snippet}")

    print("\n[SUCCESS] Live API and Ingestion Verification Passed!")

if __name__ == "__main__":
    test_live_workflow()
