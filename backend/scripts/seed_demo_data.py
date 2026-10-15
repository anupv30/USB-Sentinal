"""Seed Script: Demonstrates end-to-end ingestion of USB logs and file inspection into SQLite."""

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.database import engine, SessionLocal, Base
from app.models import Device, FileArtifact
from services.forensics_service import ForensicsService

SAMPLE_LOG = BACKEND_DIR / "tests" / "sample_data" / "setupapi.dev.log"
MOCK_FILES_DIR = BACKEND_DIR / "tests" / "mock_files"


def main():
    print("[*] Initializing Database Schema...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        print("[*] 1. Ingesting Windows SetupAPI Log...")
        content = SAMPLE_LOG.read_text(encoding="utf-8")
        devices = ForensicsService.ingest_usb_log(content, filename="setupapi.dev.log", db=db)
        print(f"[+] Successfully registered/updated {len(devices)} USB devices in SQLite:")
        for d in devices:
            print(f"    - ID: {d.id} | VID: {d.vendor_id} | PID: {d.product_id} | Serial: {d.serial_number} | Label: {d.volume_label}")

        if devices:
            primary_device = devices[0]
            print(f"\n[*] 2. Scanning Mounted Drive for Device #{primary_device.id} ({primary_device.volume_label})...")
            results = ForensicsService.analyze_and_ingest_drive(
                target_dir=MOCK_FILES_DIR,
                device_id=primary_device.id,
                db=db
            )

            print(f"[+] Scanned Files: {results['total_files_scanned']}")
            print(f"[+] Clean Files:   {results['clean_count']}")
            print(f"[+] Flagged Risk:  {results['suspicious_count']}")

            print("\n[*] 3. File Artifacts Written to SQLite:")
            for art in results["artifacts"]:
                status = "FLAGGED" if art["flag_suspicious"] else "CLEAN"
                print(f"    [{status}] {art['file_path']} ({art['file_size']} B) SHA256: {art['sha256_hash'][:16]}...")
                if art["flag_reason"]:
                    print(f"            Reason: {art['flag_reason']}")

        total_devs = db.query(Device).count()
        total_arts = db.query(FileArtifact).count()
        flagged_arts = db.query(FileArtifact).filter(FileArtifact.flag_suspicious.is_(True)).count()

        print("\n[OK] Database Ingestion Summary:")
        print(f"    - Total Devices in DB:  {total_devs}")
        print(f"    - Total Artifacts in DB:{total_arts}")
        print(f"    - Total High-Risk Flags:{flagged_arts}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
