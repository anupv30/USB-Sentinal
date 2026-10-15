"""Forensics Service Routines.

Coordinates log parsing and mounted drive file integrity inspection with the SQLite database.
"""

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Union, Optional
from sqlalchemy.orm import Session

from app.models import Device, FileArtifact, ForensicLog
from app.schemas import TimelineEvent
from parsers.usb_parser import USBLogParser, ParsedUSBDevice
from analyzers.file_analyzer import FileAnalyzer, AnalyzedFileArtifact


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class ForensicsService:
    """High-level service routines for forensics data ingestion and integrity analysis."""

    @classmethod
    def ingest_usb_log(
        cls,
        content: str,
        filename: Optional[str] = None,
        db: Optional[Session] = None
    ) -> List[Device]:
        """Parses raw log content and registers discovered USB devices into the database."""
        lower_name = (filename or "").lower()
        if "setupapi" in lower_name or "[Device Install Log]" in content or ">>>  [Device Install" in content:
            log_type = "windows_setupapi"
            parsed_devices = USBLogParser.parse_setupapi(content)
        else:
            log_type = "linux_syslog"
            parsed_devices = USBLogParser.parse_linux_log(content)

        saved_devices: List[Device] = []

        if db is not None:
            for p in parsed_devices:
                existing = db.query(Device).filter(Device.serial_number == p.serial_number).first()
                if existing:
                    if p.volume_label and not existing.volume_label:
                        existing.volume_label = p.volume_label
                    if p.first_connected:
                        if existing.first_connected is None or _to_utc(p.first_connected) < _to_utc(existing.first_connected):
                            existing.first_connected = p.first_connected
                    if p.last_connected:
                        if existing.last_connected is None or _to_utc(p.last_connected) > _to_utc(existing.last_connected):
                            existing.last_connected = p.last_connected
                    db.commit()
                    db.refresh(existing)
                    saved_devices.append(existing)
                else:
                    new_dev = Device(**p.to_dict())
                    db.add(new_dev)
                    db.commit()
                    db.refresh(new_dev)
                    saved_devices.append(new_dev)

            # Persist original forensic log entry preserving raw evidence and parsed records
            records_data = []
            for p in parsed_devices:
                records_data.append({
                    "vendor_id": p.vendor_id,
                    "product_id": p.product_id,
                    "serial_number": p.serial_number,
                    "volume_label": p.volume_label,
                    "first_connected": p.first_connected.isoformat() if p.first_connected else None,
                    "last_connected": p.last_connected.isoformat() if p.last_connected else None,
                    "raw_lines": p.raw_lines,
                })

            source = filename or ("setupapi.dev.log" if log_type == "windows_setupapi" else "syslog")
            # Prevent duplicate ForensicLog entries when identical content is uploaded multiple times
            existing_log = db.query(ForensicLog).filter(
                ForensicLog.source_name == source,
                ForensicLog.raw_content == content
            ).first()
            if not existing_log:
                log_entry = ForensicLog(
                    log_type=log_type,
                    source_name=source,
                    ingested_at=datetime.now(timezone.utc),
                    raw_content=content,
                    parsed_devices_count=len(parsed_devices),
                    parsed_records=json.dumps(records_data),
                )
                db.add(log_entry)
                db.commit()

        return saved_devices

    @classmethod
    def analyze_and_ingest_drive(
        cls,
        target_dir: Union[str, Path],
        device_id: int,
        db: Session
    ) -> Dict[str, Any]:
        """Scans a mounted volume directory, inspects file integrity, and commits records to SQLite."""
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise ValueError(f"Device with ID {device_id} does not exist.")

        # 1. Scan directory & extract metadata + hashes + flags
        artifacts = FileAnalyzer.scan_directory(target_dir)

        # 2. Persist to database linked to device_id
        inserted_count = FileAnalyzer.persist_artifacts(artifacts, device_id=device_id, db=db)

        # 3. Compile forensic summary
        suspicious_items = [a for a in artifacts if a.flag_suspicious]

        return {
            "device_id": device_id,
            "device_serial": device.serial_number,
            "target_dir": str(target_dir),
            "total_files_scanned": len(artifacts),
            "records_persisted": inserted_count,
            "suspicious_count": len(suspicious_items),
            "clean_count": len(artifacts) - len(suspicious_items),
            "artifacts": [a.model_dump() for a in artifacts],
        }

    @classmethod
    def ingest_live_system_history(cls, db: Session) -> List[Device]:
        """Automatically reads real system logs and hardware registry to extract actual USB history."""
        import platform
        from services.drive_detector import (
            detect_removable_drives,
            get_windows_registry_usb_devices,
        )

        saved_devices: List[Device] = []

        # 1. Parse physical setupapi log if available on Windows
        if platform.system() == "Windows":
            setupapi_path = Path(r"C:\Windows\INF\setupapi.dev.log")
            if setupapi_path.exists():
                try:
                    content = setupapi_path.read_text(encoding="utf-8", errors="ignore")
                    log_devs = cls.ingest_usb_log(content, filename="setupapi.dev.log", db=db)
                    saved_devices.extend(log_devs)
                except Exception:
                    pass

            # 2. Extract hardware records directly from Windows Registry
            reg_devices = get_windows_registry_usb_devices()
            for r in reg_devices:
                serial = r["serial_number"]
                existing = db.query(Device).filter(Device.serial_number == serial).first()
                if existing:
                    if r.get("volume_label") and (not existing.volume_label or existing.volume_label.startswith("USB Device")):
                        existing.volume_label = r["volume_label"]
                    if r.get("vendor_id") and existing.vendor_id == "0000":
                        existing.vendor_id = r["vendor_id"]
                    if r.get("product_id") and existing.product_id == "0001":
                        existing.product_id = r["product_id"]
                    db.commit()
                    db.refresh(existing)
                    if existing not in saved_devices:
                        saved_devices.append(existing)
                else:
                    new_dev = Device(
                        vendor_id=r["vendor_id"],
                        product_id=r["product_id"],
                        serial_number=serial,
                        volume_label=r["volume_label"],
                        first_connected=r["first_connected"],
                        last_connected=r["last_connected"],
                    )
                    db.add(new_dev)
                    db.commit()
                    db.refresh(new_dev)
                    saved_devices.append(new_dev)

        elif platform.system() == "Linux":
            # Check Linux syslog / messages
            for log_cand in ("/var/log/syslog", "/var/log/messages"):
                p = Path(log_cand)
                if p.exists():
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                        sys_devs = cls.ingest_usb_log(content, filename=p.name, db=db)
                        saved_devices.extend(sys_devs)
                        break
                    except Exception:
                        pass

        # 3. Correlate with currently mounted removable drives
        try:
            live_drives = detect_removable_drives()
            for ld in live_drives:
                mount = ld["mount_point"]
                label = f"{ld['volume_label']} ({mount.rstrip(os.sep)})"
                serial = ld.get("serial_number") or f"LIVE_MOUNT_{mount.replace(':', '').replace(os.sep, '')}"
                vid = ld.get("vendor_id") or "0000"
                pid = ld.get("product_id") or "0000"

                existing = db.query(Device).filter(
                    (Device.serial_number == serial) | (Device.volume_label.like(f"%{mount}%"))
                ).first()

                if existing:
                    existing.volume_label = label
                    existing.last_connected = datetime.now(timezone.utc)
                    db.commit()
                    db.refresh(existing)
                    if existing not in saved_devices:
                        saved_devices.append(existing)
                else:
                    new_dev = Device(
                        vendor_id=vid,
                        product_id=pid,
                        serial_number=serial,
                        volume_label=label,
                        first_connected=datetime.now(timezone.utc),
                        last_connected=datetime.now(timezone.utc),
                    )
                    db.add(new_dev)
                    db.commit()
                    db.refresh(new_dev)
                    saved_devices.append(new_dev)
        except Exception:
            pass

        return saved_devices

    @classmethod
    def get_timeline_events(
        cls,
        db: Session,
        device_id: Optional[int] = None,
        order: str = "desc"
    ) -> List[TimelineEvent]:
        """Aggregates verified forensic log events and inferred hardware observations without duplication."""
        # 1. Query registered devices
        dev_query = db.query(Device)
        if device_id is not None:
            dev_query = dev_query.filter(Device.id == device_id)
        devices = dev_query.all()
        dev_by_serial = {d.serial_number: d for d in devices}

        # 2. Extract verified forensic events from ingested logs
        raw_events: List[TimelineEvent] = []
        forensic_logs = db.query(ForensicLog).all()
        parsed_contents = set()

        for flog in forensic_logs:
            if not flog.raw_content or flog.raw_content in parsed_contents:
                continue
            parsed_contents.add(flog.raw_content)

            try:
                log_events = USBLogParser.extract_timeline_events(flog.raw_content)
            except Exception:
                log_events = []

            for le in log_events:
                d = dev_by_serial.get(le.serial_number)
                if device_id is not None:
                    if not d or d.id != device_id:
                        continue

                dev_id = d.id if d else 0
                label = (d.volume_label if d and d.volume_label else None) or le.volume_label or f"USB {le.vendor_id}:{le.product_id}"

                ts_utc = _to_utc(le.timestamp)
                ts_slug = int(ts_utc.timestamp()) if ts_utc else 0
                type_slug = le.event_type.lower().replace(" ", "_")
                eid = f"evt-{dev_id}-{type_slug}-{ts_slug}"

                raw_events.append(
                    TimelineEvent(
                        event_id=eid,
                        timestamp=le.timestamp,
                        event_type=le.event_type,
                        device_id=dev_id,
                        vendor_id=le.vendor_id,
                        product_id=le.product_id,
                        serial_number=le.serial_number,
                        volume_label=label,
                        description=le.description,
                    )
                )

        # 3. Add inferred observations for devices that do not have confirmed log events at their timestamps
        confirmed_connections = {
            (e.serial_number, _to_utc(e.timestamp).isoformat() if e.timestamp else None)
            for e in raw_events
            if e.event_type == "USB INSERTED"
        }
        confirmed_disconnections = {
            (e.serial_number, _to_utc(e.timestamp).isoformat() if e.timestamp else None)
            for e in raw_events
            if e.event_type == "USB DISCONNECTED"
        }
        recorded_events = {
            (e.serial_number, _to_utc(e.timestamp).isoformat() if e.timestamp else None, e.event_type)
            for e in raw_events
        }

        for d in devices:
            label = d.volume_label or f"USB {d.vendor_id}:{d.product_id}"

            # Inferred earliest observation
            if d.first_connected:
                fc_iso = _to_utc(d.first_connected).isoformat()
                if (d.serial_number, fc_iso) not in confirmed_connections and (d.serial_number, fc_iso, "FIRST OBSERVED") not in recorded_events:
                    ts_slug = int(_to_utc(d.first_connected).timestamp())
                    raw_events.append(
                        TimelineEvent(
                            event_id=f"dev-{d.id}-first-obs-{ts_slug}",
                            timestamp=d.first_connected,
                            event_type="FIRST OBSERVED",
                            device_id=d.id,
                            vendor_id=d.vendor_id,
                            product_id=d.product_id,
                            serial_number=d.serial_number,
                            volume_label=d.volume_label,
                            description=f"Device '{label}' first observed on system (inferred timestamp)",
                        )
                    )
                    recorded_events.add((d.serial_number, fc_iso, "FIRST OBSERVED"))

            # Inferred latest observation (only when distinct from first_connected)
            if d.last_connected and d.last_connected != d.first_connected:
                lc_iso = _to_utc(d.last_connected).isoformat()
                if (d.serial_number, lc_iso) not in confirmed_disconnections and (d.serial_number, lc_iso, "LAST OBSERVED") not in recorded_events:
                    ts_slug = int(_to_utc(d.last_connected).timestamp())
                    raw_events.append(
                        TimelineEvent(
                            event_id=f"dev-{d.id}-last-obs-{ts_slug}",
                            timestamp=d.last_connected,
                            event_type="LAST OBSERVED",
                            device_id=d.id,
                            vendor_id=d.vendor_id,
                            product_id=d.product_id,
                            serial_number=d.serial_number,
                            volume_label=d.volume_label,
                            description=f"Device '{label}' latest active connection observed (inferred timestamp)",
                        )
                    )
                    recorded_events.add((d.serial_number, lc_iso, "LAST OBSERVED"))

        # 4. Strict deduplication by (serial_number, timestamp, event_type)
        unique_events: List[TimelineEvent] = []
        seen_keys = set()
        seen_confirmed = {
            (e.serial_number, _to_utc(e.timestamp).isoformat() if e.timestamp else None): e.event_type
            for e in raw_events
            if e.event_type in ("USB INSERTED", "USB DISCONNECTED")
        }

        for ev in raw_events:
            ts_iso = _to_utc(ev.timestamp).isoformat() if ev.timestamp else "none"
            key = (ev.serial_number, ts_iso, ev.event_type)
            if key in seen_keys:
                continue

            # Suppress inferred observation if a confirmed event exists at the exact same timestamp
            if ev.event_type == "FIRST OBSERVED" and seen_confirmed.get((ev.serial_number, ts_iso)) == "USB INSERTED":
                continue
            if ev.event_type == "LAST OBSERVED" and seen_confirmed.get((ev.serial_number, ts_iso)) == "USB DISCONNECTED":
                continue

            seen_keys.add(key)
            unique_events.append(ev)

        # 5. Chronological sort
        reverse_sort = (order.lower() == "desc")
        unique_events.sort(
            key=lambda e: _to_utc(e.timestamp) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=reverse_sort,
        )

        return unique_events
