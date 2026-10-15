"""Automated USB Forensics & Artifact Parser - Primary API Application.

Provides REST endpoints for:
1. POST /api/upload-log: Upload & parse Windows setupapi.dev.log or Linux dmesg/syslog logs.
2. POST /api/scan-drive: Initiate deep filesystem inspection, hashing, and threat flagging.
3. GET  /api/devices: Retrieve recorded USB devices with connection statistics.
4. GET  /api/timeline: Chronological timeline of all USB hardware connection events.
5. GET  /api/files: Retrieve file artifacts with filtering by device_id and suspicious_only.
6. GET  /api/stats: Forensic metrics (total devices, files scanned, threats, recent connections).
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import engine, Base, get_db
from app.models import Device, FileArtifact, ForensicLog
from app.schemas import (
    DeviceCreate,
    DeviceRead,
    DeviceSummary,
    FileArtifactCreate,
    FileArtifactRead,
    TimelineEvent,
    ScanDriveRequest,
    ScanDriveResponse,
    StatsMetrics,
    DetectedDrive,
    ForensicLogRead,
    ParsedLogRecord,
)
from services.forensics_service import ForensicsService
from parsers.usb_parser import USBLogParser
from analyzers.file_analyzer import FileAnalyzer


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure SQLite tables exist on startup
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="USB Forensics & Artifact Parser API",
    description="Automated digital forensics parser and integrity inspection engine for USB hardware.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS setup
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["System"])
def health_check():
    """Health check endpoint."""
    return {
        "status": "online",
        "service": "USB Forensics API",
        "version": "1.0.0"
    }


# -----------------------------------------------------------------------------
# 1. POST /api/upload-log
# -----------------------------------------------------------------------------
@app.post(
    "/api/upload-log",
    response_model=List[DeviceSummary],
    status_code=status.HTTP_200_OK,
    tags=["Log Parsing"],
    summary="Upload and parse system log file (setupapi.dev.log or dmesg/syslog)"
)
@app.post(
    "/api/parsers/upload-log",
    response_model=List[DeviceSummary],
    status_code=status.HTTP_200_OK,
    tags=["Log Parsing"],
    include_in_schema=False
)
async def upload_log(
    file: UploadFile = File(..., description="System log file to parse"),
    save_to_db: bool = Query(True, description="Save parsed device records to SQLite"),
    db: Session = Depends(get_db)
):
    """Parses custom system log files and stores detected USB device records into database."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")

    try:
        content_bytes = await file.read()
        if not content_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        content = content_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

    # Delegate to ForensicsService
    saved_devices = ForensicsService.ingest_usb_log(
        content=content,
        filename=file.filename,
        db=db if save_to_db else None
    )

    results = []
    for d in saved_devices:
        total = db.query(FileArtifact).filter(FileArtifact.device_id == d.id).count() if save_to_db else 0
        suspicious = (
            db.query(FileArtifact)
            .filter(FileArtifact.device_id == d.id, FileArtifact.flag_suspicious.is_(True))
            .count()
            if save_to_db else 0
        )
        results.append(
            DeviceSummary(
                id=d.id,
                vendor_id=d.vendor_id,
                product_id=d.product_id,
                serial_number=d.serial_number,
                volume_label=d.volume_label,
                first_connected=d.first_connected,
                last_connected=d.last_connected,
                total_artifacts=total,
                suspicious_count=suspicious,
            )
        )

    return results


@app.post(
    "/api/ingest-live-log",
    response_model=List[DeviceSummary],
    status_code=status.HTTP_200_OK,
    tags=["Log Parsing"],
    summary="Automatically ingest host system USB logs and registry hardware history"
)
def ingest_live_log(
    db: Session = Depends(get_db)
):
    """Parses local system logs (C:\\Windows\\INF\\setupapi.dev.log) and Windows USB registry records into SQLite."""
    saved_devices = ForensicsService.ingest_live_system_history(db=db)
    results = []
    for d in saved_devices:
        total = db.query(FileArtifact).filter(FileArtifact.device_id == d.id).count()
        suspicious = (
            db.query(FileArtifact)
            .filter(FileArtifact.device_id == d.id, FileArtifact.flag_suspicious.is_(True))
            .count()
        )
        results.append(
            DeviceSummary(
                id=d.id,
                vendor_id=d.vendor_id,
                product_id=d.product_id,
                serial_number=d.serial_number,
                volume_label=d.volume_label,
                first_connected=d.first_connected,
                last_connected=d.last_connected,
                total_artifacts=total,
                suspicious_count=suspicious,
            )
        )
    return results


# -----------------------------------------------------------------------------
# 2. GET /api/detect-drives & POST /api/scan-drive
# -----------------------------------------------------------------------------
@app.get(
    "/api/detect-drives",
    response_model=List[DetectedDrive],
    status_code=status.HTTP_200_OK,
    tags=["Drive Analysis"],
    summary="Auto-detect physically mounted removable USB drives and pendrives"
)
def detect_drives():
    """Dynamically queries system storage for plugged-in removable drives, filesystems, and capacities."""
    from services.drive_detector import detect_removable_drives
    return detect_removable_drives()


@app.post(
    "/api/scan-drive",
    response_model=ScanDriveResponse,
    status_code=status.HTTP_200_OK,
    tags=["Drive Analysis"],
    summary="Scan local directory/drive, extract hashes, and flag suspicious files"
)
@app.post(
    "/api/analyzers/scan-drive",
    response_model=ScanDriveResponse,
    status_code=status.HTTP_200_OK,
    tags=["Drive Analysis"],
    include_in_schema=False
)
def scan_drive(
    payload: ScanDriveRequest,
    db: Session = Depends(get_db)
):
    """Inspects a local filesystem directory, calculates MD5 & SHA-256 hashes, and flags threats."""
    raw_path = payload.target_path.strip().strip('"').strip("'")
    if len(raw_path) == 2 and raw_path[1] == ":":
        raw_path = f"{raw_path}\\"

    target_path = Path(raw_path)
    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target path does not exist: {payload.target_path}"
        )
    if not target_path.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target path is not a directory: {payload.target_path}"
        )

    # Determine or auto-create device association
    device_id = payload.device_id
    if device_id is not None:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device with ID {device_id} not found."
            )
    else:
        # Check if target_path corresponds to a detected removable drive
        from services.drive_detector import detect_removable_drives
        live_drives = detect_removable_drives()
        matched_drive = next(
            (ld for ld in live_drives if raw_path.upper().startswith(ld["mount_point"].upper())),
            None
        )

        device = None
        if matched_drive:
            ser = matched_drive.get("serial_number") or f"USB_{matched_drive['volume_label']}"
            device = db.query(Device).filter(Device.serial_number == ser).first()
            if not device:
                device = Device(
                    vendor_id=matched_drive.get("vendor_id") or "USB",
                    product_id=matched_drive.get("product_id") or "DISK",
                    serial_number=ser,
                    volume_label=f"{matched_drive['volume_label']} ({matched_drive['mount_point'].rstrip('\\/')})",
                    first_connected=datetime.now(timezone.utc),
                    last_connected=datetime.now(timezone.utc),
                )
                db.add(device)
                db.commit()
                db.refresh(device)

        if not device:
            # Fallback to latest device in db, or create a scan record
            device = db.query(Device).first()
            if not device:
                device = Device(
                    vendor_id="USB",
                    product_id="FLASH",
                    serial_number=f"STORAGE_{target_path.name or 'ROOT'}_{int(datetime.now().timestamp())}",
                    volume_label=target_path.name or "REMOVABLE_STORAGE",
                )
                db.add(device)
                db.commit()
                db.refresh(device)
        device_id = device.id

    try:
        summary = ForensicsService.analyze_and_ingest_drive(
            target_dir=target_path,
            device_id=device_id,
            db=db,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Drive inspection error: {str(e)}"
        )

    # Fetch stored artifacts for response
    persisted = (
        db.query(FileArtifact)
        .filter(FileArtifact.device_id == device_id)
        .all()
    )

    return ScanDriveResponse(
        device_id=summary["device_id"],
        device_serial=summary["device_serial"],
        target_dir=summary["target_dir"],
        total_files_scanned=summary["total_files_scanned"],
        records_persisted=summary["records_persisted"],
        suspicious_count=summary["suspicious_count"],
        clean_count=summary["clean_count"],
        artifacts=persisted,
    )


# -----------------------------------------------------------------------------
# 3. GET /api/devices
# -----------------------------------------------------------------------------
@app.get(
    "/api/devices",
    response_model=List[DeviceSummary],
    tags=["Devices"],
    summary="Retrieve all recorded USB devices and connection logs"
)
def get_devices(db: Session = Depends(get_db)):
    """Fetches all registered USB hardware devices along with artifact counts."""
    devices = db.query(Device).order_by(desc(Device.last_connected)).all()
    results = []
    for d in devices:
        total = db.query(FileArtifact).filter(FileArtifact.device_id == d.id).count()
        suspicious = (
            db.query(FileArtifact)
            .filter(FileArtifact.device_id == d.id, FileArtifact.flag_suspicious.is_(True))
            .count()
        )
        results.append(
            DeviceSummary(
                id=d.id,
                vendor_id=d.vendor_id,
                product_id=d.product_id,
                serial_number=d.serial_number,
                volume_label=d.volume_label,
                first_connected=d.first_connected,
                last_connected=d.last_connected,
                total_artifacts=total,
                suspicious_count=suspicious,
            )
        )
    return results


@app.post(
    "/api/devices",
    response_model=DeviceRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Devices"],
    summary="Register a new USB device record"
)
def create_device(payload: DeviceCreate, db: Session = Depends(get_db)):
    """Registers a new USB device record directly in the database."""
    existing = db.query(Device).filter(Device.serial_number == payload.serial_number).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device with this serial number already registered."
        )

    device = Device(**payload.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


# -----------------------------------------------------------------------------
# 4. GET /api/timeline
# -----------------------------------------------------------------------------
@app.get(
    "/api/timeline",
    response_model=List[TimelineEvent],
    tags=["Forensic Timeline"],
    summary="Chronological timeline of all USB hardware connection events"
)
def get_timeline(
    device_id: Optional[int] = Query(None, description="Filter timeline by device ID"),
    order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order: asc or desc"),
    db: Session = Depends(get_db)
):
    """Chronological timeline of verified USB connection events and inferred hardware observations."""
    return ForensicsService.get_timeline_events(db=db, device_id=device_id, order=order)



# -----------------------------------------------------------------------------
# 5. GET /api/files
# -----------------------------------------------------------------------------
@app.get(
    "/api/files",
    response_model=List[FileArtifactRead],
    tags=["File Artifacts"],
    summary="Retrieve file artifacts with optional filtering"
)
@app.get(
    "/api/artifacts",
    response_model=List[FileArtifactRead],
    tags=["File Artifacts"],
    include_in_schema=False
)
def get_files(
    device_id: Optional[int] = Query(None, description="Filter by device ID"),
    suspicious_only: bool = Query(False, description="Filter for suspicious files only"),
    search: Optional[str] = Query(None, description="Search by path or reason keyword"),
    db: Session = Depends(get_db)
):
    """Retrieves extracted file artifacts with optional filters for device, threat status, and keyword search."""
    query = db.query(FileArtifact)

    if device_id is not None:
        query = query.filter(FileArtifact.device_id == device_id)
    if suspicious_only:
        query = query.filter(FileArtifact.flag_suspicious.is_(True))
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (FileArtifact.file_path.ilike(search_pattern)) |
            (FileArtifact.flag_reason.ilike(search_pattern))
        )

    return query.all()


@app.post(
    "/api/artifacts",
    response_model=FileArtifactRead,
    status_code=status.HTTP_201_CREATED,
    tags=["File Artifacts"],
    summary="Insert an analyzed file artifact record"
)
def create_artifact(payload: FileArtifactCreate, db: Session = Depends(get_db)):
    """Inserts a single analyzed file artifact linked to a device."""
    device = db.query(Device).filter(Device.id == payload.device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Referenced device not found."
        )

    artifact = FileArtifact(**payload.model_dump())
    db.add(artifact)
    db.commit()
    db.refresh(artifact)
    return artifact


# -----------------------------------------------------------------------------
# 6. GET /api/stats
# -----------------------------------------------------------------------------
@app.get(
    "/api/stats",
    response_model=StatsMetrics,
    tags=["Forensic Stats"],
    summary="Forensic summary metrics and recent connections"
)
def get_stats(db: Session = Depends(get_db)):
    """Returns aggregated forensic metrics and latest connection history."""
    total_devices = db.query(Device).count()
    total_files = db.query(FileArtifact).count()
    suspicious_files = db.query(FileArtifact).filter(FileArtifact.flag_suspicious.is_(True)).count()
    clean_files = total_files - suspicious_files

    # Recent 5 device connections
    recent_devices = (
        db.query(Device)
        .order_by(desc(Device.last_connected))
        .limit(5)
        .all()
    )

    recent_summaries = []
    for d in recent_devices:
        total = db.query(FileArtifact).filter(FileArtifact.device_id == d.id).count()
        suspicious = (
            db.query(FileArtifact)
            .filter(FileArtifact.device_id == d.id, FileArtifact.flag_suspicious.is_(True))
            .count()
        )
        recent_summaries.append(
            DeviceSummary(
                id=d.id,
                vendor_id=d.vendor_id,
                product_id=d.product_id,
                serial_number=d.serial_number,
                volume_label=d.volume_label,
                first_connected=d.first_connected,
                last_connected=d.last_connected,
                total_artifacts=total,
                suspicious_count=suspicious,
            )
        )

    return StatsMetrics(
        total_devices=total_devices,
        total_files_scanned=total_files,
        total_artifacts=total_files,
        flagged_suspicious_files=suspicious_files,
        suspicious_artifacts=suspicious_files,
        clean_files=clean_files,
        recent_connections=recent_summaries,
    )


# -------------------------------------------------------------
# 7. GET /api/forensic-logs
# -------------------------------------------------------------
@app.get(
    "/api/forensic-logs",
    response_model=List[ForensicLogRead],
    tags=["Forensic Logs"],
    summary="Retrieve ingested forensic log files with raw evidence and parsed records"
)
def get_forensic_logs(
    log_type: Optional[str] = Query(None, description="Filter by log type (windows_setupapi or linux_syslog)"),
    db: Session = Depends(get_db)
):
    """Fetches ingested forensic logs with their original raw lines and parsed USB device records."""
    import json
    query = db.query(ForensicLog)
    if log_type:
        query = query.filter(ForensicLog.log_type == log_type)
    logs = query.order_by(desc(ForensicLog.ingested_at)).all()

    results: List[ForensicLogRead] = []
    for l in logs:
        parsed_items: List[ParsedLogRecord] = []
        if l.parsed_records:
            try:
                raw_list = json.loads(l.parsed_records)
                for item in raw_list:
                    fc = None
                    if item.get("first_connected"):
                        try:
                            fc = datetime.fromisoformat(item["first_connected"])
                        except Exception:
                            pass
                    lc = None
                    if item.get("last_connected"):
                        try:
                            lc = datetime.fromisoformat(item["last_connected"])
                        except Exception:
                            pass
                    parsed_items.append(
                        ParsedLogRecord(
                            vendor_id=item.get("vendor_id", "0000"),
                            product_id=item.get("product_id", "0000"),
                            serial_number=item.get("serial_number", ""),
                            volume_label=item.get("volume_label"),
                            first_connected=fc,
                            last_connected=lc,
                            raw_lines=item.get("raw_lines"),
                        )
                    )
            except Exception:
                pass

        results.append(
            ForensicLogRead(
                id=l.id,
                log_type=l.log_type,
                source_name=l.source_name,
                ingested_at=l.ingested_at,
                raw_content=l.raw_content,
                parsed_devices_count=l.parsed_devices_count,
                parsed_records=parsed_items,
            )
        )

    return results


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
