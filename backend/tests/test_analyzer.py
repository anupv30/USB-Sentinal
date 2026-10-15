"""Unit and Integration Tests for File Integrity Analyzer & Database Persistence."""

import hashlib
from pathlib import Path
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from analyzers.file_analyzer import (
    FileAnalyzer,
    AnalyzedFileArtifact,
    scan_usb_drive,
)
from services.forensics_service import ForensicsService
from app.models import Device, FileArtifact
from app.database import Base, get_db
from app.main import app

TESTS_DIR = Path(__file__).resolve().parent
MOCK_FILES_DIR = TESTS_DIR / "mock_files"


@pytest.fixture
def db_session():
    """Provides a fresh transactional in-memory SQLite database session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def test_device(db_session):
    """Seed test USB device record."""
    device = Device(
        vendor_id="0781",
        product_id="5581",
        serial_number="SCAN_TEST_USB_SERIAL_999",
        volume_label="TEST_USB_SANDISK",
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_hash_calculation():
    test_file = MOCK_FILES_DIR / "innocent_document.pdf"
    assert test_file.exists(), "innocent_document.pdf must exist in mock_files"

    md5_hash, sha256_hash = FileAnalyzer.calculate_hashes(test_file)

    # Verify length and hex formatting
    assert len(md5_hash) == 32
    assert len(sha256_hash) == 64

    # Verify against direct hashlib calculation
    raw_bytes = test_file.read_bytes()
    assert md5_hash == hashlib.md5(raw_bytes).hexdigest()
    assert sha256_hash == hashlib.sha256(raw_bytes).hexdigest()


def test_threat_detection_rules():
    # 1. Safe PDF
    safe_pdf = MOCK_FILES_DIR / "innocent_document.pdf"
    is_susp, reason = FileAnalyzer.inspect_threats(safe_pdf, safe_pdf.stat().st_size)
    assert is_susp is False
    assert reason is None

    # 2. Batch script (.bat)
    bat_file = MOCK_FILES_DIR / "cleanup_script.bat"
    is_susp, reason = FileAnalyzer.inspect_threats(bat_file, bat_file.stat().st_size)
    assert is_susp is True
    assert "High-risk executable/script extension (.bat)" in (reason or "")

    # 3. VBScript (.vbs)
    vbs_file = MOCK_FILES_DIR / "update_tool.vbs"
    is_susp, reason = FileAnalyzer.inspect_threats(vbs_file, vbs_file.stat().st_size)
    assert is_susp is True
    assert "(.vbs)" in (reason or "")

    # 4. Executable (.exe)
    exe_file = MOCK_FILES_DIR / "sample_payload.exe"
    is_susp, reason = FileAnalyzer.inspect_threats(exe_file, exe_file.stat().st_size)
    assert is_susp is True
    assert "(.exe)" in (reason or "")

    # 5. Autorun file (autorun.inf)
    autorun_file = MOCK_FILES_DIR / "autorun.inf"
    is_susp, reason = FileAnalyzer.inspect_threats(autorun_file, autorun_file.stat().st_size)
    assert is_susp is True
    assert "autorun.inf" in (reason or "")

    # 6. Double extension (.pdf.exe)
    decoy_file = MOCK_FILES_DIR / "confidential_report.pdf.exe"
    is_susp, reason = FileAnalyzer.inspect_threats(decoy_file, decoy_file.stat().st_size)
    assert is_susp is True
    assert "Deceptive double-extension detected" in (reason or "")


def test_directory_scan():
    artifacts = FileAnalyzer.scan_directory(MOCK_FILES_DIR)
    assert len(artifacts) == 6

    # Verify metadata fields populated
    names = {Path(a.file_path).name: a for a in artifacts}
    assert "innocent_document.pdf" in names
    assert "sample_payload.exe" in names

    pdf_art = names["innocent_document.pdf"]
    assert pdf_art.flag_suspicious is False
    assert pdf_art.file_size > 0
    assert pdf_art.md5_hash is not None
    assert pdf_art.sha256_hash is not None
    assert pdf_art.creation_time is not None
    assert pdf_art.modification_time is not None

    suspicious_count = sum(1 for a in artifacts if a.flag_suspicious)
    assert suspicious_count == 5


def test_database_persistence(db_session, test_device):
    artifacts = FileAnalyzer.scan_directory(MOCK_FILES_DIR)
    count = FileAnalyzer.persist_artifacts(artifacts, device_id=test_device.id, db=db_session)
    assert count == 6

    # Verify records written to SQLite
    stored = (
        db_session.query(FileArtifact)
        .filter(FileArtifact.device_id == test_device.id)
        .all()
    )
    assert len(stored) == 6

    # Re-running scan should update in-place without duplicating records
    rescan_count = FileAnalyzer.persist_artifacts(artifacts, device_id=test_device.id, db=db_session)
    assert rescan_count == 0  # 0 newly inserted, 6 updated

    total_after = (
        db_session.query(FileArtifact)
        .filter(FileArtifact.device_id == test_device.id)
        .count()
    )
    assert total_after == 6


def test_forensics_service_drive_ingestion(db_session, test_device):
    summary = ForensicsService.analyze_and_ingest_drive(
        target_dir=MOCK_FILES_DIR,
        device_id=test_device.id,
        db=db_session,
    )

    assert summary["device_id"] == test_device.id
    assert summary["total_files_scanned"] == 6
    assert summary["suspicious_count"] == 5
    assert summary["clean_count"] == 1
    assert len(summary["artifacts"]) == 6


def test_api_scan_drive_endpoint():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestingSession = sessionmaker(bind=test_engine)

    def override_get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        # 1. Create Device
        dev_res = client.post("/api/devices", json={
            "vendor_id": "0781",
            "product_id": "5581",
            "serial_number": "API_SCAN_DEVICE_123",
            "volume_label": "DRIVE_E",
        })
        assert dev_res.status_code == 201
        device_id = dev_res.json()["id"]

        # 2. Trigger Scan Drive API
        scan_res = client.post("/api/analyzers/scan-drive", json={
            "device_id": device_id,
            "target_path": str(MOCK_FILES_DIR),
        })
        assert scan_res.status_code == 200
        scan_data = scan_res.json()
        assert scan_data["total_files_scanned"] == 6
        assert scan_data["suspicious_count"] == 5

        # 3. Query Stats endpoint
        stats_res = client.get("/api/stats")
        assert stats_res.status_code == 200
        stats = stats_res.json()
        assert stats["total_devices"] == 1
        assert stats["total_artifacts"] == 6
        assert stats["suspicious_artifacts"] == 5

        # 4. Filter suspicious artifacts
        art_res = client.get(f"/api/artifacts?device_id={device_id}&suspicious_only=true")
        assert art_res.status_code == 200
        assert len(art_res.json()) == 5

    app.dependency_overrides.clear()
