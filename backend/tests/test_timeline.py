"""Tests for Forensic Timeline Event Classification and Deduplication."""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.database import Base, get_db
from app.models import Device, ForensicLog
from app import app
from services.forensics_service import ForensicsService
from parsers.usb_parser import USBLogParser

TESTS_DIR = Path(__file__).resolve().parent
SAMPLE_LOG = TESTS_DIR / "sample_data" / "setupapi.dev.log"
SYSLOG_SAMPLE = TESTS_DIR / "sample_data" / "syslog_usb.log"


@pytest.fixture
def client_and_session():
    """Provides isolated in-memory SQLite database and test client."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client, TestingSession

    app.dependency_overrides.clear()


def test_confirmed_insertion_setupapi(client_and_session):
    """Test that Windows SetupAPI hardware-initiated sections generate USB INSERTED and LAST OBSERVED."""
    client, _ = client_and_session

    with open(SAMPLE_LOG, "rb") as f:
        client.post("/api/upload-log", files={"file": ("setupapi.dev.log", f, "text/plain")})

    res = client.get("/api/timeline")
    assert res.status_code == 200
    events = res.json()

    # Confirmed insertion events must be present
    inserts = [e for e in events if e["event_type"] == "USB INSERTED"]
    assert len(inserts) == 3
    assert all("hardware connection confirmed" in e["description"].lower() for e in inserts)

    # Section ends must be classified as LAST OBSERVED, never USB DISCONNECTED
    disconnects = [e for e in events if e["event_type"] == "USB DISCONNECTED"]
    assert len(disconnects) == 0, "Windows SetupAPI must never generate fake USB DISCONNECTED events"

    last_observed = [e for e in events if e["event_type"] == "LAST OBSERVED"]
    assert len(last_observed) == 3


def test_confirmed_disconnection_linux(client_and_session):
    """Test that Linux logs with disconnect lines create USB DISCONNECTED, and without disconnect lines do not."""
    client, _ = client_and_session

    linux_log_with_disconnect = """
Oct 10 12:00:00 station kernel: [ 100.0 ] usb 1-1: new high-speed USB device number 2 using xhci_hcd
Oct 10 12:00:00 station kernel: [ 100.1 ] usb 1-1: New USB device found, idVendor=1234, idProduct=5678
Oct 10 12:00:00 station kernel: [ 100.2 ] usb 1-1: SerialNumber: TEST_DISC_SERIAL_01
Oct 10 12:00:00 station kernel: [ 100.3 ] usb 1-1: Manufacturer: TestVendor
Oct 10 12:00:00 station kernel: [ 100.4 ] usb 1-1: Product: TestFlash
Oct 10 12:05:00 station kernel: [ 400.0 ] usb 1-1: USB disconnect, device number 2
"""
    client.post(
        "/api/upload-log",
        files={"file": ("syslog", linux_log_with_disconnect.encode("utf-8"), "text/plain")}
    )

    res = client.get("/api/timeline")
    assert res.status_code == 200
    events = res.json()

    test_events = [e for e in events if e["serial_number"] == "TEST_DISC_SERIAL_01"]
    assert len(test_events) == 2

    event_types = {e["event_type"] for e in test_events}
    assert "USB INSERTED" in event_types
    assert "USB DISCONNECTED" in event_types

    insert_ev = next(e for e in test_events if e["event_type"] == "USB INSERTED")
    disc_ev = next(e for e in test_events if e["event_type"] == "USB DISCONNECTED")
    assert "12:00:00" in insert_ev["timestamp"]
    assert "12:05:00" in disc_ev["timestamp"]


def test_inferred_observations_for_unconfirmed_device(client_and_session):
    """Test that devices without confirmed connection/disconnection logs use FIRST OBSERVED and LAST OBSERVED."""
    client, Session = client_and_session

    db = Session()
    try:
        # Create a device directly (simulating registry or live mount discovery)
        dev = Device(
            vendor_id="046D",
            product_id="C52B",
            serial_number="REGISTRY_INFERRED_SERIAL_99",
            volume_label="Inferred Logitech Receiver",
            first_connected=datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc),
            last_connected=datetime(2026, 8, 2, 15, 30, 0, tzinfo=timezone.utc),
        )
        db.add(dev)
        db.commit()
    finally:
        db.close()

    res = client.get("/api/timeline")
    assert res.status_code == 200
    events = res.json()

    dev_events = [e for e in events if e["serial_number"] == "REGISTRY_INFERRED_SERIAL_99"]
    assert len(dev_events) == 2

    assert dev_events[0]["event_type"] == "LAST OBSERVED"  # default sort is desc
    assert dev_events[1]["event_type"] == "FIRST OBSERVED"
    assert "inferred" in dev_events[0]["description"].lower()
    assert "inferred" in dev_events[1]["description"].lower()


def test_identical_first_and_last_connected_timestamps(client_and_session):
    """Test that identical first_connected and last_connected timestamps emit only a single event."""
    client, Session = client_and_session

    db = Session()
    try:
        single_time = datetime(2026, 9, 15, 8, 30, 0, tzinfo=timezone.utc)
        dev = Device(
            vendor_id="AAAA",
            product_id="BBBB",
            serial_number="IDENTICAL_TIMESTAMPS_SN_123",
            volume_label="Single Instant Drive",
            first_connected=single_time,
            last_connected=single_time,
        )
        db.add(dev)
        db.commit()
    finally:
        db.close()

    res = client.get("/api/timeline")
    assert res.status_code == 200
    events = res.json()

    dev_events = [e for e in events if e["serial_number"] == "IDENTICAL_TIMESTAMPS_SN_123"]
    # Must only emit ONE event, not two duplicate events or fake disconnect
    assert len(dev_events) == 1
    assert dev_events[0]["event_type"] == "FIRST OBSERVED"


def test_repeated_log_ingestion_prevents_duplicate_timeline_events(client_and_session):
    """Test that uploading the same Windows or Linux log multiple times does not produce duplicate events."""
    client, _ = client_and_session

    # Upload Windows log once
    with open(SAMPLE_LOG, "rb") as f:
        res1 = client.post("/api/upload-log", files={"file": ("setupapi.dev.log", f, "text/plain")})
    assert res1.status_code == 200

    timeline1 = client.get("/api/timeline").json()
    count_after_first_upload = len(timeline1)
    assert count_after_first_upload > 0

    # Upload the exact same Windows log a 2nd and 3rd time
    for _ in range(2):
        with open(SAMPLE_LOG, "rb") as f:
            res_rep = client.post("/api/upload-log", files={"file": ("setupapi.dev.log", f, "text/plain")})
            assert res_rep.status_code == 200

    timeline_after_repeated = client.get("/api/timeline").json()
    assert len(timeline_after_repeated) == count_after_first_upload, "Repeated uploads must not create duplicate events"

    # Now upload Linux log twice
    with open(SYSLOG_SAMPLE, "rb") as f:
        client.post("/api/upload-log", files={"file": ("syslog_usb.log", f, "text/plain")})
    count_after_linux1 = len(client.get("/api/timeline").json())

    with open(SYSLOG_SAMPLE, "rb") as f:
        client.post("/api/upload-log", files={"file": ("syslog_usb.log", f, "text/plain")})
    count_after_linux2 = len(client.get("/api/timeline").json())

    assert count_after_linux2 == count_after_linux1, "Repeated Linux log upload must not duplicate events"


def test_non_hardware_initiated_setupapi_is_inferred(client_and_session):
    """Test that non-hardware initiated SetupAPI sections are classified as FIRST OBSERVED, not USB INSERTED."""
    client, _ = client_and_session

    non_hw_log = """[Device Install Log]
>>>  [Device Install - USB\\VID_8888&PID_9999\\SOFTWARE_INSTALL_SN_42]
>>>  Section start 2026/05/01 10:00:00.000
     dvi: Selected driver: test.inf
<<<  Section end 2026/05/01 10:00:02.000
<<<  [Exit status: SUCCESS]
"""
    client.post(
        "/api/upload-log",
        files={"file": ("setupapi.dev.log", non_hw_log.encode("utf-8"), "text/plain")}
    )

    events = client.get("/api/timeline").json()
    target_events = [e for e in events if e["serial_number"] == "SOFTWARE_INSTALL_SN_42"]
    assert len(target_events) == 2

    types = {e["event_type"] for e in target_events}
    assert "FIRST OBSERVED" in types
    assert "LAST OBSERVED" in types
    assert "USB INSERTED" not in types
