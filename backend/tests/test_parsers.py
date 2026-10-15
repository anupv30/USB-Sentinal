"""Unit and Integration Tests for USB Log Parsers."""

import pytest
from pathlib import Path
from datetime import datetime, timezone

from parsers.usb_parser import (
    ParsedUSBDevice,
    USBLogParser,
    WindowsSetupApiParser,
    LinuxUsbLogParser,
)
from app.models import Device
from app.database import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

TESTS_DIR = Path(__file__).resolve().parent
SAMPLE_DATA_DIR = TESTS_DIR / "sample_data"


def test_windows_setupapi_parser_with_sample_log():
    log_path = SAMPLE_DATA_DIR / "setupapi.dev.log"
    assert log_path.exists(), "Sample setupapi.dev.log must exist"

    devices = USBLogParser.parse_setupapi(log_path)
    assert len(devices) == 3

    # Map by serial for individual validation
    dev_map = {d.serial_number: d for d in devices}

    # 1. SanDisk Ultra USB Device
    sandisk = dev_map.get("4C530001250912117462")
    assert sandisk is not None
    assert sandisk.vendor_id == "0781"
    assert sandisk.product_id == "5581"
    assert "SanDisk" in (sandisk.volume_label or "")
    assert "(E:)" in (sandisk.volume_label or "")
    assert sandisk.first_connected == datetime(2026, 9, 20, 14, 22, 10, 125000, tzinfo=timezone.utc)
    assert sandisk.last_connected == datetime(2026, 9, 20, 14, 22, 12, 890000, tzinfo=timezone.utc)
    assert sandisk.raw_lines is not None
    assert "USB\\VID_0781&PID_5581" in sandisk.raw_lines

    # 2. Kingston DataTraveler 3.0
    kingston = dev_map.get("0018F12B4F83EC21191E002B")
    assert kingston is not None
    assert kingston.vendor_id == "0951"
    assert kingston.product_id == "1666"
    assert "Kingston" in (kingston.volume_label or "")
    assert "(F:)" in (kingston.volume_label or "")
    assert kingston.raw_lines is not None

    # 3. Rubber Ducky keystroke injector
    ducky = dev_map.get("DUCKY_KBD_PAYLOAD_99")
    assert ducky is not None
    assert ducky.vendor_id == "1FC9"
    assert ducky.product_id == "0004"
    assert "Keystroke Injector" in (ducky.volume_label or "")
    assert ducky.raw_lines is not None


def test_linux_syslog_parser_with_sample_log():
    log_path = SAMPLE_DATA_DIR / "syslog_usb.log"
    assert log_path.exists(), "Sample syslog_usb.log must exist"

    devices = USBLogParser.parse_linux_log(log_path, default_year=2026)
    assert len(devices) == 2

    dev_map = {d.serial_number: d for d in devices}

    # 1. SanDisk
    sandisk = dev_map.get("4C530001250912117462")
    assert sandisk is not None
    assert sandisk.raw_lines is not None
    assert "idVendor=0781" in sandisk.raw_lines
    assert sandisk.vendor_id == "0781"
    assert sandisk.product_id == "5581"
    assert "SANDISK_32G" in (sandisk.volume_label or "")
    assert sandisk.first_connected == datetime(2026, 10, 5, 10, 14, 22, tzinfo=timezone.utc)

    # 2. Kingston
    kingston = dev_map.get("0018F12B4F83EC21191E002B")
    assert kingston is not None
    assert kingston.vendor_id == "0951"
    assert kingston.product_id == "1666"
    assert "KINGSTON_64" in (kingston.volume_label or "")
    assert kingston.first_connected == datetime(2026, 10, 6, 18, 30, 11, tzinfo=timezone.utc)


def test_linux_dmesg_parser_with_sample_log():
    log_path = SAMPLE_DATA_DIR / "dmesg_usb.log"
    assert log_path.exists(), "Sample dmesg_usb.log must exist"

    devices = USBLogParser.parse_linux_log(log_path)
    assert len(devices) == 2

    dev_map = {d.serial_number: d for d in devices}
    assert "4C530001250912117462" in dev_map
    assert "0018F12B4F83EC21191E002B" in dev_map


def test_unified_router_auto_detect():
    setupapi_path = SAMPLE_DATA_DIR / "setupapi.dev.log"
    syslog_path = SAMPLE_DATA_DIR / "syslog_usb.log"

    win_devs = USBLogParser.parse_file(setupapi_path)
    linux_devs = USBLogParser.parse_file(syslog_path)

    assert len(win_devs) == 3
    assert len(linux_devs) == 2


def test_windows_edge_cases():
    # 1. Completely malformed log content
    malformed = """
    Random error: failed to initialize PCI device
    Some garbage line without section markers
    <<< End of something else
    """
    assert WindowsSetupApiParser.parse(malformed) == []

    # 2. Missing timestamps
    missing_ts = """
    >>>  [Device Install (Hardware initiated) - USB\\VID_1234&PID_ABCD\\SN_NO_TIME_01]
         dvi: Selected driver: usbstor.inf
         dvi: Disk Name: Generic Flash Disk
    <<<  [Exit status: SUCCESS]
    """
    devs = WindowsSetupApiParser.parse(missing_ts)
    assert len(devs) == 1
    assert devs[0].vendor_id == "1234"
    assert devs[0].product_id == "ABCD"
    assert devs[0].serial_number == "SN_NO_TIME_01"
    assert devs[0].first_connected is None
    assert devs[0].last_connected is None
    assert devs[0].volume_label == "Generic Flash Disk"

    # 3. Non-USB device install (PCI) should be ignored
    pci_device = """
    >>>  [Device Install (Hardware initiated) - PCI\\VEN_8086&DEV_15D8&SUBSYS_00000000\\3&11583659&0&D0]
    >>>  Section start 2026/09/20 10:00:00.000
    <<<  Section end 2026/09/20 10:00:01.000
    """
    assert WindowsSetupApiParser.parse(pci_device) == []

    # 4. Repeated insertion of same device updating timestamps
    repeated = """
    >>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5581\\MULTI_INSERT_SN]
    >>>  Section start 2026/01/10 08:00:00.000
    <<<  Section end 2026/01/10 08:00:05.000

    >>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5581\\MULTI_INSERT_SN]
    >>>  Section start 2026/05/20 12:00:00.000
    <<<  Section end 2026/05/20 12:00:02.000
    """
    devs = WindowsSetupApiParser.parse(repeated)
    assert len(devs) == 1
    assert devs[0].first_connected == datetime(2026, 1, 10, 8, 0, 0, tzinfo=timezone.utc)
    assert devs[0].last_connected == datetime(2026, 5, 20, 12, 0, 2, tzinfo=timezone.utc)


def test_linux_edge_cases():
    # 1. Disconnect event updating last_connected timestamp
    disconnect_log = """
    Oct 08 09:00:00 station kernel: usb 1-1: New USB device found, idVendor=1005, idProduct=b113
    Oct 08 09:00:00 station kernel: usb 1-1: SerialNumber: TEST_DISC_SN
    Oct 08 09:45:00 station kernel: usb 1-1: USB disconnect, device number 2
    """
    devs = LinuxUsbLogParser.parse(disconnect_log, default_year=2026)
    assert len(devs) == 1
    assert devs[0].vendor_id == "1005"
    assert devs[0].product_id == "B113"
    assert devs[0].first_connected == datetime(2026, 10, 8, 9, 0, 0, tzinfo=timezone.utc)
    assert devs[0].last_connected == datetime(2026, 10, 8, 9, 45, 0, tzinfo=timezone.utc)

    # 2. Missing explicit SerialNumber creates fallback port serial
    no_serial_log = """
    usb 3-1: New USB device found, idVendor=058f, idProduct=6387
    usb 3-1: Product: Mass Storage
    """
    devs = LinuxUsbLogParser.parse(no_serial_log)
    assert len(devs) == 1
    assert devs[0].vendor_id == "058F"
    assert devs[0].product_id == "6387"
    assert "LINUX_USB_058F_6387_3-1" in devs[0].serial_number

    # 3. Malformed lines ignored safely
    malformed = """
    systemd[1]: Started User Manager for UID 1000.
    CRON[19283]: (root) CMD (/usr/local/bin/backup.sh)
    """
    assert LinuxUsbLogParser.parse(malformed) == []


def test_normalized_output_matches_database_model():
    """Verify to_dict output can directly instantiate SQLAlchemy Device and persist to SQLite."""
    parsed = ParsedUSBDevice(
        vendor_id="0781",
        product_id="5581",
        serial_number="TEST_NORMALIZE_SN_123",
        volume_label="TEST_SECURE_VOL",
        first_connected=datetime(2026, 10, 8, 9, 0, 0, tzinfo=timezone.utc),
        last_connected=datetime(2026, 10, 8, 9, 30, 0, tzinfo=timezone.utc),
    )

    data = parsed.to_dict()
    assert set(data.keys()) == {
        "vendor_id",
        "product_id",
        "serial_number",
        "volume_label",
        "first_connected",
        "last_connected",
    }

    # Test database persistence with SQLAlchemy
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    Session = sessionmaker(bind=test_engine)
    session = Session()

    device_row = Device(**data)
    session.add(device_row)
    session.commit()
    session.refresh(device_row)

    assert device_row.id is not None
    assert device_row.vendor_id == "0781"
    assert device_row.product_id == "5581"
    assert device_row.serial_number == "TEST_NORMALIZE_SN_123"
    assert device_row.volume_label == "TEST_SECURE_VOL"
    session.close()


def test_api_log_upload_endpoint():
    """Verify log file upload and automatic database ingestion via FastAPI endpoint."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.database import get_db

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
        log_path = SAMPLE_DATA_DIR / "setupapi.dev.log"
        with open(log_path, "rb") as f:
            res = client.post(
                "/api/parsers/upload-log?save_to_db=true",
                files={"file": ("setupapi.dev.log", f, "text/plain")}
            )

        assert res.status_code == 200
        data = res.json()
        assert len(data) == 3
        vids = {d["vendor_id"] for d in data}
        assert "0781" in vids
        assert "0951" in vids

    app.dependency_overrides.clear()
