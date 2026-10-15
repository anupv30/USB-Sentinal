from datetime import datetime
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from sqlalchemy.pool import StaticPool
from app.database import Base, get_db
from app.models import Device, FileArtifact
from app.main import app

# In-memory SQLite engine for unit tests (StaticPool ensures same memory db across connections)
TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session():
    """Provides a fresh database schema and session per test."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    """Provides FastAPI test client overriding database dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_device_and_artifact_model_crud(db_session):
    # Insert Device
    device = Device(
        vendor_id="0781",
        product_id="5581",
        serial_number="4C530001250912117462",
        volume_label="SANDISK_SECURE",
        first_connected=datetime(2026, 9, 20, 14, 22, 10),
        last_connected=datetime(2026, 9, 20, 14, 22, 12),
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)

    assert device.id is not None
    assert device.vendor_id == "0781"

    # Insert File Artifact linked to Device
    artifact = FileArtifact(
        device_id=device.id,
        file_path="E:\\autorun.inf",
        file_size=128,
        creation_time=datetime(2026, 9, 20, 14, 20, 0),
        modification_time=datetime(2026, 9, 20, 14, 20, 0),
        md5_hash="d41d8cd98f00b204e9800998ecf8427e",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        flag_suspicious=True,
        flag_reason="High risk autorun configuration file detected on removable storage root.",
    )
    db_session.add(artifact)
    db_session.commit()
    db_session.refresh(artifact)

    assert artifact.id is not None
    assert artifact.device_id == device.id
    assert artifact.flag_suspicious is True
    assert len(device.file_artifacts) == 1
    assert device.file_artifacts[0].file_path == "E:\\autorun.inf"


def test_api_endpoints(client):
    # Test Health Check
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "online"

    # Test Device Creation via API
    dev_data = {
        "vendor_id": "0951",
        "product_id": "1666",
        "serial_number": "0018F12B4F83EC21191E002B",
        "volume_label": "KINGSTON_64",
    }
    res = client.post("/api/devices", json=dev_data)
    assert res.status_code == 201
    dev_id = res.json()["id"]

    # Test Artifact Creation via API
    art_data = {
        "device_id": dev_id,
        "file_path": "F:\\sample_payload.exe",
        "file_size": 256,
        "flag_suspicious": True,
        "flag_reason": "Executable on removable storage with MZ signature",
    }
    res = client.post("/api/artifacts", json=art_data)
    assert res.status_code == 201

    # Test Stats endpoint
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_devices"] == 1
    assert stats["total_artifacts"] == 1
    assert stats["suspicious_artifacts"] == 1
