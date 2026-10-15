from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


# -------------------------------------------------------------
# File Artifact Schemas
# -------------------------------------------------------------
class FileArtifactBase(BaseModel):
    file_path: str = Field(..., description="Path of the file relative or absolute on storage")
    file_size: int = Field(0, description="Size of file in bytes")
    creation_time: Optional[datetime] = None
    modification_time: Optional[datetime] = None
    md5_hash: Optional[str] = Field(None, max_length=32)
    sha256_hash: Optional[str] = Field(None, max_length=64)
    flag_suspicious: bool = Field(False, description="Flag indicating if file is suspicious")
    flag_reason: Optional[str] = Field(None, description="Detailed reason for suspicious flag")


class FileArtifactCreate(FileArtifactBase):
    device_id: int


class FileArtifactRead(FileArtifactBase):
    id: int
    device_id: int

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------
# Device Schemas
# -------------------------------------------------------------
class DeviceBase(BaseModel):
    vendor_id: str = Field(..., max_length=32, description="USB Vendor ID (VID)")
    product_id: str = Field(..., max_length=32, description="USB Product ID (PID)")
    serial_number: str = Field(..., max_length=128, description="Device unique serial number")
    volume_label: Optional[str] = Field(None, max_length=128, description="Volume label")
    first_connected: Optional[datetime] = None
    last_connected: Optional[datetime] = None


class DeviceCreate(DeviceBase):
    pass


class DeviceRead(DeviceBase):
    id: int
    file_artifacts: List[FileArtifactRead] = []

    model_config = ConfigDict(from_attributes=True)


class DeviceSummary(DeviceBase):
    id: int
    total_artifacts: int = 0
    suspicious_count: int = 0

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------
# Timeline Schemas
# -------------------------------------------------------------
class TimelineEvent(BaseModel):
    event_id: str
    timestamp: Optional[datetime] = None
    event_type: str = Field(..., description="Type of event: FIRST_CONNECTED, LAST_SEEN, DISCONNECTED")
    device_id: int
    vendor_id: str
    product_id: str
    serial_number: str
    volume_label: Optional[str] = None
    description: str

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------
# Scan Drive Schemas
# -------------------------------------------------------------
class ScanDriveRequest(BaseModel):
    target_path: str = Field(..., description="Mounted folder or USB path to inspect")
    device_id: Optional[int] = Field(None, description="Device ID to link artifacts to")


class ScanDriveResponse(BaseModel):
    device_id: int
    device_serial: str
    target_dir: str
    total_files_scanned: int
    records_persisted: int
    suspicious_count: int
    clean_count: int
    artifacts: List[FileArtifactRead] = []


# -------------------------------------------------------------
# Summary Statistics Schemas
# -------------------------------------------------------------
class StatsMetrics(BaseModel):
    total_devices: int
    total_files_scanned: int
    total_artifacts: int = 0
    flagged_suspicious_files: int
    suspicious_artifacts: int = 0
    clean_files: int
    recent_connections: List[DeviceSummary] = []


# -------------------------------------------------------------
# Live USB Drive Detection Schemas
# -------------------------------------------------------------
class DetectedDrive(BaseModel):
    mount_point: str = Field(..., description="Drive letter or mount path (e.g., E:\\, /media/usb)")
    device_path: Optional[str] = Field(None, description="System device path")
    volume_label: str = Field("Removable Drive", description="Drive volume label")
    file_system: Optional[str] = Field(None, description="Filesystem type (e.g., FAT32, exFAT, NTFS)")
    total_bytes: int = Field(0, description="Total storage capacity in bytes")
    used_bytes: int = Field(0, description="Used storage capacity in bytes")
    free_bytes: int = Field(0, description="Available free storage in bytes")
    percent_used: float = Field(0.0, description="Percentage of space used")
    is_removable: bool = Field(True, description="Whether device is a removable media unit")
    vendor_id: Optional[str] = Field(None, description="Matched USB Vendor ID if resolved")
    product_id: Optional[str] = Field(None, description="Matched USB Product ID if resolved")
    serial_number: Optional[str] = Field(None, description="Matched USB serial number if resolved")


# -------------------------------------------------------------
# Forensic Log Schemas
# -------------------------------------------------------------
class ParsedLogRecord(BaseModel):
    vendor_id: str
    product_id: str
    serial_number: str
    volume_label: Optional[str] = None
    first_connected: Optional[datetime] = None
    last_connected: Optional[datetime] = None
    raw_lines: Optional[str] = None


class ForensicLogRead(BaseModel):
    id: int
    log_type: str  # "windows_setupapi" | "linux_syslog"
    source_name: str
    ingested_at: datetime
    raw_content: str
    parsed_devices_count: int
    parsed_records: List[ParsedLogRecord] = []

    model_config = ConfigDict(from_attributes=True)
