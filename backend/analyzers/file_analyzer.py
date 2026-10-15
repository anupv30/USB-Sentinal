"""Mounted Drive Analysis & File Integrity Inspection Module.

Provides:
1. Recursive directory traversal of removable storage volumes or mounted USB drives.
2. Metadata extraction (relative path, file size, creation/modification timestamps).
3. Streaming cryptographic hash calculation (MD5 and SHA-256).
4. Heuristic and extension-based suspicious artifact detection.
5. SQLAlchemy database persistence for forensic file artifacts.
"""

import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session

# High-risk executable & script extensions commonly abused on removable media
HIGH_RISK_EXTENSIONS: Set[str] = {
    ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".ps1", ".scr",
    ".dll", ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl",
    ".msc", ".jar", ".reg", ".pif", ".com",
}

# Decoy document extensions checked for double-extension lures (e.g. report.pdf.exe)
DECOY_EXTENSIONS: Set[str] = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".txt", ".jpg", ".png", ".zip", ".rar",
}


class AnalyzedFileArtifact(BaseModel):
    """Normalized file artifact data model matching the database schema."""
    file_path: str = Field(..., description="File path (relative to mount root or absolute)")
    file_size: int = Field(0, description="Size in bytes")
    creation_time: Optional[datetime] = Field(None, description="UTC creation timestamp")
    modification_time: Optional[datetime] = Field(None, description="UTC modification timestamp")
    md5_hash: Optional[str] = Field(None, description="32-character hexadecimal MD5 checksum")
    sha256_hash: Optional[str] = Field(None, description="64-character hexadecimal SHA-256 checksum")
    flag_suspicious: bool = Field(False, description="Flag indicating suspicious nature")
    flag_reason: Optional[str] = Field(None, description="Detailed detection rationale")

    model_config = ConfigDict(from_attributes=True)

    def to_dict(self, device_id: Optional[int] = None) -> Dict[str, Any]:
        """Convert to dictionary matching SQLAlchemy FileArtifact model columns."""
        data = {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "creation_time": self.creation_time,
            "modification_time": self.modification_time,
            "md5_hash": self.md5_hash,
            "sha256_hash": self.sha256_hash,
            "flag_suspicious": self.flag_suspicious,
            "flag_reason": self.flag_reason,
        }
        if device_id is not None:
            data["device_id"] = device_id
        return data


class FileAnalyzer:
    """Performs deep file inspection, hash calculation, and threat detection on mounted drives."""

    CHUNK_SIZE = 65536  # 64 KB streaming buffer for memory-efficient hashing

    @classmethod
    def calculate_hashes(cls, file_path: Path) -> tuple[str, str]:
        """Calculates MD5 and SHA-256 hashes concurrently using buffered streaming."""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(cls.CHUNK_SIZE):
                md5.update(chunk)
                sha256.update(chunk)

        return md5.hexdigest(), sha256.hexdigest()

    @classmethod
    def inspect_threats(cls, file_path: Path, file_size: int) -> tuple[bool, Optional[str]]:
        """Inspects file for suspicious traits such as high-risk extensions, double-extensions, and autorun files."""
        name = file_path.name
        lower_name = name.lower()
        suffix = file_path.suffix.lower()

        reasons = []

        # 1. Autorun configuration file
        if lower_name == "autorun.inf":
            reasons.append("Removable drive autorun configuration directive (autorun.inf)")

        # 2. High-risk executable or script extension
        if suffix in HIGH_RISK_EXTENSIONS:
            reasons.append(f"High-risk executable/script extension ({suffix}) on removable storage")

        # 3. Double-extension lure detection (e.g. document.pdf.exe)
        parts = lower_name.split(".")
        if len(parts) >= 3:
            second_last_ext = f".{parts[-2]}"
            if second_last_ext in DECOY_EXTENSIONS and suffix in HIGH_RISK_EXTENSIONS:
                reasons.append(f"Deceptive double-extension detected ({second_last_ext}{suffix})")

        # 4. Header heuristic check for hidden PE executable (MZ header)
        if file_size >= 2 and suffix not in HIGH_RISK_EXTENSIONS:
            try:
                with open(file_path, "rb") as f:
                    header = f.read(2)
                    if header == b"MZ":
                        reasons.append("File exhibits Portable Executable (MZ) header but uses non-executable extension")
            except (PermissionError, OSError):
                pass

        if reasons:
            return True, " | ".join(reasons)

        return False, None

    @classmethod
    def analyze_file(cls, full_path: Path, relative_to: Optional[Path] = None) -> AnalyzedFileArtifact:
        """Analyzes a single file and extracts complete forensic metadata and hashes."""
        try:
            stat = full_path.stat()
            file_size = stat.st_size
            mod_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            # On Windows, st_ctime is file creation time; on Unix it is inode change time
            ctime_attr = getattr(stat, "st_birthtime", stat.st_ctime)
            create_time = datetime.fromtimestamp(ctime_attr, tz=timezone.utc)
        except (PermissionError, OSError):
            file_size = 0
            mod_time = None
            create_time = None

        # Calculate cryptographic hashes
        try:
            md5_hash, sha256_hash = cls.calculate_hashes(full_path)
        except (PermissionError, OSError):
            md5_hash, sha256_hash = None, None

        # Inspect threat flags
        is_suspicious, flag_reason = cls.inspect_threats(full_path, file_size)

        # Compute display path
        display_path = str(full_path.relative_to(relative_to)) if relative_to else str(full_path)

        return AnalyzedFileArtifact(
            file_path=display_path,
            file_size=file_size,
            creation_time=create_time,
            modification_time=mod_time,
            md5_hash=md5_hash,
            sha256_hash=sha256_hash,
            flag_suspicious=is_suspicious,
            flag_reason=flag_reason,
        )

    CHUNK_SIZE = 1024 * 1024  # 1MB buffer for fast USB streaming

    @classmethod
    def scan_directory(
        cls,
        target_dir: Union[str, Path],
        max_files: int = 5000
    ) -> List[AnalyzedFileArtifact]:
        """Recursively scans a target directory path (e.g. mounted USB path) and returns analyzed artifacts."""
        root = Path(target_dir).resolve()
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(f"Target directory not found or not accessible: {target_dir}")

        artifacts: List[AnalyzedFileArtifact] = []

        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            # Prune Windows/macOS hidden system metadata folders
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in ("system volume information", "$recycle.bin", ".trashes", ".fseventsd", ".spotlight-v100")
            ]

            for filename in filenames:
                if len(artifacts) >= max_files:
                    break
                full_path = Path(dirpath) / filename
                try:
                    if full_path.is_file():
                        artifact = cls.analyze_file(full_path, relative_to=root)
                        artifacts.append(artifact)
                except (PermissionError, OSError):
                    continue

            if len(artifacts) >= max_files:
                break

        return artifacts

    @classmethod
    def persist_artifacts(
        cls,
        artifacts: List[AnalyzedFileArtifact],
        device_id: int,
        db: Session
    ) -> int:
        """Persists analyzed file artifacts into SQLite database linked to device_id."""
        from app.models import FileArtifact, Device

        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise ValueError(f"Cannot link artifacts: Device with ID {device_id} not found in database.")

        inserted_count = 0
        for art in artifacts:
            # Check if artifact already exists for this device and path
            existing = (
                db.query(FileArtifact)
                .filter(FileArtifact.device_id == device_id, FileArtifact.file_path == art.file_path)
                .first()
            )

            if existing:
                existing.file_size = art.file_size
                existing.creation_time = art.creation_time
                existing.modification_time = art.modification_time
                existing.md5_hash = art.md5_hash
                existing.sha256_hash = art.sha256_hash
                existing.flag_suspicious = art.flag_suspicious
                existing.flag_reason = art.flag_reason
            else:
                record = FileArtifact(**art.to_dict(device_id=device_id))
                db.add(record)
                inserted_count += 1

        db.commit()
        return inserted_count


def scan_usb_drive(
    target_dir: Union[str, Path],
    device_id: Optional[int] = None,
    db: Optional[Session] = None
) -> List[AnalyzedFileArtifact]:
    """Convenience helper to scan a drive and optionally persist directly to database."""
    artifacts = FileAnalyzer.scan_directory(target_dir)
    if device_id is not None and db is not None:
        FileAnalyzer.persist_artifacts(artifacts, device_id=device_id, db=db)
    return artifacts
