"""Core USB Log Parser Module.

Parses forensic logs across operating systems:
1. Windows: setupapi.dev.log (extracting VID, PID, Serial, Volume/Disk names, timestamps).
2. Linux: dmesg and syslog (extracting bus events, idVendor, idProduct, SerialNumber, mounts, disconnects).

Normalizes extracted records into a unified structure matching the database schema.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from pydantic import BaseModel, Field, ConfigDict


class ParsedUSBDevice(BaseModel):
    """Normalized USB device metadata model matching the database schema."""
    vendor_id: str = Field(..., description="4-digit USB Vendor ID (hex)")
    product_id: str = Field(..., description="4-digit USB Product ID (hex)")
    serial_number: str = Field(..., description="Unique device serial number")
    volume_label: Optional[str] = Field(None, description="Extracted volume label or disk description")
    first_connected: Optional[datetime] = Field(None, description="Earliest recorded connection timestamp")
    last_connected: Optional[datetime] = Field(None, description="Latest recorded connection timestamp")
    raw_lines: Optional[str] = Field(None, description="Original forensic log lines preserving raw evidence")

    model_config = ConfigDict(from_attributes=True)

    def to_dict(self) -> Dict[str, Union[str, Optional[str], Optional[datetime]]]:
        """Returns dictionary mapping directly to SQLAlchemy Device columns."""
        return {
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": self.serial_number,
            "volume_label": self.volume_label,
            "first_connected": self.first_connected,
            "last_connected": self.last_connected,
        }


class ParsedTimelineEvent(BaseModel):
    """Normalized forensic timeline event model representing confirmed or inferred events."""
    timestamp: datetime
    event_type: str = Field(..., description="'USB INSERTED' | 'USB DISCONNECTED' | 'FIRST OBSERVED' | 'LAST OBSERVED'")
    vendor_id: str
    product_id: str
    serial_number: str
    volume_label: Optional[str] = None
    description: str
    evidence_snippet: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class WindowsSetupApiParser:
    """Parser for Windows setupapi.dev.log device installation records."""

    SECTION_START_PATTERN = re.compile(
        r"^\s*>>>\s+\[Device Install(?:\s+\([^)]+\))?\s+-\s+USB\\VID_([0-9a-fA-F]{4})&PID_([0-9a-fA-F]{4})\\([^\]\r\n]+)\]",
        re.MULTILINE | re.IGNORECASE,
    )
    SECTION_USBSTOR_PATTERN = re.compile(
        r"USBSTOR#(?:Disk&)?Ven_([^&#]+)&Prod_([^&#]+)(?:&Rev_[^#]+)?#([^#&\]\r\n]+)",
        re.IGNORECASE,
    )
    INLINE_VID_PID_PATTERN = re.compile(
        r"VID_([0-9a-fA-F]{4})&PID_([0-9a-fA-F]{4})",
        re.IGNORECASE,
    )
    TIMESTAMP_START_PATTERN = re.compile(
        r"Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
        re.IGNORECASE,
    )
    TIMESTAMP_END_PATTERN = re.compile(
        r"Section end\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
        re.IGNORECASE,
    )
    DISK_NAME_PATTERN = re.compile(
        r"dvi:\s+(?:Disk Name|Device Description):\s*([^\r\n]+)",
        re.IGNORECASE,
    )
    DRIVE_LETTER_PATTERN = re.compile(
        r"dvi:\s+Assigned Drive Letter:\s*([A-Za-z]:)",
        re.IGNORECASE,
    )
    USBSTOR_DISK_PATTERN = re.compile(
        r"dvi:\s+Install Device:\s*USBSTOR\\Disk([^\\]+)\\",
        re.IGNORECASE,
    )

    @classmethod
    def parse_timestamp(cls, ts_str: str) -> Optional[datetime]:
        """Parses timestamp string from setupapi log into UTC datetime."""
        ts_str = ts_str.strip()
        for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
            try:
                dt = datetime.strptime(ts_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    @classmethod
    def parse(cls, content: str) -> List[ParsedUSBDevice]:
        """Parses raw setupapi.dev.log content into a list of normalized ParsedUSBDevice objects."""
        devices_by_serial: Dict[str, ParsedUSBDevice] = {}

        # Split content into sections starting with >>> (allowing optional leading indentation)
        sections = re.split(r"(?=^\s*>>>\s+\[)", content, flags=re.MULTILINE)

        for sec in sections:
            sec = sec.strip()
            if not sec:
                continue

            vid: Optional[str] = None
            pid: Optional[str] = None
            raw_serial: Optional[str] = None
            volume_label: Optional[str] = None

            # 1. Try standard USB\VID_xxxx&PID_xxxx section header
            match = cls.SECTION_START_PATTERN.search(sec)
            if match:
                vid = match.group(1).upper()
                pid = match.group(2).upper()
                raw_serial = match.group(3).strip()
            else:
                # 2. Try modern Windows USBSTOR header
                usbstor_match = cls.SECTION_USBSTOR_PATTERN.search(sec)
                if usbstor_match:
                    ven = usbstor_match.group(1).strip()
                    prod = usbstor_match.group(2).strip()
                    raw_serial = usbstor_match.group(3).strip()
                    volume_label = f"{ven} {prod.replace('_', ' ')} USB Device"

                    # Attempt to resolve inline VID/PID
                    inline_vp = cls.INLINE_VID_PID_PATTERN.search(sec)
                    if inline_vp:
                        vid = inline_vp.group(1).upper()
                        pid = inline_vp.group(2).upper()
                    else:
                        vid = (ven[:4].upper() if len(ven) >= 4 else ven.upper()).ljust(4, "0")
                        pid = "0001"

            if not raw_serial:
                continue

            # Clean composite instance suffixes like &0, &REV_0100
            serial = re.sub(r"&[0-9a-zA-Z]+$", "", raw_serial)

            # Extract timestamps
            start_time: Optional[datetime] = None
            end_time: Optional[datetime] = None

            start_match = cls.TIMESTAMP_START_PATTERN.search(sec)
            if start_match:
                start_time = cls.parse_timestamp(start_match.group(1))

            end_match = cls.TIMESTAMP_END_PATTERN.search(sec)
            if end_match:
                end_time = cls.parse_timestamp(end_match.group(1))

            first_conn = start_time or end_time
            last_conn = end_time or start_time

            # Extract volume label or disk description if not already set
            disk_match = cls.DISK_NAME_PATTERN.search(sec)
            if disk_match:
                volume_label = disk_match.group(1).strip()
            elif not volume_label:
                disk_stor = cls.USBSTOR_DISK_PATTERN.search(sec)
                if disk_stor:
                    volume_label = disk_stor.group(1).replace("_", " ").strip()

            drive_letter_match = cls.DRIVE_LETTER_PATTERN.search(sec)
            if drive_letter_match and volume_label:
                volume_label = f"{volume_label} ({drive_letter_match.group(1)})"

            # Merge or create device record
            if serial in devices_by_serial:
                dev = devices_by_serial[serial]
                if volume_label and not dev.volume_label:
                    dev.volume_label = volume_label

                # Update timestamps
                if first_conn and (dev.first_connected is None or first_conn < dev.first_connected):
                    dev.first_connected = first_conn
                if last_conn and (dev.last_connected is None or last_conn > dev.last_connected):
                    dev.last_connected = last_conn
                if sec:
                    dev.raw_lines = f"{dev.raw_lines}\n\n{sec}" if dev.raw_lines else sec
            else:
                devices_by_serial[serial] = ParsedUSBDevice(
                    vendor_id=vid or "0000",
                    product_id=pid or "0000",
                    serial_number=serial,
                    volume_label=volume_label,
                    first_connected=first_conn,
                    last_connected=last_conn,
                    raw_lines=sec,
                )

        return list(devices_by_serial.values())

    @classmethod
    def extract_timeline_events(cls, content: str) -> List[ParsedTimelineEvent]:
        """Extracts forensically verified timeline events from setupapi.dev.log."""
        events: List[ParsedTimelineEvent] = []
        sections = re.split(r"(?=^\s*>>>\s+\[)", content, flags=re.MULTILINE)

        for sec in sections:
            sec = sec.strip()
            if not sec:
                continue

            vid: Optional[str] = None
            pid: Optional[str] = None
            raw_serial: Optional[str] = None
            volume_label: Optional[str] = None

            match = cls.SECTION_START_PATTERN.search(sec)
            if match:
                vid = match.group(1).upper()
                pid = match.group(2).upper()
                raw_serial = match.group(3).strip()
            else:
                usbstor_match = cls.SECTION_USBSTOR_PATTERN.search(sec)
                if usbstor_match:
                    ven = usbstor_match.group(1).strip()
                    prod = usbstor_match.group(2).strip()
                    raw_serial = usbstor_match.group(3).strip()
                    volume_label = f"{ven} {prod.replace('_', ' ')} USB Device"

                    inline_vp = cls.INLINE_VID_PID_PATTERN.search(sec)
                    if inline_vp:
                        vid = inline_vp.group(1).upper()
                        pid = inline_vp.group(2).upper()
                    else:
                        vid = (ven[:4].upper() if len(ven) >= 4 else ven.upper()).ljust(4, "0")
                        pid = "0001"

            if not raw_serial:
                continue

            serial = re.sub(r"&[0-9a-zA-Z]+$", "", raw_serial)

            disk_match = cls.DISK_NAME_PATTERN.search(sec)
            if disk_match:
                volume_label = disk_match.group(1).strip()
            elif not volume_label:
                disk_stor = cls.USBSTOR_DISK_PATTERN.search(sec)
                if disk_stor:
                    volume_label = disk_stor.group(1).replace("_", " ").strip()

            drive_letter_match = cls.DRIVE_LETTER_PATTERN.search(sec)
            if drive_letter_match and volume_label:
                volume_label = f"{volume_label} ({drive_letter_match.group(1)})"

            # Check if this section confirms a hardware connection event
            is_hardware_initiated = bool(
                re.search(r"Device Install\s*\(\s*Hardware initiated\s*\)", sec, re.IGNORECASE)
            )

            start_time: Optional[datetime] = None
            end_time: Optional[datetime] = None

            start_match = cls.TIMESTAMP_START_PATTERN.search(sec)
            if start_match:
                start_time = cls.parse_timestamp(start_match.group(1))

            end_match = cls.TIMESTAMP_END_PATTERN.search(sec)
            if end_match:
                end_time = cls.parse_timestamp(end_match.group(1))

            label = volume_label or f"USB {vid}:{pid}"

            if start_time:
                if is_hardware_initiated:
                    events.append(
                        ParsedTimelineEvent(
                            timestamp=start_time,
                            event_type="USB INSERTED",
                            vendor_id=vid or "0000",
                            product_id=pid or "0000",
                            serial_number=serial,
                            volume_label=volume_label,
                            description=f"Device '{label}' hardware connection confirmed (Windows SetupAPI Hardware-Initiated Install)",
                            evidence_snippet=start_match.group(0) if start_match else None,
                        )
                    )
                else:
                    events.append(
                        ParsedTimelineEvent(
                            timestamp=start_time,
                            event_type="FIRST OBSERVED",
                            vendor_id=vid or "0000",
                            product_id=pid or "0000",
                            serial_number=serial,
                            volume_label=volume_label,
                            description=f"Device '{label}' first observed in SetupAPI log (non-hardware initiated)",
                            evidence_snippet=start_match.group(0) if start_match else None,
                        )
                    )

            # Section end represents when driver install/activity concluded - NOT a disconnection event.
            if end_time and (start_time is None or end_time != start_time):
                events.append(
                    ParsedTimelineEvent(
                        timestamp=end_time,
                        event_type="LAST OBSERVED",
                        vendor_id=vid or "0000",
                        product_id=pid or "0000",
                        serial_number=serial,
                        volume_label=volume_label,
                        description=f"Device '{label}' installation/activity concluded (SetupAPI section end)",
                        evidence_snippet=end_match.group(0) if end_match else None,
                    )
                )

        return events


class LinuxUsbLogParser:
    """Parser for Linux kernel dmesg and /var/log/syslog USB connection events."""

    VID_PID_PATTERN = re.compile(
        r"idVendor\s*=\s*([0-9a-fA-F]{4})\s*,\s*idProduct\s*=\s*([0-9a-fA-F]{4})",
        re.IGNORECASE,
    )
    SERIAL_PATTERN = re.compile(
        r"usb\s+([0-9\.\-]+):\s+SerialNumber:\s*([^\r\n]+)",
        re.IGNORECASE,
    )
    PRODUCT_PATTERN = re.compile(
        r"usb\s+([0-9\.\-]+):\s+Product:\s*([^\r\n]+)",
        re.IGNORECASE,
    )
    MFR_PATTERN = re.compile(
        r"usb\s+([0-9\.\-]+):\s+Manufacturer:\s*([^\r\n]+)",
        re.IGNORECASE,
    )
    DISCONNECT_PATTERN = re.compile(
        r"usb\s+([0-9\.\-]+):\s+USB disconnect",
        re.IGNORECASE,
    )
    MOUNT_PATTERN = re.compile(
        r"(?:Mounted\s+\S+\s+at\s+|mount:\s+.*?on\s+)/media/[^/\s\r\n]+/([^\s\r\n]+)",
        re.IGNORECASE,
    )
    SYSLOG_TIME_PATTERN = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})",
    )
    ISO_TIME_PATTERN = re.compile(
        r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
    )
    DMESG_OFFSET_PATTERN = re.compile(
        r"\[\s*(\d+\.\d+)\s*\]",
    )

    @classmethod
    def parse_syslog_timestamp(cls, line: str, default_year: int = 2026) -> Optional[datetime]:
        """Extracts standard syslog (Mmm dd HH:MM:SS) or ISO8601 timestamp from log line."""
        iso_match = cls.ISO_TIME_PATTERN.search(line)
        if iso_match:
            raw = iso_match.group(1).replace("T", " ")
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

        syslog_match = cls.SYSLOG_TIME_PATTERN.search(line)
        if syslog_match:
            raw = f"{default_year} {syslog_match.group(1)}"
            try:
                # Format: 2026 Oct 05 10:14:22
                return datetime.strptime(raw, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        return None

    @classmethod
    def parse(cls, content: str, default_year: int = 2026) -> List[ParsedUSBDevice]:
        """Parses Linux syslog or dmesg content into a list of normalized ParsedUSBDevice objects."""
        # Temporary tracking by USB port (e.g. '1-1.2', '2-2')
        port_state: Dict[str, Dict] = {}
        # Final consolidated devices keyed by serial number
        devices_by_serial: Dict[str, ParsedUSBDevice] = {}

        lines = content.splitlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            ts = cls.parse_syslog_timestamp(line, default_year=default_year)

            # Check for VID & PID line: "usb 1-1.2: New USB device found, idVendor=0781, idProduct=5581"
            vid_pid_match = cls.VID_PID_PATTERN.search(line)
            if vid_pid_match:
                port_match = re.search(r"usb\s+([0-9\.\-]+):", line)
                port = port_match.group(1) if port_match else "default"
                port_state[port] = {
                    "vid": vid_pid_match.group(1).upper(),
                    "pid": vid_pid_match.group(2).upper(),
                    "serial": None,
                    "product": None,
                    "mfr": None,
                    "first_connected": ts,
                    "last_connected": ts,
                    "raw_lines": [line],
                }
                continue

            # Check for SerialNumber line
            serial_match = cls.SERIAL_PATTERN.search(line)
            if serial_match:
                port = serial_match.group(1)
                serial_val = serial_match.group(2).strip()
                if port in port_state:
                    port_state[port]["serial"] = serial_val
                    if ts and not port_state[port]["first_connected"]:
                        port_state[port]["first_connected"] = ts
                    if ts:
                        port_state[port]["last_connected"] = ts
                    port_state[port].setdefault("raw_lines", []).append(line)
                continue

            # Check for Product line
            prod_match = cls.PRODUCT_PATTERN.search(line)
            if prod_match:
                port = prod_match.group(1)
                if port in port_state:
                    port_state[port]["product"] = prod_match.group(2).strip()
                    port_state[port].setdefault("raw_lines", []).append(line)
                continue

            # Check for Manufacturer line
            mfr_match = cls.MFR_PATTERN.search(line)
            if mfr_match:
                port = mfr_match.group(1)
                if port in port_state:
                    port_state[port]["mfr"] = mfr_match.group(2).strip()
                    port_state[port].setdefault("raw_lines", []).append(line)
                continue

            # Check for Disconnect event
            disc_match = cls.DISCONNECT_PATTERN.search(line)
            if disc_match:
                port = disc_match.group(1)
                if port in port_state:
                    if ts:
                        port_state[port]["last_connected"] = ts
                    port_state[port].setdefault("raw_lines", []).append(line)
                continue

            # Check for Volume mount event
            mount_match = cls.MOUNT_PATTERN.search(line)
            if mount_match:
                vol_label = mount_match.group(1).strip()
                # Attach to most recently registered active port state
                for p_data in reversed(list(port_state.values())):
                    if "volume_label" not in p_data or not p_data["volume_label"]:
                        p_data["volume_label"] = vol_label
                        p_data.setdefault("raw_lines", []).append(line)
                        break

        # Consolidate completed port states into devices_by_serial
        for port, info in port_state.items():
            vid = info.get("vid")
            pid = info.get("pid")
            serial = info.get("serial")

            if not vid or not pid:
                continue

            # If serial wasn't explicitly logged, generate fallback pseudo-serial based on port
            if not serial:
                serial = f"LINUX_USB_{vid}_{pid}_{port}"

            # Assemble volume label or product name
            label_parts = []
            if info.get("mfr"):
                label_parts.append(info["mfr"])
            if info.get("product"):
                label_parts.append(info["product"])

            combined_label = " ".join(label_parts).strip() or None
            if info.get("volume_label"):
                combined_label = f"{combined_label} [{info['volume_label']}]" if combined_label else info["volume_label"]

            first_conn = info.get("first_connected")
            last_conn = info.get("last_connected")
            raw_evidence = "\n".join(info.get("raw_lines", [])) or None

            if serial in devices_by_serial:
                existing = devices_by_serial[serial]
                if combined_label and not existing.volume_label:
                    existing.volume_label = combined_label
                if first_conn and (existing.first_connected is None or first_conn < existing.first_connected):
                    existing.first_connected = first_conn
                if last_conn and (existing.last_connected is None or last_conn > existing.last_connected):
                    existing.last_connected = last_conn
                if raw_evidence:
                    existing.raw_lines = f"{existing.raw_lines}\n{raw_evidence}" if existing.raw_lines else raw_evidence
            else:
                devices_by_serial[serial] = ParsedUSBDevice(
                    vendor_id=vid,
                    product_id=pid,
                    serial_number=serial,
                    volume_label=combined_label,
                    first_connected=first_conn,
                    last_connected=last_conn,
                    raw_lines=raw_evidence,
                )

        return list(devices_by_serial.values())

    @classmethod
    def _build_device_label(cls, info: Dict[str, Any]) -> Optional[str]:
        label_parts = []
        if info.get("mfr"):
            label_parts.append(info["mfr"])
        if info.get("product"):
            label_parts.append(info["product"])

        combined_label = " ".join(label_parts).strip() or None
        if info.get("volume_label"):
            combined_label = f"{combined_label} [{info['volume_label']}]" if combined_label else info["volume_label"]
        return combined_label

    @classmethod
    def extract_timeline_events(cls, content: str, default_year: int = 2026) -> List[ParsedTimelineEvent]:
        """Extracts forensically verified timeline events from Linux syslog or dmesg logs."""
        events: List[ParsedTimelineEvent] = []
        port_state: Dict[str, Dict[str, Any]] = {}
        lines = content.splitlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            ts = cls.parse_syslog_timestamp(line, default_year=default_year)

            vid_pid_match = cls.VID_PID_PATTERN.search(line)
            if vid_pid_match:
                port_match = re.search(r"usb\s+([0-9\.\-]+):", line)
                port = port_match.group(1) if port_match else "default"
                port_state[port] = {
                    "vid": vid_pid_match.group(1).upper(),
                    "pid": vid_pid_match.group(2).upper(),
                    "serial": None,
                    "product": None,
                    "mfr": None,
                    "connect_ts": ts,
                    "disconnect_ts": None,
                    "last_activity_ts": ts,
                    "volume_label": None,
                    "connect_line": line,
                    "raw_lines": [line],
                }
                continue

            serial_match = cls.SERIAL_PATTERN.search(line)
            if serial_match:
                port = serial_match.group(1)
                serial_val = serial_match.group(2).strip()
                if port in port_state:
                    port_state[port]["serial"] = serial_val
                    if ts and not port_state[port]["connect_ts"]:
                        port_state[port]["connect_ts"] = ts
                    if ts:
                        port_state[port]["last_activity_ts"] = ts
                    port_state[port].setdefault("raw_lines", []).append(line)
                continue

            prod_match = cls.PRODUCT_PATTERN.search(line)
            if prod_match:
                port = prod_match.group(1)
                if port in port_state:
                    port_state[port]["product"] = prod_match.group(2).strip()
                    if ts:
                        port_state[port]["last_activity_ts"] = ts
                    port_state[port].setdefault("raw_lines", []).append(line)
                continue

            mfr_match = cls.MFR_PATTERN.search(line)
            if mfr_match:
                port = mfr_match.group(1)
                if port in port_state:
                    port_state[port]["mfr"] = mfr_match.group(2).strip()
                    if ts:
                        port_state[port]["last_activity_ts"] = ts
                    port_state[port].setdefault("raw_lines", []).append(line)
                continue

            disc_match = cls.DISCONNECT_PATTERN.search(line)
            if disc_match:
                port = disc_match.group(1)
                if port in port_state:
                    p_info = port_state[port]
                    vid = p_info.get("vid") or "0000"
                    pid = p_info.get("pid") or "0000"
                    serial = p_info.get("serial") or f"LINUX_USB_{vid}_{pid}_{port}"
                    label = cls._build_device_label(p_info) or f"USB {vid}:{pid}"
                    p_info["disconnect_ts"] = ts
                    p_info.setdefault("raw_lines", []).append(line)

                    if ts:
                        events.append(
                            ParsedTimelineEvent(
                                timestamp=ts,
                                event_type="USB DISCONNECTED",
                                vendor_id=vid,
                                product_id=pid,
                                serial_number=serial,
                                volume_label=label,
                                description=f"Device '{label}' physical disconnect confirmed (Linux kernel USB disconnect)",
                                evidence_snippet=line,
                            )
                        )
                continue

            mount_match = cls.MOUNT_PATTERN.search(line)
            if mount_match:
                vol_label = mount_match.group(1).strip()
                for p_data in reversed(list(port_state.values())):
                    if "volume_label" not in p_data or not p_data["volume_label"]:
                        p_data["volume_label"] = vol_label
                        if ts:
                            p_data["last_activity_ts"] = ts
                        p_data.setdefault("raw_lines", []).append(line)
                        break

        for port, info in port_state.items():
            vid = info.get("vid") or "0000"
            pid = info.get("pid") or "0000"
            serial = info.get("serial") or f"LINUX_USB_{vid}_{pid}_{port}"
            label = cls._build_device_label(info) or f"USB {vid}:{pid}"

            connect_ts = info.get("connect_ts")
            last_activity = info.get("last_activity_ts")
            disconnect_ts = info.get("disconnect_ts")

            if connect_ts:
                events.append(
                    ParsedTimelineEvent(
                        timestamp=connect_ts,
                        event_type="USB INSERTED",
                        vendor_id=vid,
                        product_id=pid,
                        serial_number=serial,
                        volume_label=label,
                        description=f"Device '{label}' hardware connection confirmed (Linux kernel USB bus enumeration)",
                        evidence_snippet=info.get("connect_line"),
                    )
                )
            elif last_activity:
                events.append(
                    ParsedTimelineEvent(
                        timestamp=last_activity,
                        event_type="FIRST OBSERVED",
                        vendor_id=vid,
                        product_id=pid,
                        serial_number=serial,
                        volume_label=label,
                        description=f"Device '{label}' first observed on system (Linux system log)",
                        evidence_snippet=info.get("raw_lines", [None])[0],
                    )
                )

            # If there was subsequent activity and NO disconnect event was logged at that timestamp
            if (
                last_activity
                and connect_ts
                and last_activity != connect_ts
                and last_activity != disconnect_ts
            ):
                events.append(
                    ParsedTimelineEvent(
                        timestamp=last_activity,
                        event_type="LAST OBSERVED",
                        vendor_id=vid,
                        product_id=pid,
                        serial_number=serial,
                        volume_label=label,
                        description=f"Device '{label}' last activity observed (Volume mounted / active)",
                        evidence_snippet=None,
                    )
                )

        return events


class USBLogParser:
    """Unified parser router capable of handling Windows SetupAPI and Linux log files."""

    @staticmethod
    def parse_setupapi(content_or_path: Union[str, Path]) -> List[ParsedUSBDevice]:
        """Parses Windows setupapi.dev.log from file path or raw string."""
        if isinstance(content_or_path, Path) or (isinstance(content_or_path, str) and "\n" not in content_or_path and Path(content_or_path).is_file()):
            text = Path(content_or_path).read_text(encoding="utf-8", errors="replace")
        else:
            text = str(content_or_path)
        return WindowsSetupApiParser.parse(text)

    @staticmethod
    def parse_linux_log(content_or_path: Union[str, Path], default_year: int = 2026) -> List[ParsedUSBDevice]:
        """Parses Linux dmesg or syslog from file path or raw string."""
        if isinstance(content_or_path, Path) or (isinstance(content_or_path, str) and "\n" not in content_or_path and Path(content_or_path).is_file()):
            text = Path(content_or_path).read_text(encoding="utf-8", errors="replace")
        else:
            text = str(content_or_path)
        return LinuxUsbLogParser.parse(text, default_year=default_year)

    @classmethod
    def parse_file(cls, filepath: Union[str, Path], default_year: int = 2026) -> List[ParsedUSBDevice]:
        """Auto-detects log format (Windows SetupAPI vs Linux Syslog/dmesg) and extracts USB devices."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        content = path.read_text(encoding="utf-8", errors="replace")
        lower_name = path.name.lower()

        # Heuristic detection based on filename and header content
        if "setupapi" in lower_name or "[Device Install Log]" in content or ">>>  [Device Install" in content:
            return WindowsSetupApiParser.parse(content)
        else:
            return LinuxUsbLogParser.parse(content, default_year=default_year)

    @classmethod
    def extract_timeline_events(
        cls,
        content_or_path: Union[str, Path],
        default_year: int = 2026
    ) -> List[ParsedTimelineEvent]:
        """Auto-detects log format and extracts forensically verified timeline events."""
        if isinstance(content_or_path, Path) or (isinstance(content_or_path, str) and "\n" not in content_or_path and Path(content_or_path).is_file()):
            text = Path(content_or_path).read_text(encoding="utf-8", errors="replace")
            source_hint = str(content_or_path).lower()
        else:
            text = str(content_or_path)
            source_hint = ""

        lower_text = text[:1500].lower()
        if "setupapi" in source_hint or "setupapi" in lower_text or "[device install log]" in lower_text or ">>>  [device install" in lower_text or ">>> [device install" in lower_text:
            return WindowsSetupApiParser.extract_timeline_events(text)
        else:
            return LinuxUsbLogParser.extract_timeline_events(text, default_year=default_year)


# Convenient module-level aliases
parse_setupapi_log = USBLogParser.parse_setupapi
parse_linux_usb_log = USBLogParser.parse_linux_log
extract_usb_timeline_events = USBLogParser.extract_timeline_events
