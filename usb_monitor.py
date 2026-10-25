"""
USB Sentinel AI - Physical USB Detection & Hardware Monitoring Engine
Uses OS-native events (Windows WM_DEVICECHANGE / WMI / win32api / psutil)
to dynamically detect physical USB storage devices in real-time.
"""

import os
import sys
import time
import shutil
import platform
import psutil
from dataclasses import dataclass, asdict
from PyQt6.QtCore import QThread, pyqtSignal, QObject


# Windows API Imports if running on Windows
IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    try:
        import win32api
        import win32file
        import win32gui
        import win32con
    except ImportError:
        IS_WINDOWS = False


@dataclass
class USBDevice:
    mount_point: str            # e.g., "E:\" or "/media/usb"
    device_name: str            # e.g., "SanDisk Ultra USB 3.0"
    volume_label: str           # e.g., "SECURE_DATA"
    file_system: str            # e.g., "FAT32", "NTFS", "exFAT"
    serial_number: str          # e.g., "A1B2-C3D4"
    total_bytes: int            # Total drive size in bytes
    free_bytes: int             # Free space in bytes
    is_removable: bool = True
    device_type: str = "USB Flash Drive"

    def to_dict(self):
        d = asdict(self)
        d["total_gb"] = round(self.total_bytes / (1024**3), 2)
        d["free_gb"] = round(self.free_bytes / (1024**3), 2)
        d["used_gb"] = round((self.total_bytes - self.free_bytes) / (1024**3), 2)
        return d


def format_serial_number(serial_int: int) -> str:
    """Formats an integer volume serial number into XXXX-XXXX format."""
    try:
        unsigned = serial_int & 0xFFFFFFFF
        hex_str = f"{unsigned:08X}"
        return f"{hex_str[:4]}-{hex_str[4:]}"
    except Exception:
        return str(serial_int)


def get_drive_details_windows(drive_letter: str) -> USBDevice:
    """Dynamically queries physical drive properties using Win32 API."""
    clean_letter = drive_letter.rstrip("\\") + "\\"
    vol_name = "Removable Disk"
    fs_type = "Unknown"
    serial_num = "N/A"
    total_b = 0
    free_b = 0
    is_removable = True

    try:
        drive_type = win32file.GetDriveType(clean_letter)
        # DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3, DRIVE_CDROM = 5, etc.
        is_removable = (drive_type == win32file.DRIVE_REMOVABLE)
    except Exception:
        pass

    try:
        vol_info = win32api.GetVolumeInformation(clean_letter)
        vol_name = vol_info[0] if vol_info[0] else "USB Storage"
        serial_num = format_serial_number(vol_info[1])
        fs_type = vol_info[4]
    except Exception:
        pass

    try:
        usage = shutil.disk_usage(clean_letter)
        total_b = usage.total
        free_b = usage.free
    except Exception:
        pass

    device_name = f"{vol_name} ({clean_letter.rstrip(os.sep)})"
    return USBDevice(
        mount_point=clean_letter,
        device_name=device_name,
        volume_label=vol_name,
        file_system=fs_type,
        serial_number=serial_num,
        total_bytes=total_b,
        free_bytes=free_b,
        is_removable=is_removable,
        device_type="USB Removable Drive" if is_removable else "Storage Volume"
    )


def get_drive_details_generic(mount_point: str, fstype: str = "") -> USBDevice:
    """Fallback cross-platform drive query via psutil and shutil."""
    total_b = 0
    free_b = 0
    try:
        usage = shutil.disk_usage(mount_point)
        total_b = usage.total
        free_b = usage.free
    except Exception:
        pass

    label = os.path.basename(mount_point.rstrip("/\\")) or "USB Device"
    return USBDevice(
        mount_point=mount_point,
        device_name=f"{label} ({mount_point})",
        volume_label=label,
        file_system=fstype or "Generic",
        serial_number="N/A",
        total_bytes=total_b,
        free_bytes=free_b,
        is_removable=True,
        device_type="Removable Media"
    )


def query_all_removable_drives() -> list[USBDevice]:
    """
    Returns a list of all currently mounted removable USB storage devices.
    """
    devices = []
    if IS_WINDOWS:
        try:
            # Query drive letters bitmask A-Z
            drives_mask = win32api.GetLogicalDrives()
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                bit = 1 << (ord(letter) - ord("A"))
                if drives_mask & bit:
                    drive_path = f"{letter}:\\"
                    try:
                        dtype = win32file.GetDriveType(drive_path)
                        if dtype == win32file.DRIVE_REMOVABLE:
                            dev = get_drive_details_windows(drive_path)
                            devices.append(dev)
                    except Exception:
                        pass
        except Exception as e:
            print(f"[USB Monitor] Windows drive query error: {e}")

    # Also check psutil partitions for any other USB mountpoints
    try:
        partitions = psutil.disk_partitions(all=True)
        known_mounts = {d.mount_point.lower() for d in devices}
        for part in partitions:
            m = part.mountpoint
            if m.lower() in known_mounts:
                continue
            opts = part.opts.lower()
            if "removable" in opts or (IS_WINDOWS and "cdrom" not in opts and not part.mountpoint.upper().startswith("C:")):
                # On Windows check if DRIVE_REMOVABLE
                if IS_WINDOWS:
                    try:
                        if win32file.GetDriveType(m) == win32file.DRIVE_REMOVABLE:
                            devices.append(get_drive_details_windows(m))
                    except Exception:
                        pass
                else:
                    if "/media/" in m or "/mnt/" in m or "/Volumes/" in m:
                        devices.append(get_drive_details_generic(m, part.fstype))
    except Exception as e:
        print(f"[USB Monitor] Partition scan error: {e}")

    return devices


class USBMonitorThread(QThread):
    """
    Background hardware monitoring thread.
    Continuously listens for real physical drive insertions and removals.
    Emits PyQt signals when devices change.
    """
    device_inserted = pyqtSignal(USBDevice)
    device_removed = pyqtSignal(str)              # mount point string
    devices_updated = pyqtSignal(list)            # list of all connected USBDevice objects
    status_message = pyqtSignal(str)

    def __init__(self, poll_interval_sec: float = 1.5):
        super().__init__()
        self.poll_interval = poll_interval_sec
        self._is_running = True
        self._current_devices: dict[str, USBDevice] = {}

    def stop(self):
        self._is_running = False

    def run(self):
        self.status_message.emit("USB Sentinel Hardware Listener Active - Monitoring for device arrival...")
        
        # Initial scan of already-attached devices
        initial_list = query_all_removable_drives()
        for dev in initial_list:
            self._current_devices[dev.mount_point.upper()] = dev
        self.devices_updated.emit(initial_list)
        if initial_list:
            self.status_message.emit(f"Initial scan detected {len(initial_list)} active USB device(s).")

        # Continuous polling loop
        while self._is_running:
            try:
                active_list = query_all_removable_drives()
                active_dict = {d.mount_point.upper(): d for d in active_list}

                # Detect newly inserted devices
                for mount_key, dev in active_dict.items():
                    if mount_key not in self._current_devices:
                        self._current_devices[mount_key] = dev
                        self.status_message.emit(f"PHYSICAL USB INSERTED: {dev.device_name} [{dev.mount_point}]")
                        self.device_inserted.emit(dev)
                        self.devices_updated.emit(list(self._current_devices.values()))

                # Detect removed devices
                removed_keys = []
                for mount_key, old_dev in self._current_devices.items():
                    if mount_key not in active_dict:
                        removed_keys.append(mount_key)
                        self.status_message.emit(f"PHYSICAL USB REMOVED: [{old_dev.mount_point}]")
                        self.device_removed.emit(old_dev.mount_point)

                for k in removed_keys:
                    del self._current_devices[k]

                if removed_keys:
                    self.devices_updated.emit(list(self._current_devices.values()))

            except Exception as e:
                print(f"[USB Monitor Thread] Polling cycle error: {e}")

            time.sleep(self.poll_interval)
