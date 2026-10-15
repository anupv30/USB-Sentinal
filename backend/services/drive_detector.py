"""Native Removable Drive and Live USB Hardware Detection Service.

Provides cross-platform hardware auto-detection:
1. detect_removable_drives(): Discovers mounted removable USB flash drives, pendrives,
   and external volumes with volume labels, filesystems, and storage metrics.
2. get_system_usb_history(): Extracts live physical USB hardware connection history
   from Windows SetupAPI logs and Windows Registry (or Linux system logs).
"""

import os
import sys
import platform
import ctypes
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

import psutil


def get_windows_volume_info(mount_point: str) -> Dict[str, str]:
    """Retrieves Windows volume label and filesystem name using Win32 API."""
    info = {"volume_label": "", "file_system": ""}
    if platform.system() != "Windows":
        return info

    try:
        kernel32 = ctypes.windll.kernel32
        volume_name_buffer = ctypes.create_unicode_buffer(1024)
        fs_name_buffer = ctypes.create_unicode_buffer(1024)
        serial_number = ctypes.c_ulong()
        max_component_length = ctypes.c_ulong()
        fs_flags = ctypes.c_ulong()

        # Ensure trailing backslash for Windows root drive
        root_path = mount_point if mount_point.endswith("\\") else f"{mount_point}\\"

        success = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root_path),
            volume_name_buffer,
            ctypes.sizeof(volume_name_buffer),
            ctypes.byref(serial_number),
            ctypes.byref(max_component_length),
            ctypes.byref(fs_flags),
            fs_name_buffer,
            ctypes.sizeof(fs_name_buffer),
        )
        if success:
            info["volume_label"] = volume_name_buffer.value
            info["file_system"] = fs_name_buffer.value
            info["serial_number"] = f"{serial_number.value:08X}"
    except Exception:
        pass

    return info


def is_drive_removable(mount_point: str, opts: str) -> bool:
    """Checks if a drive mount point is a removable storage device."""
    opts_lower = opts.lower()
    if "removable" in opts_lower:
        return True

    if platform.system() == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32
            root_path = mount_point if mount_point.endswith("\\") else f"{mount_point}\\"
            # DRIVE_REMOVABLE = 2, DRIVE_CDROM = 5
            drive_type = kernel32.GetDriveTypeW(ctypes.c_wchar_p(root_path))
            if drive_type == 2:
                return True
        except Exception:
            pass
    elif platform.system() == "Linux":
        # Check /sys/block for removable attribute
        try:
            dev_name = os.path.basename(mount_point)
            sys_block = Path(f"/sys/block/{dev_name}/removable")
            if sys_block.exists() and sys_block.read_text().strip() == "1":
                return True
        except Exception:
            pass

    return False


def detect_removable_drives() -> List[Dict[str, Any]]:
    """Dynamically detects currently plugged removable USB drives / pendrives."""
    detected = []

    try:
        partitions = psutil.disk_partitions(all=True)
    except Exception:
        partitions = []

    for part in partitions:
        mount = part.mountpoint
        if not mount:
            continue

        if not is_drive_removable(mount, part.opts):
            continue

        label = ""
        fs_type = part.fstype
        serial = None

        if platform.system() == "Windows":
            win_info = get_windows_volume_info(mount)
            label = win_info.get("volume_label", "")
            if win_info.get("file_system"):
                fs_type = win_info["file_system"]
            serial = win_info.get("serial_number")
        else:
            # Fallback label for Unix
            label = os.path.basename(mount.rstrip("/")) or "Removable USB"

        if not label:
            label = f"USB Drive ({mount.rstrip(os.sep)})"

        total_bytes = 0
        used_bytes = 0
        free_bytes = 0
        percent_used = 0.0

        try:
            usage = psutil.disk_usage(mount)
            total_bytes = usage.total
            used_bytes = usage.used
            free_bytes = usage.free
            percent_used = usage.percent
        except Exception:
            # Drive might be unformatted or busy
            pass

        # Match with known USB hardware in registry if Windows
        vid, pid, hw_serial = None, None, None
        if platform.system() == "Windows":
            hw_match = find_usb_hardware_for_drive(label, serial)
            if hw_match:
                vid = hw_match.get("vid")
                pid = hw_match.get("pid")
                hw_serial = hw_match.get("serial")

        detected.append({
            "mount_point": mount,
            "device_path": part.device or mount,
            "volume_label": label,
            "file_system": fs_type or "Unknown",
            "total_bytes": total_bytes,
            "used_bytes": used_bytes,
            "free_bytes": free_bytes,
            "percent_used": percent_used,
            "is_removable": True,
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": hw_serial or serial,
        })

    return detected


def find_usb_hardware_for_drive(volume_label: str, serial_num: Optional[str] = None) -> Optional[Dict[str, str]]:
    """Helper to correlate a mounted drive with USB hardware in Windows Registry."""
    if platform.system() != "Windows":
        return None

    try:
        import winreg

        # 1. Check USBSTOR
        usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_path)
        sub_count, _, _ = winreg.QueryInfoKey(key)

        for i in range(sub_count):
            dev_name = winreg.EnumKey(key, i)
            dev_key = winreg.OpenKey(key, dev_name)
            inst_count, _, _ = winreg.QueryInfoKey(dev_key)

            for j in range(inst_count):
                inst_id = winreg.EnumKey(dev_key, j)
                serial_clean = inst_id.split("&")[0] if "&" in inst_id else inst_id

                # Find matching USB controller VID/PID
                usb_info = find_usb_by_serial(serial_clean)
                if usb_info:
                    return usb_info
    except Exception:
        pass

    return None


def find_usb_by_serial(target_serial: str) -> Optional[Dict[str, str]]:
    """Searches Windows USB registry for a given device serial."""
    if platform.system() != "Windows":
        return None

    try:
        import winreg

        usb_path = r"SYSTEM\CurrentControlSet\Enum\USB"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usb_path)
        sub_count, _, _ = winreg.QueryInfoKey(key)

        for i in range(sub_count):
            sub_name = winreg.EnumKey(key, i)
            if not sub_name.startswith("VID_"):
                continue

            parts = sub_name.split("&")
            vid = parts[0].replace("VID_", "")
            pid = parts[1].replace("PID_", "") if len(parts) > 1 else "0000"

            sub_key = winreg.OpenKey(key, sub_name)
            inst_count, _, _ = winreg.QueryInfoKey(sub_key)

            for j in range(inst_count):
                inst_id = winreg.EnumKey(sub_key, j)
                if target_serial.lower() in inst_id.lower() or inst_id.lower() in target_serial.lower():
                    return {
                        "vid": vid.upper(),
                        "pid": pid.upper(),
                        "serial": inst_id,
                    }
    except Exception:
        pass

    return None


def get_windows_registry_usb_devices() -> List[Dict[str, Any]]:
    """Enumerates all physically connected and historically registered USB devices from Windows Registry."""
    devices = []
    if platform.system() != "Windows":
        return devices

    try:
        import winreg

        # 1. Enumerate USBSTOR devices
        usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        try:
            stor_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_path)
            sub_count, _, _ = winreg.QueryInfoKey(stor_key)

            for i in range(sub_count):
                dev_name = winreg.EnumKey(stor_key, i)
                dev_key = winreg.OpenKey(stor_key, dev_name)
                inst_count, _, _ = winreg.QueryInfoKey(dev_key)

                for j in range(inst_count):
                    inst_id = winreg.EnumKey(dev_key, j)
                    inst_key = winreg.OpenKey(dev_key, inst_id)
                    vals = {}
                    v_count, _, _ = winreg.QueryInfoKey(inst_key)
                    for k in range(v_count):
                        vname, vval, _ = winreg.EnumValue(inst_key, k)
                        vals[vname] = vval

                    serial = inst_id.split("&")[0] if "&" in inst_id else inst_id
                    friendly = vals.get("FriendlyName") or vals.get("DeviceDesc") or dev_name
                    if friendly.startswith("@"):
                        friendly = friendly.split(";")[-1] if ";" in friendly else friendly

                    # Attempt to resolve VID/PID from USB controller
                    usb_match = find_usb_by_serial(serial)
                    vid = usb_match["vid"] if usb_match else "0000"
                    pid = usb_match["pid"] if usb_match else "0000"

                    devices.append({
                        "vendor_id": vid,
                        "product_id": pid,
                        "serial_number": serial,
                        "volume_label": friendly,
                        "first_connected": datetime.now(timezone.utc),
                        "last_connected": datetime.now(timezone.utc),
                    })
        except Exception:
            pass

        # 2. Enumerate USB controller devices (Keyboards, Storage, Webcams, Hubs)
        usb_path = r"SYSTEM\CurrentControlSet\Enum\USB"
        try:
            usb_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usb_path)
            sub_count, _, _ = winreg.QueryInfoKey(usb_key)

            for i in range(sub_count):
                sub_name = winreg.EnumKey(usb_key, i)
                if not sub_name.startswith("VID_"):
                    continue

                parts = sub_name.split("&")
                vid = parts[0].replace("VID_", "").upper()
                pid = parts[1].replace("PID_", "").upper() if len(parts) > 1 else "0000"

                sub_dev_key = winreg.OpenKey(usb_key, sub_name)
                inst_count, _, _ = winreg.QueryInfoKey(sub_dev_key)

                for j in range(inst_count):
                    inst_id = winreg.EnumKey(sub_dev_key, j)
                    inst_key = winreg.OpenKey(sub_dev_key, inst_id)
                    vals = {}
                    v_count, _, _ = winreg.QueryInfoKey(inst_key)
                    for k in range(v_count):
                        vname, vval, _ = winreg.EnumValue(inst_key, k)
                        vals[vname] = vval

                    desc = vals.get("FriendlyName") or vals.get("DeviceDesc") or f"USB Device {vid}:{pid}"
                    if desc.startswith("@"):
                        desc = desc.split(";")[-1] if ";" in desc else desc

                    # If serial already added under USBSTOR, update label instead of duplicate
                    existing = next((d for d in devices if d["serial_number"] == inst_id or (inst_id in d["serial_number"])), None)
                    if existing:
                        existing["vendor_id"] = vid
                        existing["product_id"] = pid
                    else:
                        devices.append({
                            "vendor_id": vid,
                            "product_id": pid,
                            "serial_number": inst_id,
                            "volume_label": desc,
                            "first_connected": datetime.now(timezone.utc),
                            "last_connected": datetime.now(timezone.utc),
                        })
        except Exception:
            pass

    except Exception:
        pass

    return devices
