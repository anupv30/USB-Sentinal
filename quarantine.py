"""
USB Sentinel AI - Isolated Quarantine Vault
Manages cryptographic isolation and safe remediation of malicious/suspicious files.
"""

import os
import json
import base64
import shutil
import hashlib
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class QuarantineVault:
    def __init__(self, vault_dir=None):
        if vault_dir:
            self.vault_dir = Path(vault_dir).resolve()
        else:
            app_dir = Path(__file__).parent.resolve()
            self.vault_dir = app_dir / ".sentinel_quarantine"
            
        self.files_dir = self.vault_dir / "vault_storage"
        self.meta_file = self.vault_dir / "vault_metadata.json"
        self.key_file = self.vault_dir / "vault.key"
        
        self._initialize_vault()
        
    def _initialize_vault(self):
        """Creates the isolated directory structure and encryption key if not exists."""
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.files_dir.mkdir(parents=True, exist_ok=True)
        
        # Load or generate AES-256-GCM key
        if not self.key_file.exists():
            key = AESGCM.generate_key(bit_length=256)
            with open(self.key_file, "wb") as f:
                f.write(base64.b64encode(key))
            self.key = key
        else:
            with open(self.key_file, "rb") as f:
                self.key = base64.b64decode(f.read().strip())
                
        # Initialize metadata database
        if not self.meta_file.exists():
            self._save_metadata([])

    def _load_metadata(self) -> list:
        try:
            if self.meta_file.exists():
                with open(self.meta_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"[Quarantine] Error reading metadata: {e}")
        return []

    def _save_metadata(self, data: list):
        try:
            with open(self.meta_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Quarantine] Error writing metadata: {e}")

    def quarantine_file(self, file_path: str, reason: str = "Heuristic Threat", threat_score: int = 100, rules_triggered: list = None) -> dict:
        """
        Encrypts and moves a file from the physical USB drive into the secure quarantine vault.
        Returns quarantine record dict or raises exception.
        """
        src = Path(file_path).resolve()
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Compute file hash
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(src, "rb") as f:
            raw_content = f.read()
            sha256.update(raw_content)
            md5.update(raw_content)

        file_sha256 = sha256.hexdigest()
        file_md5 = md5.hexdigest()
        file_size = len(raw_content)
        timestamp = datetime.now().isoformat()
        quarantine_id = f"Q_{file_sha256[:12]}_{int(datetime.now().timestamp())}"

        # Encrypt with AES-GCM
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, raw_content, None)

        vault_filename = f"{quarantine_id}.locked"
        vault_file_path = self.files_dir / vault_filename

        with open(vault_file_path, "wb") as f:
            # Store nonce (12 bytes) + encrypted payload
            f.write(nonce + encrypted_data)

        # Remove execution permissions / remove original file from USB
        try:
            # Overwrite original before removal for anti-forensic malware defense if needed
            os.remove(src)
        except Exception as e:
            # If standard remove fails, try changing permissions first
            try:
                os.chmod(src, 0o777)
                os.remove(src)
            except Exception as inner_e:
                # If removal failed, delete locked file and raise
                if vault_file_path.exists():
                    vault_file_path.unlink()
                raise PermissionError(f"Could not delete original file from USB: {inner_e}")

        record = {
            "id": quarantine_id,
            "original_path": str(src),
            "original_name": src.name,
            "vault_file": vault_filename,
            "file_size": file_size,
            "sha256": file_sha256,
            "md5": file_md5,
            "reason": reason,
            "threat_score": threat_score,
            "rules_triggered": rules_triggered or [],
            "timestamp": timestamp,
            "restored": False
        }

        records = self._load_metadata()
        records.append(record)
        self._save_metadata(records)
        return record

    def restore_file(self, quarantine_id: str, destination_dir: str = None) -> str:
        """
        Decrypts and restores a quarantined file to its original location or designated directory.
        """
        records = self._load_metadata()
        target_record = next((r for r in records if r["id"] == quarantine_id and not r.get("restored", False)), None)
        
        if not target_record:
            raise ValueError(f"Quarantine record not found or already restored: {quarantine_id}")

        vault_file_path = self.files_dir / target_record["vault_file"]
        if not vault_file_path.exists():
            raise FileNotFoundError(f"Vault payload file missing: {vault_file_path}")

        with open(vault_file_path, "rb") as f:
            raw_vault = f.read()

        nonce = raw_vault[:12]
        ciphertext = raw_vault[12:]

        aesgcm = AESGCM(self.key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)

        if destination_dir:
            dest_dir_path = Path(destination_dir)
            dest_dir_path.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir_path / target_record["original_name"]
        else:
            dest_path = Path(target_record["original_path"])
            dest_path.parent.mkdir(parents=True, exist_ok=True)

        with open(dest_path, "wb") as f:
            f.write(decrypted_bytes)

        # Mark as restored and cleanup vault file
        target_record["restored"] = True
        target_record["restored_to"] = str(dest_path)
        target_record["restored_at"] = datetime.now().isoformat()
        
        if vault_file_path.exists():
            vault_file_path.unlink()
            
        self._save_metadata(records)
        return str(dest_path)

    def delete_permanently(self, quarantine_id: str) -> bool:
        """Permanently purges a quarantined file from the vault."""
        records = self._load_metadata()
        target_record = next((r for r in records if r["id"] == quarantine_id), None)
        
        if not target_record:
            return False

        vault_file_path = self.files_dir / target_record.get("vault_file", "")
        if vault_file_path.exists():
            vault_file_path.unlink()

        records = [r for r in records if r["id"] != quarantine_id]
        self._save_metadata(records)
        return True

    def list_quarantined(self) -> list:
        """Returns all quarantined items."""
        return [r for r in self._load_metadata() if not r.get("restored", False)]

    def get_stats(self) -> dict:
        records = self.list_quarantined()
        total_size = sum(r.get("file_size", 0) for r in records)
        return {
            "total_quarantined": len(records),
            "total_bytes": total_size,
            "vault_path": str(self.vault_dir)
        }
