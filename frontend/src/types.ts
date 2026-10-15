export interface Device {
  id: number
  vendor_id: string
  product_id: string
  serial_number: string
  volume_label: string | null
  first_connected: string | null
  last_connected: string | null
  total_artifacts: number
  suspicious_count: number
}

export interface FileArtifact {
  id: number
  device_id: number
  file_path: string
  file_size: number
  creation_time: string | null
  modification_time: string | null
  md5_hash: string | null
  sha256_hash: string | null
  flag_suspicious: boolean
  flag_reason: string | null
}

export interface TimelineItem {
  event_id: string
  timestamp: string | null
  event_type: 'USB INSERTED' | 'USB DISCONNECTED' | 'FIRST OBSERVED' | 'LAST OBSERVED' | 'FIRST_CONNECTED' | 'LAST_SEEN' | string
  device_id: number
  vendor_id: string
  product_id: string
  serial_number: string
  volume_label: string | null
  description: string
}

export interface StatsMetrics {
  total_devices: number
  total_files_scanned: number
  total_artifacts?: number
  flagged_suspicious_files: number
  suspicious_artifacts?: number
  clean_files: number
  recent_connections: Device[]
}

export interface ScanDriveResponse {
  device_id: number
  device_serial: string
  target_dir: string
  total_files_scanned: number
  records_persisted: number
  suspicious_count: number
  clean_count: number
  artifacts: FileArtifact[]
}

export interface DetectedDrive {
  mount_point: string
  device_path?: string
  volume_label: string
  file_system?: string
  total_bytes: number
  used_bytes: number
  free_bytes: number
  percent_used: number
  is_removable: boolean
  vendor_id?: string
  product_id?: string
  serial_number?: string
}

export interface ParsedLogRecord {
  vendor_id: string
  product_id: string
  serial_number: string
  volume_label: string | null
  first_connected: string | null
  last_connected: string | null
  raw_lines?: string | null
}

export interface ForensicLog {
  id: number
  log_type: 'windows_setupapi' | 'linux_syslog' | string
  source_name: string
  ingested_at: string
  raw_content: string
  parsed_devices_count: number
  parsed_records: ParsedLogRecord[]
}
