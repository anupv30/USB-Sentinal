import { Device, FileArtifact, TimelineItem, StatsMetrics, ScanDriveResponse, DetectedDrive, ForensicLog } from './types'

const API_BASE = '/api'

export async function fetchHealth(): Promise<{ status: string; service: string; version: string }> {
  const res = await fetch(`${API_BASE}/health`)
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`)
  return res.json()
}

export async function fetchStats(): Promise<StatsMetrics> {
  const res = await fetch(`${API_BASE}/stats`)
  if (!res.ok) throw new Error(`Stats fetch failed: ${res.statusText}`)
  return res.json()
}

export async function fetchDevices(): Promise<Device[]> {
  const res = await fetch(`${API_BASE}/devices`)
  if (!res.ok) throw new Error(`Devices fetch failed: ${res.statusText}`)
  return res.json()
}

export async function fetchTimeline(deviceId?: number, order: 'asc' | 'desc' = 'desc'): Promise<TimelineItem[]> {
  const params = new URLSearchParams()
  if (deviceId !== undefined) params.append('device_id', deviceId.toString())
  params.append('order', order)

  const res = await fetch(`${API_BASE}/timeline?${params.toString()}`)
  if (!res.ok) throw new Error(`Timeline fetch failed: ${res.statusText}`)
  return res.json()
}

export async function fetchFiles(deviceId?: number, suspiciousOnly?: boolean, search?: string): Promise<FileArtifact[]> {
  const params = new URLSearchParams()
  if (deviceId !== undefined) params.append('device_id', deviceId.toString())
  if (suspiciousOnly) params.append('suspicious_only', 'true')
  if (search) params.append('search', search)

  const res = await fetch(`${API_BASE}/files?${params.toString()}`)
  if (!res.ok) throw new Error(`Files fetch failed: ${res.statusText}`)
  return res.json()
}

export async function uploadLogFile(file: File, saveToDb: boolean = true): Promise<Device[]> {
  const formData = new FormData()
  formData.append('file', file)

  const res = await fetch(`${API_BASE}/upload-log?save_to_db=${saveToDb}`, {
    method: 'POST',
    body: formData,
  })
  if (!res.ok) {
    const errorJson = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(errorJson.detail || 'Log upload failed')
  }
  return res.json()
}

export async function scanDrivePath(targetPath: string, deviceId?: number): Promise<ScanDriveResponse> {
  const res = await fetch(`${API_BASE}/scan-drive`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target_path: targetPath,
      device_id: deviceId,
    }),
  })
  if (!res.ok) {
    const errorJson = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(errorJson.detail || 'Drive scan failed')
  }
  return res.json()
}

export async function detectDrives(): Promise<DetectedDrive[]> {
  const res = await fetch(`${API_BASE}/detect-drives`)
  if (!res.ok) throw new Error(`Drive auto-detection failed: ${res.statusText}`)
  return res.json()
}

export async function ingestLiveSystemLogs(): Promise<Device[]> {
  const res = await fetch(`${API_BASE}/ingest-live-log`, {
    method: 'POST',
  })
  if (!res.ok) {
    const errorJson = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(errorJson.detail || 'Live system log ingestion failed')
  }
  return res.json()
}

export async function fetchForensicLogs(logType?: string): Promise<ForensicLog[]> {
  const params = new URLSearchParams()
  if (logType) params.append('log_type', logType)
  const url = `${API_BASE}/forensic-logs${params.toString() ? `?${params.toString()}` : ''}`
  const res = await fetch(url)
  if (!res.ok) throw new Error(`Forensic logs fetch failed: ${res.statusText}`)
  return res.json()
}
