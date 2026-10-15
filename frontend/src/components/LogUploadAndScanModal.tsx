import React, { useState, useEffect, useRef } from 'react'
import {
  X,
  Upload,
  HardDrive,
  FileText,
  AlertCircle,
  CheckCircle2,
  Loader2,
  FolderSearch,
  ArrowRight,
  Database,
  RefreshCw,
  Cpu,
  Layers,
  Sparkles
} from 'lucide-react'
import { uploadLogFile, scanDrivePath, detectDrives, ingestLiveSystemLogs } from '../api'
import { Device, DetectedDrive } from '../types'

interface ModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
  devices: Device[]
  detectedDrives?: DetectedDrive[]
  initialDrivePath?: string
}

export const LogUploadAndScanModal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
  devices,
  detectedDrives = [],
  initialDrivePath = '',
}) => {
  const [activeMode, setActiveMode] = useState<'scan' | 'upload'>('scan')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [drivePath, setDrivePath] = useState(initialDrivePath || (detectedDrives.length > 0 ? detectedDrives[0].mount_point : ''))
  const [selectedDeviceId, setSelectedDeviceId] = useState<number | undefined>(
    devices.length > 0 ? devices[0].id : undefined
  )
  const [drivesList, setDrivesList] = useState<DetectedDrive[]>(detectedDrives)
  const [isRefreshingDrives, setIsRefreshingDrives] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Sync initial path or detected drives
  useEffect(() => {
    if (initialDrivePath) {
      setDrivePath(initialDrivePath)
    } else if (detectedDrives.length > 0 && !drivePath) {
      setDrivePath(detectedDrives[0].mount_point)
    }
    setDrivesList(detectedDrives)
  }, [initialDrivePath, detectedDrives])

  // Fetch drives dynamically when modal opens
  useEffect(() => {
    if (isOpen) {
      refreshDrives()
    }
  }, [isOpen])

  const refreshDrives = async () => {
    setIsRefreshingDrives(true)
    try {
      const live = await detectDrives()
      setDrivesList(live)
      if (live.length > 0 && !drivePath) {
        setDrivePath(live[0].mount_point)
      }
    } catch (err) {
      console.warn('Could not auto-detect drives:', err)
    } finally {
      setIsRefreshingDrives(false)
    }
  }

  if (!isOpen) return null

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setSelectedFile(e.dataTransfer.files[0])
      setStatusMessage(null)
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0])
      setStatusMessage(null)
    }
  }

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedFile) {
      setStatusMessage({ type: 'error', text: 'Please select a log file (.log or .txt) to parse.' })
      return
    }

    setIsLoading(true)
    setStatusMessage(null)
    try {
      const parsedDevs = await uploadLogFile(selectedFile, true)
      setStatusMessage({
        type: 'success',
        text: `Success! Extracted and stored ${parsedDevs.length} USB device records in SQLite database.`,
      })
      setTimeout(() => {
        onSuccess()
        onClose()
      }, 1200)
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err.message || 'Failed to upload and parse log file.',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleLiveLogIngest = async () => {
    setIsLoading(true)
    setStatusMessage(null)
    try {
      const devs = await ingestLiveSystemLogs()
      setStatusMessage({
        type: 'success',
        text: `Success! Extracted ${devs.length} real USB hardware records from host SetupAPI and Registry.`,
      })
      setTimeout(() => {
        onSuccess()
        onClose()
      }, 1200)
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err.message || 'Failed to ingest host system USB logs.',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!drivePath.trim()) {
      setStatusMessage({ type: 'error', text: 'Please select or provide a valid USB drive path to inspect.' })
      return
    }

    setIsLoading(true)
    setStatusMessage(null)
    try {
      const result = await scanDrivePath(drivePath.trim(), selectedDeviceId)
      setStatusMessage({
        type: 'success',
        text: `Scan Complete! Inspected ${result.total_files_scanned} files (${result.suspicious_count} high-risk threats flagged).`,
      })
      setTimeout(() => {
        onSuccess()
        onClose()
      }, 1200)
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err.message || 'Drive inspection failed.',
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 relative overflow-hidden">
        {/* Modal Glow Accent */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500" />

        {/* Modal Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              {activeMode === 'scan' ? <HardDrive className="w-5 h-5" /> : <FileText className="w-5 h-5" />}
            </div>
            <div>
              <h2 className="text-base font-bold text-white">
                {activeMode === 'scan' ? 'Scan Removable Media & Filesystem' : 'Forensic USB Log Ingestion'}
              </h2>
              <p className="text-xs text-slate-400">
                {activeMode === 'scan'
                  ? 'Inspect plugged-in USB storage, calculate hashes, and identify hidden threats'
                  : 'Ingest Windows SetupAPI or Linux syslog connection audit logs'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Mode Selector Tabs */}
        <div className="flex gap-2 p-1 bg-slate-950 rounded-xl mb-5 border border-slate-800/80">
          <button
            type="button"
            onClick={() => {
              setActiveMode('scan')
              setStatusMessage(null)
            }}
            className={`flex-1 py-2 text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition ${
              activeMode === 'scan'
                ? 'bg-cyan-500 text-slate-950 shadow-md font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <HardDrive className="w-3.5 h-3.5" />
            <span>Scan USB Drive</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveMode('upload')
              setStatusMessage(null)
            }}
            className={`flex-1 py-2 text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition ${
              activeMode === 'upload'
                ? 'bg-cyan-500 text-slate-950 shadow-md font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Load System Logs</span>
          </button>
        </div>

        {/* Status Alert Banner */}
        {statusMessage && (
          <div
            className={`p-3 rounded-xl mb-4 text-xs flex items-start gap-2.5 border ${
              statusMessage.type === 'success'
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                : 'bg-red-950/40 border-red-500/40 text-red-300'
            }`}
          >
            {statusMessage.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
            ) : (
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
            )}
            <span>{statusMessage.text}</span>
          </div>
        )}

        {/* TAB 1: DIRECTORY / USB SCAN FORM */}
        {activeMode === 'scan' && (
          <form onSubmit={handleScanSubmit} className="space-y-4">
            {/* Detected Drives Selector */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Detected Removable Drives ({drivesList.length})</span>
                </label>
                <button
                  type="button"
                  onClick={refreshDrives}
                  disabled={isRefreshingDrives}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition disabled:opacity-50"
                  title="Rescan host for plugged USB drives"
                >
                  <RefreshCw className={`w-3 h-3 ${isRefreshingDrives ? 'animate-spin' : ''}`} />
                  <span>Rescan Drives</span>
                </button>
              </div>

              {drivesList.length > 0 ? (
                <div className="grid grid-cols-1 gap-2 mb-3">
                  {drivesList.map((d) => {
                    const isSelected = drivePath.toUpperCase().startsWith(d.mount_point.toUpperCase())
                    const freeGb = (d.free_bytes / 1024 ** 3).toFixed(1)
                    const totalGb = (d.total_bytes / 1024 ** 3).toFixed(1)
                    return (
                      <button
                        key={d.mount_point}
                        type="button"
                        onClick={() => {
                          setDrivePath(d.mount_point)
                          // Also try matching associated device
                          if (d.serial_number) {
                            const match = devices.find(
                              (dev) => dev.serial_number === d.serial_number || dev.volume_label?.includes(d.mount_point)
                            )
                            if (match) setSelectedDeviceId(match.id)
                          }
                        }}
                        className={`p-3 rounded-xl border text-left transition flex items-center justify-between ${
                          isSelected
                            ? 'border-cyan-500 bg-cyan-950/40 text-white shadow-sm shadow-cyan-950'
                            : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span className="px-2 py-1 rounded font-mono text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                            {d.mount_point}
                          </span>
                          <div>
                            <p className="text-xs font-semibold text-slate-100">{d.volume_label}</p>
                            <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                              {d.file_system || 'FAT'} • {freeGb} GB Free of {totalGb} GB ({d.percent_used.toFixed(0)}% used)
                            </p>
                          </div>
                        </div>
                        {isSelected ? (
                          <span className="text-[10px] px-2.5 py-0.5 rounded-full font-bold bg-cyan-500 text-slate-950">
                            Selected
                          </span>
                        ) : (
                          <span className="text-[10px] text-slate-500 group-hover:text-cyan-400">
                            Click to select
                          </span>
                        )}
                      </button>
                    )
                  })}
                </div>
              ) : (
                <div className="p-3 rounded-xl border border-dashed border-slate-800 bg-slate-950/40 text-center mb-3">
                  <p className="text-xs text-slate-400">No removable USB drives currently mounted.</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">Plug in a USB pendrive and click "Rescan Drives", or type path manually below.</p>
                </div>
              )}

              {/* Custom / Selected Path Input */}
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Target Inspection Path
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={drivePath}
                    onChange={(e) => setDrivePath(e.target.value)}
                    placeholder="e.g. D:\ or /media/usb"
                    className="flex-1 px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  {drivesList.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setDrivePath(drivesList[0].mount_point)}
                      className="px-3 py-2 text-xs font-mono rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                      title="Set to first detected pendrive"
                    >
                      Use {drivesList[0].mount_point}
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Associate with Recorded Device */}
            {devices.length > 0 && (
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Associate with Recorded Device (Optional)
                </label>
                <select
                  value={selectedDeviceId || ''}
                  onChange={(e) => setSelectedDeviceId(Number(e.target.value) || undefined)}
                  className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="">Auto-resolve from connected hardware</option>
                  {devices.map((d) => (
                    <option key={d.id} value={d.id}>
                      #{d.id} — {d.volume_label || d.serial_number} (VID:{d.vendor_id} PID:{d.product_id})
                    </option>
                  ))}
                </select>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading || !drivePath.trim()}
              className="w-full py-2.5 px-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-sm flex items-center justify-center gap-2 transition glow-cyan mt-2"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Streaming Files & Computing Integrity Hashes...
                </>
              ) : (
                <>
                  <FolderSearch className="w-4 h-4" />
                  <span>Initiate Integrity Inspection on {drivePath || 'Drive'}</span>
                </>
              )}
            </button>
          </form>
        )}

        {/* TAB 2: LOG INGESTION FORM */}
        {activeMode === 'upload' && (
          <div className="space-y-4">
            {/* 1-Click Live System Ingestion Banner */}
            <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/60 to-slate-900 border border-cyan-500/30 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Live Host System Ingestion</span>
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-1">
                  Directly read <span className="font-mono text-cyan-400">setupapi.dev.log</span> and Windows Registry on this PC to pull all physical USB connections.
                </p>
              </div>
              <button
                type="button"
                onClick={handleLiveLogIngest}
                disabled={isLoading}
                className="px-3.5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition shrink-0 ml-3 shadow-md shadow-cyan-950"
              >
                {isLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5" />}
                <span>Auto-Ingest Host Logs</span>
              </button>
            </div>

            <div className="relative flex py-1 items-center">
              <div className="flex-grow border-t border-slate-800"></div>
              <span className="flex-shrink mx-4 text-[10px] uppercase font-mono text-slate-500">Or Upload External File</span>
              <div className="flex-grow border-t border-slate-800"></div>
            </div>

            {/* Custom Log Upload Drag & Drop */}
            <form onSubmit={handleUploadSubmit} className="space-y-4">
              <div
                onDragOver={(e) => {
                  e.preventDefault()
                  setDragOver(true)
                }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`p-6 border-2 border-dashed rounded-xl flex flex-col items-center justify-center text-center cursor-pointer transition ${
                  dragOver
                    ? 'border-cyan-400 bg-cyan-950/30'
                    : selectedFile
                    ? 'border-emerald-500/60 bg-emerald-950/20'
                    : 'border-slate-800 hover:border-slate-700 bg-slate-950/40'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".log,.txt"
                  onChange={handleFileChange}
                  className="hidden"
                />
                <div className="p-2.5 rounded-full bg-slate-800/80 mb-2 text-cyan-400">
                  <Upload className="w-5 h-5" />
                </div>
                {selectedFile ? (
                  <div>
                    <p className="text-sm font-semibold text-emerald-300 font-mono">{selectedFile.name}</p>
                    <p className="text-xs text-slate-400 mt-0.5">
                      {(selectedFile.size / 1024).toFixed(1)} KB • Click to swap file
                    </p>
                  </div>
                ) : (
                  <div>
                    <p className="text-sm font-medium text-slate-200">
                      Drag and drop forensic log file
                    </p>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Supports Windows <span className="text-cyan-400 font-mono">setupapi.dev.log</span> or Linux <span className="text-emerald-400 font-mono">syslog</span>
                    </p>
                  </div>
                )}
              </div>

              <button
                type="submit"
                disabled={isLoading || !selectedFile}
                className="w-full py-2.5 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white font-semibold text-xs flex items-center justify-center gap-2 transition"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    Parsing Forensic Data...
                  </>
                ) : (
                  <>
                    <span>Parse Uploaded File</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  )
}
