import React, { useState, useEffect, useCallback } from 'react'
import {
  HardDrive,
  ShieldAlert,
  FileText,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Cpu,
  Layers,
  Search,
  RefreshCw,
  Activity,
  Plus,
  Clock,
  Binary,
  Radio,
  FileWarning,
  Sparkles,
  ArrowRight,
  Usb,
  FolderSearch,
  Database
} from 'lucide-react'
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts'

import { Device, FileArtifact, TimelineItem, StatsMetrics, DetectedDrive, ForensicLog } from './types'
import { fetchHealth, fetchStats, fetchDevices, fetchTimeline, fetchFiles, detectDrives, ingestLiveSystemLogs, fetchForensicLogs } from './api'
import { LogUploadAndScanModal } from './components/LogUploadAndScanModal'
import { TimelineChart } from './components/TimelineChart'
import { DevicesTable } from './components/DevicesTable'
import { FileIntegrityTable } from './components/FileIntegrityTable'
import { ForensicLogsView } from './components/ForensicLogsView'

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'timeline' | 'devices' | 'files' | 'logs'>('dashboard')
  const [devices, setDevices] = useState<Device[]>([])
  const [artifacts, setArtifacts] = useState<FileArtifact[]>([])
  const [timelineEvents, setTimelineEvents] = useState<TimelineItem[]>([])
  const [detectedDrives, setDetectedDrives] = useState<DetectedDrive[]>([])
  const [preselectedDrive, setPreselectedDrive] = useState<string>('')
  const [stats, setStats] = useState<StatsMetrics>({
    total_devices: 0,
    total_files_scanned: 0,
    flagged_suspicious_files: 0,
    clean_files: 0,
    recent_connections: [],
  })
  const [isApiOnline, setIsApiOnline] = useState<boolean>(false)
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false)
  const [isDetectingDrives, setIsDetectingDrives] = useState<boolean>(false)
  const [isIngestingLogs, setIsIngestingLogs] = useState<boolean>(false)
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false)
  const [selectedDeviceFilter, setSelectedDeviceFilter] = useState<Device | null>(null)
  const [forensicLogs, setForensicLogs] = useState<ForensicLog[]>([])

  // Load all live forensics data from backend
  const loadData = useCallback(async () => {
    setIsRefreshing(true)
    try {
      await fetchHealth()
      setIsApiOnline(true)

      const [statsData, devicesData, timelineData, filesData, drivesData, logsData] = await Promise.all([
        fetchStats(),
        fetchDevices(),
        fetchTimeline(),
        fetchFiles(),
        detectDrives().catch(() => []),
        fetchForensicLogs().catch(() => []),
      ])

      setStats(statsData)
      setDevices(devicesData)
      setTimelineEvents(timelineData)
      setArtifacts(filesData)
      setDetectedDrives(drivesData)
      setForensicLogs(logsData)

      if (drivesData.length > 0 && !preselectedDrive) {
        setPreselectedDrive(drivesData[0].mount_point)
      }
    } catch (err) {
      console.warn('API connection error:', err)
      setIsApiOnline(false)
    } finally {
      setIsRefreshing(false)
    }
  }, [preselectedDrive])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Explicit physical drive detection handler
  const handleDetectDrives = async () => {
    setIsDetectingDrives(true)
    try {
      const live = await detectDrives()
      setDetectedDrives(live)
      if (live.length > 0) {
        setPreselectedDrive(live[0].mount_point)
      }
    } catch (err) {
      console.error('Failed to detect drives:', err)
    } finally {
      setIsDetectingDrives(false)
    }
  }

  // 1-Click System Log Ingestion
  const handleIngestLiveLogs = async () => {
    setIsIngestingLogs(true)
    try {
      await ingestLiveSystemLogs()
      await loadData()
    } catch (err) {
      console.error('Failed to ingest live logs:', err)
    } finally {
      setIsIngestingLogs(false)
    }
  }

  const suspiciousCount = stats.flagged_suspicious_files
  const cleanCount = stats.clean_files

  const pieData = [
    { name: 'Clean Files', value: cleanCount || 0, color: '#10b981' },
    { name: 'Suspicious Threats', value: suspiciousCount || 0, color: '#ef4444' },
  ]

  const barData = devices.slice(0, 8).map((d) => ({
    name: d.volume_label ? d.volume_label.slice(0, 14) : `Dev #${d.id}`,
    total: d.total_artifacts,
    threats: d.suspicious_count,
  }))

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-white">
      {/* Primary Cyber Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-3.5">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 glow-cyan">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-2">
                USB Sentinel
                <span className="text-[10px] px-2 py-0.5 rounded-full font-mono bg-cyan-950 border border-cyan-800 text-cyan-300">
                  Forensic Live
                </span>
              </h1>
            </div>
            <p className="text-xs text-slate-400">Automated Removable Media Forensics & Integrity Engine</p>
          </div>
        </div>

        {/* Global Status Badges & CTAs */}
        <div className="flex items-center gap-3">
          {/* Detect Connected USBs Button */}
          <button
            onClick={handleDetectDrives}
            disabled={isDetectingDrives}
            className={`px-3.5 py-1.5 rounded-xl border text-xs font-semibold flex items-center gap-2 transition ${
              detectedDrives.length > 0
                ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50'
                : 'border-slate-800 bg-slate-900 hover:border-slate-700 text-slate-300'
            }`}
            title="Scan system for physically plugged USB drives"
          >
            <Usb className={`w-3.5 h-3.5 ${isDetectingDrives ? 'animate-spin' : detectedDrives.length > 0 ? 'text-emerald-400' : 'text-slate-400'}`} />
            <span>
              {isDetectingDrives
                ? 'Scanning USBs...'
                : detectedDrives.length > 0
                ? `${detectedDrives.length} Removable USB Connected`
                : 'Detect Connected USBs'}
            </span>
            {detectedDrives.length > 0 && (
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping shrink-0" />
            )}
          </button>

          <button
            onClick={() => {
              if (detectedDrives.length > 0) {
                setPreselectedDrive(detectedDrives[0].mount_point)
              }
              setIsModalOpen(true)
            }}
            className="px-3.5 py-1.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition glow-cyan"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Scan Drive / Ingest Logs</span>
          </button>

          <button
            onClick={loadData}
            disabled={isRefreshing}
            className="p-2 rounded-xl border border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition"
            title="Refresh Forensic Data"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>

          <div
            className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded-xl border font-mono ${
              isApiOnline
                ? 'border-emerald-800 bg-emerald-950/60 text-emerald-400'
                : 'border-amber-800 bg-amber-950/40 text-amber-400'
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${isApiOnline ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'}`} />
            <span>{isApiOnline ? 'API Connected' : 'Offline'}</span>
          </div>
        </div>
      </header>

      {/* Main Container Layout */}
      <div className="flex-1 flex flex-col md:flex-row">
        {/* Sleek Sidebar Navigation */}
        <aside className="w-full md:w-64 border-r border-slate-800 bg-slate-900/30 p-4 space-y-1.5 shrink-0">
          <div className="text-[10px] uppercase font-bold tracking-wider text-slate-500 px-3 py-2">
            Investigation Suite
          </div>

          <button
            onClick={() => setActiveTab('dashboard')}
            className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
              activeTab === 'dashboard'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-bold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Dashboard Overview</span>
          </button>

          <button
            onClick={() => setActiveTab('timeline')}
            className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
              activeTab === 'timeline'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-bold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <div className="flex items-center gap-3">
              <Clock className="w-4 h-4" />
              <span>Forensic Timeline</span>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
              {timelineEvents.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('devices')}
            className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
              activeTab === 'devices'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-bold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <div className="flex items-center gap-3">
              <Cpu className="w-4 h-4" />
              <span>Connected Devices</span>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
              {devices.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('files')}
            className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
              activeTab === 'files'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-bold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <div className="flex items-center gap-3">
              <FileText className="w-4 h-4" />
              <span>File Integrity Table</span>
            </div>
            <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold ${
              stats.flagged_suspicious_files > 0
                ? 'bg-red-950 border border-red-800 text-red-300'
                : 'bg-slate-800 text-slate-400'
            }`}>
              {stats.flagged_suspicious_files} !
            </span>
          </button>

          <div className="pt-4 text-[10px] uppercase font-bold tracking-wider text-slate-500 px-3 py-2">
            Inspection & Parsers
          </div>

          <button
            onClick={() => setActiveTab('logs')}
            className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
              activeTab === 'logs'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-bold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Forensic Log View</span>
          </button>
        </aside>

        {/* Dynamic Center Work Area */}
        <main className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* PROMINENT LIVE USB AUTO-DETECTION BANNER */}
          {detectedDrives.length > 0 && (
            <div className="p-4 rounded-2xl bg-gradient-to-r from-cyan-950/80 via-slate-900 to-slate-900 border border-cyan-500/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-xl shadow-cyan-950/20">
              <div className="flex items-center gap-3.5">
                <div className="p-3 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 shrink-0">
                  <HardDrive className="w-6 h-6 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Physical USB Storage Detected</span>
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full font-mono bg-cyan-900/60 text-cyan-200 border border-cyan-700/50">
                      {detectedDrives[0].mount_point} • {detectedDrives[0].file_system || 'exFAT'}
                    </span>
                  </div>
                  <p className="text-sm font-semibold text-white mt-1">
                    {detectedDrives[0].volume_label} — {(detectedDrives[0].free_bytes / 1024 ** 3).toFixed(1)} GB Free of {(detectedDrives[0].total_bytes / 1024 ** 3).toFixed(1)} GB
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setPreselectedDrive(detectedDrives[0].mount_point)
                    setIsModalOpen(true)
                  }}
                  className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition shadow-md shadow-cyan-500/20 shrink-0"
                >
                  <FolderSearch className="w-3.5 h-3.5" />
                  <span>Scan Connected Drive ({detectedDrives[0].mount_point})</span>
                </button>
              </div>
            </div>
          )}

          {/* EMPTY STATE BANNER WHEN NO DEVICES IN DATABASE */}
          {devices.length === 0 && (
            <div className="p-8 rounded-2xl border-2 border-dashed border-slate-800 bg-slate-900/30 text-center space-y-4">
              <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mx-auto">
                <Usb className="w-7 h-7" />
              </div>
              <div className="max-w-md mx-auto">
                <h3 className="text-base font-bold text-white">No USB Devices Recorded Yet</h3>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                  Database is completely empty. Plug in a USB drive and click <strong className="text-cyan-300">Scan Drive</strong> or automatically pull device connection history from the operating system with <strong className="text-cyan-300">Load System Logs</strong>.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                <button
                  onClick={handleIngestLiveLogs}
                  disabled={isIngestingLogs}
                  className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs flex items-center gap-2 transition glow-cyan"
                >
                  <Database className={`w-3.5 h-3.5 ${isIngestingLogs ? 'animate-spin' : ''}`} />
                  <span>{isIngestingLogs ? 'Ingesting Logs...' : 'Load System Logs (SetupAPI)'}</span>
                </button>
                <button
                  onClick={() => {
                    if (detectedDrives.length > 0) {
                      setPreselectedDrive(detectedDrives[0].mount_point)
                    }
                    setIsModalOpen(true)
                  }}
                  className="px-4 py-2 rounded-xl border border-slate-700 bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs flex items-center gap-2 transition"
                >
                  <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Scan Drive</span>
                </button>
              </div>
            </div>
          )}

          {/* Top 4 Cyber Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Card 1: Devices */}
            <div className="p-4 rounded-2xl border border-slate-800 bg-slate-900/50 flex items-center gap-4">
              <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
                <HardDrive className="w-5 h-5" />
              </div>
              <div>
                <p className="text-[11px] text-slate-400 font-medium">Total USB Devices</p>
                <p className="text-2xl font-bold font-mono text-white tracking-tight">{stats.total_devices}</p>
              </div>
            </div>

            {/* Card 2: Files Scanned */}
            <div className="p-4 rounded-2xl border border-slate-800 bg-slate-900/50 flex items-center gap-4">
              <div className="p-3 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
                <Layers className="w-5 h-5" />
              </div>
              <div>
                <p className="text-[11px] text-slate-400 font-medium">Total Files Indexed</p>
                <p className="text-2xl font-bold font-mono text-white tracking-tight">{stats.total_files_scanned}</p>
              </div>
            </div>

            {/* Card 3: Suspicious Threats */}
            <div className="p-4 rounded-2xl border border-red-900/40 bg-red-950/20 flex items-center gap-4">
              <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <p className="text-[11px] text-red-400 font-medium">High-Risk Flagged</p>
                <p className="text-2xl font-bold font-mono text-red-300 tracking-tight">{stats.flagged_suspicious_files}</p>
              </div>
            </div>

            {/* Card 4: Verified Clean */}
            <div className="p-4 rounded-2xl border border-emerald-900/40 bg-emerald-950/20 flex items-center gap-4">
              <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div>
                <p className="text-[11px] text-emerald-400 font-medium">Verified Clean Files</p>
                <p className="text-2xl font-bold font-mono text-emerald-300 tracking-tight">{stats.clean_files}</p>
              </div>
            </div>
          </div>

          {/* TAB 1: DASHBOARD OVERVIEW */}
          {activeTab === 'dashboard' && devices.length > 0 && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Visual Chart 1: Threat Distribution */}
                <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40">
                  <h3 className="text-xs font-bold font-mono uppercase text-cyan-300 tracking-wider mb-4 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    Threat Risk Ratio
                  </h3>
                  <div className="h-64 w-full">
                    {artifacts.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={pieData}
                            dataKey="value"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            outerRadius={85}
                            innerRadius={50}
                            paddingAngle={6}
                          >
                            {pieData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                          </Pie>
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#090d16',
                              borderColor: '#334155',
                              borderRadius: '0.75rem',
                              fontFamily: 'monospace',
                              fontSize: '12px',
                            }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
                        No files scanned yet. Initiate a drive scan to view metrics.
                      </div>
                    )}
                  </div>
                </div>

                {/* Visual Chart 2: Artifacts per Volume */}
                <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40">
                  <h3 className="text-xs font-bold font-mono uppercase text-cyan-300 tracking-wider mb-4 flex items-center gap-2">
                    <HardDrive className="w-4 h-4 text-cyan-400" />
                    Volume Artifact Density
                  </h3>
                  <div className="h-64 w-full">
                    {barData.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                          <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                          <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#090d16',
                              borderColor: '#334155',
                              borderRadius: '0.75rem',
                              fontFamily: 'monospace',
                              fontSize: '12px',
                            }}
                          />
                          <Bar dataKey="total" fill="#06b6d4" name="Total Files" radius={[4, 4, 0, 0]} />
                          <Bar dataKey="threats" fill="#ef4444" name="Threats" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
                        No device volume history recorded.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* High Priority Alerts List */}
              {artifacts.filter((a) => a.flag_suspicious).length > 0 && (
                <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold font-mono uppercase text-red-400 tracking-wider flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      High Priority Flagged Artifacts ({artifacts.filter((a) => a.flag_suspicious).length})
                    </h3>
                    <button
                      onClick={() => setActiveTab('files')}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
                    >
                      Open File Integrity Manager →
                    </button>
                  </div>

                  <div className="space-y-2">
                    {artifacts.filter((a) => a.flag_suspicious).slice(0, 4).map((a) => (
                      <div
                        key={a.id}
                        className="p-3.5 rounded-xl border border-red-900/40 bg-red-950/20 flex items-start justify-between gap-4 font-mono text-xs"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <FileWarning className="w-4 h-4 text-red-400 shrink-0" />
                            <span className="text-white font-bold">{a.file_path}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-red-900/50 text-red-300">
                              {a.file_size} B
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 font-sans pl-6">{a.flag_reason}</p>
                        </div>
                        <span className="text-[11px] text-slate-500 shrink-0">Device #{a.device_id}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: INTERACTIVE TIMELINE */}
          {activeTab === 'timeline' && (
            <TimelineChart
              events={timelineEvents}
              devices={devices}
              onSelectDevice={(device) => {
                setSelectedDeviceFilter(device)
                setActiveTab('files')
              }}
            />
          )}

          {/* TAB 3: CONNECTED DEVICES */}
          {activeTab === 'devices' && (
            <DevicesTable
              devices={devices}
              onFilterFiles={(device) => {
                setSelectedDeviceFilter(device)
                setActiveTab('files')
              }}
            />
          )}

          {/* TAB 4: FILE INTEGRITY MANAGER */}
          {activeTab === 'files' && (
            <FileIntegrityTable
              artifacts={artifacts}
              devices={devices}
              selectedDevice={selectedDeviceFilter}
              onClearDeviceFilter={() => setSelectedDeviceFilter(null)}
              onSelectDeviceFilter={(devId) => {
                if (devId === 'all') {
                  setSelectedDeviceFilter(null)
                } else {
                  const found = devices.find((d) => d.id === devId) || null
                  setSelectedDeviceFilter(found)
                }
              }}
            />
          )}

          {/* TAB 5: FORENSIC LOG & INSPECTION VIEW */}
          {activeTab === 'logs' && (
            <ForensicLogsView
              logs={forensicLogs}
              onIngestLiveLogs={handleIngestLiveLogs}
              onOpenUploadModal={() => setIsModalOpen(true)}
              isIngestingLogs={isIngestingLogs}
            />
          )}
        </main>
      </div>

      {/* Upload and Scan Modal */}
      <LogUploadAndScanModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={loadData}
        devices={devices}
        detectedDrives={detectedDrives}
        initialDrivePath={preselectedDrive}
      />
    </div>
  )
}
