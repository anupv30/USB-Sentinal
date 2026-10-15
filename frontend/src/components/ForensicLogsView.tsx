import React, { useState, useMemo } from 'react'
import {
  Terminal,
  Database,
  Upload,
  Clock,
  HardDrive,
  Copy,
  Check,
  Search,
  ChevronDown,
  ChevronRight,
  FileText,
  AlertCircle,
  Binary,
  Layers,
  Sparkles
} from 'lucide-react'
import { ForensicLog, ParsedLogRecord } from '../types'

interface ForensicLogsViewProps {
  logs: ForensicLog[]
  onIngestLiveLogs: () => void
  onOpenUploadModal: (defaultType?: 'windows' | 'linux') => void
  isIngestingLogs: boolean
}

interface LogPanelProps {
  title: string
  defaultPath: string
  logType: 'windows_setupapi' | 'linux_syslog'
  accentColor: 'cyan' | 'emerald'
  logs: ForensicLog[]
  onIngestLiveLogs?: () => void
  onOpenUploadModal: (defaultType?: 'windows' | 'linux') => void
  isIngestingLogs: boolean
}

function SingleLogPanel({
  title,
  defaultPath,
  logType,
  accentColor,
  logs,
  onIngestLiveLogs,
  onOpenUploadModal,
  isIngestingLogs,
}: LogPanelProps) {
  const [selectedLogIndex, setSelectedLogIndex] = useState<number>(0)
  const [viewMode, setViewMode] = useState<'parsed' | 'raw'>('parsed')
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [expandedSnippets, setExpandedSnippets] = useState<Record<string, boolean>>({})
  const [copiedRaw, setCopiedRaw] = useState<boolean>(false)

  // Current active log for this panel
  const currentLog: ForensicLog | undefined = logs[selectedLogIndex] || logs[0]

  const rawLines = useMemo(() => {
    if (!currentLog?.raw_content) return []
    return currentLog.raw_content.split(/\r?\n/)
  }, [currentLog?.raw_content])

  const filteredRawLines = useMemo(() => {
    if (!searchQuery.trim()) return rawLines
    const q = searchQuery.toLowerCase()
    return rawLines.filter((l) => l.toLowerCase().includes(q))
  }, [rawLines, searchQuery])

  const handleCopyRaw = () => {
    if (!currentLog?.raw_content) return
    navigator.clipboard.writeText(currentLog.raw_content)
    setCopiedRaw(true)
    setTimeout(() => setCopiedRaw(false), 2000)
  }

  const toggleSnippet = (serial: string) => {
    setExpandedSnippets((prev) => ({
      ...prev,
      [serial]: !prev[serial],
    }))
  }

  const isCyan = accentColor === 'cyan'
  const titleColor = isCyan ? 'text-cyan-300' : 'text-emerald-300'
  const badgeBg = isCyan ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
  const activeTabBg = isCyan ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40' : 'bg-emerald-500/20 text-emerald-200 border-emerald-500/40'

  return (
    <div className="border border-slate-800 bg-slate-900/60 rounded-2xl overflow-hidden flex flex-col shadow-xl">
      {/* Panel Header */}
      <div className="bg-slate-800/80 px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Terminal className={`w-4 h-4 ${isCyan ? 'text-cyan-400' : 'text-emerald-400'}`} />
          <span className={`text-xs font-bold font-mono ${titleColor}`}>{title}</span>
          <span className="text-[10px] text-slate-400 font-mono hidden sm:inline">{defaultPath}</span>
        </div>

        {/* Ingested Log Selector if multiple exist */}
        {logs.length > 1 && (
          <select
            value={selectedLogIndex}
            onChange={(e) => setSelectedLogIndex(Number(e.target.value))}
            aria-label={`Select ingested ${title}`}
            className="text-[11px] font-mono bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            {logs.map((l, idx) => (
              <option key={l.id} value={idx}>
                {l.source_name} ({new Date(l.ingested_at).toLocaleTimeString()})
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Main Panel Content: Empty State vs Real Forensic Evidence */}
      {!currentLog ? (
        /* REAL EMPTY STATE: No fabricated data */
        <div className="p-8 flex flex-col items-center justify-center text-center space-y-4 my-auto min-h-[380px]">
          <div className={`w-12 h-12 rounded-2xl flex items-center justify-center border ${badgeBg}`}>
            <AlertCircle className="w-6 h-6" />
          </div>
          <div className="max-w-sm space-y-1.5">
            <h4 className="text-sm font-bold text-white">No {title} Logs Ingested</h4>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              {logType === 'windows_setupapi'
                ? 'No Windows SetupAPI installation logs recorded yet. Ingest live host logs or upload a setupapi.dev.log file to parse real plug-and-play USB hardware events.'
                : 'No Linux syslog or dmesg kernel connection logs ingested yet. Upload an external syslog or dmesg file to extract physical USB bus identifiers.'}
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
            {logType === 'windows_setupapi' && onIngestLiveLogs && (
              <button
                onClick={onIngestLiveLogs}
                disabled={isIngestingLogs}
                className="px-3.5 py-1.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs font-mono flex items-center gap-1.5 transition glow-cyan"
              >
                <Database className={`w-3.5 h-3.5 ${isIngestingLogs ? 'animate-spin' : ''}`} />
                <span>{isIngestingLogs ? 'Ingesting...' : 'Auto-Ingest Host Logs'}</span>
              </button>
            )}
            <button
              onClick={() => onOpenUploadModal(logType === 'windows_setupapi' ? 'windows' : 'linux')}
              className="px-3.5 py-1.5 rounded-xl border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold flex items-center gap-1.5 transition"
            >
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              <span>Upload Log File</span>
            </button>
          </div>
        </div>
      ) : (
        /* REAL EVIDENCE VIEW */
        <div className="flex flex-col flex-1">
          {/* Metadata Bar */}
          <div className="bg-slate-950/60 border-b border-slate-800/80 px-4 py-2.5 flex flex-wrap items-center justify-between text-xs gap-3">
            <div className="flex flex-wrap items-center gap-3 text-slate-300">
              <span className="flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-cyan-400" />
                <strong className="text-white font-mono text-[11px]">{currentLog.source_name}</strong>
              </span>
              <span className="text-slate-500">•</span>
              <span className="flex items-center gap-1.5 text-slate-400 text-[11px]">
                <Clock className="w-3 h-3 text-slate-400" />
                <span>Ingested: {new Date(currentLog.ingested_at).toUTCString()}</span>
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-md border ${badgeBg}`}>
                {currentLog.parsed_devices_count} Devices Identified
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-slate-800 bg-slate-800/60 text-slate-400">
                {rawLines.length} Raw Lines
              </span>
            </div>
          </div>

          {/* Tab Navigation: Parsed Records vs Raw Evidence */}
          <div className="px-4 pt-2.5 pb-2 bg-slate-900/40 border-b border-slate-800/60 flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setViewMode('parsed')}
                className={`px-3 py-1 text-xs font-mono rounded-lg border transition flex items-center gap-1.5 ${
                  viewMode === 'parsed'
                    ? activeTabBg
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Binary className="w-3.5 h-3.5" />
                <span>Parsed Records ({currentLog.parsed_records.length})</span>
              </button>
              <button
                onClick={() => setViewMode('raw')}
                className={`px-3 py-1 text-xs font-mono rounded-lg border transition flex items-center gap-1.5 ${
                  viewMode === 'raw'
                    ? activeTabBg
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Raw Evidence Stream</span>
              </button>
            </div>

            {viewMode === 'raw' && (
              <button
                onClick={handleCopyRaw}
                className="px-2 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono flex items-center gap-1 transition"
                title="Copy entire raw forensic log"
              >
                {copiedRaw ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy Raw</span>
                  </>
                )}
              </button>
            )}
          </div>

          {/* VIEW TAB 1: PARSED STRUCTURED RECORDS */}
          {viewMode === 'parsed' && (
            <div className="p-4 space-y-3.5 overflow-y-auto max-h-[460px]">
              {currentLog.parsed_records.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-400 font-mono">
                  No USB hardware records identified in this log file.
                </div>
              ) : (
                currentLog.parsed_records.map((rec: ParsedLogRecord, rIdx: number) => {
                  const isExpanded = !!expandedSnippets[rec.serial_number]
                  return (
                    <div
                      key={rec.serial_number || rIdx}
                      className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/70 hover:border-slate-700 transition space-y-2.5 font-mono text-xs"
                    >
                      {/* Hardware Device Summary Row */}
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                        <div className="flex items-center gap-2">
                          <HardDrive className={`w-4 h-4 ${isCyan ? 'text-cyan-400' : 'text-emerald-400'}`} />
                          <span className="text-white font-bold text-xs">
                            {rec.volume_label || `USB Device (${rec.vendor_id}:${rec.product_id})`}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 text-[11px]">
                            VID: {rec.vendor_id}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 text-[11px]">
                            PID: {rec.product_id}
                          </span>
                        </div>
                      </div>

                      {/* Hardware Identifiers & Timestamps */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                        <div>
                          <span className="text-slate-500">Serial Number: </span>
                          <span className="text-slate-200 select-all font-mono break-all font-semibold">
                            {rec.serial_number}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500">Volume / Label: </span>
                          <span className="text-slate-300">
                            {rec.volume_label || 'None designated'}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500">First Connected: </span>
                          <span className="text-slate-300">
                            {rec.first_connected
                              ? new Date(rec.first_connected).toLocaleString()
                              : 'Not recorded in section'}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500">Last Seen: </span>
                          <span className="text-slate-300">
                            {rec.last_connected
                              ? new Date(rec.last_connected).toLocaleString()
                              : 'Not recorded in section'}
                          </span>
                        </div>
                      </div>

                      {/* Raw Evidence Snippet Accordion for this record */}
                      {rec.raw_lines && (
                        <div className="pt-1">
                          <button
                            onClick={() => toggleSnippet(rec.serial_number)}
                            className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
                          >
                            {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                            <span>
                              {isExpanded ? 'Hide Raw Evidence Lines' : 'Inspect Raw Evidence Snippet'} (
                              {rec.raw_lines.split('\n').length} lines)
                            </span>
                          </button>

                          {isExpanded && (
                            <pre className="mt-2 p-3 rounded-lg bg-black/80 border border-cyan-900/40 text-[10px] text-slate-300 overflow-x-auto leading-relaxed select-all">
                              {rec.raw_lines}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })
              )}
            </div>
          )}

          {/* VIEW TAB 2: RAW FORENSIC LOG STREAM */}
          {viewMode === 'raw' && (
            <div className="flex flex-col flex-1">
              {/* Search filter for raw log */}
              <div className="p-2.5 bg-slate-950/80 border-b border-slate-800 flex items-center gap-2">
                <Search className="w-3.5 h-3.5 text-slate-500" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter log lines (e.g., VID, Serial, Section start, Attached)..."
                  className="w-full bg-transparent text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none"
                />
                {searchQuery && (
                  <span className="text-[10px] font-mono text-slate-400 whitespace-nowrap">
                    {filteredRawLines.length} / {rawLines.length}
                  </span>
                )}
              </div>

              <div className="p-4 bg-slate-950/90 text-[11px] font-mono text-slate-300 overflow-x-auto overflow-y-auto max-h-[460px] leading-relaxed">
                {filteredRawLines.length === 0 ? (
                  <div className="p-4 text-center text-slate-500">
                    No log lines match &quot;{searchQuery}&quot;
                  </div>
                ) : (
                  filteredRawLines.map((line, idx) => {
                    const isSectionHeader = line.includes('>>>') || line.includes('<<<') || line.includes('[Device Install')
                    const isVidPid = line.includes('VID_') || line.includes('idVendor')
                    const isSerial = line.includes('SerialNumber') || line.includes('Disk')

                    let lineStyle = 'text-slate-300'
                    if (isSectionHeader) lineStyle = isCyan ? 'text-cyan-300 font-semibold' : 'text-emerald-300 font-semibold'
                    else if (isVidPid) lineStyle = 'text-amber-300 font-semibold'
                    else if (isSerial) lineStyle = 'text-purple-300'

                    return (
                      <div key={idx} className="flex hover:bg-slate-900/60 py-0.5 px-1 rounded">
                        <span className="w-10 text-right pr-3 select-none text-slate-600 font-mono text-[10px]">
                          {idx + 1}
                        </span>
                        <span className={`whitespace-pre-wrap break-all ${lineStyle}`}>{line}</span>
                      </div>
                    )
                  })
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function ForensicLogsView({
  logs,
  onIngestLiveLogs,
  onOpenUploadModal,
  isIngestingLogs,
}: ForensicLogsViewProps) {
  // Separate Windows setupapi logs from Linux syslog/dmesg logs
  const windowsLogs = useMemo(() => {
    return logs.filter((l) => l.log_type === 'windows_setupapi')
  }, [logs])

  const linuxLogs = useMemo(() => {
    return logs.filter((l) => l.log_type === 'linux_syslog' || l.log_type === 'linux_dmesg')
  }, [logs])

  return (
    <div className="space-y-4">
      {/* Top Banner & Control Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            Forensic USB System Logs
          </h2>
          <p className="text-xs text-slate-400">
            Real host device installation logs and kernel USB event evidence audit from the ingestion pipeline.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={onIngestLiveLogs}
            disabled={isIngestingLogs}
            className="px-3.5 py-1.5 rounded-xl border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs font-mono font-semibold flex items-center gap-1.5 transition glow-cyan"
          >
            <Database className={`w-3.5 h-3.5 ${isIngestingLogs ? 'animate-spin' : ''}`} />
            <span>{isIngestingLogs ? 'Ingesting Host Logs...' : 'Auto-Ingest Host Logs'}</span>
          </button>
          <button
            onClick={() => onOpenUploadModal()}
            className="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold flex items-center gap-1.5 transition"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Upload External Log</span>
          </button>
        </div>
      </div>

      {/* Grid of the 2 Forensic Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Panel 1: Windows SetupAPI */}
        <SingleLogPanel
          title="Windows setupapi.dev.log"
          defaultPath="C:\Windows\INF\setupapi.dev.log"
          logType="windows_setupapi"
          accentColor="cyan"
          logs={windowsLogs}
          onIngestLiveLogs={onIngestLiveLogs}
          onOpenUploadModal={onOpenUploadModal}
          isIngestingLogs={isIngestingLogs}
        />

        {/* Panel 2: Linux Syslog & Dmesg */}
        <SingleLogPanel
          title="Linux syslog & dmesg"
          defaultPath="/var/log/syslog"
          logType="linux_syslog"
          accentColor="emerald"
          logs={linuxLogs}
          onOpenUploadModal={onOpenUploadModal}
          isIngestingLogs={isIngestingLogs}
        />
      </div>
    </div>
  )
}
