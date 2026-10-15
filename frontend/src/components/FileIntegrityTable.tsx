import React, { useState, useMemo } from 'react'
import {
  FileText,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Search,
  Copy,
  Check,
  Filter,
  FileWarning,
  Binary,
  Layers,
  FileCode,
  HardDrive
} from 'lucide-react'
import { FileArtifact, Device } from '../types'

interface FileIntegrityTableProps {
  artifacts: FileArtifact[]
  devices: Device[]
  selectedDevice: Device | null
  onClearDeviceFilter: () => void
  onSelectDeviceFilter: (devId: number | 'all') => void
}

export const FileIntegrityTable: React.FC<FileIntegrityTableProps> = ({
  artifacts,
  devices,
  selectedDevice,
  onClearDeviceFilter,
  onSelectDeviceFilter,
}) => {
  const [searchTerm, setSearchTerm] = useState('')
  const [suspiciousOnly, setSuspiciousOnly] = useState(false)
  const [copiedHash, setCopiedHash] = useState<string | null>(null)
  const [selectedFileForModal, setSelectedFileForModal] = useState<FileArtifact | null>(null)

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopiedHash(label)
    setTimeout(() => setCopiedHash(null), 2000)
  }

  const filteredArtifacts = useMemo(() => {
    return artifacts.filter((a) => {
      const q = searchTerm.toLowerCase()
      const matchesSearch =
        searchTerm === '' ||
        a.file_path.toLowerCase().includes(q) ||
        (a.flag_reason && a.flag_reason.toLowerCase().includes(q)) ||
        (a.sha256_hash && a.sha256_hash.toLowerCase().includes(q))
      const matchesSusp = suspiciousOnly ? a.flag_suspicious : true
      const matchesDev = selectedDevice ? a.device_id === selectedDevice.id : true
      return matchesSearch && matchesSusp && matchesDev
    })
  }, [artifacts, searchTerm, suspiciousOnly, selectedDevice])

  const suspiciousCount = artifacts.filter((a) => a.flag_suspicious).length

  return (
    <div className="space-y-4">
      {/* Header and Control Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            File Manager & Cryptographic Integrity Table
          </h2>
          <p className="text-xs text-slate-400">
            Filesystem hierarchy, cryptographic digests (MD5 / SHA-256), and security threat alerts.
          </p>
        </div>

        {/* Device Active Filter Chip */}
        {selectedDevice && (
          <div className="flex items-center gap-2 text-xs bg-cyan-950 border border-cyan-800 text-cyan-300 px-3.5 py-1.5 rounded-xl">
            <HardDrive className="w-3.5 h-3.5" />
            <span>Filtering: <strong className="text-white">{selectedDevice.volume_label || selectedDevice.serial_number}</strong></span>
            <button
              onClick={onClearDeviceFilter}
              className="ml-2 font-bold hover:text-white bg-cyan-900/60 rounded px-1.5"
              title="Clear device filter"
            >
              ✕
            </button>
          </div>
        )}
      </div>

      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by file path, hash substring, or detection reason..."
            className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Device selector */}
        <select
          value={selectedDevice ? selectedDevice.id : 'all'}
          onChange={(e) => onSelectDeviceFilter(e.target.value === 'all' ? 'all' : Number(e.target.value))}
          className="px-3.5 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
        >
          <option value="all">All Devices ({devices.length})</option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              Device #{d.id}: {d.volume_label || d.serial_number}
            </option>
          ))}
        </select>

        {/* Show Suspicious Only Toggle Switch */}
        <button
          onClick={() => setSuspiciousOnly(!suspiciousOnly)}
          className={`px-4 py-2 rounded-xl text-xs font-semibold border flex items-center gap-2 transition ${
            suspiciousOnly
              ? 'bg-red-950 border-red-700 text-red-200 glow-red'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className={`w-4 h-4 ${suspiciousOnly ? 'text-red-400' : 'text-slate-500'}`} />
          <span>Show Suspicious Only</span>
          <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono ${
            suspiciousOnly ? 'bg-red-900 text-white' : 'bg-slate-800 text-slate-400'
          }`}>
            {suspiciousCount}
          </span>
        </button>
      </div>

      {/* Main Files Table */}
      <div className="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-800/60 text-slate-400 uppercase font-mono tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-3.5 px-4">Integrity Status</th>
              <th className="py-3.5 px-4">File Name & Path</th>
              <th className="py-3.5 px-4">Size</th>
              <th className="py-3.5 px-4">Cryptographic Hashes</th>
              <th className="py-3.5 px-4">Security Assessment</th>
              <th className="py-3.5 px-4 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80 font-mono">
            {filteredArtifacts.map((art) => (
              <tr key={art.id} className="hover:bg-slate-800/40 transition">
                {/* Status Column */}
                <td className="py-3.5 px-4">
                  {art.flag_suspicious ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-950 border border-red-800 text-red-300 text-[10px] font-bold">
                      <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                      SUSPICIOUS
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-300 text-[10px] font-bold">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      CLEAN
                    </span>
                  )}
                </td>

                {/* File Path Column */}
                <td className="py-3.5 px-4">
                  <div className="flex items-center gap-2.5">
                    {art.flag_suspicious ? (
                      <FileWarning className="w-4 h-4 text-red-400 shrink-0" />
                    ) : (
                      <FileText className="w-4 h-4 text-slate-400 shrink-0" />
                    )}
                    <span className="text-white font-medium text-xs break-all">
                      {art.file_path}
                    </span>
                  </div>
                </td>

                {/* Size Column */}
                <td className="py-3.5 px-4 text-slate-300">
                  {art.file_size < 1024
                    ? `${art.file_size} B`
                    : `${(art.file_size / 1024).toFixed(1)} KB`}
                </td>

                {/* Hashes Column */}
                <td className="py-3.5 px-4">
                  <div className="space-y-1">
                    {art.sha256_hash && (
                      <div className="flex items-center gap-1.5 text-[10px]">
                        <span className="text-cyan-400 font-bold">SHA256:</span>
                        <span className="text-slate-400 font-mono">{art.sha256_hash.slice(0, 12)}...{art.sha256_hash.slice(-6)}</span>
                        <button
                          onClick={() => copyToClipboard(art.sha256_hash!, `sha-${art.id}`)}
                          className="text-slate-500 hover:text-cyan-300 p-0.5 rounded transition"
                          title="Copy SHA-256"
                        >
                          {copiedHash === `sha-${art.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    )}
                    {art.md5_hash && (
                      <div className="flex items-center gap-1.5 text-[10px]">
                        <span className="text-slate-500 font-bold">MD5:</span>
                        <span className="text-slate-500 font-mono">{art.md5_hash.slice(0, 10)}...</span>
                        <button
                          onClick={() => copyToClipboard(art.md5_hash!, `md5-${art.id}`)}
                          className="text-slate-500 hover:text-cyan-300 p-0.5 rounded transition"
                          title="Copy MD5"
                        >
                          {copiedHash === `md5-${art.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    )}
                  </div>
                </td>

                {/* Threat Reason Column */}
                <td className="py-3.5 px-4 max-w-xs font-sans text-xs">
                  {art.flag_reason ? (
                    <span className="text-red-300 text-[11px] block leading-tight">
                      {art.flag_reason}
                    </span>
                  ) : (
                    <span className="text-slate-500 text-[11px]">Normal document/asset</span>
                  )}
                </td>

                {/* Action Details Column */}
                <td className="py-3.5 px-4 text-right">
                  <button
                    onClick={() => setSelectedFileForModal(art)}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono transition"
                  >
                    Inspect
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Forensic Inspection Modal */}
      {selectedFileForModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="relative w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4 font-mono">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Binary className="w-4 h-4 text-cyan-400" />
                Forensic File Properties
              </h3>
              <button
                onClick={() => setSelectedFileForModal(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <p className="text-slate-500 uppercase text-[10px]">File Path</p>
                <p className="text-slate-200 font-semibold break-all">{selectedFileForModal.file_path}</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-slate-500 uppercase text-[10px]">Size</p>
                  <p className="text-slate-300">{selectedFileForModal.file_size} bytes</p>
                </div>
                <div>
                  <p className="text-slate-500 uppercase text-[10px]">Associated Device</p>
                  <p className="text-slate-300">Device #{selectedFileForModal.device_id}</p>
                </div>
              </div>

              <div>
                <p className="text-slate-500 uppercase text-[10px]">SHA-256 Digest</p>
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] text-cyan-300 break-all select-all">
                  {selectedFileForModal.sha256_hash || 'N/A'}
                </div>
              </div>

              <div>
                <p className="text-slate-500 uppercase text-[10px]">MD5 Digest</p>
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-300 break-all select-all">
                  {selectedFileForModal.md5_hash || 'N/A'}
                </div>
              </div>

              {selectedFileForModal.flag_reason && (
                <div className="p-3 rounded-xl border border-red-800 bg-red-950/40 text-red-200">
                  <p className="text-[10px] uppercase font-bold text-red-400 mb-1">Threat Assessment</p>
                  <p className="font-sans text-xs">{selectedFileForModal.flag_reason}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
