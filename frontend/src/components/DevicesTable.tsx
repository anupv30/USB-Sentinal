import React, { useState } from 'react'
import {
  HardDrive,
  Copy,
  Check,
  Search,
  Filter,
  ChevronRight,
  ShieldAlert,
  Cpu,
  Calendar,
  Layers
} from 'lucide-react'
import { Device } from '../types'

interface DevicesTableProps {
  devices: Device[]
  onFilterFiles: (device: Device) => void
}

export const DevicesTable: React.FC<DevicesTableProps> = ({
  devices,
  onFilterFiles,
}) => {
  const [searchTerm, setSearchTerm] = useState('')
  const [copiedSerial, setCopiedSerial] = useState<string | null>(null)

  const copyToClipboard = (serial: string) => {
    navigator.clipboard.writeText(serial)
    setCopiedSerial(serial)
    setTimeout(() => setCopiedSerial(null), 2000)
  }

  const filteredDevices = devices.filter((d) => {
    const q = searchTerm.toLowerCase()
    return (
      d.serial_number.toLowerCase().includes(q) ||
      d.vendor_id.toLowerCase().includes(q) ||
      d.product_id.toLowerCase().includes(q) ||
      (d.volume_label && d.volume_label.toLowerCase().includes(q))
    )
  })

  return (
    <div className="space-y-4">
      {/* Table Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            Connected USB Hardware Devices
          </h2>
          <p className="text-xs text-slate-400">
            Catalog of physical USB mass storage and keystroke injection endpoints.
          </p>
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search VID, PID, serial, label..."
            className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Devices Data Table */}
      <div className="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-800/60 text-slate-400 uppercase font-mono tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-3.5 px-4">Device</th>
              <th className="py-3.5 px-4">Hardware IDs</th>
              <th className="py-3.5 px-4">Serial Number</th>
              <th className="py-3.5 px-4">First Connected</th>
              <th className="py-3.5 px-4">Last Seen</th>
              <th className="py-3.5 px-4 text-center">Threat Status</th>
              <th className="py-3.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80 font-mono">
            {filteredDevices.map((d) => (
              <tr key={d.id} className="hover:bg-slate-800/40 transition">
                <td className="py-3.5 px-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                      <HardDrive className="w-4 h-4" />
                    </div>
                    <div>
                      <span className="font-bold text-white text-xs block">
                        {d.volume_label || 'Unnamed Removable Disk'}
                      </span>
                      <span className="text-[10px] text-slate-500">ID #{d.id}</span>
                    </div>
                  </div>
                </td>

                <td className="py-3.5 px-4">
                  <span className="px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[11px]">
                    VID:{d.vendor_id} | PID:{d.product_id}
                  </span>
                </td>

                <td className="py-3.5 px-4">
                  <div className="flex items-center gap-1.5">
                    <span className="text-slate-300 font-mono text-[11px]" title={d.serial_number}>
                      {d.serial_number.length > 20
                        ? `${d.serial_number.slice(0, 16)}...`
                        : d.serial_number}
                    </span>
                    <button
                      onClick={() => copyToClipboard(d.serial_number)}
                      className="p-1 text-slate-500 hover:text-cyan-400 rounded transition"
                      title="Copy Serial Number"
                    >
                      {copiedSerial === d.serial_number ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </td>

                <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                  {d.first_connected?.slice(0, 19).replace('T', ' ') || 'N/A'}
                </td>

                <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                  {d.last_connected?.slice(0, 19).replace('T', ' ') || 'N/A'}
                </td>

                <td className="py-3.5 px-4 text-center">
                  {d.suspicious_count > 0 ? (
                    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-red-950/80 border border-red-800 text-red-300 text-[10px] font-semibold">
                      <ShieldAlert className="w-3 h-3 text-red-400" />
                      {d.suspicious_count} Threats Flagged
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-[10px] font-semibold">
                      Clean Volume
                    </span>
                  )}
                </td>

                <td className="py-3.5 px-4 text-right">
                  <button
                    onClick={() => onFilterFiles(d)}
                    className="px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs font-semibold inline-flex items-center gap-1 transition"
                  >
                    <span>View Files ({d.total_artifacts})</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
