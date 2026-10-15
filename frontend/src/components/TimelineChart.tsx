import React, { useState, useMemo } from 'react'
import {
  Clock,
  Filter,
  ArrowUpDown,
  Search,
  HardDrive,
  Calendar,
  Layers,
  ChevronRight,
  ShieldCheck,
  CheckCircle2
} from 'lucide-react'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts'
import { TimelineItem, Device } from '../types'

interface TimelineChartProps {
  events: TimelineItem[]
  devices: Device[]
  onSelectDevice: (device: Device) => void
}

type TimelineFilterType =
  | 'all'
  | 'USB INSERTED'
  | 'USB DISCONNECTED'
  | 'FIRST OBSERVED'
  | 'LAST OBSERVED'

export const TimelineChart: React.FC<TimelineChartProps> = ({
  events,
  devices,
  onSelectDevice,
}) => {
  const [selectedDeviceId, setSelectedDeviceId] = useState<number | 'all'>('all')
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc')
  const [eventTypeFilter, setEventTypeFilter] = useState<TimelineFilterType>('all')
  const [searchTerm, setSearchTerm] = useState('')

  // Filtered timeline events
  const filteredEvents = useMemo(() => {
    return events
      .filter((e) => {
        const matchesDev = selectedDeviceId === 'all' || e.device_id === selectedDeviceId
        const matchesType =
          eventTypeFilter === 'all' ||
          e.event_type === eventTypeFilter ||
          (eventTypeFilter === 'USB INSERTED' && e.event_type === 'FIRST_CONNECTED') ||
          (eventTypeFilter === 'LAST OBSERVED' && e.event_type === 'LAST_SEEN')
        const matchesSearch =
          searchTerm === '' ||
          e.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
          e.serial_number.toLowerCase().includes(searchTerm.toLowerCase()) ||
          (e.volume_label && e.volume_label.toLowerCase().includes(searchTerm.toLowerCase()))
        return matchesDev && matchesType && matchesSearch
      })
      .sort((a, b) => {
        const timeA = a.timestamp ? new Date(a.timestamp).getTime() : 0
        const timeB = b.timestamp ? new Date(b.timestamp).getTime() : 0
        return sortOrder === 'desc' ? timeB - timeA : timeA - timeB
      })
  }, [events, selectedDeviceId, eventTypeFilter, searchTerm, sortOrder])

  // Aggregated histogram for Recharts visualization over days/hours
  const chartData = useMemo(() => {
    const buckets: {
      [key: string]: {
        date: string
        inserts: number
        disconnects: number
        observed: number
        total: number
      }
    } = {}

    events.forEach((evt) => {
      if (!evt.timestamp) return
      const dateStr = evt.timestamp.slice(0, 10) // YYYY-MM-DD
      if (!buckets[dateStr]) {
        buckets[dateStr] = { date: dateStr, inserts: 0, disconnects: 0, observed: 0, total: 0 }
      }
      if (evt.event_type === 'USB INSERTED' || evt.event_type === 'FIRST_CONNECTED') {
        buckets[dateStr].inserts += 1
      } else if (evt.event_type === 'USB DISCONNECTED') {
        buckets[dateStr].disconnects += 1
      } else {
        buckets[dateStr].observed += 1
      }
      buckets[dateStr].total += 1
    })

    const result = Object.values(buckets).sort((a, b) => a.date.localeCompare(b.date))
    return result.length > 0
      ? result
      : [
          { date: '2026-09-20', inserts: 1, disconnects: 0, observed: 1, total: 2 },
          { date: '2026-09-28', inserts: 1, disconnects: 0, observed: 1, total: 2 },
          { date: '2026-10-02', inserts: 1, disconnects: 0, observed: 1, total: 2 },
        ]
  }, [events])

  const getEventMeta = (type: string) => {
    switch (type) {
      case 'USB INSERTED':
      case 'FIRST_CONNECTED':
        return {
          label: 'USB Inserted',
          pillClass: 'bg-emerald-950 text-emerald-300 border-emerald-800',
          dotClass: 'border-emerald-400 bg-emerald-950 shadow-[0_0_12px_rgba(16,185,129,0.3)]',
          badge: 'CONFIRMED',
          badgeClass: 'bg-emerald-900/60 text-emerald-300 border-emerald-700',
        }
      case 'USB DISCONNECTED':
        return {
          label: 'USB Disconnected',
          pillClass: 'bg-rose-950 text-rose-300 border-rose-800',
          dotClass: 'border-rose-400 bg-rose-950 shadow-[0_0_12px_rgba(244,63,94,0.3)]',
          badge: 'CONFIRMED',
          badgeClass: 'bg-rose-900/60 text-rose-300 border-rose-700',
        }
      case 'FIRST OBSERVED':
        return {
          label: 'First Observed',
          pillClass: 'bg-blue-950 text-blue-300 border-blue-800',
          dotClass: 'border-blue-400 bg-blue-950 shadow-[0_0_12px_rgba(96,165,250,0.3)]',
          badge: 'INFERRED',
          badgeClass: 'bg-blue-900/60 text-blue-300 border-blue-700',
        }
      case 'LAST OBSERVED':
      case 'LAST_SEEN':
      default:
        return {
          label: 'Last Observed',
          pillClass: 'bg-indigo-950 text-indigo-300 border-indigo-800',
          dotClass: 'border-indigo-400 bg-indigo-950 shadow-[0_0_12px_rgba(129,140,248,0.3)]',
          badge: 'INFERRED',
          badgeClass: 'bg-indigo-900/60 text-indigo-300 border-indigo-700',
        }
    }
  }

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Clock className="w-5 h-5 text-cyan-400" />
            Interactive Forensic Timeline
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit hardware connect & disconnect history mapped over chronological events.
          </p>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Device selector */}
          <select
            value={selectedDeviceId}
            onChange={(e) =>
              setSelectedDeviceId(e.target.value === 'all' ? 'all' : Number(e.target.value))
            }
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Devices ({devices.length})</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                #{d.id}: {d.volume_label || d.serial_number.slice(0, 10)}
              </option>
            ))}
          </select>

          {/* Event type filter */}
          <select
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value as TimelineFilterType)}
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Events</option>
            <option value="USB INSERTED">USB Inserted (Confirmed)</option>
            <option value="USB DISCONNECTED">USB Disconnected (Confirmed)</option>
            <option value="FIRST OBSERVED">First Observed (Inferred)</option>
            <option value="LAST OBSERVED">Last Observed (Inferred)</option>
          </select>

          {/* Sort order toggle */}
          <button
            onClick={() => setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')}
            className="px-3 py-1.5 rounded-xl border border-slate-800 bg-slate-950 hover:bg-slate-800 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition"
            title="Toggle chronological sorting"
          >
            <ArrowUpDown className="w-3.5 h-3.5" />
            <span>{sortOrder === 'desc' ? 'Newest First' : 'Oldest First'}</span>
          </button>
        </div>
      </div>

      {/* Recharts Visual Timeline Histogram */}
      <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40">
        <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
          <div className="flex items-center gap-2 text-xs font-bold font-mono text-cyan-300 uppercase tracking-wider">
            <Calendar className="w-4 h-4 text-cyan-400" />
            USB Connection Activity Over Time
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono flex-wrap">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> Inserts (Confirmed)
            </span>
            <span className="flex items-center gap-1.5 text-rose-400">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-400" /> Disconnects (Confirmed)
            </span>
            <span className="flex items-center gap-1.5 text-cyan-400">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> Observations (Inferred)
            </span>
          </div>
        </div>

        <div className="h-48 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="insertGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="discGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="obsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#090d16',
                  borderColor: '#334155',
                  borderRadius: '0.75rem',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                }}
              />
              <Area
                type="monotone"
                dataKey="inserts"
                stroke="#10b981"
                fillOpacity={1}
                fill="url(#insertGradient)"
                name="Confirmed Inserts"
              />
              <Area
                type="monotone"
                dataKey="disconnects"
                stroke="#f43f5e"
                fillOpacity={1}
                fill="url(#discGradient)"
                name="Confirmed Disconnects"
              />
              <Area
                type="monotone"
                dataKey="observed"
                stroke="#06b6d4"
                fillOpacity={1}
                fill="url(#obsGradient)"
                name="Inferred Observations"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chronological Vertical Event Stream */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs text-slate-400 px-1">
          <span>Displaying {filteredEvents.length} chronological audit events</span>
          <div className="relative w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search timeline notes..."
              className="w-full pl-8 pr-3 py-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="space-y-3 relative before:absolute before:inset-0 before:left-5 before:w-0.5 before:bg-slate-800">
          {filteredEvents.map((evt, idx) => {
            const matchedDevice = devices.find((d) => d.id === evt.device_id)
            const meta = getEventMeta(evt.event_type)

            return (
              <div key={evt.event_id || idx} className="relative flex items-start gap-4 pl-3">
                <div
                  className={`mt-2 w-4 h-4 rounded-full border-2 shrink-0 z-10 transition ${meta.dotClass}`}
                />

                <div className="flex-1 p-4 rounded-xl border border-slate-800 bg-slate-900/50 hover:border-slate-700 transition">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`text-[10px] px-2.5 py-0.5 rounded-full font-mono font-bold uppercase tracking-wider border ${meta.pillClass}`}
                      >
                        {meta.label}
                      </span>
                      <span
                        className={`text-[9px] px-1.5 py-0.2 rounded font-mono uppercase tracking-wider border ${meta.badgeClass}`}
                      >
                        {meta.badge}
                      </span>
                      <span className="text-xs font-mono text-white font-bold">
                        {evt.volume_label || (matchedDevice?.volume_label) || `Device #${evt.device_id}`}
                      </span>
                    </div>

                    <div className="text-right text-[11px] font-mono text-slate-400 flex items-center gap-2">
                      <Clock className="w-3 h-3 text-cyan-400" />
                      <span>{evt.timestamp?.slice(0, 19).replace('T', ' ') || 'Unknown'} UTC</span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 mt-2 font-sans">{evt.description}</p>

                  <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono">
                    <div className="flex items-center gap-4 text-slate-400">
                      <span>VID:<strong className="text-slate-200">{evt.vendor_id}</strong></span>
                      <span>PID:<strong className="text-slate-200">{evt.product_id}</strong></span>
                      <span className="text-slate-500">SN: {evt.serial_number}</span>
                    </div>

                    {matchedDevice && (
                      <button
                        onClick={() => onSelectDevice(matchedDevice)}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono hover:underline"
                      >
                        View Device Profile <ChevronRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
