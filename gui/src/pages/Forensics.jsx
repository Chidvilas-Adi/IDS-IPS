import React, { useState, useEffect, useCallback } from 'react';
import { Microscope, RefreshCw } from 'lucide-react';
import { api } from '../api/client';

export default function Forensics() {
  const activeTab = 'packets';
  const [packets, setPackets] = useState([]);
  const [packetStats, setPacketStats] = useState({
    total: 0,
    protocolCounts: {},
    sourceCounts: {},
    lastCapturedAt: null,
  });
  const [packetError, setPacketError] = useState('');
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchLogs = useCallback(async () => {
    try {
      if (activeTab === 'packets') {
        const res = await api.getPackets({ limit: 100 });
        setPackets(res.data.packets || []);
        setPacketStats({
          total: res.data.total || 0,
          protocolCounts: res.data.protocol_counts || {},
          sourceCounts: res.data.source_counts || {},
          lastCapturedAt: res.data.last_captured_at,
        });
        setPacketError('');
        setLastUpdated(new Date());
      }
    } catch (e) {
      console.error(e);
      if (activeTab === 'packets') {
        setPacketError(e.response?.data?.error || 'Could not load captured packets.');
      }
    }
  }, [activeTab]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  useEffect(() => {
    if (activeTab !== 'packets') return undefined;
    const interval = window.setInterval(fetchLogs, 3000);
    return () => window.clearInterval(interval);
  }, [activeTab, fetchLogs]);

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Microscope className="text-amber-400" /> Captured Packet Log
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          PostgreSQL ingress records refresh every 3 seconds. Legacy rows predate source tracking and may include earlier tests.
        </p>
      </div>

      {activeTab === 'packets' && (
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2">
            Ingress rows: <strong className="text-white">{packetStats.total.toLocaleString()}</strong>
          </span>
          {[
            ['Capture adapter', packetStats.sourceCounts.capture || 0],
            ['UI simulation', packetStats.sourceCounts.simulation || 0],
            ['Legacy / unclassified', packetStats.sourceCounts.legacy || 0],
          ].map(([label, count]) => (
            <span key={label} className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2">
              {label}: <strong className="text-white">{count.toLocaleString()}</strong>
            </span>
          ))}
          {Object.entries(packetStats.protocolCounts).map(([protocol, count]) => (
            <span key={protocol} className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2">
              {protocol}: <strong className="text-white">{count.toLocaleString()}</strong>
            </span>
          ))}
          <button
            type="button"
            onClick={fetchLogs}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw size={14} /> Refresh
          </button>
          {lastUpdated && <span className="text-xs text-slate-500">Updated {lastUpdated.toLocaleTimeString()}</span>}
          {packetStats.lastCapturedAt && (
            <span className="text-xs text-slate-500">
              Last adapter packet {new Date(packetStats.lastCapturedAt).toLocaleString()}
            </span>
          )}
        </div>
      )}

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 overflow-x-auto">
        {activeTab === 'packets' && (
          <>
            {packetError && (
              <div role="alert" className="mb-4 rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">
                {packetError}
              </div>
            )}
            <table className="w-full min-w-[1000px] text-left text-xs">
              <thead className="border-b border-slate-800 bg-slate-950 text-slate-400">
                <tr>
                  {['Time', 'Origin', 'Protocol', 'Source IP:Port', 'Destination IP:Port', 'Length', 'TCP flags', 'Payload (first 96 bytes, hex)'].map((label) => (
                    <th key={label} className="p-3">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {packets.map((packet) => (
                  <tr key={packet.id} className="align-top hover:bg-slate-800/30">
                    <td className="whitespace-nowrap p-3 text-slate-400">{new Date(packet.timestamp).toLocaleString()}</td>
                    <td className={packet.capture_source === 'capture' ? 'p-3 text-emerald-300' : 'p-3 text-slate-400'}>
                      {packet.capture_source}
                    </td>
                    <td className="p-3 text-amber-300">{packet.protocol}</td>
                    <td className="p-3 text-indigo-300">{packet.src_ip}:{packet.src_port ?? '—'}</td>
                    <td className="p-3 text-indigo-300">{packet.dst_ip}:{packet.dst_port ?? '—'}</td>
                    <td className="p-3">{packet.packet_length} B</td>
                    <td className="p-3">{packet.tcp_flags || '—'}</td>
                    <td className="max-w-md break-all p-3 text-slate-400">
                      {packet.payload_size ? `${packet.payload_hex}${packet.payload_size > 96 ? '…' : ''}` : 'No application payload'}
                    </td>
                  </tr>
                ))}
                {packets.length === 0 && !packetError && (
                  <tr><td colSpan={8} className="p-8 text-center text-slate-500">No packet records in PostgreSQL yet. Start the packet adapter.</td></tr>
                )}
              </tbody>
            </table>
          </>
        )}

      </div>
    </div>
  );
}
