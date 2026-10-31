import React, { useState, useEffect } from 'react';
import { Network, Activity, XOctagon } from 'lucide-react';
import client from '../api/client';
import toast from 'react-hot-toast';

export default function SessionInspector() {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSessions();
    const interval = setInterval(fetchSessions, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchSessions = async () => {
    try {
      const res = await client.get('/sessions?limit=50');
      setSessions(res.data.sessions || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const killSession = async (id) => {
    try {
      await client.delete(`/sessions/${id}`);
      toast.success('Session killed (TCP RST dispatched)');
      fetchSessions();
    } catch (e) {
      toast.error('Failed to kill session');
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Network className="text-emerald-400" /> Active Session Inspector
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Stateful TCP/UDP sessions tracked in PostgreSQL and enriched in real time.
        </p>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
            <tr>
              <th className="p-3">Source Socket</th>
              <th className="p-3">Destination Socket</th>
              <th className="p-3">Protocol</th>
              <th className="p-3">State</th>
              <th className="p-3">Traffic (Sent / Recv)</th>
              <th className="p-3">Last Seen</th>
              <th className="p-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {sessions.map((s) => (
              <tr key={s.id} className="hover:bg-slate-800/30">
                <td className="p-3 font-mono text-xs text-indigo-300">{s.src_ip}:{s.src_port}</td>
                <td className="p-3 font-mono text-xs text-slate-300">{s.dst_ip}:{s.dst_port}</td>
                <td className="p-3 font-bold text-xs">{s.protocol}</td>
                <td className="p-3">
                  <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-mono">
                    {s.state}
                  </span>
                </td>
                <td className="p-3 text-xs text-slate-400 font-mono">
                  {s.bytes_sent} B / {s.bytes_recv} B
                </td>
                <td className="p-3 text-xs text-slate-400">{s.last_seen_at}</td>
                <td className="p-3">
                  <button
                    onClick={() => killSession(s.id)}
                    className="text-xs flex items-center gap-1 text-rose-400 hover:text-rose-300 font-semibold"
                  >
                    <XOctagon size={14} /> Kill
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
