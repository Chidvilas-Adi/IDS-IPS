import React, { useCallback, useEffect, useState } from 'react';
import { Database, RefreshCw, Server } from 'lucide-react';
import client from '../api/client';

export default function Settings() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState('');
  const [updatedAt, setUpdatedAt] = useState(null);

  const fetchHealth = useCallback(async () => {
    try {
      const { data } = await client.get('/health');
      setHealth(data);
      setError('');
      setUpdatedAt(new Date());
    } catch (e) {
      console.error('Failed to load service health', e);
      setError(e.response?.data?.error || 'Could not load service health.');
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = window.setInterval(fetchHealth, 15000);
    return () => window.clearInterval(interval);
  }, [fetchHealth]);

  return (
    <div className="max-w-4xl space-y-6 p-6 text-slate-100">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <Server className="text-slate-300" /> System Status
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Live service state reported by the API, refreshed every 15 seconds.
          </p>
        </div>
        <button
          type="button"
          onClick={fetchHealth}
          aria-label="Refresh system health"
          className="rounded-lg border border-slate-700 p-2 text-slate-300 hover:bg-slate-800"
        >
          <RefreshCw size={16} />
        </button>
      </div>

      {error && (
        <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <section className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/80 p-5">
        <h2 className="flex items-center gap-2 text-lg font-bold text-white">
          <Database size={18} className="text-indigo-400" /> PostgreSQL-Centric Detection
        </h2>
        <p className="text-sm text-slate-300">
          PostgreSQL stores packet ingress, detection rules, alerts, sessions, blocked-IP state, compliance results, and audit records.
          SQL triggers and procedures make detection and block decisions.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          {health?.components && Object.entries(health.components).map(([name, status]) => (
            <div key={name} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-3">
              <span className="text-sm capitalize text-slate-300">{name}</span>
              <span className={`text-xs font-semibold ${status === 'UP' ? 'text-emerald-400' : 'text-red-400'}`}>
                {status}
              </span>
            </div>
          ))}
          {!health?.components && !error && (
            <p className="text-sm text-slate-500">Waiting for the API health response…</p>
          )}
        </div>
        {updatedAt && <p className="text-xs text-slate-500">Last checked {updatedAt.toLocaleTimeString()}</p>}
      </section>

      <section className="rounded-xl border border-amber-900/60 bg-amber-950/20 p-5">
        <h2 className="text-sm font-bold text-amber-200">Host enforcement is separate</h2>
        <p className="mt-2 text-sm text-amber-100/80">
          The API health check does not prove packet capture or Windows Firewall enforcement is running.
          Those require the elevated host adapter; verify its capture count in Forensics and test blocks from another device.
        </p>
      </section>
    </div>
  );
}
