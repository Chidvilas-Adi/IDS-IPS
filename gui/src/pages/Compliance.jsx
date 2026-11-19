import React, { useState, useEffect, useCallback } from 'react';
import { ClipboardCheck, Play, CheckCircle2, AlertTriangle, Download, RefreshCw } from 'lucide-react';
import client from '../api/client';
import toast from 'react-hot-toast';

export default function Compliance() {
  const [checks, setChecks] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');

  const fetchChecks = useCallback(async () => {
    try {
      const [res, auditRes] = await Promise.all([
        client.get('/api/compliance/checks'),
        client.get('/api/compliance/audit-log', { params: { limit: 100 } }),
      ]);
      setChecks(res.data.checks || []);
      setAuditLogs(auditRes.data.audit_logs || []);
      setError('');
    } catch (e) {
      console.error('Failed to load compliance and audit records from PostgreSQL', e);
      setError(e.response?.data?.error || 'Could not load compliance or audit records from PostgreSQL.');
    }
  }, []);

  useEffect(() => {
    fetchChecks();
  }, [fetchChecks]);

  useEffect(() => {
    const interval = window.setInterval(fetchChecks, 15000);
    return () => window.clearInterval(interval);
  }, [fetchChecks]);

  const runAllChecks = async () => {
    setRunning(true);
    try {
      await client.post('/api/compliance/checks/run');
      toast.success('All SQL compliance verification checks evaluated');
      await fetchChecks();
    } catch (e) {
      toast.error('Error running checks');
    } finally {
      setRunning(false);
    }
  };

  const exportReport = async () => {
    try {
      const response = await client.get('/api/compliance/reports/export', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data], { type: 'text/html' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'database-compliance-report.html';
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      toast.error(e.response?.data?.error || 'Could not export the compliance report');
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ClipboardCheck className="text-emerald-400" /> Automated Compliance Auditing
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Dynamic SQL queries continuously assessing PCI-DSS, HIPAA, and SOC2 controls directly in database.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={exportReport}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2 rounded-lg font-medium text-sm transition text-slate-200"
          >
            <Download size={15} /> Export HTML Report
          </button>
          <button
            onClick={runAllChecks}
            disabled={running}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg font-medium shadow-lg transition text-sm"
          >
            <Play size={16} /> {running ? 'Evaluating...' : 'Run All Verification Checks'}
          </button>
          <button
            type="button"
            onClick={fetchChecks}
            aria-label="Refresh compliance and audit data"
            className="rounded-lg border border-slate-700 p-2 text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      {error && <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">{error}</div>}

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
            <tr>
              <th className="p-4">Framework</th>
              <th className="p-4">Control Name</th>
              <th className="p-4">Description</th>
              <th className="p-4">Status</th>
              <th className="p-4">Last Evaluated</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {checks.map((c) => (
              <tr key={c.id} className="hover:bg-slate-800/30">
                <td className="p-4 font-bold text-xs text-indigo-400">{c.framework}</td>
                <td className="p-4 font-semibold text-white">{c.check_name}</td>
                <td className="p-4 text-xs text-slate-400">{c.description}</td>
                <td className="p-4">
                  <span
                    className={`inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded font-semibold ${
                      c.last_status === 'PASS'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                    }`}
                  >
                    {c.last_status === 'PASS' ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                    {c.last_status || 'NOT_RUN'}
                  </span>
                </td>
                <td className="p-4 text-xs text-slate-400">{c.last_run_at || 'Never'}</td>
              </tr>
            ))}
            {checks.length === 0 && !error && (
              <tr><td colSpan={5} className="p-8 text-center text-slate-500">No compliance checks are configured in PostgreSQL.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <section className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/80 p-5">
        <div>
          <h2 className="text-lg font-bold text-white">Database Audit Log</h2>
          <p className="text-sm text-slate-400">Block, unblock, expiry, and account actions recorded in PostgreSQL.</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-800 bg-slate-950/60 text-slate-400">
              <tr>
                <th className="p-3">Time</th>
                <th className="p-3">Action</th>
                <th className="p-3">Actor</th>
                <th className="p-3">IP</th>
                <th className="p-3">Details</th>
                <th className="p-3">Record</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {auditLogs.map((entry) => (
                <tr key={entry.id}>
                  <td className="p-3 text-xs text-slate-400">{entry.created_at ? new Date(entry.created_at).toLocaleString() : '—'}</td>
                  <td className="p-3 font-mono text-xs text-amber-300">{entry.action}</td>
                  <td className="p-3 text-xs text-slate-300">{entry.actor} ({entry.actor_type})</td>
                  <td className="p-3 font-mono text-xs text-rose-300">{entry.ip_address || '—'}</td>
                  <td className="p-3 text-xs text-slate-400">{entry.details || '—'}</td>
                  <td className="p-3 text-xs text-slate-400">{entry.table_name}{entry.record_id ? ` #${entry.record_id}` : ''}</td>
                </tr>
              ))}
              {auditLogs.length === 0 && !error && (
                <tr><td colSpan={6} className="p-8 text-center text-slate-500">No audit records in PostgreSQL yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
