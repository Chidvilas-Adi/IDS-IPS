import React, { useState, useEffect, useCallback } from 'react';
import { Shield, CheckCircle, XCircle, RefreshCw } from 'lucide-react';
import client from '../api/client';
import toast from 'react-hot-toast';

export default function RuleManager() {
  const [activeTab, setActiveTab] = useState('correlation');
  const [correlationRules, setCorrelationRules] = useState([]);
  const [dpiSignatures, setDpiSignatures] = useState([]);
  const [firewallRules, setFirewallRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      if (activeTab === 'correlation') {
        const res = await client.get('/api/rules/correlation');
        setCorrelationRules(res.data.rules || []);
      } else if (activeTab === 'dpi') {
        const res = await client.get('/api/rules/signatures');
        setDpiSignatures(res.data.signatures || []);
      } else {
        const res = await client.get('/api/rules');
        setFirewallRules(res.data.items || []);
      }
    } catch (err) {
      console.error('Failed to load rules from PostgreSQL', err);
      setError(err.response?.data?.error || 'Could not load rules from PostgreSQL.');
    } finally {
      setLoading(false);
    }
  }, [activeTab]);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const toggleRule = async (id, currentEnabled) => {
    try {
      const path = activeTab === 'correlation'
        ? `/api/rules/correlation/${id}`
        : activeTab === 'dpi'
          ? `/api/rules/signatures/${id}`
          : `/api/rules/${id}`;
      await client.put(path, { enabled: !currentEnabled });
      toast.success('Rule state updated in database');
      fetchRules();
    } catch (err) {
      toast.error('Failed to update rule');
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="text-indigo-400" /> Database-Driven Rule Engine
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Correlation rules, DPI signatures, and L3/L4 rules are read and edited in PostgreSQL.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={fetchRules}
            className="rounded-lg border border-slate-700 p-2 text-slate-300 hover:bg-slate-800"
            aria-label="Refresh database rules"
          >
            <RefreshCw size={16} />
          </button>
          <label className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-2 rounded-lg font-medium text-sm transition cursor-pointer text-slate-200">
            <span>📜 Import Snort / Suricata .rules</span>
            <input
              type="file"
              accept=".rules,.txt"
              className="hidden"
              onChange={async (e) => {
                const file = e.target.files?.[0];
                if (!file) return;
                const text = await file.text();
                try {
                  const res = await client.post('/api/rules/import/snort', { rules_text: text });
                  toast.success(`Imported ${res.data.imported || 0} signatures into database`);
                  fetchRules();
                } catch (err) {
                  toast.error('Failed to import Snort rules');
                }
              }}
            />
          </label>
        </div>
      </div>

      {error && <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">{error}</div>}

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-4">
        {['correlation', 'dpi', 'firewall'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`pb-3 px-2 font-medium capitalize transition relative ${
              activeTab === tab ? 'text-indigo-400 border-b-2 border-indigo-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab === 'correlation' && 'Multi-Event Correlation Rules'}
            {tab === 'dpi' && 'DPI Signatures (Regex/Hex)'}
            {tab === 'firewall' && 'L3/L4 Firewall Rules'}
          </button>
        ))}
      </div>

      {/* Content Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
            <tr>
              <th className="p-4">Rule Name</th>
              <th className="p-4">Type / Proto</th>
              <th className="p-4">Condition / Pattern</th>
              <th className="p-4">Action</th>
              <th className="p-4">Severity</th>
              <th className="p-4">Status</th>
              <th className="p-4">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {activeTab === 'correlation' && correlationRules.map((r) => (
              <tr key={r.id} className="hover:bg-slate-800/30">
                <td className="p-4 font-semibold text-white">{r.name}</td>
                <td className="p-4 text-indigo-300 font-mono text-xs">{r.rule_type}</td>
                <td className="p-4 text-xs font-mono text-slate-400 truncate max-w-xs">
                  {JSON.stringify(r.event_filter)} ({r.threshold_count} in {r.window_seconds}s)
                </td>
                <td className="p-4 font-bold text-rose-400">{r.action}</td>
                <td className="p-4">
                  <span className="px-2 py-0.5 rounded text-xs bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    {r.severity}
                  </span>
                </td>
                <td className="p-4">
                  <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded ${r.enabled ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-700/50 text-slate-400'}`}>
                    {r.enabled ? <CheckCircle size={12} /> : <XCircle size={12} />}
                    {r.enabled ? 'Active' : 'Disabled'}
                  </span>
                </td>
                <td className="p-4">
                  <button
                    onClick={() => toggleRule(r.id, r.enabled)}
                    className="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded transition"
                  >
                    {r.enabled ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}

            {activeTab === 'dpi' && dpiSignatures.map((s) => (
              <tr key={s.id} className="hover:bg-slate-800/30">
                <td className="p-4 font-semibold text-white">{s.name}</td>
                <td className="p-4 text-indigo-300 font-mono text-xs">{s.protocol} ({s.pattern_type})</td>
                <td className="p-4 text-xs font-mono text-slate-400 truncate max-w-xs">{s.pattern}</td>
                <td className="p-4 font-bold text-rose-400">{s.action}</td>
                <td className="p-4">
                  <span className="px-2 py-0.5 rounded text-xs bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    {s.severity}
                  </span>
                </td>
                <td className="p-4">
                  <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded ${s.enabled ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-700/50 text-slate-400'}`}>
                    {s.enabled ? <CheckCircle size={12} /> : <XCircle size={12} />}
                    {s.enabled ? 'Active' : 'Disabled'}
                  </span>
                </td>
                <td className="p-4">
                  <button
                    onClick={() => toggleRule(s.id, s.enabled)}
                    className="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded transition"
                  >
                    {s.enabled ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
            {activeTab === 'firewall' && firewallRules.map((r) => (
              <tr key={r.id} className="hover:bg-slate-800/30">
                <td className="p-4 font-semibold text-white">{r.name}</td>
                <td className="p-4 text-indigo-300 font-mono text-xs">{r.rule_type} / {r.protocol || 'ANY'}</td>
                <td className="p-4 text-xs font-mono text-slate-400">
                  {r.src_ip || 'ANY'}:{r.src_port ?? '*'} → {r.dst_ip || 'ANY'}:{r.dst_port ?? '*'}
                </td>
                <td className="p-4 font-bold text-rose-400">{r.action}</td>
                <td className="p-4">{r.severity}</td>
                <td className="p-4">{r.enabled ? 'Active' : 'Disabled'}</td>
                <td className="p-4">
                  <button
                    onClick={() => toggleRule(r.id, r.enabled)}
                    className="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded transition"
                  >
                    {r.enabled ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
            {!loading && !error && (
              (activeTab === 'correlation' && correlationRules.length === 0)
              || (activeTab === 'dpi' && dpiSignatures.length === 0)
              || (activeTab === 'firewall' && firewallRules.length === 0)
            ) && (
              <tr><td colSpan={7} className="p-8 text-center text-slate-500">No rules are configured in this PostgreSQL table.</td></tr>
            )}
            {loading && <tr><td colSpan={7} className="p-8 text-center text-slate-500">Loading rules from PostgreSQL…</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
