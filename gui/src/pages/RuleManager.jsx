import React, { useState, useEffect } from 'react';
import { Shield, Plus, Filter, Play, CheckCircle, XCircle } from 'lucide-react';
import client from '../api/client';
import toast from 'react-hot-toast';

export default function RuleManager() {
  const [activeTab, setActiveTab] = useState('correlation');
  const [correlationRules, setCorrelationRules] = useState([]);
  const [dpiSignatures, setDpiSignatures] = useState([]);
  const [firewallRules, setFirewallRules] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchRules();
  }, [activeTab]);

  const fetchRules = async () => {
    setLoading(true);
    try {
      if (activeTab === 'correlation') {
        const res = await client.get('/rules/correlation');
        setCorrelationRules(res.data.rules || []);
      } else if (activeTab === 'dpi') {
        const res = await client.get('/rules/signatures');
        setDpiSignatures(res.data.signatures || []);
      } else {
        const res = await client.get('/rules');
        setFirewallRules(res.data.rules || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const toggleRule = async (id, currentEnabled) => {
    try {
      await client.put(`/rules/${id}`, { enabled: !currentEnabled });
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
            Rules, thresholds, and DPI signatures stored directly in PostgreSQL tables. Changes take effect instantly.
          </p>
        </div>
        <div className="flex items-center gap-3">
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
                  const res = await client.post('/rules/import/snort', { rules_text: text });
                  toast.success(`Imported ${res.data.imported || 0} signatures into database`);
                  fetchRules();
                } catch (err) {
                  toast.error('Failed to import Snort rules');
                }
              }}
            />
          </label>
          <button className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 px-4 py-2 rounded-lg font-medium text-sm shadow-lg transition">
            <Plus size={18} /> Add Database Rule
          </button>
        </div>
      </div>

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
                <td className="p-4 text-xs font-mono text-slate-400 truncate max-w-xs">{JSON.stringify(r.event_filter)}</td>
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
          </tbody>
        </table>
      </div>
    </div>
  );
}
