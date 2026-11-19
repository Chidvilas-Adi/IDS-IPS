import React, { useState, useEffect, useCallback } from 'react';
import { PlayCircle, Cpu, CheckCircle2, RefreshCw, ChevronDown, ChevronRight } from 'lucide-react';
import client from '../api/client';

export default function PlaybookStudio() {
  const [playbooks, setPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [selectedSteps, setSelectedSteps] = useState({});
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [pRes, eRes] = await Promise.all([
        client.get('/api/playbooks'),
        client.get('/api/playbooks/executions'),
      ]);
      setPlaybooks(Array.isArray(pRes.data) ? pRes.data : []);
      setExecutions(eRes.data.items || []);
      setError('');
    } catch (e) {
      console.error('Failed to load playbook data from PostgreSQL', e);
      setError(e.response?.data?.error || 'Could not load playbooks from PostgreSQL.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const toggleSteps = async (playbookId) => {
    if (selectedSteps[playbookId]) {
      setSelectedSteps((current) => ({ ...current, [playbookId]: null }));
      return;
    }
    try {
      const response = await client.get(`/api/playbooks/${playbookId}`);
      setSelectedSteps((current) => ({ ...current, [playbookId]: response.data.steps || [] }));
    } catch (e) {
      console.error('Failed to load playbook steps from PostgreSQL', e);
      setError(e.response?.data?.error || 'Could not load playbook steps.');
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <PlayCircle className="text-rose-400" />           Database Playbook Configuration
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Definitions and execution history are read from PostgreSQL. A running task worker is required to execute playbooks.
        </p>
        <button type="button" onClick={fetchData} className="mt-3 inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800">
          <RefreshCw size={14} /> Refresh database records
        </button>
      </div>

      {error && <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">{error}</div>}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {playbooks.map((p) => (
          <div key={p.id} className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex justify-between items-start">
              <h3 className="font-bold text-lg text-white">{p.name}</h3>
              <span className="text-xs px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono">
                {p.trigger_severity}
              </span>
            </div>
            <p className="text-xs text-slate-400">{p.description}</p>
            <p className="text-xs text-slate-400">Trigger rule: {p.trigger_rule_type || 'Any'}</p>
            <button type="button" onClick={() => toggleSteps(p.id)} className="inline-flex items-center gap-2 text-xs text-indigo-300 hover:text-indigo-200">
              {selectedSteps[p.id] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              {selectedSteps[p.id] ? 'Hide configured steps' : 'View configured steps'}
            </button>
            {selectedSteps[p.id] && (
              <ol className="list-inside list-decimal space-y-1 border-t border-slate-800 pt-3 text-xs text-slate-300">
                {selectedSteps[p.id].map((step) => (
                  <li key={step.id}>{step.action_type}: {JSON.stringify(step.action_params || {})}</li>
                ))}
                {selectedSteps[p.id].length === 0 && <li className="list-none text-slate-500">No steps configured in PostgreSQL.</li>}
              </ol>
            )}
          </div>
        ))}
        {!loading && playbooks.length === 0 && !error && (
          <p className="col-span-full rounded-lg border border-slate-800 p-5 text-sm text-slate-500">No playbooks are configured in PostgreSQL.</p>
        )}
      </div>

      {/* Execution History */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
        <h2 className="text-lg font-bold flex items-center gap-2">
          <Cpu className="text-indigo-400" /> Recent Playbook Executions
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-3">Execution ID</th>
                <th className="p-3">Playbook</th>
                <th className="p-3">Status</th>
                <th className="p-3">Started At</th>
                <th className="p-3">Steps Executed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {executions.map((e) => (
                <tr key={e.id} className="hover:bg-slate-800/30">
                  <td className="p-3 font-mono text-xs">#{e.id}</td>
                  <td className="p-3 font-semibold text-white">{e.playbook_name || `Playbook #${e.playbook_id}`}</td>
                  <td className="p-3">
                    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded ${e.status?.toUpperCase() === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-300'}`}>
                      <CheckCircle2 size={12} /> {e.status}
                    </span>
                  </td>
                  <td className="p-3 text-xs text-slate-400">{e.started_at}</td>
                  <td className="p-3 text-xs text-slate-300">
                    {Array.isArray(e.step_results) ? e.step_results.length : 0}
                    {e.error_message && <span className="ml-2 text-red-300">{e.error_message}</span>}
                  </td>
                </tr>
              ))}
              {executions.length === 0 && !loading && !error && (
                  <tr><td colSpan={5} className="p-8 text-center text-slate-500">No playbook executions recorded in PostgreSQL.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
