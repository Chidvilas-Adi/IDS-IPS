import React, { useState, useEffect } from 'react';
import { PlayCircle, ShieldAlert, Cpu, ArrowRight, CheckCircle2 } from 'lucide-react';
import client from '../api/client';

export default function PlaybookStudio() {
  const [playbooks, setPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const pRes = await client.get('/playbooks');
      setPlaybooks(pRes.data.playbooks || []);
      const eRes = await client.get('/playbooks/executions');
      setExecutions(eRes.data.executions || []);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <PlayCircle className="text-rose-400" /> Automated Incident Response Playbooks
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Multi-step playbooks executed atomically by the ActionEngine upon critical threat detection.
        </p>
      </div>

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
            <div className="border-t border-slate-800 pt-3">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Sequential Workflow</span>
              <div className="flex items-center gap-2 mt-2 text-xs font-mono text-indigo-300">
                <span>Block IP</span>
                <ArrowRight size={14} className="text-slate-600" />
                <span>Inject RST</span>
                <ArrowRight size={14} className="text-slate-600" />
                <span>Log Alert</span>
              </div>
            </div>
          </div>
        ))}
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
                    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400">
                      <CheckCircle2 size={12} /> {e.status}
                    </span>
                  </td>
                  <td className="p-3 text-xs text-slate-400">{e.started_at}</td>
                  <td className="p-3 text-xs font-mono text-slate-300">{JSON.stringify(e.step_results)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
