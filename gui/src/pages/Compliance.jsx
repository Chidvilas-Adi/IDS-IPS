import React, { useState, useEffect } from 'react';
import { ClipboardCheck, Play, CheckCircle2, AlertTriangle, ShieldCheck } from 'lucide-react';
import client from '../api/client';
import toast from 'react-hot-toast';

export default function Compliance() {
  const [checks, setChecks] = useState([]);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    fetchChecks();
  }, []);

  const fetchChecks = async () => {
    try {
      const res = await client.get('/compliance/checks');
      setChecks(res.data.checks || []);
    } catch (e) {
      console.error(e);
    }
  };

  const runAllChecks = async () => {
    setRunning(true);
    try {
      await client.post('/compliance/checks/run');
      toast.success('All SQL compliance verification checks evaluated');
      fetchChecks();
    } catch (e) {
      toast.error('Error running checks');
    } finally {
      setRunning(false);
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
        <button
          onClick={runAllChecks}
          disabled={running}
          className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg font-medium shadow-lg transition"
        >
          <Play size={16} /> {running ? 'Evaluating...' : 'Run All Verification Checks'}
        </button>
      </div>

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
          </tbody>
        </table>
      </div>
    </div>
  );
}
