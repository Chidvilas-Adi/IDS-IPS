import React, { useState, useEffect } from 'react';
import { Database, FileCode, ShieldAlert } from 'lucide-react';
import client from '../api/client';

export default function NoSQLExplorer() {
  const [collections, setCollections] = useState([]);
  const [selectedCol, setSelectedCol] = useState(null);
  const [docs, setDocs] = useState([]);

  useEffect(() => {
    fetchCollections();
  }, []);

  const fetchCollections = async () => {
    try {
      const res = await client.get('/nosql/collections');
      setCollections(res.data.collections || []);
      if (res.data.collections?.length > 0) {
        loadDocs(res.data.collections[0].name);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const loadDocs = async (colName) => {
    setSelectedCol(colName);
    try {
      if (colName === 'raw_packets') {
        const res = await client.get('/nosql/raw-packets');
        setDocs(res.data.documents || []);
      } else if (colName === 'canary_access_log') {
        const res = await client.get('/nosql/canary-log');
        setDocs(res.data.canary_logs || []);
      } else {
        const res = await client.get('/nosql/threat-intel');
        setDocs(res.data.threat_intel || []);
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Database className="text-teal-400" /> MongoDB NoSQL Big Data Explorer
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Explore high-throughput unstructured network logs, raw packet buffers, and deception canary logs.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Collections List */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-2">
          <h3 className="font-bold text-sm text-slate-400 uppercase tracking-wider mb-3">Collections</h3>
          {collections.map((c) => (
            <button
              key={c.name}
              onClick={() => loadDocs(c.name)}
              className={`w-full text-left p-3 rounded-lg text-sm flex justify-between items-center transition ${
                selectedCol === c.name ? 'bg-teal-500/20 text-teal-300 font-bold border border-teal-500/30' : 'hover:bg-slate-800 text-slate-300'
              }`}
            >
              <span>{c.name}</span>
              <span className="text-xs bg-slate-950 px-2 py-0.5 rounded text-slate-500">{c.count}</span>
            </button>
          ))}
        </div>

        {/* JSON Document Viewer */}
        <div className="md:col-span-3 bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="font-bold text-lg text-white flex items-center gap-2">
            <FileCode size={18} className="text-teal-400" /> Documents in <span className="text-teal-300 font-mono">{selectedCol}</span>
          </h3>
          <div className="space-y-3 max-h-[600px] overflow-y-auto">
            {docs.map((d, i) => (
              <div key={i} className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto">
                <pre className="text-teal-300/90">{JSON.stringify(d, null, 2)}</pre>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
