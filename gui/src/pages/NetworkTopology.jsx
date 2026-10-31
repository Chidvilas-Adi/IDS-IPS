import React, { useState, useEffect } from 'react';
import { Share2, Server, ArrowUpRight } from 'lucide-react';
import client from '../api/client';

export default function NetworkTopology() {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);

  useEffect(() => {
    fetchTopology();
  }, []);

  const fetchTopology = async () => {
    try {
      const res = await client.get('/sessions/topology');
      setNodes(res.data.nodes || []);
      setEdges(res.data.edges || []);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Share2 className="text-purple-400" /> Auto-Discovered Network Topology
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Dynamic connection graph synthesized in PostgreSQL (connection_graph_edges) to detect lateral movement.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Nodes */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="font-bold text-lg text-white flex items-center gap-2">
            <Server size={18} className="text-purple-400" /> Discovered Network Entities ({nodes.length})
          </h3>
          <div className="grid grid-cols-2 gap-3 max-h-96 overflow-y-auto">
            {nodes.map((n) => (
              <div key={n.id} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center gap-2 font-mono text-xs">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                <span className="text-white truncate">{n.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Edges / Connections */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="font-bold text-lg text-white flex items-center gap-2">
            <ArrowUpRight size={18} className="text-indigo-400" /> Active Communication Edges ({edges.length})
          </h3>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {edges.map((e, idx) => (
              <div key={idx} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex justify-between items-center font-mono text-xs">
                <div className="flex items-center gap-2 text-indigo-300">
                  <span>{e.source}</span>
                  <span className="text-slate-600">→</span>
                  <span>{e.target}</span>
                </div>
                <span className="text-slate-400">{e.count} handshakes</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
