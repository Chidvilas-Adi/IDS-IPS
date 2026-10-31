import React, { useState, useEffect } from 'react';
import { Microscope, FileText, Database, ShieldCheck } from 'lucide-react';
import client from '../api/client';

export default function Forensics() {
  const [activeTab, setActiveTab] = useState('packets');
  const [packets, setPackets] = useState([]);
  const [dnsLogs, setDnsLogs] = useState([]);

  useEffect(() => {
    fetchLogs();
  }, [activeTab]);

  const fetchLogs = async () => {
    try {
      if (activeTab === 'packets') {
        const res = await client.get('/forensics/packets?limit=25');
        setPackets(res.data.packets || []);
      } else {
        const res = await client.get('/forensics/dns?limit=25');
        setDnsLogs(res.data.dns_logs || []);
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Microscope className="text-amber-400" /> Deep Packet Forensics (MongoDB NoSQL)
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          High-volume raw packet payloads, hex dumps, and protocol transaction logs stored with TTL expiration.
        </p>
      </div>

      <div className="flex border-b border-slate-800 gap-4">
        <button
          onClick={() => setActiveTab('packets')}
          className={`pb-3 px-2 font-medium transition ${
            activeTab === 'packets' ? 'text-amber-400 border-b-2 border-amber-400' : 'text-slate-400'
          }`}
        >
          Raw Packets & Payload Dumps
        </button>
        <button
          onClick={() => setActiveTab('dns')}
          className={`pb-3 px-2 font-medium transition ${
            activeTab === 'dns' ? 'text-amber-400 border-b-2 border-amber-400' : 'text-slate-400'
          }`}
        >
          DNS Transactions
        </button>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 overflow-hidden">
        {activeTab === 'packets' && (
          <div className="space-y-4">
            {packets.map((p) => (
              <div key={p._id} className="bg-slate-950 p-4 rounded-lg border border-slate-800/80 font-mono text-xs">
                <div className="flex justify-between text-slate-400 border-b border-slate-800 pb-2 mb-2">
                  <span>{p.src_ip}:{p.src_port} → {p.dst_ip}:{p.dst_port} ({p.protocol})</span>
                  <span>{p.timestamp}</span>
                </div>
                <div className="text-amber-300 break-all font-mono">
                  {p.payload_hex ? `HEX: ${p.payload_hex}` : 'No raw application payload'}
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'dns' && (
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-3">Source IP</th>
                <th className="p-3">Query Domain</th>
                <th className="p-3">Type</th>
                <th className="p-3">Response Code</th>
                <th className="p-3">Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {dnsLogs.map((d, i) => (
                <tr key={i} className="hover:bg-slate-800/30">
                  <td className="p-3 text-indigo-300">{d.src_ip}</td>
                  <td className="p-3 text-white font-bold">{d.query_name}</td>
                  <td className="p-3">{d.query_type}</td>
                  <td className="p-3">{d.response_code}</td>
                  <td className="p-3 text-emerald-400">{d.classification}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
