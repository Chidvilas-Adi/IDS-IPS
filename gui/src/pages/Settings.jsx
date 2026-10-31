import React from 'react';
import { Settings as SettingsIcon, Sliders, Database, HardDrive, Key } from 'lucide-react';

export default function Settings() {
  return (
    <div className="p-6 space-y-6 text-slate-100 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <SettingsIcon className="text-slate-400" /> Platform Configuration
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Dynamic engine parameters and runtime database connection topology.
        </p>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="font-bold text-lg text-white flex items-center gap-2">
          <Database size={18} className="text-indigo-400" /> Database-Driven Architecture State
        </h3>
        <div className="grid grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-400 block mb-1">Relational Master</span>
            <span className="text-white font-bold">PostgreSQL 16 / TimescaleDB (Port 5432)</span>
          </div>
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-400 block mb-1">NoSQL Buffer</span>
            <span className="text-white font-bold">MongoDB 7.0 (Port 27017)</span>
          </div>
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-400 block mb-1">Hot-Path Cache</span>
            <span className="text-white font-bold">Redis 7.0 (Port 6379, O(1) Blocklist)</span>
          </div>
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-400 block mb-1">Network Sniffer</span>
            <span className="text-white font-bold">Scapy Raw Socket / AF_PACKET</span>
          </div>
        </div>
      </div>
    </div>
  );
}
