import React, { useState, useEffect } from 'react';
import { Globe, Search, ShieldBan, Rss, Trash2 } from 'lucide-react';
import client from '../api/client';
import toast from 'react-hot-toast';

export default function ThreatIntelligence() {
  const [blockedIps, setBlockedIps] = useState([]);
  const [feeds, setFeeds] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResult, setSearchResult] = useState(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const bRes = await client.get('/threats/blocked-ips');
      setBlockedIps(bRes.data.blocked_ips || []);
      const fRes = await client.get('/threats/feeds');
      setFeeds(fRes.data.feeds || []);
    } catch (e) {
      console.error(e);
    }
  };

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchQuery) return;
    try {
      const res = await client.get(`/threats/ioc/search?q=${searchQuery}`);
      setSearchResult(res.data);
    } catch (e) {
      toast.error('Search failed');
    }
  };

  const unblockIp = async (id) => {
    try {
      await client.delete(`/threats/blocked-ips/${id}`);
      toast.success('IP unblocked and removed from Redis hot path');
      fetchData();
    } catch (e) {
      toast.error('Failed to unblock IP');
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Globe className="text-cyan-400" /> Threat Intelligence & Blocklist
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Automated OSINT feeds, IOC database, and dynamic sub-millisecond Redis firewall blocklist.
        </p>
      </div>

      {/* IOC Search */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <form onSubmit={handleSearch} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-3 text-slate-500" size={18} />
            <input
              type="text"
              placeholder="Search IOC IPv4, domain, or malicious hash in database..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button type="submit" className="bg-cyan-600 hover:bg-cyan-500 px-5 py-2 rounded-lg font-medium text-sm transition">
            Lookup Threat
          </button>
        </form>
        {searchResult && (
          <div className="mt-4 p-4 bg-slate-950/80 border border-slate-800 rounded-lg text-sm font-mono">
            <pre>{JSON.stringify(searchResult, null, 2)}</pre>
          </div>
        )}
      </div>

      {/* Feed Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {feeds.map((f) => (
          <div key={f.id} className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
            <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-lg">
              <Rss size={20} />
            </div>
            <div className="flex-1">
              <h4 className="font-semibold text-sm text-white">{f.name}</h4>
              <p className="text-xs text-slate-400">Total IOCs: {f.ioc_count || 0}</p>
            </div>
            <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400">Active</span>
          </div>
        ))}
      </div>

      {/* Blocked IPs Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
        <h2 className="text-lg font-bold flex items-center gap-2">
          <ShieldBan className="text-rose-400" /> Active Blocklist (Synchronized with Redis & Firewall)
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-3">IP Address</th>
                <th className="p-3">Reason</th>
                <th className="p-3">Blocked At</th>
                <th className="p-3">Expires At</th>
                <th className="p-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {blockedIps.map((b) => (
                <tr key={b.id} className="hover:bg-slate-800/30">
                  <td className="p-3 font-mono font-bold text-rose-400">{b.ip}</td>
                  <td className="p-3 text-slate-300 text-xs">{b.reason}</td>
                  <td className="p-3 text-xs text-slate-400">{b.created_at}</td>
                  <td className="p-3 text-xs text-slate-400">{b.expires_at || 'Permanent'}</td>
                  <td className="p-3">
                    <button
                      onClick={() => unblockIp(b.id)}
                      className="text-xs flex items-center gap-1 text-slate-400 hover:text-rose-400 transition"
                    >
                      <Trash2 size={14} /> Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
