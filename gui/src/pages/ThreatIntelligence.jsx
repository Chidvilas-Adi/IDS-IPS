import React, { useState, useEffect, useCallback } from 'react';
import { Globe, Search, ShieldBan, Rss, Trash2, Plus, RefreshCw } from 'lucide-react';
import client from '../api/client';
import toast from 'react-hot-toast';

export default function ThreatIntelligence() {
  const [blockedIps, setBlockedIps] = useState([]);
  const [feeds, setFeeds] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResult, setSearchResult] = useState(null);
  const [ipAddress, setIpAddress] = useState('');
  const [reason, setReason] = useState('');
  const [durationMinutes, setDurationMinutes] = useState(60);
  const [pageError, setPageError] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [bRes, fRes] = await Promise.all([
        client.get('/api/threats/blocked-ips'),
        client.get('/api/threats/feeds'),
      ]);
      setBlockedIps(bRes.data.items || []);
      setFeeds(Array.isArray(fRes.data) ? fRes.data : []);
      setPageError('');
    } catch (e) {
      console.error('Failed to load PostgreSQL threat data', e);
      setPageError(e.response?.data?.error || 'Could not load threat data from PostgreSQL.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = window.setInterval(fetchData, 15000);
    return () => window.clearInterval(interval);
  }, [fetchData]);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    try {
      const res = await client.get('/api/threats/ioc/search', { params: { q: searchQuery.trim() } });
      setSearchResult(res.data);
    } catch (e) {
      toast.error('Search failed');
    }
  };

  const blockIp = async (e) => {
    e.preventDefault();
    try {
      await client.post('/api/threats/blocked-ips', {
        ip_address: ipAddress.trim(),
        reason: reason.trim() || 'Manual block from Threat Intelligence',
        duration_minutes: Number(durationMinutes),
      });
      toast.success(`${ipAddress.trim()} blocked in PostgreSQL`);
      setIpAddress('');
      setReason('');
      await fetchData();
    } catch (e) {
      toast.error(e.response?.data?.error || 'Failed to block IP in PostgreSQL');
    }
  };

  const unblockIp = async (id) => {
    try {
      await client.delete(`/api/threats/blocked-ips/${id}`);
      toast.success('IP unblocked in PostgreSQL');
      await fetchData();
    } catch (e) {
      toast.error(e.response?.data?.error || 'Failed to unblock IP');
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Globe className="text-cyan-400" /> Threat Intelligence & Blocklist
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          PostgreSQL IOC feeds and active IP blocks. Database decisions are audited; host firewall enforcement requires the privileged adapter.
        </p>
      </div>

      {pageError && (
        <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">
          {pageError}
        </div>
      )}

      <form onSubmit={blockIp} className="grid gap-3 rounded-xl border border-slate-800 bg-slate-900/80 p-5 md:grid-cols-[1fr_1fr_140px_auto]">
        <input
          required
          type="text"
          value={ipAddress}
          onChange={(e) => setIpAddress(e.target.value)}
          placeholder="IP address to block"
          aria-label="IP address to block"
          className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white"
        />
        <input
          type="text"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason"
          aria-label="Block reason"
          className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white"
        />
        <label className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400">
          Minutes
          <input
            required
            type="number"
            min="1"
            max="1440"
            value={durationMinutes}
            onChange={(e) => setDurationMinutes(e.target.value)}
            aria-label="Block duration in minutes"
            className="w-full bg-transparent text-sm text-white outline-none"
          />
        </label>
        <button type="submit" className="inline-flex items-center justify-center gap-2 rounded-lg bg-rose-600 px-4 py-2 text-sm font-medium hover:bg-rose-500">
          <Plus size={16} /> Block IP
        </button>
      </form>

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
              <p className="text-xs text-slate-400">Records: {f.record_count ?? 0}</p>
            </div>
            <span className={`text-xs px-2 py-0.5 rounded ${f.enabled ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-700 text-slate-400'}`}>
              {f.enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
        ))}
        {!loading && feeds.length === 0 && (
          <p className="col-span-full rounded-lg border border-slate-800 p-4 text-sm text-slate-500">
            No threat feeds are configured in PostgreSQL.
          </p>
        )}
      </div>

      {/* Blocked IPs Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
        <h2 className="text-lg font-bold flex items-center gap-2">
        <ShieldBan className="text-rose-400" /> Active PostgreSQL Blocklist
        <button type="button" onClick={fetchData} aria-label="Refresh blocklist" className="ml-auto rounded p-2 text-slate-400 hover:bg-slate-800">
          <RefreshCw size={15} />
        </button>
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
                  <td className="p-3 font-mono font-bold text-rose-400">{b.ip_address}</td>
                  <td className="p-3 text-slate-300 text-xs">{b.reason}</td>
                  <td className="p-3 text-xs text-slate-400">{b.blocked_at ? new Date(b.blocked_at).toLocaleString() : '—'}</td>
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
              {!loading && blockedIps.length === 0 && (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500">No active IP blocks in PostgreSQL.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
