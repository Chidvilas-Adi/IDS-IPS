import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Bell, Filter, Download, RefreshCw, Ban, CheckCircle,
  XCircle, ChevronLeft, ChevronRight, X, ExternalLink, Search
} from 'lucide-react';
import { format } from 'date-fns';
import toast from 'react-hot-toast';
import { api } from '../api/client';
import useSocket from '../hooks/useSocket';
import SeverityBadge from '../components/SeverityBadge';
import IPReputationCard from '../components/IPReputationCard';

const STATUS_COLORS = {
  open:          'bg-red-950 border-red-800 text-red-400',
  acknowledged:  'bg-yellow-950 border-yellow-800 text-yellow-400',
  false_positive:'bg-slate-800 border-slate-600 text-slate-400',
  resolved:      'bg-green-950 border-green-800 text-green-400',
};

// ─── Alert Detail Modal ───────────────────────────────────────────────────────
const AlertDetailModal = ({ alert, onClose }) => {
  const [tab, setTab] = useState('details');
  const [repData, setRepData] = useState(null);
  const qc = useQueryClient();

  useEffect(() => {
    if (alert?.src_ip) {
      api.lookupReputation(alert.src_ip)
        .then((r) => setRepData(r.data))
        .catch(() => {});
    }
  }, [alert]);

  const ackMut = useMutation({
    mutationFn: () => api.acknowledgeAlert(alert.id),
    onSuccess: () => {
      toast.success('Alert acknowledged');
      qc.invalidateQueries(['alerts']);
      onClose();
    },
  });

  if (!alert) return null;

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal-box w-full max-w-3xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={alert.severity} />
            <h2 className="font-semibold text-slate-100">{alert.rule_name}</h2>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-slate-700 px-6">
          {['details', 'reputation', 'playbook', 'raw'].map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2.5 text-sm font-medium capitalize border-b-2 transition-colors ${
                tab === t ? 'border-brand-500 text-brand-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="p-6">
          {tab === 'details' && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                {[
                  ['Alert ID', alert.id],
                  ['Timestamp', alert.timestamp ? format(new Date(alert.timestamp), 'yyyy-MM-dd HH:mm:ss') : '—'],
                  ['Source IP', alert.src_ip],
                  ['Destination IP', alert.dst_ip],
                  ['Source Port', alert.src_port],
                  ['Destination Port', alert.dst_port],
                  ['Protocol', alert.protocol],
                  ['Rule Type', alert.rule_type],
                  ['Status', alert.status],
                  ['Action Taken', alert.action],
                ].map(([k, v]) => (
                  <div key={k}>
                    <div className="text-slate-500 text-xs mb-0.5">{k}</div>
                    <div className="text-slate-200 font-mono">{v || '—'}</div>
                  </div>
                ))}
              </div>
              {alert.description && (
                <div>
                  <div className="text-xs text-slate-500 mb-1">Description</div>
                  <p className="text-sm text-slate-300">{alert.description}</p>
                </div>
              )}
              {alert.payload_preview && (
                <div>
                  <div className="text-xs text-slate-500 mb-1">Payload Preview</div>
                  <pre className="hex-viewer bg-slate-800 rounded-lg p-3 text-slate-300 overflow-x-auto">
                    {alert.payload_preview}
                  </pre>
                </div>
              )}
            </div>
          )}

          {tab === 'reputation' && (
            <IPReputationCard ip={alert.src_ip} data={repData} />
          )}

          {tab === 'playbook' && (
            <div className="space-y-3">
              <p className="text-sm text-slate-400">Playbook execution status for this alert:</p>
              {alert.playbook_executions?.length ? (
                alert.playbook_executions.map((ex) => (
                  <div key={ex.id} className="ids-card p-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-slate-200">{ex.playbook_name}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${ex.status === 'completed' ? 'bg-green-950 text-green-400' : 'bg-yellow-950 text-yellow-400'}`}>
                        {ex.status}
                      </span>
                    </div>
                    <div className="text-xs text-slate-500 mt-1">{ex.executed_at}</div>
                  </div>
                ))
              ) : (
                <p className="text-sm text-slate-500">No playbooks executed for this alert.</p>
              )}
            </div>
          )}

          {tab === 'raw' && (
            <pre className="hex-viewer bg-slate-800 rounded-lg p-4 text-slate-300 text-xs overflow-auto max-h-80">
              {JSON.stringify(alert, null, 2)}
            </pre>
          )}
        </div>

        {/* Footer actions */}
        <div className="flex items-center gap-3 px-6 py-4 border-t border-slate-700">
          <button
            onClick={() => ackMut.mutate()}
            className="ids-btn-primary"
            disabled={ackMut.isPending || alert.status === 'acknowledged'}
          >
            <CheckCircle className="w-4 h-4" />
            Acknowledge
          </button>
          <button
            onClick={() => api.markFalsePositive(alert.id).then(() => { toast.success('Marked false positive'); onClose(); })}
            className="ids-btn-outline"
          >
            <XCircle className="w-4 h-4" />
            False Positive
          </button>
          <button
            onClick={() => api.blockIP(alert.src_ip, `Alert ${alert.id}`).then(() => toast.success(`Blocked ${alert.src_ip}`))}
            className="ids-btn-danger"
          >
            <Ban className="w-4 h-4" />
            Block {alert.src_ip}
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── Alert Feed ───────────────────────────────────────────────────────────────
const AlertFeed = () => {
  const qc = useQueryClient();
  const { alertQueue } = useSocket();
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ severity: '', status: '', protocol: '', ip: '', startDate: '', endDate: '' });
  const [selected, setSelected] = useState(null);
  const PAGE_SIZE = 50;

  // Merge live alerts with fetched
  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['alerts', page, filters],
    queryFn: () => api.getAlerts({ page, page_size: PAGE_SIZE, ...filters }).then((r) => r.data),
    keepPreviousData: true,
    refetchInterval: 60000,
  });

  // Inject live WebSocket alerts at top
  const [liveAlerts, setLiveAlerts] = useState([]);
  useEffect(() => {
    if (alertQueue.length) {
      setLiveAlerts((prev) => {
        const existing = new Set(prev.map((a) => a.id));
        const newOnes = alertQueue.filter((a) => !existing.has(a.id));
        return [...newOnes, ...prev].slice(0, 20);
      });
    }
  }, [alertQueue]);

  const alerts = [...liveAlerts, ...(data?.items || [])];
  const totalPages = Math.ceil((data?.total || 0) / PAGE_SIZE);

  // Stats bar
  const metricCounts = {
    total:        data?.total || 0,
    open:         data?.open ?? 0,
    acknowledged: data?.acknowledged ?? 0,
    critical:     data?.critical ?? 0,
    high:         data?.high ?? 0,
  };

  const handleExport = async () => {
    try {
      const res = await api.exportAlerts(filters);
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.download = `alerts-${format(new Date(), 'yyyyMMdd-HHmmss')}.csv`;
      a.click();
      toast.success('CSV export started');
    } catch {
      toast.error('Export failed');
    }
  };

  const blockIP = async (ip, e) => {
    e.stopPropagation();
    try {
      await api.blockIP(ip, 'Quick block from alert feed');
      toast.success(`${ip} blocked`);
    } catch { toast.error('Block failed'); }
  };

  const ackAlert = async (id, e) => {
    e.stopPropagation();
    try {
      await api.acknowledgeAlert(id);
      toast.success('Acknowledged');
      qc.invalidateQueries(['alerts']);
    } catch { toast.error('Failed'); }
  };

  return (
    <div className="flex flex-col h-full p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Bell className="w-5 h-5 text-red-400" />
            Alert Feed
            {isFetching && <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />}
          </h1>
          <p className="text-sm text-slate-500">Real-time intrusion detection alerts</p>
        </div>
        <button onClick={handleExport} className="ids-btn-outline">
          <Download className="w-4 h-4" />
          Export CSV
        </button>
      </div>

      {/* Metric chips */}
      <div className="flex flex-wrap gap-3">
        {[
          { label: 'Total', value: metricCounts.total, color: 'text-slate-300' },
          { label: 'Open', value: metricCounts.open, color: 'text-red-400' },
          { label: 'Acknowledged', value: metricCounts.acknowledged, color: 'text-yellow-400' },
          { label: 'Critical', value: metricCounts.critical, color: 'text-red-500' },
          { label: 'High', value: metricCounts.high, color: 'text-orange-400' },
        ].map((m) => (
          <div key={m.label} className="ids-card px-4 py-2 flex items-center gap-2">
            <span className="text-xs text-slate-500">{m.label}</span>
            <span className={`text-sm font-bold ${m.color}`}>{m.value}</span>
          </div>
        ))}
      </div>

      {/* Filter bar */}
      <div className="ids-card p-3">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="flex items-center gap-2 text-slate-500">
            <Filter className="w-4 h-4" />
            <span className="text-sm">Filters:</span>
          </div>
          <select
            value={filters.severity}
            onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}
            className="ids-input py-1.5 text-xs"
          >
            <option value="">All Severities</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select
            value={filters.status}
            onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}
            className="ids-input py-1.5 text-xs"
          >
            <option value="">All Statuses</option>
            {['open', 'acknowledged', 'false_positive', 'resolved'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select
            value={filters.protocol}
            onChange={(e) => setFilters((f) => ({ ...f, protocol: e.target.value }))}
            className="ids-input py-1.5 text-xs"
          >
            <option value="">All Protocols</option>
            {['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'].map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP…"
              value={filters.ip}
              onChange={(e) => setFilters((f) => ({ ...f, ip: e.target.value }))}
              className="ids-input py-1.5 pl-8 text-xs w-36"
            />
          </div>
          <input
            type="date"
            value={filters.startDate}
            onChange={(e) => setFilters((f) => ({ ...f, startDate: e.target.value }))}
            className="ids-input py-1.5 text-xs"
          />
          <input
            type="date"
            value={filters.endDate}
            onChange={(e) => setFilters((f) => ({ ...f, endDate: e.target.value }))}
            className="ids-input py-1.5 text-xs"
          />
          {Object.values(filters).some(Boolean) && (
            <button
              onClick={() => setFilters({ severity: '', status: '', protocol: '', ip: '', startDate: '', endDate: '' })}
              className="ids-btn-ghost text-xs py-1.5"
            >
              <X className="w-3.5 h-3.5" /> Clear
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="ids-card flex-1 overflow-auto">
        <table className="ids-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Rule Name</th>
              <th>Src IP</th>
              <th>Dst IP</th>
              <th>Port</th>
              <th>Protocol</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading
              ? [...Array(10)].map((_, i) => (
                  <tr key={i}>
                    <td colSpan={9}>
                      <div className="h-5 bg-slate-700/40 rounded animate-pulse" />
                    </td>
                  </tr>
                ))
              : alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => setSelected(alert)}
                    className={alert.severity === 'CRITICAL' ? 'border-l-2 border-red-700' : ''}
                  >
                    <td className="text-xs font-mono text-slate-400">
                      {alert.timestamp ? format(new Date(alert.timestamp), 'MM-dd HH:mm:ss') : '—'}
                    </td>
                    <td><SeverityBadge severity={alert.severity} /></td>
                    <td className="max-w-[180px] truncate text-slate-200">{alert.rule_name}</td>
                    <td className="font-mono text-xs">{alert.src_ip}</td>
                    <td className="font-mono text-xs">{alert.dst_ip}</td>
                    <td className="font-mono text-xs">{alert.dst_port}</td>
                    <td>
                      <span className="text-xs bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded font-mono">
                        {alert.protocol}
                      </span>
                    </td>
                    <td>
                      <span className={`ids-badge border text-xs ${STATUS_COLORS[alert.status] || STATUS_COLORS.open}`}>
                        {alert.status}
                      </span>
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center gap-1">
                        <button
                          title="Block IP"
                          onClick={(e) => blockIP(alert.src_ip, e)}
                          className="p-1 text-red-400 hover:text-red-300 hover:bg-red-950/50 rounded transition-colors"
                        >
                          <Ban className="w-3.5 h-3.5" />
                        </button>
                        <button
                          title="Acknowledge"
                          onClick={(e) => ackAlert(alert.id, e)}
                          className="p-1 text-green-400 hover:text-green-300 hover:bg-green-950/50 rounded transition-colors"
                        >
                          <CheckCircle className="w-3.5 h-3.5" />
                        </button>
                        <button
                          title="View Details"
                          onClick={(e) => { e.stopPropagation(); setSelected(alert); }}
                          className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded transition-colors"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
          </tbody>
        </table>
        {!isLoading && alerts.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 text-slate-500">
            <Bell className="w-12 h-12 mb-3 opacity-30" />
            <p className="text-sm">No alerts found</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-slate-500">
          <span>Page {page} of {totalPages} · {data?.total} total alerts</span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="ids-btn-outline py-1.5 px-3 text-xs"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="ids-btn-outline py-1.5 px-3 text-xs"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Detail modal */}
      {selected && <AlertDetailModal alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
};

export default AlertFeed;
