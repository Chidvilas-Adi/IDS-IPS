import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Area, AreaChart
} from 'recharts';
import {
  AlertTriangle, Ban, Activity, Minus, Shield, Database, Zap, RefreshCw,
  Server, ArrowUp, ArrowDown
} from 'lucide-react';
import { format, subHours } from 'date-fns';
import { api } from '../api/client';
import useSocket from '../hooks/useSocket';
import SeverityBadge from '../components/SeverityBadge';

// ─── Colour constants ────────────────────────────────────────────────────────
const SEVERITY_COLORS = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#6b7280',
};
const PROTOCOL_COLORS = ['#6366f1', '#22c55e', '#f97316', '#3b82f6', '#a855f7', '#14b8a6'];

// ─── Helpers ─────────────────────────────────────────────────────────────────
const fmt = (n) => n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M`
  : n >= 1_000 ? `${(n / 1_000).toFixed(1)}K` : String(n ?? 0);

const TrendIcon = ({ trend }) => {
  if (trend > 0) return <ArrowUp className="w-3.5 h-3.5 text-red-400" />;
  if (trend < 0) return <ArrowDown className="w-3.5 h-3.5 text-green-400" />;
  return <Minus className="w-3.5 h-3.5 text-slate-500" />;
};

// ─── Stat Card ───────────────────────────────────────────────────────────────
const StatCard = ({ title, value, subtext, icon: Icon, iconClass, trend, trendLabel, loading }) => (
  <div className="ids-card p-5">
    <div className="flex items-start justify-between mb-3">
      <div className={`p-2.5 rounded-lg ${iconClass || 'bg-slate-700'}`}>
        {Icon && <Icon className="w-5 h-5 text-white" />}
      </div>
      {trend !== undefined && trend !== null && (
        <div className="flex items-center gap-1 text-xs text-slate-500">
          <TrendIcon trend={trend} />
          <span className={trend > 0 ? 'text-red-400' : trend < 0 ? 'text-green-400' : 'text-slate-500'}>
            {trendLabel}
          </span>
        </div>
      )}
    </div>
    <div className="text-2xl font-bold text-slate-100">{loading ? '—' : fmt(value)}</div>
    <div className="text-sm text-slate-400 mt-0.5">{title}</div>
    {subtext && <div className="text-xs text-slate-500 mt-1">{subtext}</div>}
  </div>
);

// ─── Engine Health ────────────────────────────────────────────────────────────
const ENGINE_ICONS = {
  postgres: Database, mongodb: Database, redis: Zap,
};
const EngineHealth = ({ engines = {}, loading }) => (
  <div className="ids-card p-5">
    <div className="section-header">
      <span className="section-title">Core Service Health</span>
      <RefreshCw className="w-4 h-4 text-slate-500" />
    </div>
    <div className="space-y-2.5">
      {loading ? (
        [...Array(5)].map((_, i) => (
          <div key={i} className="h-8 bg-slate-700/50 rounded-lg animate-pulse" />
        ))
      ) : (
        Object.entries(engines).length > 0 ? Object.entries(engines).map(([name, status]) => {
          const Icon = ENGINE_ICONS[name] || Server;
          const dot = status === 'running' ? 'bg-green-500' : status === 'warning' ? 'bg-yellow-500' : 'bg-red-500';
          const label = name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
          return (
            <div key={name} className="flex items-center gap-3 p-2 bg-slate-800/40 rounded-lg">
              <Icon className="w-4 h-4 text-slate-400 flex-shrink-0" />
              <span className="flex-1 text-sm text-slate-300">{label}</span>
              <span className={`w-2 h-2 rounded-full pulse-dot ${dot}`} />
              <span className={`text-xs font-medium ${status === 'running' ? 'text-green-400' : status === 'warning' ? 'text-yellow-400' : 'text-red-400'}`}>
                {status}
              </span>
            </div>
          );
        }) : (
          <p className="text-sm text-slate-500">Service health information is unavailable.</p>
        )
      )}
    </div>
    <p className="text-xs text-slate-500 mt-3">
      Packet capture and host firewall adapters run separately and are not inferred from database health.
    </p>
  </div>
);

// ─── Live Ticker ─────────────────────────────────────────────────────────────
const AlertTicker = ({ alerts }) => {
  if (!alerts.length) return null;
  const doubled = [...alerts, ...alerts]; // infinite scroll
  return (
    <div className="ids-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-slate-700/50 bg-red-950/20">
        <span className="w-2 h-2 bg-red-500 rounded-full pulse-dot" />
        <span className="text-xs font-semibold text-red-400 uppercase tracking-widest">Live Alerts</span>
      </div>
      <div className="ticker-wrap py-2">
        <div className="ticker-inner flex gap-12">
          {doubled.map((a, i) => (
            <div key={i} className="flex items-center gap-3 whitespace-nowrap">
              <SeverityBadge severity={a.severity} showDot size="xs" />
              <span className="text-xs text-slate-400 font-mono">{a.src_ip} → {a.dst_ip}:{a.dst_port}</span>
              <span className="text-xs text-slate-300">{a.rule_name || a.rule_type || 'Unclassified alert'}</span>
              <span className="text-slate-700">|</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ─── Custom Tooltip ───────────────────────────────────────────────────────────
const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-3 text-xs shadow-xl">
      <div className="text-slate-400 mb-1.5">{label}</div>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          <span className="text-slate-300">{p.name}:</span>
          <span className="font-semibold text-slate-100">{p.value}</span>
        </div>
      ))}
    </div>
  );
};

// ─── Top Attackers ────────────────────────────────────────────────────────────
const TopAttackers = ({ data = [], loading }) => (
  <div className="ids-card p-5">
    <div className="section-header">
      <span className="section-title">Top Attackers</span>
      <Ban className="w-4 h-4 text-slate-500" />
    </div>
    <table className="ids-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Source IP</th>
          <th>Alerts</th>
          <th>Rep. Score</th>
          <th>Country</th>
        </tr>
      </thead>
      <tbody>
        {loading
          ? [...Array(5)].map((_, i) => (
              <tr key={i}>
                <td colSpan={5}>
                  <div className="h-4 bg-slate-700/50 rounded animate-pulse" />
                </td>
              </tr>
            ))
          : data.slice(0, 5).map((row, i) => (
              <tr key={row.src_ip}>
                <td className="text-slate-500 font-mono">{i + 1}</td>
                <td className="font-mono text-slate-200">{row.src_ip}</td>
                <td>
                  <span className="text-red-400 font-semibold">{row.alert_count}</span>
                </td>
                <td>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden max-w-[60px]">
                      <div
                        className={`h-full rounded-full ${(Number(row.reputation_score) || 0) >= 80 ? 'bg-red-500' : (Number(row.reputation_score) || 0) >= 50 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                        style={{ width: `${Number(row.reputation_score) || 0}%` }}
                      />
                    </div>
                    <span className="text-xs text-slate-400 font-mono">{Number(row.reputation_score) || 0}</span>
                  </div>
                </td>
                <td className="text-slate-400">{row.country || '—'}</td>
              </tr>
            ))}
      </tbody>
    </table>
  </div>
);

// ─── Dashboard ────────────────────────────────────────────────────────────────
const Dashboard = () => {
  const { alertQueue, stats: liveStats } = useSocket();

  const { data: overview, isLoading: loadingOverview } = useQuery({
    queryKey: ['stats-overview'],
    queryFn: () => api.getStats().then((r) => r.data),
    refetchInterval: 30000,
  });

  const { data: hourlyData } = useQuery({
    queryKey: ['alerts-by-hour'],
    queryFn: () => api.getAlertsByHour().then((r) => r.data),
    refetchInterval: 60000,
  });

  const { data: severityData } = useQuery({
    queryKey: ['severity-distribution'],
    queryFn: () => api.getSeverityDistribution().then((r) => r.data),
    refetchInterval: 60000,
  });

  const { data: protocolData } = useQuery({
    queryKey: ['protocol-breakdown'],
    queryFn: () => api.getProtocolBreakdown().then((r) => r.data),
    refetchInterval: 60000,
  });

  const { data: topAttackers, isLoading: loadingAttackers } = useQuery({
    queryKey: ['top-attackers'],
    queryFn: () => api.getTopAttackers().then((r) => r.data),
    refetchInterval: 60000,
  });

  const { data: engineData, isLoading: loadingEngines } = useQuery({
    queryKey: ['engine-health'],
    queryFn: () => api.getEngineHealth().then((r) => r.data),
    refetchInterval: 15000,
  });

  const stats = liveStats || overview || {};
  const engines = Object.fromEntries(
    Object.entries(engineData?.components || {}).map(([name, status]) => [
      name,
      status === 'UP' ? 'running' : 'stopped',
    ])
  );

  // Generate hourly labels for last 24h if server returns empty
  const hourlyRows = hourlyData?.timeseries || [];
  const hourly = hourlyRows.length
    ? hourlyRows.map((row) => ({
        hour: String(row.time_slot).slice(11, 16),
        count: row.count,
        blocked: 0,
      }))
    : [...Array(24)].map((_, i) => ({
        hour: format(subHours(new Date(), 23 - i), 'HH:00'),
        count: 0,
        blocked: 0,
      }));

  const severityRows = severityData?.severities || [];
  const severityDist = severityRows.length
    ? severityRows
    : Object.entries(SEVERITY_COLORS).map(([name]) => ({ name, value: 0 }));

  const protocolRows = protocolData?.protocols || [];
  const protocols = protocolRows.length
    ? protocolRows.map((row) => ({ protocol: row.name, count: row.value }))
    : [{ protocol: 'TCP', count: 0 }, { protocol: 'UDP', count: 0 }];

  return (
    <div className="p-6 space-y-6 min-h-full">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Security Overview</h1>
          <p className="text-sm text-slate-500 mt-0.5">Real-time IDS/IPS monitoring dashboard</p>
        </div>
        <div className="text-xs text-slate-500">
          {format(new Date(), 'EEEE, MMMM d yyyy · HH:mm:ss')}
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Alerts Today"
          value={stats.alerts_today ?? 0}
          icon={AlertTriangle}
          iconClass="bg-red-700"
          trend={stats.alerts_trend}
          trendLabel={`${Math.abs(stats.alerts_trend ?? 0)}% vs yesterday`}
          loading={loadingOverview}
        />
        <StatCard
          title="Blocked IPs"
          value={stats.blocked_ips ?? 0}
          icon={Ban}
          iconClass="bg-orange-700"
          trend={stats.blocked_trend}
          trendLabel={`${Math.abs(stats.blocked_trend ?? 0)}% vs yesterday`}
          loading={loadingOverview}
        />
        <StatCard
          title="Active Sessions"
          value={stats.active_sessions ?? 0}
          icon={Activity}
          iconClass="bg-brand-700"
          trend={stats.sessions_trend}
          trendLabel="current"
          loading={loadingOverview}
        />
        <StatCard
          title="Threat Score"
          value={stats.threat_score ?? 0}
          subtext="Environment risk level"
          icon={Shield}
          iconClass={
            (stats.threat_score ?? 0) >= 80 ? 'bg-red-700' :
            (stats.threat_score ?? 0) >= 50 ? 'bg-orange-700' :
            'bg-green-700'
          }
          trend={stats.score_trend}
          trendLabel="today"
          loading={loadingOverview}
        />
      </div>

      {/* Live ticker */}
      {alertQueue.length > 0 && <AlertTicker alerts={alertQueue.slice(0, 8)} />}

      {/* Charts row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alerts per hour — spans 2 cols */}
        <div className="ids-card p-5 lg:col-span-2">
          <div className="section-header">
            <span className="section-title">Alerts Per Hour (Last 24h)</span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={hourly} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis tick={{ fill: '#64748b', fontSize: 11 }} />
              <Tooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: 12, color: '#94a3b8' }} />
              <Area type="monotone" dataKey="count" name="Alerts" stroke="#ef4444" fill="url(#alertGrad)" strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity donut */}
        <div className="ids-card p-5">
          <div className="section-header">
            <span className="section-title">Severity Distribution</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={severityDist}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                dataKey="value"
                nameKey="name"
                paddingAngle={2}
              >
                {severityDist.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#6b7280'} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Charts row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Protocol breakdown */}
        <div className="ids-card p-5">
          <div className="section-header">
            <span className="section-title">Protocol Breakdown</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={protocols} layout="vertical" margin={{ left: 10, right: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis dataKey="protocol" type="category" tick={{ fill: '#94a3b8', fontSize: 11 }} width={50} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Alerts" radius={[0, 4, 4, 0]}>
                {protocols.map((_, i) => (
                  <Cell key={i} fill={PROTOCOL_COLORS[i % PROTOCOL_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top attackers */}
        <div className="lg:col-span-2">
          <TopAttackers data={topAttackers?.attackers || []} loading={loadingAttackers} />
        </div>
      </div>

      {/* Engine health */}
      <EngineHealth engines={engines} loading={loadingEngines} />
    </div>
  );
};

export default Dashboard;
