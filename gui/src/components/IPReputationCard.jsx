import React, { useState } from 'react';
import { Shield, MapPin, Clock, Tag, AlertTriangle, Ban, ExternalLink } from 'lucide-react';
import { api } from '../api/client';
import toast from 'react-hot-toast';

const getScoreColor = (score) => {
  if (score >= 80) return { bar: 'bg-red-500', text: 'text-red-400', label: 'CRITICAL' };
  if (score >= 60) return { bar: 'bg-orange-500', text: 'text-orange-400', label: 'HIGH' };
  if (score >= 40) return { bar: 'bg-yellow-500', text: 'text-yellow-400', label: 'MEDIUM' };
  if (score >= 20) return { bar: 'bg-blue-500', text: 'text-blue-400', label: 'LOW' };
  return { bar: 'bg-green-500', text: 'text-green-400', label: 'CLEAN' };
};

const ScoreGauge = ({ score }) => {
  const { bar, text, label } = getScoreColor(score);
  const pct = Math.min(100, Math.max(0, score));
  return (
    <div className="flex flex-col gap-1">
      <div className="flex justify-between items-center text-xs">
        <span className="text-slate-400">Reputation Score</span>
        <span className={`font-bold text-lg ${text}`}>{score}</span>
      </div>
      <div className="h-2.5 bg-slate-700 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${bar}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="flex justify-between text-2xs text-slate-500">
        <span>0 (Clean)</span>
        <span className={`font-semibold ${text}`}>{label}</span>
        <span>100 (Malicious)</span>
      </div>
    </div>
  );
};

const IPReputationCard = ({ ip, data, onBlock, compact = false }) => {
  const [blocking, setBlocking] = useState(false);
  const reputation = data || {};
  const score = reputation.score ?? 0;
  const { text, label } = getScoreColor(score);

  const handleBlock = async () => {
    setBlocking(true);
    try {
      await api.blockIP(ip, `Manual block from reputation card`);
      toast.success(`IP ${ip} blocked successfully`);
      onBlock?.();
    } catch (err) {
      toast.error(`Failed to block ${ip}`);
    } finally {
      setBlocking(false);
    }
  };

  if (compact) {
    return (
      <div className="ids-card p-3 flex items-center gap-3">
        <div className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${score >= 60 ? 'bg-red-950' : 'bg-slate-700'}`}>
          <Shield className={`w-5 h-5 ${text}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="font-mono text-sm text-slate-100 truncate">{ip}</div>
          <div className={`text-xs font-semibold ${text}`}>{label} · Score {score}</div>
        </div>
        {reputation.tags?.slice(0, 2).map((t) => (
          <span key={t} className="text-2xs bg-slate-700 text-slate-400 px-1.5 py-0.5 rounded">{t}</span>
        ))}
      </div>
    );
  }

  return (
    <div className="ids-card p-5 space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="font-mono text-lg font-bold text-slate-100">{ip}</div>
          {reputation.hostname && (
            <div className="text-xs text-slate-500 mt-0.5">{reputation.hostname}</div>
          )}
        </div>
        <button
          onClick={handleBlock}
          disabled={blocking || reputation.is_blocked}
          className={`ids-btn text-xs ${reputation.is_blocked ? 'bg-slate-700 text-slate-500 cursor-not-allowed' : 'ids-btn-danger'}`}
        >
          <Ban className="w-3.5 h-3.5" />
          {reputation.is_blocked ? 'Blocked' : blocking ? 'Blocking…' : 'Block IP'}
        </button>
      </div>

      {/* Score gauge */}
      <ScoreGauge score={score} />

      {/* Meta grid */}
      <div className="grid grid-cols-2 gap-3 text-sm">
        {reputation.country && (
          <div className="flex items-center gap-2 text-slate-400">
            <MapPin className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
            <span>{reputation.country}{reputation.city ? `, ${reputation.city}` : ''}</span>
          </div>
        )}
        {reputation.asn && (
          <div className="flex items-center gap-2 text-slate-400">
            <ExternalLink className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
            <span className="truncate">{reputation.asn}</span>
          </div>
        )}
        {reputation.last_seen && (
          <div className="flex items-center gap-2 text-slate-400">
            <Clock className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
            <span>{reputation.last_seen}</span>
          </div>
        )}
        {reputation.ioc_matches !== undefined && (
          <div className="flex items-center gap-2 text-slate-400">
            <AlertTriangle className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
            <span>{reputation.ioc_matches} IOC matches</span>
          </div>
        )}
      </div>

      {/* Tags */}
      {reputation.tags?.length > 0 && (
        <div className="flex items-start gap-2 flex-wrap">
          <Tag className="w-3.5 h-3.5 text-slate-500 mt-0.5 flex-shrink-0" />
          {reputation.tags.map((tag) => (
            <span key={tag} className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded-full">
              {tag}
            </span>
          ))}
        </div>
      )}

      {/* IOC sources */}
      {reputation.sources?.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1.5">Sources</div>
          <div className="space-y-1">
            {reputation.sources.map((src) => (
              <div key={src.name} className="flex items-center justify-between text-xs">
                <span className="text-slate-400">{src.name}</span>
                <span className={`font-semibold ${getScoreColor(src.confidence * 100).text}`}>
                  {Math.round(src.confidence * 100)}% confidence
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Alert count */}
      {reputation.alert_count !== undefined && (
        <div className="flex items-center justify-between text-sm border-t border-slate-700/50 pt-3">
          <span className="text-slate-500">Related Alerts</span>
          <span className={`font-bold ${reputation.alert_count > 0 ? 'text-red-400' : 'text-slate-400'}`}>
            {reputation.alert_count}
          </span>
        </div>
      )}
    </div>
  );
};

export default IPReputationCard;
