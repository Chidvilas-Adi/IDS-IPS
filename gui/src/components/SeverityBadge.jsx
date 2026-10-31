import React from 'react';

const SEVERITY_CONFIG = {
  CRITICAL: {
    label: 'CRITICAL',
    bg: 'bg-red-950',
    border: 'border-red-700',
    text: 'text-red-400',
    dot: 'bg-red-500',
    glow: 'shadow-[0_0_8px_rgba(239,68,68,0.5)]',
  },
  HIGH: {
    label: 'HIGH',
    bg: 'bg-orange-950',
    border: 'border-orange-700',
    text: 'text-orange-400',
    dot: 'bg-orange-500',
    glow: 'shadow-[0_0_8px_rgba(249,115,22,0.5)]',
  },
  MEDIUM: {
    label: 'MEDIUM',
    bg: 'bg-yellow-950',
    border: 'border-yellow-700',
    text: 'text-yellow-400',
    dot: 'bg-yellow-500',
    glow: '',
  },
  LOW: {
    label: 'LOW',
    bg: 'bg-blue-950',
    border: 'border-blue-800',
    text: 'text-blue-400',
    dot: 'bg-blue-500',
    glow: '',
  },
  INFO: {
    label: 'INFO',
    bg: 'bg-slate-800',
    border: 'border-slate-600',
    text: 'text-slate-400',
    dot: 'bg-slate-500',
    glow: '',
  },
};

const SeverityBadge = ({ severity, showDot = true, size = 'sm' }) => {
  const key = (severity || 'INFO').toUpperCase();
  const cfg = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.INFO;

  const sizeClass = size === 'lg'
    ? 'px-3 py-1 text-sm gap-2'
    : size === 'xs'
    ? 'px-1.5 py-0.5 text-2xs gap-1'
    : 'px-2 py-0.5 text-xs gap-1.5';

  return (
    <span
      className={`
        inline-flex items-center font-semibold rounded-full border
        ${cfg.bg} ${cfg.border} ${cfg.text} ${cfg.glow} ${sizeClass}
      `}
    >
      {showDot && (
        <span className={`inline-block rounded-full flex-shrink-0 ${cfg.dot} ${size === 'lg' ? 'w-2 h-2' : 'w-1.5 h-1.5'}`} />
      )}
      {cfg.label}
    </span>
  );
};

export const severityColor = (severity) => {
  const key = (severity || 'INFO').toUpperCase();
  return SEVERITY_CONFIG[key]?.text || 'text-slate-400';
};

export const severityBg = (severity) => {
  const key = (severity || 'INFO').toUpperCase();
  return SEVERITY_CONFIG[key]?.bg || 'bg-slate-800';
};

export const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export default SeverityBadge;
