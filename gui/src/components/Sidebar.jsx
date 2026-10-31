import React, { useState, useEffect, useContext, createContext } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, Bell, Shield, BookOpen, Globe, Monitor,
  Search, Network, ClipboardCheck, Database, Settings,
  ChevronLeft, ChevronRight, LogOut, User, Wifi, WifiOff,
  AlertTriangle, X
} from 'lucide-react';
import useAuthStore from '../store/authStore';
import useSocket from '../hooks/useSocket';

const NAV_ITEMS = [
  { path: '/',           label: 'Dashboard',         icon: LayoutDashboard },
  { path: '/alerts',     label: 'Alert Feed',         icon: Bell,           badgeKey: 'alerts' },
  { path: '/rules',      label: 'Rule Manager',       icon: Shield },
  { path: '/playbooks',  label: 'Playbook Studio',    icon: BookOpen },
  { path: '/threats',    label: 'Threat Intel',       icon: Globe },
  { path: '/sessions',   label: 'Session Inspector',  icon: Monitor },
  { path: '/forensics',  label: 'Forensics',          icon: Search },
  { path: '/topology',   label: 'Network Topology',   icon: Network },
  { path: '/compliance', label: 'Compliance',         icon: ClipboardCheck },
  { path: '/nosql',      label: 'NoSQL Explorer',     icon: Database },
  { path: '/settings',   label: 'Settings',           icon: Settings },
];

const EngineStatusDot = ({ status }) => {
  const colors = {
    running: 'bg-green-500',
    warning: 'bg-yellow-500',
    stopped: 'bg-red-500',
    unknown: 'bg-slate-500',
  };
  return (
    <span className={`inline-block w-2 h-2 rounded-full ${colors[status] || colors.unknown} pulse-dot`} />
  );
};

const Sidebar = ({ collapsed, onToggle }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const logout = useAuthStore((s) => s.logout);
  const user = useAuthStore((s) => s.user);
  const { connected, alertCount, clearAlertCount, engineStatus } = useSocket();

  const allEnginesRunning = Object.values(engineStatus).every((s) => s === 'running');
  const anyEngineStopped = Object.values(engineStatus).some((s) => s === 'stopped');
  const overallStatus = anyEngineStopped ? 'stopped' : allEnginesRunning ? 'running' : 'warning';

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside
      className={`
        flex flex-col bg-slate-900 border-r border-slate-800
        transition-all duration-300 ease-in-out h-full
        ${collapsed ? 'w-16' : 'w-60'}
      `}
    >
      {/* Logo / Header */}
      <div className={`flex items-center h-16 border-b border-slate-800 px-4 ${collapsed ? 'justify-center' : 'justify-between'}`}>
        {!collapsed && (
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 bg-brand-600 rounded-lg flex items-center justify-center flex-shrink-0">
              <Shield className="w-4.5 h-4.5 text-white" strokeWidth={2.5} />
            </div>
            <div className="leading-tight">
              <div className="text-sm font-bold text-slate-100">IDS/IPS</div>
              <div className="text-2xs text-slate-500">Database-Driven</div>
            </div>
          </div>
        )}
        {collapsed && (
          <div className="w-8 h-8 bg-brand-600 rounded-lg flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" strokeWidth={2.5} />
          </div>
        )}
        <button
          onClick={onToggle}
          className="p-1 rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors ml-auto"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Connection status */}
      <div className={`flex items-center gap-2 px-4 py-2 border-b border-slate-800/50 ${collapsed ? 'justify-center' : ''}`}>
        {connected ? (
          <Wifi className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
        ) : (
          <WifiOff className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
        )}
        {!collapsed && (
          <span className={`text-xs ${connected ? 'text-green-400' : 'text-red-400'}`}>
            {connected ? 'Live' : 'Disconnected'}
          </span>
        )}
      </div>

      {/* Nav items */}
      <nav className="flex-1 py-3 overflow-y-auto overflow-x-hidden">
        {NAV_ITEMS.map(({ path, label, icon: Icon, badgeKey }) => {
          const isActive = path === '/'
            ? location.pathname === '/'
            : location.pathname.startsWith(path);
          const showBadge = badgeKey === 'alerts' && alertCount > 0;

          return (
            <NavLink
              key={path}
              to={path}
              onClick={() => badgeKey === 'alerts' && clearAlertCount()}
              className={`
                flex items-center h-10 px-4 rounded-lg mx-2 mb-0.5 group transition-all duration-150
                ${isActive
                  ? 'bg-brand-600/20 text-brand-400 border border-brand-600/30'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'}
                ${collapsed ? 'justify-center' : 'gap-3'}
              `}
              title={collapsed ? label : undefined}
            >
              <div className="relative flex-shrink-0">
                <Icon className={`w-4.5 h-4.5 ${isActive ? 'text-brand-400' : ''}`} />
                {showBadge && (
                  <span className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-red-500 text-white text-2xs font-bold rounded-full flex items-center justify-center">
                    {alertCount > 99 ? '99+' : alertCount}
                  </span>
                )}
              </div>
              {!collapsed && (
                <span className="text-sm font-medium truncate flex-1">{label}</span>
              )}
              {!collapsed && showBadge && (
                <span className="ml-auto bg-red-500 text-white text-2xs font-bold px-1.5 py-0.5 rounded-full min-w-[1.25rem] text-center">
                  {alertCount > 99 ? '99+' : alertCount}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom: engine status + user */}
      <div className="border-t border-slate-800">
        {/* Engine status */}
        <div className={`flex items-center gap-2 px-4 py-2.5 ${collapsed ? 'justify-center' : ''}`}>
          <EngineStatusDot status={overallStatus} />
          {!collapsed && (
            <span className="text-xs text-slate-500">
              {overallStatus === 'running' ? 'All engines running' :
               overallStatus === 'warning' ? 'Engine warning' : 'Engine offline'}
            </span>
          )}
        </div>

        {/* User / Logout */}
        <div className={`flex items-center px-4 py-3 border-t border-slate-800 ${collapsed ? 'justify-center' : 'gap-3'}`}>
          {!collapsed && (
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-slate-200 truncate">{user?.username || 'Admin'}</div>
              <div className="text-xs text-slate-500 truncate">{user?.role || 'Analyst'}</div>
            </div>
          )}
          <button
            onClick={handleLogout}
            title="Logout"
            className="p-1.5 rounded-md text-slate-500 hover:text-red-400 hover:bg-slate-800 transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
