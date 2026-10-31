import React, { useState, useEffect } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import AlertFeed from './pages/AlertFeed';
import RuleManager from './pages/RuleManager';
import PlaybookStudio from './pages/PlaybookStudio';
import ThreatIntelligence from './pages/ThreatIntelligence';
import SessionInspector from './pages/SessionInspector';
import Forensics from './pages/Forensics';
import NetworkTopology from './pages/NetworkTopology';
import Compliance from './pages/Compliance';
import NoSQLExplorer from './pages/NoSQLExplorer';
import Settings from './pages/Settings';
import Login from './pages/Login';
import useAuthStore from './store/authStore';

// Protected route wrapper
const ProtectedRoute = ({ children }) => {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const token = useAuthStore((s) => s.token);
  const location = useLocation();

  if (!isAuthenticated || !token) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return children;
};

// Layout wrapper with sidebar
const AppLayout = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
      <main className="flex-1 overflow-hidden flex flex-col min-w-0">
        <div className="flex-1 overflow-auto">
          {children}
        </div>
      </main>
    </div>
  );
};

const App = () => {
  // Apply dark class to document
  useEffect(() => {
    document.documentElement.classList.add('dark');
  }, []);

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AppLayout><Dashboard /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/alerts"
        element={
          <ProtectedRoute>
            <AppLayout><AlertFeed /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/rules"
        element={
          <ProtectedRoute>
            <AppLayout><RuleManager /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/playbooks"
        element={
          <ProtectedRoute>
            <AppLayout><PlaybookStudio /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/threats"
        element={
          <ProtectedRoute>
            <AppLayout><ThreatIntelligence /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/sessions"
        element={
          <ProtectedRoute>
            <AppLayout><SessionInspector /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/forensics"
        element={
          <ProtectedRoute>
            <AppLayout><Forensics /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/topology"
        element={
          <ProtectedRoute>
            <AppLayout><NetworkTopology /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/compliance"
        element={
          <ProtectedRoute>
            <AppLayout><Compliance /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/nosql"
        element={
          <ProtectedRoute>
            <AppLayout><NoSQLExplorer /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <AppLayout><Settings /></AppLayout>
          </ProtectedRoute>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
};

export default App;
