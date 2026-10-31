import { useEffect, useRef, useState, useCallback } from 'react';
import { io } from 'socket.io-client';
import useAuthStore from '../store/authStore';

const SOCKET_URL = process.env.REACT_APP_WS_URL || 'http://localhost:8000';

let globalSocket = null;
let subscriberCount = 0;

const useSocket = () => {
  const token = useAuthStore((s) => s.token);
  const [connected, setConnected] = useState(false);
  const [latestAlert, setLatestAlert] = useState(null);
  const [alertQueue, setAlertQueue] = useState([]);
  const [stats, setStats] = useState(null);
  const [engineStatus, setEngineStatus] = useState({});
  const [alertCount, setAlertCount] = useState(0);
  const socketRef = useRef(null);
  const alertQueueRef = useRef([]);

  const pushAlert = useCallback((alert) => {
    setLatestAlert(alert);
    alertQueueRef.current = [alert, ...alertQueueRef.current].slice(0, 50);
    setAlertQueue([...alertQueueRef.current]);
    setAlertCount((c) => c + 1);
  }, []);

  useEffect(() => {
    if (!token) return;

    subscriberCount++;

    if (!globalSocket || !globalSocket.connected) {
      globalSocket = io(SOCKET_URL, {
        auth: { token },
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: 10,
        reconnectionDelay: 2000,
        timeout: 10000,
      });
    }

    socketRef.current = globalSocket;
    const socket = socketRef.current;

    const onConnect = () => {
      setConnected(true);
      socket.emit('subscribe', { channels: ['alerts', 'stats', 'engines', 'sessions'] });
    };

    const onDisconnect = () => setConnected(false);

    const onAlert = (alert) => pushAlert(alert);

    const onStats = (data) => setStats(data);

    const onEngineStatus = (data) => setEngineStatus(data);

    const onBulkAlerts = (alerts) => {
      if (Array.isArray(alerts)) {
        alerts.forEach(pushAlert);
      }
    };

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('alert', onAlert);
    socket.on('alert:new', onAlert);
    socket.on('alert:bulk', onBulkAlerts);
    socket.on('stats:update', onStats);
    socket.on('engine:status', onEngineStatus);

    if (socket.connected) {
      setConnected(true);
    }

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('alert', onAlert);
      socket.off('alert:new', onAlert);
      socket.off('alert:bulk', onBulkAlerts);
      socket.off('stats:update', onStats);
      socket.off('engine:status', onEngineStatus);

      subscriberCount--;
      if (subscriberCount <= 0) {
        subscriberCount = 0;
        if (globalSocket) {
          globalSocket.disconnect();
          globalSocket = null;
        }
      }
    };
  }, [token, pushAlert]);

  const clearAlertCount = useCallback(() => setAlertCount(0), []);

  const emit = useCallback((event, data) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit(event, data);
    }
  }, []);

  return {
    connected,
    latestAlert,
    alertQueue,
    stats,
    engineStatus,
    alertCount,
    clearAlertCount,
    emit,
  };
};

export default useSocket;
