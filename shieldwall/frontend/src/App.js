import React, { useState, useEffect, useRef } from 'react';
import Dashboard from './Dashboard';
import Alerts from './Alerts';
import Packets from './Packets';
import { fetchStats, fetchAlerts, fetchPackets, fetchTimeline, ackAlert, connectWebSocket } from './api';

const styles = {
  app: { background: '#0a0e17', color: '#c8d6e5', minHeight: '100vh', fontFamily: "'Fira Code', 'Cascadia Code', monospace", padding: '20px' },
  header: { borderBottom: '2px solid #00d2ff', paddingBottom: '15px', marginBottom: '20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
  title: { color: '#00d2ff', fontSize: '24px', fontWeight: 'bold', margin: 0 },
  subtitle: { color: '#576574', fontSize: '12px', margin: 0 },
  nav: { display: 'flex', gap: '10px', marginBottom: '20px' },
  navBtn: (active) => ({ padding: '8px 20px', background: active ? '#00d2ff' : '#1e2a3a', color: active ? '#0a0e17' : '#c8d6e5', border: '1px solid #00d2ff', cursor: 'pointer', fontSize: '13px' }),
  status: { display: 'flex', gap: '20px', padding: '10px 15px', background: '#111827', border: '1px solid #1e2a3a', fontSize: '12px', marginBottom: '20px' },
  dot: (on) => ({ width: 8, height: 8, borderRadius: '50%', background: on ? '#00ff88' : '#ff4757', display: 'inline-block', marginRight: 6 }),
};

function App() {
  const [tab, setTab] = useState('dashboard');
  const [stats, setStats] = useState({ total_packets: 0, total_alerts: 0, open_alerts: 0, protocols: {} });
  const [alerts, setAlerts] = useState([]);
  const [packets, setPackets] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    fetchStats().then(setStats);
    fetchAlerts(100).then(setAlerts);
    fetchPackets(100).then(setPackets);
    fetchTimeline().then(setTimeline);
    const ws = connectWebSocket((msg) => {
      setConnected(true);
      if (msg.type === 'alert') setAlerts(prev => [msg.data, ...prev].slice(0, 200));
      if (msg.type === 'packet') setPackets(prev => [msg.data, ...prev].slice(0, 200));
    });
    wsRef.current = ws;
    const interval = setInterval(() => { fetchStats().then(setStats); fetchTimeline().then(setTimeline); }, 5000);
    return () => { clearInterval(interval); ws.close(); };
  }, []);

  const handleAck = async (id) => {
    await ackAlert(id);
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, acknowledged: true } : a));
  };

  return (
    <div style={styles.app}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.title}>SHIELDWALL</h1>
          <p style={styles.subtitle}>Network Security Monitor v1.0</p>
        </div>
        <div style={styles.status}>
          <span><span style={styles.dot(connected)} />{connected ? 'LIVE' : 'DISCONNECTED'}</span>
          <span>Packets: {stats.total_packets}</span>
          <span>Alerts: {stats.total_alerts}</span>
          <span>Open: {stats.open_alerts}</span>
        </div>
      </div>
      <div style={styles.nav}>
        {['dashboard', 'alerts', 'packets'].map(t => (
          <button key={t} style={styles.navBtn(tab === t)} onClick={() => setTab(t)}>
            {t.toUpperCase()}
          </button>
        ))}
      </div>
      {tab === 'dashboard' && <Dashboard stats={stats} timeline={timeline} alerts={alerts} />}
      {tab === 'alerts' && <Alerts alerts={alerts} onAck={handleAck} />}
      {tab === 'packets' && <Packets packets={packets} />}
    </div>
  );
}

export default App;
