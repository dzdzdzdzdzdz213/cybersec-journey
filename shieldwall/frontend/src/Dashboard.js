import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area } from 'recharts';

const colors = ['#00d2ff', '#ff6b6b', '#ffd93d', '#6bcb77', '#c084fc', '#fb923c'];

const styles = {
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '15px', marginBottom: '20px' },
  card: { background: '#111827', border: '1px solid #1e2a3a', padding: '20px' },
  value: { color: '#00d2ff', fontSize: '28px', fontWeight: 'bold', margin: '5px 0' },
  label: { color: '#576574', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '1px' },
  section: { marginBottom: '20px' },
  sectionTitle: { color: '#00d2ff', fontSize: '14px', marginBottom: '10px', borderBottom: '1px solid #1e2a3a', paddingBottom: '5px' },
};

function Dashboard({ stats, timeline, alerts }) {
  const protoData = Object.entries(stats.protocols || {}).map(([name, value]) => ({ name, value }));
  const criticalAlerts = alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length;
  const highAlerts = alerts.filter(a => a.severity === 'high' && !a.acknowledged).length;

  return (
    <div>
      <div style={styles.grid}>
        <div style={styles.card}>
          <div style={styles.label}>Total Packets</div>
          <div style={styles.value}>{stats.total_packets}</div>
        </div>
        <div style={styles.card}>
          <div style={styles.label}>Total Alerts</div>
          <div style={styles.value}>{stats.total_alerts}</div>
        </div>
        <div style={styles.card}>
          <div style={styles.label}>Open Alerts</div>
          <div style={{ ...styles.value, color: stats.open_alerts > 0 ? '#ff6b6b' : '#00d2ff' }}>{stats.open_alerts}</div>
        </div>
        <div style={styles.card}>
          <div style={styles.label}>Critical</div>
          <div style={{ ...styles.value, color: criticalAlerts > 0 ? '#ff4757' : '#00d2ff' }}>{criticalAlerts}</div>
        </div>
        <div style={styles.card}>
          <div style={styles.label}>High</div>
          <div style={{ ...styles.value, color: highAlerts > 0 ? '#ffd93d' : '#00d2ff' }}>{highAlerts}</div>
        </div>
        <div style={styles.card}>
          <div style={styles.label}>Data Captured</div>
          <div style={styles.value}>{(stats.total_bytes / 1024 / 1024).toFixed(1)}MB</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px' }}>
        <div>
          <div style={styles.section}>
            <div style={styles.sectionTitle}>Traffic Timeline (last 60 min)</div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timeline}>
                <Area type="monotone" dataKey="count" stroke="#00d2ff" fill="#00d2ff" fillOpacity={0.1} />
                <XAxis dataKey="time" tick={{ fill: '#576574', fontSize: 10 }} />
                <YAxis tick={{ fill: '#576574', fontSize: 10 }} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #00d2ff', borderRadius: 0 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div style={styles.section}>
            <div style={styles.sectionTitle}>Recent Alerts</div>
            {alerts.slice(0, 5).map(a => (
              <div key={a.id} style={{ padding: '8px', borderBottom: '1px solid #1e2a3a', fontSize: '12px', display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: a.severity === 'critical' ? '#ff4757' : a.severity === 'high' ? '#ffd93d' : '#576574' }}>
                  [{a.severity.toUpperCase()}]
                </span>
                <span>{a.signature}</span>
                <span style={{ color: '#576574' }}>{a.src} → {a.dst}</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <div style={styles.section}>
            <div style={styles.sectionTitle}>Protocol Distribution</div>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={protoData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80}>
                  {protoData.map((_, i) => <Cell key={i} fill={colors[i % colors.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #00d2ff' }} />
              </PieChart>
            </ResponsiveContainer>
            {protoData.map((p, i) => (
              <div key={p.name} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', padding: '3px 0', color: '#576574' }}>
                <span><span style={{ color: colors[i], marginRight: 5 }}>■</span>{p.name}</span>
                <span>{p.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
