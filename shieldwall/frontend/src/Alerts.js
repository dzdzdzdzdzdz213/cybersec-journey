import React from 'react';

const styles = {
  container: { background: '#111827', border: '1px solid #1e2a3a' },
  header: { display: 'grid', gridTemplateColumns: '80px 1fr 1fr 100px 140px 60px', padding: '10px 15px', borderBottom: '2px solid #00d2ff', color: '#00d2ff', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '1px' },
  row: (sev) => ({ display: 'grid', gridTemplateColumns: '80px 1fr 1fr 100px 140px 60px', padding: '8px 15px', borderBottom: '1px solid #1e2a3a', fontSize: '12px', alignItems: 'center', borderLeft: `3px solid ${sev === 'critical' ? '#ff4757' : sev === 'high' ? '#ffd93d' : '#576574'}` }),
  severity: (s) => ({ color: s === 'critical' ? '#ff4757' : s === 'high' ? '#ffd93d' : '#576574', fontWeight: 'bold' }),
  ackBtn: { background: '#1e2a3a', border: '1px solid #576574', color: '#c8d6e5', padding: '3px 10px', cursor: 'pointer', fontSize: '11px' },
};

function Alerts({ alerts, onAck }) {
  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <span>Severity</span>
        <span>Signature</span>
        <span>Source → Dest</span>
        <span>Protocol</span>
        <span>Time</span>
        <span></span>
      </div>
      {alerts.length === 0 && <div style={{ padding: '30px', textAlign: 'center', color: '#576574', fontSize: '13px' }}>No alerts yet</div>}
      {alerts.map(a => (
        <div key={a.id} style={styles.row(a.severity)}>
          <span style={styles.severity(a.severity)}>{a.severity.toUpperCase()}</span>
          <span>{a.signature}</span>
          <span style={{ color: '#576574' }}>{a.src} → {a.dst}</span>
          <span>{a.protocol}</span>
          <span style={{ color: '#576574', fontSize: '11px' }}>{new Date(a.timestamp).toLocaleTimeString()}</span>
          <span>
            {!a.acknowledged ? (
              <button style={styles.ackBtn} onClick={() => onAck(a.id)}>ACK</button>
            ) : (
              <span style={{ color: '#576574', fontSize: '11px' }}>✓ done</span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}

export default Alerts;
