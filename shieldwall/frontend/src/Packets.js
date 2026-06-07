import React from 'react';

const styles = {
  container: { background: '#111827', border: '1px solid #1e2a3a' },
  header: { display: 'grid', gridTemplateColumns: '130px 120px 120px 50px 60px 100px', padding: '10px 15px', borderBottom: '2px solid #00d2ff', color: '#00d2ff', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '1px' },
  row: { display: 'grid', gridTemplateColumns: '130px 120px 120px 50px 60px 100px', padding: '6px 15px', borderBottom: '1px solid #1e2a3a', fontSize: '11px', alignItems: 'center' },
};

function Packets({ packets }) {
  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <span>Time</span>
        <span>Source</span>
        <span>Dest</span>
        <span>Prtcl</span>
        <span>Size</span>
        <span>Info</span>
      </div>
      {packets.length === 0 && <div style={{ padding: '30px', textAlign: 'center', color: '#576574', fontSize: '13px' }}>No packets yet</div>}
      {packets.map((p, i) => (
        <div key={i} style={styles.row}>
          <span style={{ color: '#576574' }}>{new Date(p.timestamp).toLocaleTimeString()}</span>
          <span>{p.src}</span>
          <span style={{ color: '#576574' }}>{p.dst}</span>
          <span style={{ color: p.protocol === 'TCP' ? '#00d2ff' : p.protocol === 'UDP' ? '#ffd93d' : '#6bcb77' }}>{p.protocol}</span>
          <span>{p.length}B</span>
          <span style={{ color: '#576574', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.info || '—'}</span>
        </div>
      ))}
    </div>
  );
}

export default Packets;
