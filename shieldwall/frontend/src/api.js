const API = 'http://localhost:8000';

export async function fetchStats() {
  const r = await fetch(`${API}/api/stats`);
  return r.json();
}

export async function fetchAlerts(limit = 50, severity = null, ack = null) {
  let url = `${API}/api/alerts?limit=${limit}`;
  if (severity) url += `&severity=${severity}`;
  if (ack !== null) url += `&ack=${ack}`;
  const r = await fetch(url);
  return r.json();
}

export async function fetchPackets(limit = 50, protocol = null) {
  let url = `${API}/api/packets?limit=${limit}`;
  if (protocol) url += `&protocol=${protocol}`;
  const r = await fetch(url);
  return r.json();
}

export async function fetchTimeline() {
  const r = await fetch(`${API}/api/timeline`);
  return r.json();
}

export async function ackAlert(id) {
  const r = await fetch(`${API}/api/alerts/${id}/ack`, { method: 'POST' });
  return r.json();
}

export function connectWebSocket(onMessage) {
  const ws = new WebSocket('ws://localhost:8000/ws');
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    onMessage(msg);
  };
  ws.onclose = () => setTimeout(() => connectWebSocket(onMessage), 3000);
  return ws;
}
