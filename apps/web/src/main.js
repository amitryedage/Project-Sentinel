import './style.css';
const $ = (id) => document.getElementById(id);
let apiKey = '', offset = 0, evidence = null, generation = 0;
const limit = 50;
const text = (id, value) => { $(id).textContent = value; };
const message = (value) => text('message', value);
async function request(path) {
  const response = await fetch(path, { headers: { 'x-api-key': apiKey }, cache: 'no-store' });
  if (!response.ok) {
    if (response.status === 401) throw new Error('Invalid API key. Connect again with your operator key.');
    throw new Error(`Request failed (${response.status}). Please retry or check the API configuration.`);
  }
  return response.json();
}
function badge(status) {
  const span = document.createElement('span');
  span.className = 'badge';
  if (['clear','review','flagged','remediated'].includes(status)) span.classList.add(status);
  span.textContent = status || 'pending';
  return span;
}
async function load() {
  const current = ++generation;
  message('Loading incidents…');
  try {
    const rows = await request(`/api/v1/incidents?limit=${limit}&offset=${offset}`);
    if (current !== generation) return;
    $('board').hidden = false;
    $('disconnect').hidden = false;
    $('incidents').replaceChildren();
    $('stats').replaceChildren();
    for (const [label, count] of [['On this page',rows.length],...['clear','review','flagged'].map(s => [s, rows.filter(r => r.status === s).length])]) {
      const box = document.createElement('div'); box.className = 'stat'; box.textContent = label;
      const number = document.createElement('strong'); number.textContent = count; box.append(number); $('stats').append(box);
    }
    for (const row of rows) {
      const tr = document.createElement('tr');
      const td = document.createElement('td'); const button = document.createElement('button');
      button.className = 'link'; button.textContent = row.incident_id;
      button.onclick = () => showDetail(row); td.append(button); tr.append(td);
      for (const value of [row.merchant_name || '—',row.amount_in_paise == null ? '—' : new Intl.NumberFormat('en-IN',{style:'currency',currency:'INR'}).format(row.amount_in_paise/100),row.tis == null ? '—' : `${row.tis} / 100`]) {
        const cell = document.createElement('td'); cell.textContent = value; tr.append(cell);
      }
      const status = document.createElement('td'); status.append(badge(row.status)); tr.append(status); $('incidents').append(tr);
    }
    $('previous').disabled = offset === 0; $('next').disabled = rows.length < limit;
    text('page', `Page ${Math.floor(offset/limit)+1}`);
    message(rows.length ? 'Select an incident to inspect its findings and evidence.' : 'No incidents yet. Ingest telemetry or run the seed batch to populate the board.');
  } catch (error) { if (current === generation) message(error.message); }
}
async function showDetail(row) {
  const current = ++generation;
  $('detail').hidden = true; evidence = null;
  message(`Loading ${row.incident_id}…`);
  try {
    const [detail, trace, packet] = await Promise.all([
      request(`/api/v1/incidents/${encodeURIComponent(row.incident_id)}`),
      request(`/api/v1/sessions/${encodeURIComponent(row.session_id)}/trace`),
      request(`/api/v1/incidents/${encodeURIComponent(row.incident_id)}/evidence`),
    ]);
    if (current !== generation) return;
    text('detail-title', `${row.incident_id} · ${row.status}`);
    text('detail-summary', `Session ${row.session_id} · Evidence chain ${packet.verify?.ok ? 'verified' : 'requires review'}`);
    $('findings').replaceChildren();
    for (const finding of detail.findings) {
      const item = document.createElement('div'); item.className = 'finding';
      item.textContent = `${finding.severity} / ${finding.finding_type}: ${finding.description}`; $('findings').append(item);
    }
    if (!detail.findings.length) text('findings', 'No semantic findings.');
    text('score',JSON.stringify(detail.score,null,2)); text('trace',JSON.stringify(trace,null,2));
    text('evidence',JSON.stringify(packet,null,2)); evidence = packet;
    $('detail').hidden = false; $('detail').scrollIntoView({behavior:'smooth'}); message('Incident loaded.');
  } catch (error) { if (current === generation) message(error.message); }
}
$('connect').onsubmit = (event) => { event.preventDefault(); apiKey = $('key').value; $('key').value = ''; $('board').hidden = true; offset = 0; $('detail').hidden = true; load(); };
$('disconnect').onclick = () => { generation++; apiKey = ''; evidence = null; $('board').hidden = true; $('detail').hidden = true; $('disconnect').hidden = true; $('incidents').replaceChildren(); for(const id of ['evidence','trace','score','findings']) text(id,''); message('Disconnected.'); };
$('refresh').onclick = load;
$('previous').onclick = () => { offset = Math.max(0,offset-limit); load(); };
$('next').onclick = () => { offset += limit; load(); };
$('close-detail').onclick = () => { generation++; $('detail').hidden = true; };
$('download').onclick = () => {
  if (!evidence) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(evidence,null,2)],{type:'application/json'}));
  const a = document.createElement('a'); a.href = url; a.download = 'sentinel-evidence.json'; a.click(); URL.revokeObjectURL(url);
};
fetch('/health').then(r => { if (!r.ok) throw new Error(); return r.json(); }).then(h => text('health',`API online · ${h.gateway} payments`)).catch(() => text('health','API unavailable'));
