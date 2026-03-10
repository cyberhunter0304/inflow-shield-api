// ─────────────────────────────────────────────────────────────
//  Helpers — copied verbatim from dashboard.html
// ─────────────────────────────────────────────────────────────
export const BACKEND_URL = window.location.origin;
export const ITEMS_PER_PAGE = 20;

export function formatDate(iso) {
  if (!iso) return 'N/A';
  return new Date(iso).toLocaleString();
}

export function getRelativeTime(iso) {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000), h = Math.floor(diff / 3600000), d = Math.floor(diff / 86400000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  if (h < 24) return `${h}h ago`;
  if (d < 7)  return `${d}d ago`;
  return formatDate(iso);
}

// ─────────────────────────────────────────────────────────────
//  Data Fetching — copied verbatim from dashboard.html
// ─────────────────────────────────────────────────────────────
export async function fetchAllThreads() {
  try {
    const r = await fetch(`${BACKEND_URL}/api/security`);
    const data = await r.json();

    return (data.sessions || []).map(botLog => {
      const events = botLog.security_events || [];
      const convMap = {};
      events.forEach(evt => {
        const cid = evt.conversation_id || 'unknown';
        if (!convMap[cid]) {
          convMap[cid] = {
            conversation_id: cid, thread_id: evt.thread_id || botLog.bot_id,
            started_at: evt.timestamp, ended_at: evt.timestamp,
            security_events: [], total_prompts: 0, blocked_prompts: 0,
            pii_detections: 0, jailbreak_attempts: 0, toxicity_detections: 0, secrets_detections: 0
          };
        }
        const c = convMap[cid];
        if (evt.timestamp < c.started_at) c.started_at = evt.timestamp;
        if (evt.timestamp > c.ended_at)   c.ended_at   = evt.timestamp;
        c.security_events.push(evt);
        c.total_prompts++;
        if (evt.blocked)                                c.blocked_prompts++;
        if (evt.detections?.pii?.detected)              c.pii_detections++;
        if (evt.detections?.prompt_injection?.detected) c.jailbreak_attempts++;
        if (evt.detections?.toxicity?.detected)         c.toxicity_detections++;
        if (evt.detections?.pii?.secrets_detected)      c.secrets_detections++;
      });
      const conversations = Object.values(convMap);
      const threadId = events[0]?.thread_id || botLog.bot_id;
      const userId   = events[0]?.thread_id ? `user_${events[0].thread_id.replace(/^thread_/,'')}` : botLog.bot_id;
      return {
        thread_id: threadId, bot_id: botLog.bot_id, user_id: userId,
        created_at: botLog.created_at, last_updated: botLog.last_updated,
        total_prompts: botLog.total_prompts || 0, blocked_prompts: botLog.blocked_prompts || 0,
        pii_detections: botLog.pii_detections || 0, jailbreak_attempts: botLog.jailbreak_attempts || 0,
        toxicity_detections: botLog.toxicity_detections || 0, secrets_detections: botLog.secrets_detections || 0,
        conversations, conversation_count: conversations.length
      };
    });
  } catch (e) {
    console.error('Failed to fetch threads:', e);
    return [];
  }
}

export async function deleteThreadApi(botId) {
  await fetch(`${BACKEND_URL}/api/security-logs/${botId}`, { method: 'DELETE' });
}

// ─────────────────────────────────────────────────────────────
//  Derived State — copied verbatim from dashboard.html
// ─────────────────────────────────────────────────────────────
export function getStats(threads) {
  return threads.reduce((a, t) => ({
    totalThreads:        a.totalThreads + 1,
    totalConversations:  a.totalConversations + (t.conversation_count || 0),
    totalPrompts:        a.totalPrompts + (t.total_prompts || 0),
    totalBlocked:        a.totalBlocked + (t.blocked_prompts || 0),
    totalPII:            a.totalPII + (t.pii_detections || 0),
    totalJailbreaks:     a.totalJailbreaks + (t.jailbreak_attempts || 0),
    totalToxicity:       a.totalToxicity + (t.toxicity_detections || 0),
    totalSecrets:        a.totalSecrets + (t.secrets_detections || 0),
  }), { totalThreads:0, totalConversations:0, totalPrompts:0, totalBlocked:0, totalPII:0, totalJailbreaks:0, totalToxicity:0, totalSecrets:0 });
}

export function getFilteredThreads(threads, searchTerm, searchMode, filterType, sortBy) {
  let f = [...threads];
  const q = searchTerm.toLowerCase();
  if (q) {
    if (searchMode === 'botId')    f = f.filter(t => (t.bot_id||'').toLowerCase().includes(q));
    if (searchMode === 'threadId') f = f.filter(t => (t.thread_id||'').toLowerCase().includes(q));
    if (searchMode === 'prompt')   f = f.filter(t =>
      t.conversations?.some(c =>
        c.security_events?.some(e => (e.prompt||'').toLowerCase().includes(q))
      )
    );
  }
  if (filterType === 'threats')   f = f.filter(t => t.pii_detections>0 || t.jailbreak_attempts>0 || t.toxicity_detections>0 || t.secrets_detections>0 || t.blocked_prompts>0);
  if (filterType === 'clean')     f = f.filter(t => !t.pii_detections && !t.jailbreak_attempts && !t.toxicity_detections && !t.secrets_detections && !t.blocked_prompts);
  if (filterType === 'pii')       f = f.filter(t => t.pii_detections > 0);
  if (filterType === 'jailbreak') f = f.filter(t => t.jailbreak_attempts > 0);
  if (filterType === 'toxicity')  f = f.filter(t => t.toxicity_detections > 0);
  if (filterType === 'secrets')   f = f.filter(t => t.secrets_detections > 0);
  f.sort((a, b) => {
    if (sortBy === 'date-desc')    return new Date(b.last_updated||b.created_at) - new Date(a.last_updated||a.created_at);
    if (sortBy === 'date-asc')     return new Date(a.last_updated||a.created_at) - new Date(b.last_updated||b.created_at);
    if (sortBy === 'threats-desc') return ((b.pii_detections||0)+(b.jailbreak_attempts||0)+(b.toxicity_detections||0)+(b.secrets_detections||0)) - ((a.pii_detections||0)+(a.jailbreak_attempts||0)+(a.toxicity_detections||0)+(a.secrets_detections||0));
    if (sortBy === 'prompts-desc') return (b.total_prompts||0) - (a.total_prompts||0);
    return 0;
  });
  return f;
}

// ─────────────────────────────────────────────────────────────
//  Export Helpers — copied verbatim from dashboard.html
// ─────────────────────────────────────────────────────────────
export function downloadFile(content, filename, type) {
  const mime = type === 'csv' ? 'text/csv;charset=utf-8;' : 'application/json';
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

export function toCSV(rows) {
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]).join(',');
  const body = rows.map(r => Object.values(r).map(v=>`"${v}"`).join(',')).join('\n');
  return `${headers}\n${body}`;
}

export function exportSummaryCSV(threads) {
  const rows = threads.map(s => ({
    'Bot ID': s.bot_id, 'Created': new Date(s.created_at).toLocaleString(),
    'Total Prompts': s.total_prompts, 'Blocked': s.blocked_prompts,
    'PII': s.pii_detections, 'Secrets': s.secrets_detections||0,
    'Jailbreaks': s.jailbreak_attempts, 'Toxicity': s.toxicity_detections
  }));
  downloadFile(toCSV(rows), `security-summary-${new Date().toISOString().split('T')[0]}.csv`, 'csv');
}

export function exportFullJSON(threads) {
  downloadFile(JSON.stringify(threads, null, 2), `security-full-${new Date().toISOString().split('T')[0]}.json`, 'json');
}

export function exportThreatsCSV(threads) {
  const rows = threads
    .filter(s=>s.pii_detections>0||s.jailbreak_attempts>0||s.toxicity_detections>0||s.secrets_detections>0||s.blocked_prompts>0)
    .map(s => ({
      'Bot ID': s.bot_id, 'Total Prompts': s.total_prompts, 'Blocked': s.blocked_prompts,
      'PII': s.pii_detections, 'Secrets': s.secrets_detections||0,
      'Jailbreaks': s.jailbreak_attempts, 'Toxicity': s.toxicity_detections,
      'Total Threats': (s.pii_detections||0)+(s.secrets_detections||0)+(s.jailbreak_attempts||0)+(s.toxicity_detections||0)
    }));
  downloadFile(toCSV(rows), `all-threats-${new Date().toISOString().split('T')[0]}.csv`, 'csv');
}

// ─────────────────────────────────────────────────────────────
//  Counter animation — copied verbatim from dashboard.html
// ─────────────────────────────────────────────────────────────
export function animateCounters() {
  const counters = document.querySelectorAll('[data-count-to]');
  counters.forEach(el => {
    const target = parseInt(el.dataset.countTo, 10);
    if (target === 0) { el.textContent = '0'; return; }
    const duration = 800;
    const startTime = performance.now();
    const easeOutQuad = t => t * (2 - t);
    function update(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easedProgress = easeOutQuad(progress);
      const current = Math.floor(easedProgress * target);
      el.textContent = current.toLocaleString();
      if (progress < 1) requestAnimationFrame(update);
      else el.textContent = target.toLocaleString();
    }
    requestAnimationFrame(update);
  });
}
