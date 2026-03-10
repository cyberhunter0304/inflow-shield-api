import { useEffect, useRef } from 'react';

// Exact DOM from renderAnalytics()
// Chart.js is on window.Chart (loaded via CDN in index.html — same as original)
export default function AnalyticsView({ threads, stats }) {
  const chartsRef = useRef({});

  useEffect(() => {
    // Destroy old charts — exact logic from initCharts()
    Object.values(chartsRef.current).forEach(c => c.destroy());
    chartsRef.current = {};

    const Chart = window.Chart;
    if (!Chart) return;

    // ── Pie chart — exact from initCharts() ──────────────────────────────
    const pieData = [
      { label: 'PII',       value: stats.totalPII,        color: '#f59e0b' },
      { label: 'Secrets',   value: stats.totalSecrets,    color: '#8b5cf6' },
      { label: 'Jailbreak', value: stats.totalJailbreaks, color: '#ef4444' },
      { label: 'Toxicity',  value: stats.totalToxicity,   color: '#dc2626' },
    ].filter(d => d.value > 0);

    const cleanCount = threads.filter(t =>
      !t.pii_detections && !t.jailbreak_attempts && !t.toxicity_detections && !t.secrets_detections
    ).length;
    if (cleanCount > 0) pieData.push({ label: 'Clean', value: cleanCount, color: '#10b981' });

    const pieCtx = document.getElementById('pieChart');
    if (pieCtx && pieData.length > 0) {
      chartsRef.current.pie = new Chart(pieCtx, {
        type: 'pie',
        data: {
          labels: pieData.map(d => d.label),
          datasets: [{ data: pieData.map(d => d.value), backgroundColor: pieData.map(d => d.color) }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
      });
    }

    // ── Bar chart — exact from initCharts() ──────────────────────────────
    const barData = [
      { label: 'PII',       value: stats.totalPII,        color: '#f59e0b' },
      { label: 'Secrets',   value: stats.totalSecrets,    color: '#8b5cf6' },
      { label: 'Jailbreak', value: stats.totalJailbreaks, color: '#ef4444' },
      { label: 'Toxicity',  value: stats.totalToxicity,   color: '#dc2626' },
    ].filter(d => d.value > 0);

    const barCtx = document.getElementById('barChart');
    if (barCtx && barData.length > 0) {
      chartsRef.current.bar = new Chart(barCtx, {
        type: 'bar',
        data: {
          labels: barData.map(d => d.label),
          datasets: [{ label: 'Detections', data: barData.map(d => d.value), backgroundColor: barData.map(d => d.color) }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true } }
        }
      });
    }

    // ── Timeline chart — exact from initCharts() ─────────────────────────
    const grouped = {};
    threads.forEach(t => {
      t.conversations?.forEach(c => {
        const date = new Date(c.started_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        if (!grouped[date]) grouped[date] = { date, sessions: 0, threats: 0 };
        grouped[date].sessions++;
        grouped[date].threats += (c.pii_detections || 0) + (c.jailbreak_attempts || 0) +
                                  (c.toxicity_detections || 0) + (c.blocked_prompts || 0);
      });
    });
    const timelineData = Object.values(grouped)
      .sort((a, b) => new Date(a.date) - new Date(b.date))
      .slice(-14);

    const tlCtx = document.getElementById('timelineChart');
    if (tlCtx && timelineData.length > 0) {
      chartsRef.current.timeline = new Chart(tlCtx, {
        type: 'line',
        data: {
          labels: timelineData.map(d => d.date),
          datasets: [
            { label: 'Sessions', data: timelineData.map(d => d.sessions), borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.1)', fill: true, tension: 0.4 },
            { label: 'Threats',  data: timelineData.map(d => d.threats),  borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)',  fill: true, tension: 0.4 },
          ]
        },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
      });
    }

    // ── Top threatening threads — exact from initCharts() ────────────────
    const topData = [...threads]
      .map(t => ({
        id: (t.thread_id || 'unknown').substring(0, 20) + '…',
        threats: (t.pii_detections || 0) + (t.jailbreak_attempts || 0) +
                 (t.toxicity_detections || 0) + (t.secrets_detections || 0)
      }))
      .filter(t => t.threats > 0)
      .sort((a, b) => b.threats - a.threats)
      .slice(0, 10);

    const topCtx = document.getElementById('topChart');
    if (topCtx && topData.length > 0) {
      chartsRef.current.top = new Chart(topCtx, {
        type: 'bar',
        data: {
          labels: topData.map(d => d.id),
          datasets: [{ label: 'Total Threats', data: topData.map(d => d.threats), backgroundColor: '#ef4444' }]
        },
        options: {
          indexAxis: 'y', responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { x: { beginAtZero: true } }
        }
      });
    }

    // Cleanup on unmount or when deps change
    return () => {
      Object.values(chartsRef.current).forEach(c => c.destroy());
      chartsRef.current = {};
    };
  }, [threads, stats]);

  // Exact DOM from renderAnalytics()
  return (
    <div className="charts-grid">
      <div className="chart-container">
        <div className="chart-title">🎯 Threat Distribution</div>
        <div className="chart-canvas-wrapper"><canvas id="pieChart"></canvas></div>
      </div>
      <div className="chart-container">
        <div className="chart-title">⚠️ Threat Types Breakdown</div>
        <div className="chart-canvas-wrapper"><canvas id="barChart"></canvas></div>
      </div>
      <div className="chart-container">
        <div className="chart-title">📅 Activity Timeline</div>
        <div className="chart-canvas-wrapper"><canvas id="timelineChart"></canvas></div>
      </div>
      <div className="chart-container">
        <div className="chart-title">🔥 Top Threatening Threads</div>
        <div className="chart-canvas-wrapper"><canvas id="topChart"></canvas></div>
      </div>
    </div>
  );
}
