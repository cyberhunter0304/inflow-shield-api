import { useEffect } from 'react';
import { animateCounters } from '../utils.js'; // ../utils.js is correct: components/ → src/utils.js

// Exact card data from renderStats()
function getCards(stats) {
  return [
    { icon: '💬', label: 'Total Threads',      value: stats.totalThreads,    color: '#3b82f6' },
    { icon: '📝', label: 'Total Prompts',      value: stats.totalPrompts,    color: '#10b981' },
    { icon: '🚫', label: 'Blocked Prompts',    value: stats.totalBlocked,    color: '#ef4444' },
    { icon: '🔒', label: 'PII Detections',     value: stats.totalPII,        color: '#f59e0b' },
    { icon: '🔑', label: 'Secrets Detected',   value: stats.totalSecrets,    color: '#8b5cf6' },
    { icon: '⚠️', label: 'Jailbreak Attempts', value: stats.totalJailbreaks, color: '#dc2626' },
    { icon: '☣️', label: 'Toxicity Detected',  value: stats.totalToxicity,   color: '#991b1b' },
  ];
}

export default function StatsGrid({ stats }) {
  // Run counter animation after render — same as original requestAnimationFrame call
  useEffect(() => {
    requestAnimationFrame(() => animateCounters());
  }, [stats]);

  const cards = getCards(stats);

  return (
    <div className="stats-grid">
      {cards.map((c) => (
        <div className="stat-card" key={c.label} style={{ borderLeftColor: c.color }}>
          <div className="stat-icon">{c.icon}</div>
          <div className="stat-content">
            {/* data-count-to is read by animateCounters() exactly as in the original */}
            <div className="stat-value" data-count-to={c.value}>0</div>
            <div className="stat-label">{c.label}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
