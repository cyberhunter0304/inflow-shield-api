import { formatDate } from '../utils.js';

// Exact logic + DOM from renderEventCard()
export default function EventCard({ ev, idx }) {
  const isBlocked = ev.blocked;
  const hasPII    = ev.detections?.pii?.detected;

  let cardClass = 'safe';
  if (hasPII)    cardClass = 'pii';
  if (isBlocked) cardClass = 'blocked';

  const hasDetections = ev.detections && Object.values(ev.detections).some(r => r?.detected);
  const detectionEntries = hasDetections
    ? Object.entries(ev.detections).filter(([, r]) => r?.detected)
    : [];

  return (
    <div className={`event-card-compact ${cardClass}`}>
      <div className="event-row-main">
        <span className="event-num">#{idx}</span>
        <span className={`event-status-sm ${isBlocked ? 'blocked' : 'safe'}`}>
          {isBlocked ? '🚫 BLOCKED' : '✅ SAFE'}
        </span>
        {ev.risk_level && (
          <span className={`risk-tag risk-${(ev.risk_level || '').toLowerCase()}`}>
            {ev.risk_level}
          </span>
        )}
        <span className="event-time">🕐 {formatDate(ev.timestamp)}</span>
        {ev.metrics?.scan_time && (
          <span className="event-perf">⏱️ {ev.metrics.scan_time.toFixed(2)}s</span>
        )}
      </div>

      <div className="event-prompt-row">
        <span className="prompt-label">📝</span>
        <span className="prompt-text-compact">{ev.prompt || 'N/A'}</span>
      </div>

      {detectionEntries.length > 0 && (
        <div className="event-threats-row">
          {detectionEntries.map(([name]) => {
            const threatClass = name.toLowerCase().replace(/[^a-z]/g, '');
            return (
              <span key={name} className={`threat-tag ${threatClass}`}>{name}</span>
            );
          })}
        </div>
      )}

      {isBlocked && ev.block_reason && (
        <div className="event-block-row">🛡️ {ev.block_reason}</div>
      )}
    </div>
  );
}
