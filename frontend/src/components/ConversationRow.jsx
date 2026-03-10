import { useState, useRef } from 'react';
import { formatDate } from '../utils.js';
import EventCard from './EventCard.jsx';

// Exact DOM from renderConversationRow() + toggleConversation() logic
export default function ConversationRow({ conv }) {
  const [isOpen, setIsOpen] = useState(false);
  const eventsRef = useRef(null);

  const threats = (conv.pii_detections || 0) + (conv.jailbreak_attempts || 0) +
                  (conv.toxicity_detections || 0) + (conv.blocked_prompts || 0);

  // Replicates toggleConversation() animation using inline styles on the real DOM node
  function handleToggle() {
    const el = eventsRef.current;
    if (!el) return;

    if (!isOpen) {
      // Opening
      el.style.display = 'flex';
      el.style.flexDirection = 'column';
      el.style.maxHeight = '0';
      el.style.opacity = '0';
      requestAnimationFrame(() => {
        el.style.transition = 'max-height 0.3s ease-out, opacity 0.2s ease-out';
        el.style.maxHeight = '2000px';
        el.style.opacity = '1';
      });
    } else {
      // Closing
      el.style.maxHeight = '0';
      el.style.opacity = '0';
      setTimeout(() => { el.style.display = 'none'; }, 200);
    }
    setIsOpen(o => !o);
  }

  return (
    <div className="conversation-card" id={`conv-${conv.conversation_id}`}>
      <div className="conversation-header" onClick={handleToggle}>
        <div className="conversation-expand-icon" id={`conv-icon-${conv.conversation_id}`}>
          {isOpen ? '▼' : '▶'}
        </div>
        <div className="conversation-info">
          <div>
            <span className="conversation-label">Conversation: </span>
            <span className="conversation-id-text">{conv.conversation_id}</span>
          </div>
          <div className="conversation-meta">
            <span>📝 <strong>{conv.total_prompts || 0}</strong> message{(conv.total_prompts || 0) !== 1 ? 's' : ''}</span>
            <span>
              🕐 {formatDate(conv.started_at)}
              {conv.ended_at ? ` → ${formatDate(conv.ended_at)}` : ''}
            </span>
          </div>
        </div>
        <div className="conversation-threats">
          {threats > 0 ? (
            <div className="threat-badges-compact">
              {conv.pii_detections > 0      && <span className="badge-pii">PII <strong>{conv.pii_detections}</strong></span>}
              {conv.jailbreak_attempts > 0  && <span className="badge-jailbreak">JB <strong>{conv.jailbreak_attempts}</strong></span>}
              {conv.toxicity_detections > 0 && <span className="badge-toxicity">TOX <strong>{conv.toxicity_detections}</strong></span>}
              {conv.blocked_prompts > 0     && <span className="badge-blocked">BLK <strong>{conv.blocked_prompts}</strong></span>}
            </div>
          ) : (
            <span className="clean-badge-small">✅</span>
          )}
        </div>
      </div>

      {/* events-list — hidden by default, shown/hidden via ref animation */}
      <div
        className="events-list"
        id={`events-${conv.conversation_id}`}
        ref={eventsRef}
        style={{ display: 'none' }}
      >
        {conv.security_events?.length > 0
          ? conv.security_events.map((ev, i) => (
              <EventCard key={i} ev={ev} idx={i + 1} />
            ))
          : (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#a8a29e' }}>
              <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📭</div>
              No security events
            </div>
          )
        }
      </div>
    </div>
  );
}
