import { getRelativeTime } from '../utils.js';

// Exact DOM from renderThreadsTable() + renderThreadRow()
export default function ThreadsTable({ threads, onOpenThread, onDeleteThread }) {
  if (threads.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">🔭</div>
        <div className="empty-state-title">No threads found</div>
        <div>Start conversations to see security analytics here</div>
      </div>
    );
  }

  return (
    <div className="threads-container">
      {threads.map(t => (
        <ThreadRow
          key={t.bot_id}
          t={t}
          onOpen={() => onOpenThread(t.thread_id)}
          onDelete={e => { e.stopPropagation(); onDeleteThread(t.bot_id, t.thread_id); }}
        />
      ))}
    </div>
  );
}

function ThreadRow({ t, onOpen, onDelete }) {
  const threats = (t.pii_detections || 0) + (t.jailbreak_attempts || 0) +
                  (t.toxicity_detections || 0) + (t.secrets_detections || 0);

  return (
    <div className="thread-card">
      <div
        className={`thread-header ${threats > 0 ? 'has-threats' : 'clean'}`}
        onClick={onOpen}
      >
        <div className="thread-expand-icon">▶</div>
        <div className="thread-info">
          <div className="thread-id-row">
            <span className="thread-id-label">Thread:</span>
            <span className="thread-id">{t.thread_id}</span>
          </div>
          <div className="thread-meta">
            <span>👤 {t.user_id || 'N/A'}</span>
            <span>💬 {t.conversation_count || 0} conversation{t.conversation_count !== 1 ? 's' : ''}</span>
            <span>📝 {t.total_prompts || 0} prompts</span>
            <span>🕐 {getRelativeTime(t.last_updated || t.created_at)}</span>
          </div>
        </div>

        <div className="thread-threats">
          {threats > 0 ? (
            <div className="threat-summary">
              <span className="threat-count">⚠️ {threats} threats</span>
              <div className="threat-badges-compact">
                {t.pii_detections > 0       && <span className="badge-pii">{t.pii_detections} PII</span>}
                {t.secrets_detections > 0   && <span className="badge-secrets">{t.secrets_detections} SEC</span>}
                {t.jailbreak_attempts > 0   && <span className="badge-jailbreak">{t.jailbreak_attempts} JB</span>}
                {t.toxicity_detections > 0  && <span className="badge-toxicity">{t.toxicity_detections} TOX</span>}
              </div>
            </div>
          ) : (
            <span className="clean-badge">✅ Clean</span>
          )}
        </div>

        <button
          className="thread-delete-btn"
          onClick={onDelete}
          title="Delete thread"
        >
          🗑️
        </button>
      </div>
    </div>
  );
}
