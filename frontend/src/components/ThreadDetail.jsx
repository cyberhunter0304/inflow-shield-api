import { formatDate } from '../utils.js';
import ConversationRow from './ConversationRow.jsx';

// Exact DOM from renderThreadDetail()
export default function ThreadDetail({ thread, onGoBack, onDeleteThread }) {
  const threats = (thread.pii_detections || 0) + (thread.jailbreak_attempts || 0) +
                  (thread.toxicity_detections || 0) + (thread.secrets_detections || 0);

  return (
    <div className="details-container">
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        <button className="back-btn" onClick={onGoBack}>← Back to Threads</button>
        <button
          className="btn-delete-session"
          onClick={() => onDeleteThread(thread.bot_id, thread.thread_id, true)}
        >
          🗑️ Delete Thread
        </button>
      </div>

      <div className="bot-info-grid">
        <div>
          <div className="info-label">Thread ID</div>
          <div className="info-value" style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
            {thread.thread_id}
          </div>
        </div>
        <div>
          <div className="info-label">User</div>
          <div className="info-value">{thread.user_id || 'N/A'}</div>
        </div>
        <div>
          <div className="info-label">Conversations</div>
          <div className="info-value">{thread.conversation_count || 0}</div>
        </div>
        <div>
          <div className="info-label">Total Prompts</div>
          <div className="info-value">{thread.total_prompts || 0}</div>
        </div>
        <div>
          <div className="info-label">Threats</div>
          <div className="info-value" style={{ color: threats > 0 ? '#dc2626' : '#10b981' }}>
            {threats}
          </div>
        </div>
        <div>
          <div className="info-label">Created</div>
          <div className="info-value">{formatDate(thread.created_at)}</div>
        </div>
      </div>

      <div>
        <div className="section-title">
          💬 Conversations ({thread.conversations?.length || 0})
        </div>
        {thread.conversations?.length > 0 ? (
          <div className="conversations-list">
            {thread.conversations.map((c, i) => (
              <ConversationRow key={c.conversation_id || i} conv={c} />
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon">💬</div>
            <div className="empty-state-title">No conversations yet</div>
          </div>
        )}
      </div>
    </div>
  );
}
