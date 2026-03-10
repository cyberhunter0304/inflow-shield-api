import ExportMenu from './ExportMenu.jsx';
import {
  exportSummaryCSV, exportFullJSON, exportThreatsCSV,
} from '../utils.js';

const FILTER_LABELS = {
  all:      'All',
  threats:  '⚠️ Threats',
  pii:      '🔒 PII',
  secrets:  '🔑 Secrets',
  jailbreak:'🚨 Jailbreak',
  toxicity: '☣️ Toxicity',
  clean:    '✅ Clean',
};

const SEARCH_PLACEHOLDERS = {
  botId:    'Search by Bot ID...',
  threadId: 'Search by Thread ID...',
  prompt:   'Search prompt text...',
};

export default function ControlsSection({
  threads, filtered, searchTerm, searchMode, filterType, sortBy, showExportMenu,
  onSearch, onSetSearchMode, onSetFilter, onSetSort,
  onToggleExportMenu, onRefresh, onClearAll,
}) {
  return (
    <div className="controls-section">
      {/* Search box — exact DOM from renderControls() */}
      <div className="search-box">
        <div className="search-icon">🔍</div>
        <input
          className="search-input"
          id="searchInput"
          type="text"
          placeholder={SEARCH_PLACEHOLDERS[searchMode]}
          value={searchTerm}
          onChange={e => onSearch(e.target.value)}
          style={{ paddingRight: '1rem' }}
        />
      </div>

      {/* Search mode group */}
      <div className="search-mode-group">
        <span style={{ fontSize: '0.8125rem', color: '#a8a29e', fontWeight: 600, whiteSpace: 'nowrap' }}>
          Search by:
        </span>
        {[['botId', '🤖 Bot ID'], ['threadId', '🧵 Thread ID'], ['prompt', '💬 Prompt']].map(([mode, label]) => (
          <button
            key={mode}
            className={`search-mode-btn${searchMode === mode ? ' active' : ''}`}
            onClick={() => onSetSearchMode(mode)}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Filter buttons */}
      <div className="filter-group">
        {['all', 'threats', 'pii', 'secrets', 'jailbreak', 'toxicity', 'clean'].map(f => (
          <button
            key={f}
            className={`filter-btn${filterType === f ? ' active' : ''}`}
            onClick={() => onSetFilter(f)}
          >
            {FILTER_LABELS[f]}
          </button>
        ))}
      </div>

      {/* Right controls */}
      <div className="controls-right">
        <div className="select-wrapper">
          <select className="sort-select" value={sortBy} onChange={e => onSetSort(e.target.value)}>
            <option value="date-desc">Newest First</option>
            <option value="date-asc">Oldest First</option>
            <option value="threats-desc">Most Threats</option>
            <option value="prompts-desc">Most Prompts</option>
          </select>
          <span className="select-arrow">▼</span>
        </div>

        {/* Export wrapper — position:relative keeps the menu anchored */}
        <div className="export-wrapper">
          <button className="icon-btn" onClick={onToggleExportMenu}>
            📥 Export {showExportMenu ? '▲' : '▼'}
          </button>
          {showExportMenu && (
            <ExportMenu
              threads={threads}
              onExportSummaryCSV={() => { exportSummaryCSV(threads); onToggleExportMenu(); }}
              onExportFullJSON={() => { exportFullJSON(threads); onToggleExportMenu(); }}
              onExportThreatsCSV={() => { exportThreatsCSV(threads); onToggleExportMenu(); }}
            />
          )}
        </div>

        <button className="icon-btn" onClick={onRefresh}>🔄 Refresh</button>
        {threads.length > 0 && (
          <button className="icon-btn danger" onClick={onClearAll}>🗑️ Clear All</button>
        )}
      </div>
    </div>
  );
}
