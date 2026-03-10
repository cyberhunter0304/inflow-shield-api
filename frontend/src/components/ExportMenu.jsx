// Exact DOM from renderExportMenu()
export default function ExportMenu({ threads, onExportSummaryCSV, onExportFullJSON, onExportThreatsCSV }) {
  const threatSessions = threads.filter(s =>
    s.pii_detections > 0 || s.jailbreak_attempts > 0 ||
    s.toxicity_detections > 0 || s.secrets_detections > 0 || s.blocked_prompts > 0
  );

  return (
    <div className="export-menu">
      <div className="export-menu-header">📊 Export Options</div>
      <div className="export-option" onClick={onExportSummaryCSV}>
        <span>📄</span>
        <span>Summary (CSV)</span>
        <span className="export-option-count">{threads.length} sessions</span>
      </div>
      <div className="export-option" onClick={onExportFullJSON}>
        <span>📦</span>
        <span>Full Data + Prompts (JSON)</span>
        <span className="export-option-count">All details</span>
      </div>
      <div className="export-option" onClick={onExportThreatsCSV}>
        <span>⚠️</span>
        <span>All Threats (CSV)</span>
        <span className="export-option-count">{threatSessions.length} sessions</span>
      </div>
    </div>
  );
}
