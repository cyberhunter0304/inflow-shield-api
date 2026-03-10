import { ITEMS_PER_PAGE } from '../utils.js';

// Exact logic + DOM from renderPagination()
export default function Pagination({ filteredCount, currentPage, onSetPage }) {
  const total      = filteredCount;
  const totalPages = Math.ceil(total / ITEMS_PER_PAGE);
  if (totalPages <= 1) return null;

  const start = (currentPage - 1) * ITEMS_PER_PAGE + 1;
  const end   = Math.min(currentPage * ITEMS_PER_PAGE, total);

  // Build page number array — exact logic from renderPagination()
  const pages = [];
  const max = 7;
  const sp = Math.max(1, currentPage - 3);
  const ep = Math.min(totalPages, sp + max - 1);
  if (sp > 1) { pages.push(1); if (sp > 2) pages.push('...'); }
  for (let i = sp; i <= ep; i++) pages.push(i);
  if (ep < totalPages) { if (ep < totalPages - 1) pages.push('...'); pages.push(totalPages); }

  return (
    <div className="pagination-container">
      <div className="page-info">Showing {start}–{end} of {total} results</div>
      <div className="pagination-controls">
        <button
          className="page-btn"
          onClick={() => onSetPage(currentPage - 1)}
          disabled={currentPage === 1}
        >
          ← Prev
        </button>
        {pages.map((p, i) =>
          p === '...'
            ? <span key={`ellipsis-${i}`} style={{ padding: '0 4px', color: '#a8a29e' }}>…</span>
            : (
              <button
                key={p}
                className={`page-btn${currentPage === p ? ' active' : ''}`}
                onClick={() => onSetPage(p)}
              >
                {p}
              </button>
            )
        )}
        <button
          className="page-btn"
          onClick={() => onSetPage(currentPage + 1)}
          disabled={currentPage === totalPages}
        >
          Next →
        </button>
      </div>
      <div className="page-info" style={{ color: '#a8a29e', fontStyle: 'italic' }}>
        Page {currentPage} of {totalPages}
      </div>
    </div>
  );
}
