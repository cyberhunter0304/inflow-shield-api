import { useState, useEffect, useCallback } from 'react';
import './styles/dashboard.css';

import {
  fetchAllThreads, deleteThreadApi,
  getStats, getFilteredThreads,
  ITEMS_PER_PAGE,
} from './utils.js';

import PageHeader      from './components/PageHeader.jsx';
import StatsGrid       from './components/StatsGrid.jsx';
import ControlsSection from './components/ControlsSection.jsx';
import ThreadsTable    from './components/ThreadsTable.jsx';
import ThreadDetail    from './components/ThreadDetail.jsx';
import Pagination      from './components/Pagination.jsx';
import AnalyticsView   from './components/AnalyticsView.jsx';

export default function App() {
  const [threads,        setThreads]        = useState([]);
  const [view,           setView]           = useState('overview');
  const [selectedThread, setSelectedThread] = useState(null);
  const [searchTerm,     setSearchTerm]     = useState('');
  const [searchMode,     setSearchMode]     = useState('botId');
  const [filterType,     setFilterType]     = useState('all');
  const [sortBy,         setSortBy]         = useState('date-desc');
  const [currentPage,    setCurrentPage]    = useState(1);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [loading,        setLoading]        = useState(true);

  useEffect(() => {
    (async () => {
      const data = await fetchAllThreads();
      setThreads(data);
      setLoading(false);
    })();
  }, []);

  useEffect(() => {
    if (!showExportMenu) return;
    const handler = e => {
      if (!e.target.closest('.export-wrapper')) setShowExportMenu(false);
    };
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, [showExportMenu]);

  const stats    = getStats(threads);
  const filtered = getFilteredThreads(threads, searchTerm, searchMode, filterType, sortBy);
  const start    = (currentPage - 1) * ITEMS_PER_PAGE;
  const paginated = filtered.slice(start, start + ITEMS_PER_PAGE);

  const handleSetView = useCallback((v) => { setView(v); setCurrentPage(1); }, []);
  const goBack = useCallback(() => { setView('overview'); setSelectedThread(null); }, []);
  const onSearch = useCallback((v) => { setSearchTerm(v); setCurrentPage(1); }, []);
  const setFilter = useCallback((f) => { setFilterType(f); setSearchTerm(''); setCurrentPage(1); }, []);
  const setSort = useCallback((v) => { setSortBy(v); setCurrentPage(1); }, []);
  const setPage = useCallback((p) => setCurrentPage(p), []);
  const handleSetSearchMode = useCallback((mode) => { setSearchMode(mode); setSearchTerm(''); setCurrentPage(1); }, []);
  const toggleExportMenu = useCallback(() => setShowExportMenu(s => !s), []);

  const openThread = useCallback((threadId) => {
    const t = threads.find(t => t.thread_id === threadId);
    if (!t) return;
    setSelectedThread(t);
    setView('details');
  }, [threads]);

  const onDeleteThread = useCallback(async (botId, threadId, andGoBack = false) => {
    if (!confirm(`Delete thread ${(threadId || '').substring(0, 24)}...?`)) return;
    await deleteThreadApi(botId);
    const updated = await fetchAllThreads();
    setThreads(updated);
    if (andGoBack) goBack();
  }, [goBack]);

  const onClearAll = useCallback(async () => {
    if (!confirm('⚠️ Delete ALL threads? This cannot be undone.')) return;
    await Promise.all(threads.map(t => deleteThreadApi(t.bot_id)));
    setThreads([]);
    setView('overview');
  }, [threads]);

  const refresh = useCallback(async () => {
    setLoading(true);
    const data = await fetchAllThreads();
    setThreads(data);
    setCurrentPage(1);
    setLoading(false);
  }, []);

  if (loading) {
    return (
      <div className="dashboard-container" id="app">
        <div className="loading-screen">
          <div className="loading-spinner">⏳</div>
          <div style={{ fontSize: '18px', color: '#6b7280' }}>Loading security logs...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-container" id="app">
      <PageHeader />

      <div className="view-toggle">
        <button
          className={`view-btn${view === 'overview' ? ' active' : ''}`}
          onClick={() => handleSetView('overview')}
        >
          📊 Threads Overview
        </button>
        <button
          className={`view-btn${view === 'analytics' ? ' active' : ''}`}
          onClick={() => handleSetView('analytics')}
        >
          📈 Analytics
        </button>
      </div>

      <StatsGrid stats={stats} />

      <div className="view-content">
        {view === 'details' && selectedThread ? (
          <ThreadDetail
            thread={selectedThread}
            onGoBack={goBack}
            onDeleteThread={onDeleteThread}
          />
        ) : view === 'overview' ? (
          <>
            <ControlsSection
              threads={threads}
              filtered={filtered}
              searchTerm={searchTerm}
              searchMode={searchMode}
              filterType={filterType}
              sortBy={sortBy}
              showExportMenu={showExportMenu}
              onSearch={onSearch}
              onSetSearchMode={handleSetSearchMode}
              onSetFilter={setFilter}
              onSetSort={setSort}
              onToggleExportMenu={toggleExportMenu}
              onRefresh={refresh}
              onClearAll={onClearAll}
            />
            <div className="results-summary">
              Showing {filtered.length} thread{filtered.length !== 1 ? 's' : ''}
              {searchTerm ? ` matching "${searchTerm}" in ${searchMode}` : ''}
              {filterType !== 'all' ? ` · filter: ${filterType}` : ''}
            </div>
            <ThreadsTable
              threads={paginated}
              onOpenThread={openThread}
              onDeleteThread={onDeleteThread}
            />
            <Pagination
              filteredCount={filtered.length}
              currentPage={currentPage}
              onSetPage={setPage}
            />
          </>
        ) : (
          <AnalyticsView threads={threads} stats={stats} />
        )}
      </div>
    </div>
  );
}