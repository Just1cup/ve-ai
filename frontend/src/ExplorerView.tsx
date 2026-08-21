import { useDeferredValue, useEffect, useMemo, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clock3,
  Database,
  Download,
  FileText,
  GitFork,
  KeyRound,
  Maximize2,
  Minimize2,
  Network,
  Search,
  Tag,
  Terminal,
  X,
} from 'lucide-react';
import {
  fetchExplorerCategories,
  fetchExplorerEntities,
  fetchExplorerEntity,
} from './api';
import { nodeTypeColor } from './graphTheme';
import { displaySource } from './sourceDisplay';
import type {
  Alert,
  ExplorerCategory,
  ExplorerEntityDetails,
  ExplorerEntityRow,
  GraphEdge,
  GraphNode,
  TimeRangeParams,
} from './types';

type SortDirection = 'asc' | 'desc';
type ExplorerTab = 'overview' | 'relations' | 'timeline' | 'events' | 'correlations';

interface ExplorerViewProps {
  selectedEntityId: string | null;
  onSelectEntity: (id: string | null) => void;
  onOpenGraph: (node: GraphNode) => void;
  timeRange: TimeRangeParams;
}

const pageSize = 50;

const categoryLabels: Record<string, string> = {
  IP: 'IP Addresses',
  Domain: 'Domains',
  URL: 'URLs',
  ASN: 'ASN',
  File: 'Files',
  Hash: 'Hashes',
  Email: 'Emails',
  CVE: 'CVEs',
  Malware: 'Malware',
  Command: 'Commands',
  Alert: 'Alerts',
  'MITRE Technique': 'MITRE Techniques',
  Country: 'Countries',
  Source: 'Sources',
};

const preferredCategoryOrder = [
  'IP',
  'Domain',
  'URL',
  'ASN',
  'File',
  'Hash',
  'Email',
  'CVE',
  'Malware',
  'Command',
  'Alert',
  'MITRE Technique',
  'Country',
  'Source',
];

const sortLabels: Record<string, string> = {
  ioc: 'IOC',
  type: 'Tipo',
  score: 'Score',
  confidence: 'Confidence',
  threat: 'Threat',
  first_seen: 'Primeira ocorrencia',
  last_seen: 'Ultima ocorrencia',
  observations: 'Observacoes',
  relationships: 'Relacionamentos',
  alerts: 'Alertas',
  source: 'Fonte',
};

export default function ExplorerView({
  selectedEntityId,
  onSelectEntity,
  onOpenGraph,
  timeRange,
}: ExplorerViewProps) {
  const [categories, setCategories] = useState<ExplorerCategory[]>([]);
  const [selectedType, setSelectedType] = useState<string | null>('IP');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [categorySort, setCategorySort] = useState<'name' | 'count'>('count');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [offset, setOffset] = useState(0);
  const [sort, setSort] = useState('last_seen');
  const [direction, setDirection] = useState<SortDirection>('desc');
  const [page, setPage] = useState<ExplorerEntityRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loadingRows, setLoadingRows] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [details, setDetails] = useState<ExplorerEntityDetails | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [activeTab, setActiveTab] = useState<ExplorerTab>('overview');
  const [timelineFrom, setTimelineFrom] = useState('');
  const [timelineTo, setTimelineTo] = useState('');
  const [recentSearches, setRecentSearches] = useState<string[]>([]);
  const [investigationExpanded, setInvestigationExpanded] = useState(false);
  const [investigationCollapsed, setInvestigationCollapsed] = useState(false);
  const [investigationPanelWidth, setInvestigationPanelWidth] = useState(430);
  const [navState, setNavState] = useState<{ items: string[]; index: number }>({
    items: [],
    index: -1,
  });
  const [error, setError] = useState<string | null>(null);
  const deferredQuery = useDeferredValue(query);
  const deferredSource = useDeferredValue(sourceFilter);

  useEffect(() => {
    let cancelled = false;

    async function loadCategories() {
      try {
        const next = await fetchExplorerCategories(timeRange);
        if (cancelled) return;
        setCategories(next);
        if (selectedType && !next.some((category) => category.node_type === selectedType)) {
          setSelectedType(next[0]?.node_type || null);
        }
      } catch (err) {
        if (!cancelled) setError(errorMessage(err, 'Falha ao carregar categorias'));
      }
    }

    void loadCategories();
    return () => {
      cancelled = true;
    };
  }, [timeRange]);

  useEffect(() => {
    setOffset(0);
    setSelectedIds(new Set());
    onSelectEntity(null);
  }, [
    selectedType,
    deferredQuery,
    severity,
    deferredSource,
    timeRange.from,
    timeRange.to,
    onSelectEntity,
  ]);

  useEffect(() => {
    let cancelled = false;
    setLoadingRows(true);

    async function loadRows() {
      try {
        const result = await fetchExplorerEntities({
          type: selectedType,
          search: deferredQuery,
          severity,
          source: deferredSource,
          from: timeRange.from,
          to: timeRange.to,
          limit: pageSize,
          offset,
          sort,
          direction,
        });
        if (cancelled) return;
        setPage(result.items);
        setTotal(result.total);
        setError(null);
      } catch (err) {
        if (!cancelled) setError(errorMessage(err, 'Falha ao carregar entidades'));
      } finally {
        if (!cancelled) setLoadingRows(false);
      }
    }

    void loadRows();
    return () => {
      cancelled = true;
    };
  }, [
    deferredQuery,
    deferredSource,
    direction,
    offset,
    selectedType,
    severity,
    sort,
    timeRange.from,
    timeRange.to,
  ]);

  useEffect(() => {
    if (!selectedEntityId) return;

    setNavState((current) => {
      if (current.index >= 0 && current.items[current.index] === selectedEntityId) {
        return current;
      }

      const base = current.index >= 0 ? current.items.slice(0, current.index + 1) : current.items;
      if (base[base.length - 1] === selectedEntityId) {
        return { items: base, index: base.length - 1 };
      }

      const items = [...base, selectedEntityId].slice(-50);
      return { items, index: items.length - 1 };
    });
  }, [selectedEntityId]);

  useEffect(() => {
    if (!selectedEntityId) {
      setDetails(null);
      return;
    }

    const entityId = selectedEntityId;
    let cancelled = false;
    setLoadingDetails(true);

    async function loadDetails() {
      try {
        const next = await fetchExplorerEntity(entityId);
        if (cancelled) return;
        setDetails(next);
        setActiveTab('overview');
        setError(null);
      } catch (err) {
        if (!cancelled) {
          setDetails(null);
          setError(errorMessage(err, 'Falha ao carregar entidade'));
        }
      } finally {
        if (!cancelled) setLoadingDetails(false);
      }
    }

    void loadDetails();
    return () => {
      cancelled = true;
    };
  }, [selectedEntityId]);

  const categoryCounts = useMemo(() => {
    return new Map(categories.map((category) => [category.node_type, category.total]));
  }, [categories]);

  const sidebarCategories = useMemo(() => {
    const known = new Set(preferredCategoryOrder);
    const base = preferredCategoryOrder
      .filter((type) => categoryCounts.has(type))
      .map((type) => ({
        type,
        label: categoryLabels[type] || type,
        total: categoryCounts.get(type) || 0,
      }));
    const unknown = categories
      .filter((category) => !known.has(category.node_type))
      .map((category) => ({
        type: category.node_type,
        label: categoryLabels[category.node_type] || category.node_type,
        total: category.total,
      }));

    return [...base, ...unknown]
      .filter((category) =>
        `${category.label} ${category.type}`.toLowerCase().includes(categoryFilter.toLowerCase()),
      )
      .sort((left, right) => {
        if (categorySort === 'name') return left.label.localeCompare(right.label);
        return right.total - left.total || left.label.localeCompare(right.label);
      });
  }, [categories, categoryCounts, categoryFilter, categorySort]);

  const totalEntities = useMemo(
    () => categories.reduce((sum, category) => sum + category.total, 0),
    [categories],
  );

  const showAllCategory = useMemo(() => {
    const filter = categoryFilter.trim().toLowerCase();
    if (!filter) return true;
    return ['all', 'todos', 'tudo'].some((label) => label.includes(filter));
  }, [categoryFilter]);

  const shellStyle = {
    '--investigation-width': `${investigationPanelWidth}px`,
  } as CSSProperties;

  const selectedRow = useMemo(() => {
    if (!selectedEntityId) return null;
    return page.find((item) => item.id === selectedEntityId) || null;
  }, [page, selectedEntityId]);

  const autocompleteValues = useMemo(() => {
    return Array.from(new Set([...recentSearches, ...page.map((item) => item.value)])).slice(0, 12);
  }, [page, recentSearches]);

  const maxPage = Math.max(Math.ceil(total / pageSize), 1);
  const currentPage = Math.floor(offset / pageSize) + 1;
  const allPageRowsSelected = page.length > 0 && page.every((item) => selectedIds.has(item.id));
  const canGoBack = navState.index > 0;
  const canGoForward = navState.index >= 0 && navState.index < navState.items.length - 1;

  function navigateToEntity(id: string | null) {
    onSelectEntity(id);
  }

  function moveHistory(delta: -1 | 1) {
    const nextIndex = navState.index + delta;
    const nextId = navState.items[nextIndex];
    if (!nextId) return;

    setNavState((current) => ({
      ...current,
      index: nextIndex,
    }));
    onSelectEntity(nextId);
  }

  function selectCategory(type: string | null) {
    setSelectedType(type);
    setSelectedIds(new Set());
    onSelectEntity(null);
  }

  function startInvestigationResize(event: React.PointerEvent<HTMLButtonElement>) {
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = investigationPanelWidth;
    let latestRawWidth = startWidth;

    const onPointerMove = (moveEvent: PointerEvent) => {
      latestRawWidth = startWidth + startX - moveEvent.clientX;
      const nextWidth = Math.max(320, Math.min(720, latestRawWidth));
      setInvestigationCollapsed(false);
      setInvestigationPanelWidth(nextWidth);
    };

    const onPointerUp = () => {
      if (latestRawWidth < 260) {
        setInvestigationCollapsed(true);
      }
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
    };

    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
  }

  function rememberSearch() {
    const trimmed = query.trim();
    if (!trimmed) return;
    setRecentSearches((current) =>
      [trimmed, ...current.filter((item) => item !== trimmed)].slice(0, 8),
    );
  }

  function toggleSort(nextSort: string) {
    if (sort === nextSort) {
      setDirection((current) => (current === 'asc' ? 'desc' : 'asc'));
      return;
    }
    setSort(nextSort);
    setDirection('desc');
  }

  function toggleSelected(id: string) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function togglePageSelection() {
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const item of page) {
        if (allPageRowsSelected) next.delete(item.id);
        else next.add(item.id);
      }
      return next;
    });
  }

  return (
    <div
      className={`explorer-shell${investigationCollapsed ? ' investigation-collapsed' : ''}`}
      style={shellStyle}
    >
      <aside className="explorer-sidebar">
        <div className="explorer-sidebar-head">
          <h2>Intelligence Explorer</h2>
          <span>{totalEntities} entidades</span>
        </div>

        <div className="mini-search">
          <Search size={15} />
          <input
            value={categoryFilter}
            onChange={(event) => setCategoryFilter(event.target.value)}
            placeholder="Filtrar tipos"
            aria-label="Filtrar tipos"
          />
        </div>

        <div className="sidebar-sort">
          <button
            type="button"
            className={categorySort === 'count' ? 'active' : ''}
            onClick={() => setCategorySort('count')}
          >
            Quantidade
          </button>
          <button
            type="button"
            className={categorySort === 'name' ? 'active' : ''}
            onClick={() => setCategorySort('name')}
          >
            Nome
          </button>
        </div>

        <div className="entity-tree">
          {showAllCategory && (
            <button
              type="button"
              className={selectedType === null ? 'active' : ''}
              onClick={() => selectCategory(null)}
            >
              {selectedType === null ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
              <span className="type-swatch all" aria-hidden="true" />
              <strong>All</strong>
              <em>{totalEntities}</em>
            </button>
          )}
          {sidebarCategories.map((category) => {
            const active = selectedType === category.type;
            return (
              <button
                type="button"
                key={category.type}
                className={active ? 'active' : ''}
                onClick={() => selectCategory(category.type)}
              >
                {active ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                <span
                  className="type-swatch"
                  style={{ backgroundColor: nodeTypeColor(category.type) }}
                  aria-hidden="true"
                />
                <strong>{category.label}</strong>
                <em>{category.total}</em>
              </button>
            );
          })}
        </div>
      </aside>

      <section className="explorer-list">
        <div className="explorer-toolbar">
          <div className="global-search">
            <Search size={16} />
            <input
              value={query}
              onBlur={rememberSearch}
              onKeyDown={(event) => {
                if (event.key === 'Enter') rememberSearch();
              }}
              onChange={(event) => setQuery(event.target.value)}
              list="explorer-search-history"
              placeholder="Buscar IP, dominio, URL, hash, ASN, malware..."
              aria-label="Busca global do Explorer"
            />
            <datalist id="explorer-search-history">
              {autocompleteValues.map((value) => (
                <option value={value} key={value} />
              ))}
            </datalist>
          </div>

          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            aria-label="Filtrar threat level"
          >
            <option value="">Threat level</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <input
            value={sourceFilter}
            onChange={(event) => setSourceFilter(event.target.value)}
            placeholder="Fonte"
            aria-label="Filtrar fonte"
          />

          <button
            type="button"
            className="text-button"
            onClick={() => exportRows(page)}
            title="Exportar pagina atual"
          >
            <Download size={15} />
            Exportar
          </button>
        </div>

        {recentSearches.length > 0 && (
          <div className="recent-searches">
            {recentSearches.map((item) => (
              <button type="button" key={item} onClick={() => setQuery(item)}>
                {item}
              </button>
            ))}
          </div>
        )}

        <div className="entity-table-wrap">
          <table className="entity-table">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    checked={allPageRowsSelected}
                    onChange={togglePageSelection}
                    aria-label="Selecionar pagina"
                  />
                </th>
                <SortableHeader label="IOC" sortKey="ioc" activeSort={sort} direction={direction} onSort={toggleSort} />
                <SortableHeader label="Tipo" sortKey="type" activeSort={sort} direction={direction} onSort={toggleSort} />
                <SortableHeader label="Score" sortKey="score" activeSort={sort} direction={direction} onSort={toggleSort} />
                <SortableHeader label="Confidence" sortKey="confidence" activeSort={sort} direction={direction} onSort={toggleSort} />
                <SortableHeader label="Threat" sortKey="threat" activeSort={sort} direction={direction} onSort={toggleSort} />
                <th>Tags</th>
                <SortableHeader label="Primeira" sortKey="first_seen" activeSort={sort} direction={direction} onSort={toggleSort} />
                <SortableHeader label="Ultima" sortKey="last_seen" activeSort={sort} direction={direction} onSort={toggleSort} />
                <SortableHeader label="Obs." sortKey="observations" activeSort={sort} direction={direction} onSort={toggleSort} />
                <SortableHeader label="Rel." sortKey="relationships" activeSort={sort} direction={direction} onSort={toggleSort} />
                <SortableHeader label="Fonte" sortKey="source" activeSort={sort} direction={direction} onSort={toggleSort} />
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {page.map((entity) => (
                <tr
                  key={entity.id}
                  className={entity.id === selectedEntityId ? 'selected' : ''}
                  onClick={() => navigateToEntity(entity.id)}
                >
                  <td onClick={(event) => event.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(entity.id)}
                      onChange={() => toggleSelected(entity.id)}
                      aria-label={`Selecionar ${entity.value}`}
                    />
                  </td>
                  <td className="ioc-cell">
                    <strong>{entity.label || entity.value}</strong>
                    <span>{entity.value}</span>
                  </td>
                  <td>
                    <TypePill type={entity.node_type} />
                  </td>
                  <td>{metadataText(entity.metadata, ['score', 'risk_score', 'reputation'])}</td>
                  <td>{metadataText(entity.metadata, ['confidence', 'confidence_score'])}</td>
                  <td>{entity.severity || metadataText(entity.metadata, ['threat_level'])}</td>
                  <td>
                    <TagList tags={entityTags(entity)} onTagClick={setQuery} />
                  </td>
                  <td>{formatDate(entity.first_seen)}</td>
                  <td>{formatDate(entity.last_seen)}</td>
                  <td>{entity.observation_count}</td>
                  <td>{entity.relationship_count}</td>
                  <td>{displaySource(entity.source, entity.metadata)}</td>
                  <td>{metadataText(entity.metadata, ['status', 'classification'])}</td>
                </tr>
              ))}
              {!loadingRows && page.length === 0 && (
                <tr>
                  <td colSpan={13} className="table-empty">
                    Nenhuma entidade encontrada.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          {loadingRows && <div className="table-loading">Carregando pagina...</div>}
        </div>

        <div className="pagination-bar">
          <span>
            Pagina {currentPage} de {maxPage} - {total} resultados - {selectedIds.size} selecionados
          </span>
          <div>
            <button
              type="button"
              className="text-button"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - pageSize))}
            >
              Anterior
            </button>
            <button
              type="button"
              className="text-button"
              disabled={offset + pageSize >= total}
              onClick={() => setOffset(offset + pageSize)}
            >
              Proxima
            </button>
          </div>
        </div>
      </section>

      <aside className={`investigation-panel${investigationCollapsed ? ' collapsed' : ''}`}>
        <button
          type="button"
          className="investigation-collapse-button"
          onClick={() => setInvestigationCollapsed((current) => !current)}
          title={investigationCollapsed ? 'Expandir painel lateral' : 'Minimizar painel lateral'}
          aria-label={investigationCollapsed ? 'Expandir painel lateral' : 'Minimizar painel lateral'}
        >
          {investigationCollapsed ? <ChevronLeft size={16} /> : <ChevronRight size={16} />}
        </button>
        {!investigationCollapsed && (
          <button
            type="button"
            className="investigation-resize-handle"
            onPointerDown={startInvestigationResize}
            onDoubleClick={() => setInvestigationCollapsed(true)}
            aria-label="Arrastar para redimensionar painel lateral"
            title="Arraste para redimensionar. Dois cliques minimiza."
          />
        )}
        {investigationCollapsed ? (
          <button
            type="button"
            className="investigation-collapsed-tab"
            onClick={() => setInvestigationCollapsed(false)}
            title="Expandir painel lateral"
          >
            <Database size={16} />
            <span>Investigacao</span>
          </button>
        ) : (
          <>
            {details ? (
              <InvestigationPanel
                details={details}
                selectedRow={selectedRow}
                activeTab={activeTab}
                setActiveTab={setActiveTab}
                loading={loadingDetails}
                timelineFrom={timelineFrom}
                timelineTo={timelineTo}
                setTimelineFrom={setTimelineFrom}
                setTimelineTo={setTimelineTo}
                onSelectEntity={navigateToEntity}
                onOpenGraph={onOpenGraph}
                onTagClick={setQuery}
                expanded={false}
                onToggleExpanded={() => setInvestigationExpanded(true)}
                canGoBack={canGoBack}
                canGoForward={canGoForward}
                onGoBack={() => moveHistory(-1)}
                onGoForward={() => moveHistory(1)}
              />
            ) : (
              <div className="empty-investigation">
                <Database size={18} />
                <p>Selecione uma entidade para investigar atributos, eventos e relacoes.</p>
              </div>
            )}
            {error && <p className="error-text">{error}</p>}
          </>
        )}
      </aside>
      {details && investigationExpanded && (
        <div
          className="investigation-expanded-backdrop"
          role="dialog"
          aria-modal="true"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setInvestigationExpanded(false);
          }}
        >
          <section className="investigation-panel investigation-panel-expanded">
            <InvestigationPanel
              details={details}
              selectedRow={selectedRow}
              activeTab={activeTab}
              setActiveTab={setActiveTab}
              loading={loadingDetails}
              timelineFrom={timelineFrom}
              timelineTo={timelineTo}
              setTimelineFrom={setTimelineFrom}
              setTimelineTo={setTimelineTo}
              onSelectEntity={navigateToEntity}
              onOpenGraph={onOpenGraph}
              onTagClick={setQuery}
              expanded
              onToggleExpanded={() => setInvestigationExpanded(false)}
              canGoBack={canGoBack}
              canGoForward={canGoForward}
              onGoBack={() => moveHistory(-1)}
              onGoForward={() => moveHistory(1)}
            />
          </section>
        </div>
      )}
    </div>
  );
}

function SortableHeader({
  label,
  sortKey,
  activeSort,
  direction,
  onSort,
}: {
  label: string;
  sortKey: string;
  activeSort: string;
  direction: SortDirection;
  onSort: (sort: string) => void;
}) {
  const active = activeSort === sortKey;
  return (
    <th>
      <button type="button" className={active ? 'active' : ''} onClick={() => onSort(sortKey)}>
        {label}
        {active && <span>{direction === 'asc' ? 'ASC' : 'DESC'}</span>}
      </button>
    </th>
  );
}

function InvestigationPanel({
  details,
  selectedRow,
  activeTab,
  setActiveTab,
  loading,
  timelineFrom,
  timelineTo,
  setTimelineFrom,
  setTimelineTo,
  onSelectEntity,
  onOpenGraph,
  onTagClick,
  expanded,
  onToggleExpanded,
  canGoBack,
  canGoForward,
  onGoBack,
  onGoForward,
}: {
  details: ExplorerEntityDetails;
  selectedRow: ExplorerEntityRow | null;
  activeTab: ExplorerTab;
  setActiveTab: (tab: ExplorerTab) => void;
  loading: boolean;
  timelineFrom: string;
  timelineTo: string;
  setTimelineFrom: (value: string) => void;
  setTimelineTo: (value: string) => void;
  onSelectEntity: (id: string | null) => void;
  onOpenGraph: (node: GraphNode) => void;
  onTagClick: (value: string) => void;
  expanded: boolean;
  onToggleExpanded: () => void;
  canGoBack: boolean;
  canGoForward: boolean;
  onGoBack: () => void;
  onGoForward: () => void;
}) {
  const [detailModal, setDetailModal] = useState<InvestigationModal | null>(null);
  const relatedById = useMemo(() => {
    return new Map(details.related_nodes.map((node) => [node.id, node]));
  }, [details.related_nodes]);
  const relationGroups = useMemo(() => buildRelationGroups(details, relatedById), [details, relatedById]);
  const timeline = useMemo(
    () => filterTimeline(buildTimeline(details), timelineFrom, timelineTo),
    [details, timelineFrom, timelineTo],
  );
  const tags = entityTags(details.node);
  const sources = entitySources(details);
  const overviewFields = useMemo(() => buildOverviewFields(details), [details]);
  const stats = {
    events: details.alerts.length,
    correlations: details.edges.length,
    related: details.related_nodes.length,
    sources: sources.length,
    observations: selectedRow?.observation_count || details.edges.length,
  };

  return (
    <>
      <header className="investigation-heading">
        <div className="investigation-badges">
          <TypePill type={details.node.node_type} />
          {details.node.severity && <span className={`severity-pill ${details.node.severity}`}>{details.node.severity}</span>}
        </div>
        <h2>{details.node.label || details.node.value}</h2>
        <p>{details.node.value}</p>
        <div className="investigation-history-controls" aria-label="Historico de navegacao">
          <button type="button" onClick={onGoBack} disabled={!canGoBack} title="Voltar IOC anterior">
            <ChevronLeft size={15} />
            <span>Anterior</span>
          </button>
          <button
            type="button"
            onClick={onGoForward}
            disabled={!canGoForward}
            title="Avancar para proximo IOC"
          >
            <span>Proximo</span>
            <ChevronRight size={15} />
          </button>
        </div>
        <button type="button" className="text-button primary" onClick={() => onOpenGraph(details.node)}>
          <Network size={15} />
          Visualizar no Grafo
        </button>
        <button
          type="button"
          className="text-button"
          onClick={onToggleExpanded}
          title={expanded ? 'Voltar para lateral' : 'Expandir investigacao'}
        >
          {expanded ? <Minimize2 size={15} /> : <Maximize2 size={15} />}
          {expanded ? 'Voltar para lateral' : 'Tela completa'}
        </button>
      </header>

      {loading && <div className="panel-loading">Atualizando detalhes...</div>}

      <nav className="investigation-tabs">
        <TabButton tab="overview" active={activeTab} onClick={setActiveTab} label="Overview" />
        <TabButton tab="relations" active={activeTab} onClick={setActiveTab} label="Relacoes" />
        <TabButton tab="timeline" active={activeTab} onClick={setActiveTab} label="Timeline" />
        <TabButton tab="events" active={activeTab} onClick={setActiveTab} label="Eventos" />
        <TabButton tab="correlations" active={activeTab} onClick={setActiveTab} label="Correlation View" />
      </nav>

      {activeTab === 'overview' && (
        <div className="investigation-content">
          <SectionTitle icon={<Activity size={15} />} title={overviewTitle(details.node.node_type)} />
          <div className="info-grid">
            {overviewFields.map((field) => (
              <InfoItem key={field.label} label={field.label} value={field.value} />
            ))}
          </div>

          <SectionTitle icon={<Database size={15} />} title="Estatisticas" />
          <div className="stat-strip">
            <Metric label="Eventos" value={stats.events} />
            <Metric label="Correlacoes" value={stats.correlations} />
            <Metric label="IOCs relacionados" value={stats.related} />
            <Metric label="Fontes" value={stats.sources} />
            <Metric label="Observacoes" value={stats.observations} />
          </div>

          <SectionTitle icon={<Tag size={15} />} title="Tags" />
          <TagList tags={tags} onTagClick={onTagClick} />

          <SectionTitle icon={<Database size={15} />} title="Fontes" />
          <div className="source-list">
            {sources.map((source) => (
              <div key={source}>
                <strong>{source}</strong>
                <span>Ingestao: {formatDate(details.node.last_seen)}</span>
                <span>Confidence: {metadataText(details.node.metadata, ['confidence', 'confidence_score'])}</span>
              </div>
            ))}
          </div>

          <SectionTitle icon={<Database size={15} />} title="Atributos" />
          <AttributeGrid metadata={details.node.metadata} />
        </div>
      )}

      {activeTab === 'relations' && (
        <div className="investigation-content">
          <SectionTitle icon={<GitFork size={15} />} title="Relacoes" />
          <RelationGroups
            groups={relationGroups}
            onSelectEntity={onSelectEntity}
            onOpenModal={setDetailModal}
          />
        </div>
      )}

      {activeTab === 'timeline' && (
        <div className="investigation-content">
          <SectionTitle icon={<Clock3 size={15} />} title="Timeline" />
          <div className="timeline-filters">
            <input type="date" value={timelineFrom} onChange={(event) => setTimelineFrom(event.target.value)} />
            <input type="date" value={timelineTo} onChange={(event) => setTimelineTo(event.target.value)} />
          </div>
          <div className="timeline-list">
            {timeline.map((item) => (
              <div key={`${item.date}-${item.title}`}>
                <time>{formatDate(item.date)}</time>
                <strong>{item.title}</strong>
                <span>{item.description}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'events' && (
        <div className="investigation-content">
          <SectionTitle icon={<AlertTriangle size={15} />} title="Eventos" />
          <div className="event-list">
            {details.alerts.map((alert) => (
              <EventCard
                key={alert.id}
                alert={alert}
                currentNode={details.node}
                relatedNodes={details.related_nodes}
                onOpenModal={setDetailModal}
              />
            ))}
            {!details.alerts.length && <p className="muted">Nenhum evento relacionado.</p>}
          </div>
        </div>
      )}

      {activeTab === 'correlations' && (
        <div className="investigation-content">
          <SectionTitle icon={<Network size={15} />} title="Correlation View" />
          <div className="correlation-chain-list">
            {relationGroups.flatMap((group) =>
              group.items.map((item) => (
                <div className="correlation-chain-row" key={item.edge.id}>
                  <button
                    type="button"
                    onClick={() => onSelectEntity(item.node?.id || null)}
                    disabled={!item.node}
                  >
                    <span>{details.node.node_type}</span>
                    <em>- {item.edge.relation}</em>
                    <span>{item.node?.node_type || 'Entidade'}</span>
                    <strong>{item.node?.label || item.node?.value || shortId(item.edge.id)}</strong>
                    <small>
                      Distancia 1 - Evidencias {edgeEvidence(item.edge)} - Forca {correlationStrength(item.edge)}
                    </small>
                  </button>
                  <button
                    type="button"
                    disabled={!item.node}
                    onClick={() =>
                      item.node &&
                      setDetailModal({
                        title: item.node.label || item.node.value,
                        subtitle: item.node.node_type,
                        body: nodeModalBody(item.node),
                        node: item.node,
                      })
                    }
                    title="Abrir detalhes do IOC"
                  >
                    <ArrowRight size={14} />
                  </button>
                </div>
              )),
            )}
          </div>
        </div>
      )}
      {detailModal && (
        <InvestigationDetailModal modal={detailModal} onClose={() => setDetailModal(null)} />
      )}
    </>
  );
}

function TabButton({
  tab,
  active,
  label,
  onClick,
}: {
  tab: ExplorerTab;
  active: ExplorerTab;
  label: string;
  onClick: (tab: ExplorerTab) => void;
}) {
  return (
    <button type="button" className={active === tab ? 'active' : ''} onClick={() => onClick(tab)}>
      {label}
    </button>
  );
}

function TypePill({ type }: { type: string }) {
  return (
    <span className="explorer-type-pill">
      <span style={{ backgroundColor: nodeTypeColor(type) }} aria-hidden="true" />
      {type}
    </span>
  );
}

function TagList({ tags, onTagClick }: { tags: string[]; onTagClick: (tag: string) => void }) {
  if (!tags.length) return <span className="muted">-</span>;
  return (
    <div className="tag-list">
      {tags.map((tag) => (
        <button type="button" key={tag} onClick={() => onTagClick(tag)}>
          {tag}
        </button>
      ))}
    </div>
  );
}

function SectionTitle({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <h3 className="section-title">
      {icon}
      {title}
    </h3>
  );
}

function InfoItem({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value || '-'}</strong>
    </div>
  );
}

interface OverviewField {
  label: string;
  value: string | number;
}

function buildOverviewFields(details: ExplorerEntityDetails): OverviewField[] {
  const { node } = details;
  const fields: OverviewField[] = [];
  const add = (label: string, value: unknown, keepEmpty = false) => {
    const formatted = normalizeFieldValue(value);
    if (!keepEmpty && formatted === '-') return;
    fields.push({ label, value: formatted });
  };
  const addCommon = () => {
    add('Fonte', displaySource(node.source, node.metadata));
    add('Primeira ocorrencia', formatDate(node.first_seen), true);
    add('Ultima ocorrencia', formatDate(node.last_seen), true);
  };

  switch (node.node_type) {
    case 'IP':
      add('Endereco IP', node.value, true);
      add('Versao', ipVersion(node), true);
      add('Pais', firstPresent([metadataText(node.metadata, ['country', 'geo.country']), descriptionValue(node, 'Country / ASN')]));
      add('ASN', firstPresent([metadataText(node.metadata, ['asn', 'as']), relatedPreview(details, 'ASN')]));
      add('Organizacao / provedor', firstPresent([
        metadataText(node.metadata, ['organization', 'org', 'provider']),
        descriptionValue(node, 'Org'),
      ]));
      add('Hostname', metadataText(node.metadata, ['hostname', 'host']));
      add('Reverse DNS', metadataText(node.metadata, ['reverse_dns', 'rdns', 'ptr']));
      add('Protocolos observados', descriptionValue(node, 'Protocols Hit'));
      add('Tentativas', descriptionValue(node, 'Attempts'));
      add('Score', firstPresent([metadataText(node.metadata, ['score', 'risk_score', 'reputation']), descriptionValue(node, 'Threat Score')]));
      add('Confidence', metadataText(node.metadata, ['confidence', 'confidence_score']));
      add('Enriquecimento', enrichmentSummary(node.metadata));
      addCommon();
      break;
    case 'Domain':
      add('Dominio', node.value, true);
      add('TLD', domainPart(node.value, 'tld'));
      add('Dominio raiz', domainPart(node.value, 'root'));
      add('Resolve para IPs', relatedPreview(details, 'IP'));
      add('ASNs relacionados', relatedPreview(details, 'ASN'));
      add('URLs relacionadas', relatedPreview(details, 'URL'));
      add('Registrar / WHOIS', metadataText(node.metadata, ['registrar', 'whois.registrar', 'whois']));
      add('Reputacao', firstPresent([metadataText(node.metadata, ['score', 'reputation']), enrichmentSummary(node.metadata)]));
      add('Malicioso', maliciousStatus(details));
      addCommon();
      break;
    case 'URL': {
      const url = parseUrl(node.value);
      add('URL', node.value, true);
      add('Esquema', url?.protocol.replace(':', ''));
      add('Dominio', url?.hostname || relatedPreview(details, 'Domain'));
      add('Caminho', url?.pathname);
      add('Parametros', url?.search ? url.search.slice(1) : null);
      add('Arquivo relacionado', relatedPreview(details, 'File'));
      add('Hashes relacionados', relatedPreview(details, 'Hash'));
      add('Status', metadataText(node.metadata, ['status', 'http_status', 'classification']));
      add('Malicioso', maliciousStatus(details));
      addCommon();
      break;
    }
    case 'Hash':
      add('Hash', node.value, true);
      add('Algoritmo', hashAlgorithm(node.value), true);
      add('Arquivo relacionado', relatedPreview(details, 'File'));
      add('Malware relacionado', relatedPreview(details, 'Malware'));
      add('Malicioso', maliciousStatus(details), true);
      add('Deteccao', enrichmentSummary(node.metadata));
      add('Observacoes', metadataText(node.metadata, ['count']));
      addCommon();
      break;
    case 'Email':
      add('Email', node.value, true);
      add('Dominio', node.value.split('@')[1]);
      add('Alertas relacionados', relatedPreview(details, 'Alert'));
      addCommon();
      break;
    case 'CVE':
      add('CVE', node.value, true);
      add('Alertas relacionados', relatedPreview(details, 'Alert'));
      add('Malware relacionado', relatedPreview(details, 'Malware'));
      addCommon();
      break;
    case 'File':
      add('Arquivo', node.value, true);
      add('Nome do executavel', fileName(node.value), true);
      add('Extensao', fileExtension(node.value));
      add('Hashes relacionados', relatedPreview(details, 'Hash'));
      add('Baixado de', firstPresent([relatedPreview(details, 'URL'), relatedPreview(details, 'Domain'), relatedPreview(details, 'IP')]));
      add('Malware relacionado', relatedPreview(details, 'Malware'));
      add('Malicioso', maliciousStatus(details), true);
      addCommon();
      break;
    case 'Malware':
      add('Nome / assinatura', node.label || node.value, true);
      add('Tipo de malware', malwareType(node), true);
      add('Familia', metadataText(node.metadata, ['family', 'malware_family', 'signature']));
      add('Malicioso', maliciousStatus(details), true);
      add('Severidade', node.severity);
      add('Derivado de', metadataText(node.metadata, ['derived_from', 'source_provider']));
      add('Arquivos relacionados', relatedPreview(details, 'File'));
      add('Hashes relacionados', relatedPreview(details, 'Hash'));
      add('IPs relacionados', relatedPreview(details, 'IP'));
      add('Dominios relacionados', relatedPreview(details, 'Domain'));
      addCommon();
      break;
    case 'Command':
      add('Comando', node.value, true);
      add('Resumo', node.label || compactText(node.value, 96), true);
      add('IPs relacionados', relatedPreview(details, 'IP'));
      add('Alertas relacionados', relatedPreview(details, 'Alert'));
      add('Fonte', displaySource(node.source, node.metadata));
      add('Primeira ocorrencia', formatDate(node.first_seen), true);
      add('Ultima ocorrencia', formatDate(node.last_seen), true);
      break;
    case 'Alert':
      add('Titulo', node.label || node.value, true);
      add('Severidade', node.severity);
      add('ID externo', metadataText(node.metadata, ['external_id', 'id']));
      add('Fonte', displaySource(node.source, node.metadata));
      add('IPs relacionados', relatedPreview(details, 'IP'));
      add('Dominios relacionados', relatedPreview(details, 'Domain'));
      add('Hashes relacionados', relatedPreview(details, 'Hash'));
      add('Arquivos relacionados', relatedPreview(details, 'File'));
      add('Tecnicas MITRE', relatedPreview(details, 'MITRE Technique'));
      add('Primeira ocorrencia', formatDate(node.first_seen), true);
      add('Ultima ocorrencia', formatDate(node.last_seen), true);
      break;
    case 'MITRE Technique':
      add('Technique ID', node.value, true);
      add('Tecnica', firstPresent([metadataText(node.metadata, ['technique']), node.label]));
      add('Tatica', metadataText(node.metadata, ['tactic', 'kill_chain_phase']));
      add('IOCs mapeados', relatedCountLabel(details, ['IP', 'Domain', 'URL', 'Hash', 'File']));
      add('Alertas relacionados', relatedPreview(details, 'Alert'));
      addCommon();
      break;
    case 'ASN':
      add('ASN', node.value, true);
      add('Organizacao', node.description || metadataText(node.metadata, ['org', 'organization', 'provider']));
      add('Pais', relatedPreview(details, 'Country'));
      add('IPs no ASN', relatedPreview(details, 'IP'));
      add('Dominios relacionados', relatedPreview(details, 'Domain'));
      addCommon();
      break;
    case 'Country':
      add('Pais', node.label || node.value, true);
      add('IPs relacionados', relatedPreview(details, 'IP'));
      add('ASNs relacionados', relatedPreview(details, 'ASN'));
      add('Alertas relacionados', relatedPreview(details, 'Alert'));
      addCommon();
      break;
    case 'Source':
      add('Fonte', displaySource(node.value, node.metadata), true);
      add('Tipo de fonte', metadataText(node.metadata, ['kind', 'type']));
      add('Entidades ingeridas', details.related_nodes.length);
      add('IPs', relatedCount(details, 'IP'));
      add('Dominios', relatedCount(details, 'Domain'));
      add('Hashes', relatedCount(details, 'Hash'));
      add('Alertas', relatedCount(details, 'Alert'));
      addCommon();
      break;
    default:
      add('IOC', node.value, true);
      add('Tipo', node.node_type, true);
      add('Rotulo', node.label);
      add('Severidade', node.severity);
      add('Relacionamentos', details.edges.length);
      addCommon();
      break;
  }

  return uniqueFields(fields);
}

function overviewTitle(type: string): string {
  const titles: Record<string, string> = {
    IP: 'Informacoes do IP',
    Domain: 'Informacoes do Dominio',
    URL: 'Informacoes da URL',
    Hash: 'Informacoes do Hash',
    Email: 'Informacoes do Email',
    CVE: 'Informacoes da CVE',
    File: 'Informacoes do Arquivo',
    Malware: 'Informacoes do Malware',
    Command: 'Informacoes do Comando',
    Alert: 'Informacoes do Alerta',
    'MITRE Technique': 'Informacoes da Tecnica MITRE',
    ASN: 'Informacoes do ASN',
    Country: 'Informacoes do Pais',
    Source: 'Informacoes da Fonte',
  };
  return titles[type] || 'Informacoes Gerais';
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function AttributeGrid({ metadata }: { metadata: Record<string, unknown> }) {
  const entries = Object.entries(metadata || {});
  if (!entries.length) return <p className="muted">Nenhum atributo adicional disponivel.</p>;
  return (
    <div className="attribute-grid">
      {entries.map(([key, value]) => (
        <div key={key}>
          <span>{key}</span>
          <strong>{formatMetadataValue(value)}</strong>
        </div>
      ))}
    </div>
  );
}

interface RelationGroup {
  title: string;
  relation: string;
  items: RelationItem[];
}

interface RelationItem {
  edge: GraphEdge;
  node: GraphNode | null;
}

function RelationGroups({
  groups,
  onSelectEntity,
  onOpenModal,
}: {
  groups: RelationGroup[];
  onSelectEntity: (id: string | null) => void;
  onOpenModal: (modal: InvestigationModal) => void;
}) {
  if (!groups.length) return <p className="muted">Sem relacoes para esta entidade.</p>;
  return (
    <div className="explorer-relations">
      {groups.map((group) => (
        <section key={`${group.title}-${group.relation}`}>
          <h4>
            {group.title} <span>{group.items.length}</span>
          </h4>
          <div>
            {group.items.map((item) => (
              <div className="relation-ioc-row" key={item.edge.id}>
                <button
                  type="button"
                  onClick={() => onSelectEntity(item.node?.id || null)}
                  disabled={!item.node}
                >
                  <TypePill type={item.node?.node_type || 'Unknown'} />
                  <strong>{item.node?.label || item.node?.value || shortId(item.edge.id)}</strong>
                  <span>{relationText(item.edge.relation)} - evidencias {edgeEvidence(item.edge)}</span>
                </button>
                <button
                  type="button"
                  disabled={!item.node}
                  onClick={() =>
                    item.node &&
                    onOpenModal({
                      title: item.node.label || item.node.value,
                      subtitle: item.node.node_type,
                      body: nodeModalBody(item.node),
                      node: item.node,
                    })
                  }
                  title="Abrir detalhes do IOC"
                >
                  <ArrowRight size={14} />
                </button>
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

interface InvestigationModal {
  title: string;
  subtitle?: string;
  body: string;
  node?: GraphNode;
}

function EventCard({
  alert,
  currentNode,
  relatedNodes,
  onOpenModal,
}: {
  alert: Alert;
  currentNode: GraphNode;
  relatedNodes: GraphNode[];
  onOpenModal: (modal: InvestigationModal) => void;
}) {
  const intel = parseAlertIntel(alert);
  const eventIocs = findEventIocs(alert, currentNode, relatedNodes);

  return (
    <article>
      <div className="event-card-heading">
        <strong>{alert.title}</strong>
        {alert.severity && <span className={`severity-pill ${alert.severity}`}>{alert.severity}</span>}
      </div>
      <div className="event-summary-grid">
        <InfoItem label="Data" value={formatDate(alert.last_seen)} />
        <InfoItem label="Origem" value={displaySource(alert.source, alert.raw)} />
        <InfoItem label="ID externo" value={alert.external_id} />
        <InfoItem label="Source IP" value={intel.fields.sourceIp} />
        <InfoItem label="Pais / ASN" value={intel.fields.countryAsn} />
        <InfoItem label="Organizacao" value={intel.fields.org} />
        <InfoItem label="Threat score" value={intel.fields.threatScore} />
        <InfoItem label="Protocolos" value={intel.fields.protocols} />
        <InfoItem label="Ferramentas" value={intel.fields.tools} />
        <InfoItem label="Tentativas" value={intel.fields.attempts} />
      </div>

      <ParsedList
        icon={<KeyRound size={14} />}
        title="Credenciais usadas"
        emptyLabel="Nenhuma credencial observada"
        items={intel.credentials}
        onOpenModal={onOpenModal}
      />
      <ParsedList
        icon={<Terminal size={14} />}
        title="Comandos executados"
        emptyLabel="Nenhum comando observado"
        items={intel.commands}
        onOpenModal={onOpenModal}
      />
      <ParsedList
        icon={<Download size={14} />}
        title="Downloads / arquivos"
        emptyLabel="Nenhum download observado"
        items={intel.downloadedFiles}
        onOpenModal={onOpenModal}
      />
      <ParsedList
        icon={<FileText size={14} />}
        title="Hashes / MITRE"
        emptyLabel="Nenhum hash ou MITRE observado"
        items={[...intel.hashes, ...intel.mitre]}
        onOpenModal={onOpenModal}
      />

      <section className="parsed-event-section">
        <h4>
          <Network size={14} />
          IOCs neste evento
        </h4>
        {eventIocs.length ? (
          <div className="event-ioc-list">
            {eventIocs.map((node) => (
              <div key={node.id}>
                <TypePill type={node.node_type} />
                <strong>{compactText(node.label || node.value, 64)}</strong>
                <button
                  type="button"
                  onClick={() =>
                    onOpenModal({
                      title: node.label || node.value,
                      subtitle: node.node_type,
                      body: nodeModalBody(node),
                      node,
                    })
                  }
                  title="Abrir detalhes do IOC"
                >
                  <ArrowRight size={14} />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="muted">Nenhum IOC detectado no texto do evento.</p>
        )}
      </section>

      <button
        type="button"
        className="text-button event-raw-button"
        onClick={() =>
          onOpenModal({
            title: alert.title,
            subtitle: 'Evento bruto',
            body: alertRawText(alert),
          })
        }
      >
        <FileText size={14} />
        Abrir evento completo
      </button>
    </article>
  );
}

function ParsedList({
  icon,
  title,
  emptyLabel,
  items,
  onOpenModal,
}: {
  icon: ReactNode;
  title: string;
  emptyLabel: string;
  items: string[];
  onOpenModal: (modal: InvestigationModal) => void;
}) {
  return (
    <section className="parsed-event-section">
      <h4>
        {icon}
        {title}
      </h4>
      {items.length ? (
        <div className="parsed-value-list">
          {items.map((item, index) => {
            const compact = compactText(item, 130);
            const isLong = compact !== item;
            return (
              <div key={`${item.slice(0, 28)}-${index}`}>
                <code>{compact}</code>
                {isLong && (
                  <button
                    type="button"
                    onClick={() =>
                      onOpenModal({
                        title,
                        subtitle: 'Conteudo completo',
                        body: item,
                      })
                    }
                    title="Abrir conteudo completo"
                  >
                    <ArrowRight size={14} />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <p className="muted">{emptyLabel}</p>
      )}
    </section>
  );
}

function InvestigationDetailModal({
  modal,
  onClose,
}: {
  modal: InvestigationModal;
  onClose: () => void;
}) {
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label={modal.title}>
      <div className="investigation-modal">
        <header>
          <div>
            {modal.subtitle && <span className="modal-kicker">{modal.subtitle}</span>}
            <h2>{modal.title}</h2>
          </div>
          <button type="button" onClick={onClose} title="Fechar">
            <X size={16} />
          </button>
        </header>
        {modal.node && (
          <div className="modal-grid">
            <InfoItem label="Tipo" value={modal.node.node_type} />
            <InfoItem label="Valor" value={modal.node.value} />
            <InfoItem label="Fonte" value={displaySource(modal.node.source, modal.node.metadata)} />
            <InfoItem label="Ultima ocorrencia" value={formatDate(modal.node.last_seen)} />
          </div>
        )}
        <pre>{modal.body}</pre>
      </div>
    </div>
  );
}

interface ParsedAlertIntel {
  fields: {
    sourceIp: string;
    countryAsn: string;
    org: string;
    threatScore: string;
    protocols: string;
    tools: string;
    attempts: string;
  };
  credentials: string[];
  commands: string[];
  downloadedFiles: string[];
  hashes: string[];
  mitre: string[];
}

const parsedSectionHeaders = new Set([
  'Credentials',
  'Commands',
  'Downloaded Files',
  'SHA256',
  'MITRE ATT&CK',
  'Event Types',
]);

function parseAlertIntel(alert: Alert): ParsedAlertIntel {
  const text = alertText(alert);
  const hashes = uniqueValues([...sectionValues(text, 'SHA256'), ...extractHashes(text)]);

  return {
    fields: {
      sourceIp: fieldValues(text, 'Source IP'),
      countryAsn: fieldValues(text, 'Country / ASN'),
      org: fieldValues(text, 'Org'),
      threatScore: fieldValues(text, 'Threat Score'),
      protocols: fieldValues(text, 'Protocols Hit'),
      tools: fieldValues(text, 'Tools'),
      attempts: fieldValues(text, 'Attempts'),
    },
    credentials: sectionValues(text, 'Credentials'),
    commands: sectionValues(text, 'Commands'),
    downloadedFiles: sectionValues(text, 'Downloaded Files'),
    hashes,
    mitre: sectionValues(text, 'MITRE ATT&CK'),
  };
}

function fieldValues(text: string, label: string): string {
  const prefix = `${label}:`.toLowerCase();
  const values = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.toLowerCase().startsWith(prefix))
    .map((line) => line.slice(line.indexOf(':') + 1).trim())
    .filter(Boolean);

  return uniqueValues(values).join('; ') || '-';
}

function sectionValues(text: string, header: string): string[] {
  const values: string[] = [];
  let collecting = false;

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.toLowerCase() === header.toLowerCase()) {
      collecting = true;
      continue;
    }

    if (!collecting) continue;
    if (!trimmed) {
      collecting = false;
      continue;
    }

    if (parsedSectionHeaders.has(trimmed)) {
      collecting = trimmed.toLowerCase() === header.toLowerCase();
      continue;
    }

    const value = stripListMarker(trimmed);
    if (isObservedValue(value)) values.push(value);
  }

  return uniqueValues(values);
}

function stripListMarker(value: string): string {
  return value.replace(/^[-*]\s*/, '').trim();
}

function isObservedValue(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return Boolean(normalized) && normalized !== 'none observed' && normalized !== 'none';
}

function extractHashes(text: string): string[] {
  return text.match(/\b[a-fA-F0-9]{32,128}\b/g) || [];
}

function findEventIocs(
  alert: Alert,
  currentNode: GraphNode,
  relatedNodes: GraphNode[],
): GraphNode[] {
  const text = alertText(alert).toLowerCase();
  const nodes = [currentNode, ...relatedNodes];
  const seen = new Set<string>();
  const matches: GraphNode[] = [];

  for (const node of nodes) {
    if (seen.has(node.id)) continue;
    const value = node.value.toLowerCase();
    const label = node.label.toLowerCase();
    const appearsInEvent =
      node.id === currentNode.id ||
      (value.length > 2 && text.includes(value)) ||
      (label.length > 2 && text.includes(label));

    if (appearsInEvent) {
      seen.add(node.id);
      matches.push(node);
    }
  }

  return matches.sort((left, right) => {
    if (left.id === currentNode.id) return -1;
    if (right.id === currentNode.id) return 1;
    return left.node_type.localeCompare(right.node_type) || left.value.localeCompare(right.value);
  });
}

function alertText(alert: Alert): string {
  return [alert.description, rawTextValue(alert.raw)].filter(Boolean).join('\n\n');
}

function alertRawText(alert: Alert): string {
  const raw = rawTextValue(alert.raw);
  if (raw) return raw;
  return alert.description || JSON.stringify(alert.raw || {}, null, 2);
}

function rawTextValue(raw: Record<string, unknown>): string {
  const content = readMetadataPath(raw, 'content');
  if (typeof content === 'string' && content.trim()) return content;
  return Object.keys(raw || {}).length ? JSON.stringify(raw, null, 2) : '';
}

function nodeModalBody(node: GraphNode): string {
  return [
    `Tipo: ${node.node_type}`,
    `Valor: ${node.value}`,
    `Label: ${node.label}`,
    `Severity: ${node.severity || '-'}`,
    `Fonte: ${displaySource(node.source, node.metadata)}`,
    `First seen: ${formatDate(node.first_seen)}`,
    `Last seen: ${formatDate(node.last_seen)}`,
    '',
    'Descricao:',
    node.description || '-',
    '',
    'Metadados:',
    JSON.stringify(node.metadata || {}, null, 2),
  ].join('\n');
}

function compactText(value: string, limit: number): string {
  if (value.length <= limit) return value;
  return `${value.slice(0, Math.max(0, limit - 3))}...`;
}

function uniqueValues(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}

function buildRelationGroups(
  details: ExplorerEntityDetails,
  relatedById: Map<string, GraphNode>,
): RelationGroup[] {
  const groups = new Map<string, RelationGroup>();

  for (const edge of details.edges) {
    const peerId =
      edge.source_node_id === details.node.id ? edge.target_node_id : edge.source_node_id;
    const peer = relatedById.get(peerId) || null;
    const title = peer ? categoryLabels[peer.node_type] || peer.node_type : 'Other IOC Types';
    const key = `${title}:${edge.relation}`;
    const group = groups.get(key) || { title, relation: edge.relation, items: [] };
    group.items.push({ edge, node: peer });
    groups.set(key, group);
  }

  return Array.from(groups.values()).sort(
    (left, right) => left.title.localeCompare(right.title) || left.relation.localeCompare(right.relation),
  );
}

interface TimelineItem {
  date: string;
  title: string;
  description: string;
}

function buildTimeline(details: ExplorerEntityDetails): TimelineItem[] {
  const items: TimelineItem[] = [
    {
      date: details.node.first_seen,
      title: 'Primeira observacao',
      description: details.node.value,
    },
    {
      date: details.node.last_seen,
      title: 'Ultima observacao',
      description: details.node.value,
    },
  ];

  for (const alert of details.alerts) {
    items.push({
      date: alert.last_seen,
      title: alert.title,
      description: `Evento ${displaySource(alert.source, alert.raw)}`,
    });
  }

  for (const edge of details.edges) {
    items.push({
      date: edge.last_seen,
      title: `Relacionamento ${relationText(edge.relation)}`,
      description: `Evidencias ${edgeEvidence(edge)}`,
    });
  }

  return items.sort((left, right) => new Date(right.date).getTime() - new Date(left.date).getTime());
}

function filterTimeline(items: TimelineItem[], from: string, to: string): TimelineItem[] {
  const fromMs = from ? new Date(`${from}T00:00:00`).getTime() : Number.NEGATIVE_INFINITY;
  const toMs = to ? new Date(`${to}T23:59:59`).getTime() : Number.POSITIVE_INFINITY;
  return items.filter((item) => {
    const value = new Date(item.date).getTime();
    return value >= fromMs && value <= toMs;
  });
}

function entityTags(entity: Pick<GraphNode, 'metadata' | 'severity' | 'node_type'>): string[] {
  const raw = entity.metadata?.tags || entity.metadata?.tag || entity.metadata?.labels;
  const values = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(',') : [];
  const tags = values.map((value) => String(value).trim()).filter(Boolean);
  if (entity.severity) tags.push(entity.severity);
  tags.push(entity.node_type);
  return Array.from(new Set(tags)).slice(0, 8);
}

function entitySources(details: ExplorerEntityDetails): string[] {
  const sources = new Set<string>();
  const nodeSource = displaySource(details.node.source, details.node.metadata);
  if (nodeSource !== '-') sources.add(nodeSource);
  for (const alert of details.alerts) {
    const source = displaySource(alert.source, alert.raw);
    if (source !== '-') sources.add(source);
  }
  return Array.from(sources);
}

function normalizeFieldValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '-';
  if (Array.isArray(value)) {
    const values = value.map((item) => normalizeFieldValue(item)).filter((item) => item !== '-');
    return values.length ? values.join(', ') : '-';
  }
  return formatMetadataValue(value);
}

function uniqueFields(fields: OverviewField[]): OverviewField[] {
  const seen = new Set<string>();
  const output: OverviewField[] = [];

  for (const field of fields) {
    if (seen.has(field.label)) continue;
    seen.add(field.label);
    output.push(field);
  }

  return output;
}

function firstPresent(values: unknown[]): string {
  for (const value of values) {
    const formatted = normalizeFieldValue(value);
    if (formatted !== '-') return formatted;
  }
  return '-';
}

function descriptionValue(node: GraphNode, label: string): string {
  if (!node.description) return '-';
  const prefix = `${label}:`;
  const line = node.description
    .split('\n')
    .find((item) => item.trim().toLowerCase().startsWith(prefix.toLowerCase()));
  if (!line) return '-';
  return line.slice(line.indexOf(':') + 1).trim() || '-';
}

function enrichmentSummary(metadata: Record<string, unknown>): string {
  const enrichment = metadata.enrichment;
  if (!enrichment || typeof enrichment !== 'object') return '-';
  const providers = (enrichment as Record<string, unknown>).providers;
  if (!Array.isArray(providers)) return '-';

  const summaries = providers
    .map((provider) => {
      if (!provider || typeof provider !== 'object') return null;
      const item = provider as Record<string, unknown>;
      const name = normalizeFieldValue(item.name);
      const score = normalizeFieldValue(item.score);
      const summary = normalizeFieldValue(item.summary);
      if (name === '-') return null;
      if (score !== '-') return `${name}: ${score}`;
      if (summary !== '-') return `${name}: ${summary}`;
      return null;
    })
    .filter(Boolean);

  return summaries.length ? summaries.join('; ') : '-';
}

function relatedPreview(details: ExplorerEntityDetails, type: string, limit = 3): string {
  const values = relatedValues(details, type);
  if (!values.length) return '-';
  const visible = values.slice(0, limit);
  const remaining = values.length - visible.length;
  return remaining > 0 ? `${visible.join(', ')} +${remaining}` : visible.join(', ');
}

function relatedValues(details: ExplorerEntityDetails, type: string): string[] {
  return details.related_nodes
    .filter((node) => node.node_type === type)
    .map((node) => node.label || node.value)
    .filter(Boolean);
}

function relatedCount(details: ExplorerEntityDetails, type: string): number {
  return details.related_nodes.filter((node) => node.node_type === type).length;
}

function relatedCountLabel(details: ExplorerEntityDetails, types: string[]): string {
  const total = details.related_nodes.filter((node) => types.includes(node.node_type)).length;
  return total ? String(total) : '-';
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function domainPart(value: string, part: 'root' | 'tld'): string {
  const pieces = value.split('.').filter(Boolean);
  if (pieces.length < 2) return '-';
  if (part === 'tld') return pieces[pieces.length - 1];
  return pieces.slice(-2).join('.');
}

function hashAlgorithm(value: string): string {
  const normalized = value.trim();
  if (!/^[a-fA-F0-9]+$/.test(normalized)) return 'Desconhecido';
  const algorithms: Record<number, string> = {
    32: 'MD5',
    40: 'SHA1',
    56: 'SHA224',
    64: 'SHA256',
    96: 'SHA384',
    128: 'SHA512',
  };
  return algorithms[normalized.length] || `${normalized.length * 4}-bit hash`;
}

function fileName(value: string): string {
  const normalized = value.replace(/\\/g, '/');
  return normalized.split('/').filter(Boolean).pop() || value;
}

function fileExtension(value: string): string {
  const name = fileName(value);
  const index = name.lastIndexOf('.');
  if (index <= 0 || index === name.length - 1) return '-';
  return name.slice(index + 1).toLowerCase();
}

function malwareType(node: GraphNode): string {
  const explicit = metadataText(node.metadata, [
    'malware_type',
    'type',
    'category',
    'classification',
    'kind',
  ]);
  if (explicit !== '-') return explicit;

  const value = `${node.value} ${node.label}`.toLowerCase();
  if (value.includes('botnet')) return 'Botnet';
  if (value.includes('trojan')) return 'Trojan';
  if (value.includes('worm')) return 'Worm';
  if (value.includes('ransom')) return 'Ransomware';
  if (value.includes('miner')) return 'Cryptominer';
  if (value.includes('malicious')) return 'Deteccao por reputacao';
  return 'Nao classificado';
}

function maliciousStatus(details: ExplorerEntityDetails): string {
  const severity = details.node.severity?.toLowerCase();
  if (severity === 'critical' || severity === 'high') return 'Sim';
  if (details.node.node_type === 'Malware') return 'Sim';
  if (details.related_nodes.some((node) => node.node_type === 'Malware')) return 'Sim';

  const enrichment = enrichmentSummary(details.node.metadata).toLowerCase();
  if (/\b[1-9][0-9]*\//.test(enrichment) || enrichment.includes('malicious')) return 'Sim';
  return 'Nao confirmado';
}

function metadataText(metadata: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = readMetadataPath(metadata, key);
    if (value !== null && value !== undefined && value !== '') return formatMetadataValue(value);
  }
  return '-';
}

function readMetadataPath(metadata: Record<string, unknown>, path: string): unknown {
  let current: unknown = metadata;
  for (const part of path.split('.')) {
    if (!current || typeof current !== 'object' || !(part in current)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function formatMetadataValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '-';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}

function ipVersion(node: GraphNode): string {
  if (node.node_type !== 'IP') return '-';
  return node.value.includes(':') ? 'IPv6' : 'IPv4';
}

function relationText(relation: string): string {
  const labels: Record<string, string> = {
    resolves_to: 'resolve para',
    hosts: 'hospeda',
    detected_as: 'detectado como',
    seen_in: 'visto em',
    related_to: 'relacionado a',
    belongs_to: 'pertence a',
    mapped_to: 'mapeado para',
    contacted: 'contatou',
    downloaded_from: 'baixado de',
  };
  return labels[relation] || relation;
}

function edgeEvidence(edge: GraphEdge): number {
  return typeof edge.metadata?.count === 'number' ? edge.metadata.count : 1;
}

function correlationStrength(edge: GraphEdge): string {
  const evidence = edgeEvidence(edge);
  if (evidence >= 8) return 'alta';
  if (evidence >= 3) return 'media';
  return 'baixa';
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'short',
    timeStyle: 'short',
  }).format(date);
}

function shortId(value: string): string {
  return value.slice(0, 8);
}

function exportRows(rows: ExplorerEntityRow[]) {
  const headers = [
    'IOC',
    'Tipo',
    'Score',
    'Confidence',
    'Threat',
    'Primeira ocorrencia',
    'Ultima ocorrencia',
    'Observacoes',
    'Relacionamentos',
    'Fonte',
  ];
  const csv = [
    headers.join(','),
    ...rows.map((row) =>
      [
        row.value,
        row.node_type,
        metadataText(row.metadata, ['score', 'risk_score', 'reputation']),
        metadataText(row.metadata, ['confidence', 'confidence_score']),
        row.severity || metadataText(row.metadata, ['threat_level']),
        row.first_seen,
        row.last_seen,
        row.observation_count,
        row.relationship_count,
        displaySource(row.source, row.metadata),
      ]
        .map(csvCell)
        .join(','),
    ),
  ].join('\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'ioc-explorer.csv';
  link.click();
  URL.revokeObjectURL(url);
}

function csvCell(value: unknown): string {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}
