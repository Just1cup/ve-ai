import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import {
  Clock3,
  Filter,
  Network,
  RefreshCw,
  Rows3,
  Search,
  ShieldCheck,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import { fetchGraphLayer, fetchIocDetails, websocketUrl } from './api';
import {
  readGraphSnapshot,
  readIocDetails,
  readViewState,
  writeGraphSnapshot,
  writeIocDetails,
  writeViewState,
} from './cache';
import DetailsPanel from './DetailsPanel';
import ExplorerView from './ExplorerView';
import GraphCanvas from './GraphCanvas';
import { NODE_COLORS, nodeTypeColor } from './graphTheme';
import type {
  Alert,
  GraphEdge,
  GraphLayer,
  GraphNode,
  GraphResponse,
  IocDetails,
  SocketMessage,
  TimeRangeParams,
} from './types';

const emptyGraph: GraphResponse = {
  nodes: [],
  edges: [],
  alerts: [],
  generated_at: new Date(0).toISOString(),
};

const primaryLayer: GraphLayer = 'ips';
const graphLayers: GraphLayer[] = [
  primaryLayer,
  'domains',
  'hashes',
  'emails',
  'cves',
  'urls',
  'files',
  'malware',
  'commands',
  'alerts',
  'mitre',
  'asns',
  'countries',
  'sources',
];
const backgroundLayers = graphLayers.filter((layer) => layer !== primaryLayer);
const defaultEnabledTypes = new Set(['IP']);
const knownNodeTypes = Object.keys(NODE_COLORS).sort();
type TimePreset = 'all' | 'hour' | 'week' | 'month' | 'custom';

export default function App() {
  const [layerGraphs, setLayerGraphs] = useState<Partial<Record<GraphLayer, GraphResponse>>>({});
  const [viewMode, setViewMode] = useState<'graph' | 'explorer'>('graph');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [explorerEntityId, setExplorerEntityId] = useState<string | null>(null);
  const [details, setDetails] = useState<IocDetails | null>(null);
  const [query, setQuery] = useState('');
  const [timePreset, setTimePreset] = useState<TimePreset>('all');
  const [customFrom, setCustomFrom] = useState('');
  const [customTo, setCustomTo] = useState('');
  const [enabledTypes, setEnabledTypes] = useState<Set<string>>(() => new Set(['IP']));
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [viewStateRestored, setViewStateRestored] = useState(false);
  const deferredQuery = useDeferredValue(query);
  const timeRange = useMemo(
    () => resolveTimeRange(timePreset, customFrom, customTo),
    [customFrom, customTo, timePreset],
  );
  const timeRangeKey = useMemo(() => graphTimeRangeKey(timeRange), [timeRange]);
  const activeLayers = useMemo(() => layersForEnabledTypes(enabledTypes), [enabledTypes]);
  const activeLayersRef = useRef<GraphLayer[]>(activeLayers);
  const visibleLayerGraphs = useMemo(
    () => pickLayerGraphs(layerGraphs, activeLayers),
    [activeLayers, layerGraphs],
  );
  const graph = useMemo(() => mergeGraphLayers(visibleLayerGraphs), [visibleLayerGraphs]);

  const refreshLayer = useCallback(
    async (layer: GraphLayer, etag?: string | null, attach = true) => {
      const result = await fetchGraphLayer(layer, etag, timeRange);
      if (result.status === 'not-modified') return;

      if (attach) {
        setLayerGraphs((current) => ({ ...current, [layer]: result.graph }));
      }
      await writeGraphSnapshot(graphSnapshotKey(layer, timeRangeKey), result.graph, result.etag);
    },
    [timeRange, timeRangeKey],
  );

  const loadGraph = useCallback(async () => {
    setLoading(true);
    try {
      const cachedViewState = await readViewState();
      const restoredTypes = cachedViewState
        ? new Set(cachedViewState.enabledTypes)
        : new Set(defaultEnabledTypes);
      if (cachedViewState) {
        setEnabledTypes(restoredTypes);
        setQuery(cachedViewState.query);
      }
      setViewStateRestored(true);

      const startupLayers = layersForEnabledTypes(restoredTypes);
      const cached = await Promise.all(
        startupLayers.map(async (layer) => [
          layer,
          await readGraphSnapshot(graphSnapshotKey(layer, timeRangeKey)),
        ] as const),
      );
      const cachedLayers: Partial<Record<GraphLayer, GraphResponse>> = {};
      for (const [layer, snapshot] of cached) {
        if (snapshot) cachedLayers[layer] = snapshot.data;
      }

      if (Object.keys(cachedLayers).length) {
        setLayerGraphs(cachedLayers);
        setLoading(false);
      }

      const cachedByLayer = new Map(cached);
      await Promise.all(
        startupLayers.map((layer) => refreshLayer(layer, cachedByLayer.get(layer)?.etag, true)),
      );
      setError(null);
      setLoading(false);

      void Promise.allSettled(
        backgroundLayers.map(async (layer) => {
          if (startupLayers.includes(layer)) return;
          const cachedLayer = await readGraphSnapshot(graphSnapshotKey(layer, timeRangeKey));
          await refreshLayer(layer, cachedLayer?.etag, false);
        }),
      );
    } catch (err) {
      setViewStateRestored(true);
      setError(err instanceof Error ? err.message : 'Falha ao carregar grafo');
      setLoading(false);
    }
  }, [refreshLayer]);

  const cacheLayerGraphs = useCallback(
    async (layers: Partial<Record<GraphLayer, GraphResponse>>) => {
      await Promise.all(
        Object.entries(layers).map(([layer, snapshot]) =>
          snapshot
            ? writeGraphSnapshot(graphSnapshotKey(layer as GraphLayer, 'all'), snapshot, null)
            : Promise.resolve(),
        ),
      );
    },
    [],
  );

  useEffect(() => {
    void loadGraph();
  }, [loadGraph]);

  useEffect(() => {
    activeLayersRef.current = activeLayers;
  }, [activeLayers]);

  useEffect(() => {
    if (!viewStateRestored) return;
    void writeViewState(Array.from(enabledTypes), query);
  }, [enabledTypes, query, viewStateRestored]);

  useEffect(() => {
    if (!viewStateRestored) return;

    const missingLayers = activeLayers.filter((layer) => !layerGraphs[layer]);
    if (!missingLayers.length) return;

    let cancelled = false;
    async function loadMissingLayers() {
      for (const layer of missingLayers) {
        const cached = await readGraphSnapshot(graphSnapshotKey(layer, timeRangeKey));
        if (cancelled) return;

        if (cached) {
          setLayerGraphs((current) => ({ ...current, [layer]: cached.data }));
        }

        await refreshLayer(layer, cached?.etag, true);
      }
    }

    void loadMissingLayers();
    return () => {
      cancelled = true;
    };
  }, [activeLayers, layerGraphs, refreshLayer, timeRangeKey, viewStateRestored]);

  useEffect(() => {
    let closed = false;
    let socket: WebSocket | null = null;
    let retry: number | undefined;

    const connect = () => {
      socket = new WebSocket(websocketUrl());
      socket.onopen = () => setConnected(true);
      socket.onmessage = (event) => {
        const message = JSON.parse(event.data) as SocketMessage;
        if (message.graph) {
          const nextLayers = splitGraphIntoLayers(message.graph);
          setLayerGraphs((current) => ({
            ...current,
            ...pickLayerGraphs(nextLayers, activeLayersRef.current),
          }));
          void cacheLayerGraphs(nextLayers);
          setError(null);
          return;
        }

        if (message.type === 'graph_updated') {
          void Promise.allSettled(
            activeLayersRef.current.map(async (layer) => {
              const cached = await readGraphSnapshot(graphSnapshotKey(layer, timeRangeKey));
              await refreshLayer(layer, cached?.etag, true);
            }),
          ).then((results) => {
            if (results.some((result) => result.status === 'rejected')) {
              setError('O grafo mudou, mas algumas camadas nao puderam ser atualizadas.');
            } else {
              setError(null);
            }
          });
        }
      };
      socket.onerror = () => setConnected(false);
      socket.onclose = () => {
        setConnected(false);
        if (!closed) {
          retry = window.setTimeout(connect, 1500);
        }
      };
    };

    connect();

    return () => {
      closed = true;
      if (retry) window.clearTimeout(retry);
      socket?.close();
    };
  }, [cacheLayerGraphs, refreshLayer, timeRangeKey]);

  useEffect(() => {
    if (!selectedNodeId) {
      setDetails(null);
      return;
    }

    let cancelled = false;

    async function loadDetails(id: string) {
      const cached = await readIocDetails(id);
      if (cancelled) return;

      if (cached && isFreshIocDetails(cached.detail, cached.cachedAt)) {
        setDetails(cached.detail);
      } else {
        setDetails(null);
      }

      try {
        const next = await fetchIocDetails(id);
        if (cancelled) return;
        setDetails(next);
        await writeIocDetails(id, next);
      } catch {
        if (!cancelled && !cached) setDetails(null);
      }
    }

    void loadDetails(selectedNodeId);

    return () => {
      cancelled = true;
    };
  }, [selectedNodeId, graph.generated_at]);

  const nodeTypes = knownNodeTypes;

  const filteredGraph = useMemo(() => {
    return filterGraph(graph, enabledTypes, deferredQuery, timeRange);
  }, [graph, enabledTypes, deferredQuery, timeRange]);

  const nodesById = useMemo(() => {
    return new Map(graph.nodes.map((node) => [node.id, node]));
  }, [graph.nodes]);
  const selectedNode = selectedNodeId ? nodesById.get(selectedNodeId) || null : null;
  const onSelectNode = useCallback((id: string | null) => {
    setSelectedNodeId(id);
    if (id) setExplorerEntityId(id);
  }, []);
  const openExplorer = useCallback((id: string) => {
    setExplorerEntityId(id);
    setSelectedNodeId(id);
    setViewMode('explorer');
  }, []);
  const selectExplorerEntity = useCallback((id: string | null) => {
    setExplorerEntityId(id);
  }, []);
  const openGraphFromExplorer = useCallback((node: GraphNode) => {
    setSelectedNodeId(node.id);
    setEnabledTypes((current) => {
      if (current.has(node.node_type)) return current;
      const next = new Set(current);
      next.add(node.node_type);
      return next;
    });
    setViewMode('graph');
  }, []);

  const toggleType = useCallback((type: string) => {
    setEnabledTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-workspace">Pular para a investigacao</a>
      <header className="topbar">
        <div className="product-brand">
          <span className="brand-mark" aria-hidden="true"><ShieldCheck size={21} /></span>
          <div>
            <span className="product-kicker">Threat intelligence workspace</span>
            <h1>IOC Graph</h1>
            <p>Investigacao visual e correlacao de indicadores</p>
          </div>
        </div>
        <div className="topbar-status">
          <nav className="view-switcher" aria-label="Modo de investigacao">
            <button
              type="button"
              className={viewMode === 'graph' ? 'active' : ''}
              onClick={() => setViewMode('graph')}
            >
              <Network size={15} />
              Grafo
            </button>
            <button
              type="button"
              className={viewMode === 'explorer' ? 'active' : ''}
              onClick={() => setViewMode('explorer')}
            >
              <Rows3 size={15} />
              Explorer
            </button>
          </nav>
          <TimeFilterControls
            preset={timePreset}
            customFrom={customFrom}
            customTo={customTo}
            onPresetChange={setTimePreset}
            onCustomFromChange={setCustomFrom}
            onCustomToChange={setCustomTo}
          />
          <span className={connected ? 'live on' : 'live off'} role="status" aria-live="polite">
            {connected ? <Wifi size={16} /> : <WifiOff size={16} />}
            {connected ? 'Tempo real' : 'Reconectando'}
          </span>
          <button
            type="button"
            className="icon-button"
            onClick={loadGraph}
            disabled={loading}
            title="Atualizar dados"
            aria-label="Atualizar dados"
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </header>

      {viewMode === 'graph' ? (
      <div className="workspace" id="main-workspace">
        <aside className="filters-panel">
          <div className="panel-heading">
            <div>
              <span className="panel-kicker">Escopo da analise</span>
              <h2>Filtros do grafo</h2>
            </div>
            <span className="filter-count">{enabledTypes.size} ativos</span>
          </div>
          <div className="search-box">
            <Search size={16} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Buscar IOC"
              aria-label="Buscar IOC"
            />
            {query && (
              <button type="button" onClick={() => setQuery('')} title="Limpar busca">
                <X size={14} />
              </button>
            )}
          </div>

          <section>
            <div className="section-heading">
              <h2><Filter size={16} />Tipos de entidade</h2>
              <div className="filter-actions">
                <button type="button" onClick={() => setEnabledTypes(new Set(knownNodeTypes))}>Todos</button>
                <button type="button" onClick={() => setEnabledTypes(new Set())}>Limpar</button>
              </div>
            </div>
            <div className="type-list">
              {nodeTypes.map((type) => (
                <label key={type}>
                  <input
                    type="checkbox"
                    checked={enabledTypes.has(type)}
                    onChange={() => toggleType(type)}
                  />
                  <span
                    className="type-swatch"
                    style={{ backgroundColor: nodeTypeColor(type) }}
                    aria-hidden="true"
                  />
                  <span>{type}</span>
                </label>
              ))}
            </div>
          </section>

          <section className="stats">
            <Metric label="Nós visíveis" value={filteredGraph.nodes.length} />
            <Metric label="Conexões" value={filteredGraph.edges.length} />
            <Metric label="Alertas" value={filteredGraph.alerts.length} />
            <Metric label="Atualizado" value={formatTime(graph.generated_at)} />
          </section>

          {error && <p className="error-text" role="alert">{error}</p>}
        </aside>

        <main className="graph-panel" aria-busy={loading}>
          {loading && !graph.nodes.length ? (
            <div className="loading-state">
              <span className="loading-spinner" aria-hidden="true" />
              <strong>Preparando investigacao</strong>
              <span>Carregando entidades e relacionamentos...</span>
            </div>
          ) : (
            <GraphCanvas
              graph={filteredGraph}
              selectedNodeId={selectedNodeId}
              onSelectNode={onSelectNode}
            />
          )}
        </main>

        <DetailsPanel
          node={selectedNode || details?.node || null}
          details={details}
          nodesById={nodesById}
          onSelectNode={onSelectNode}
          onOpenExplorer={openExplorer}
        />
      </div>
      ) : (
        <ExplorerView
          selectedEntityId={explorerEntityId}
          onSelectEntity={selectExplorerEntity}
          onOpenGraph={openGraphFromExplorer}
          timeRange={timeRange}
        />
      )}
    </div>
  );
}

function TimeFilterControls({
  preset,
  customFrom,
  customTo,
  onPresetChange,
  onCustomFromChange,
  onCustomToChange,
}: {
  preset: TimePreset;
  customFrom: string;
  customTo: string;
  onPresetChange: (value: TimePreset) => void;
  onCustomFromChange: (value: string) => void;
  onCustomToChange: (value: string) => void;
}) {
  return (
    <div className="time-filter" aria-label="Filtro de horario">
      <Clock3 size={15} />
      <select
        value={preset}
        onChange={(event) => onPresetChange(event.target.value as TimePreset)}
        aria-label="Filtrar por horario"
      >
        <option value="all">Todo periodo</option>
        <option value="hour">Ultima hora</option>
        <option value="week">Ultima semana</option>
        <option value="month">Ultimo mes</option>
        <option value="custom">Tempo personalizado</option>
      </select>
      {preset === 'custom' && (
        <>
          <input
            type="datetime-local"
            value={customFrom}
            onChange={(event) => onCustomFromChange(event.target.value)}
            aria-label="Inicio personalizado"
          />
          <input
            type="datetime-local"
            value={customTo}
            onChange={(event) => onCustomToChange(event.target.value)}
            aria-label="Fim personalizado"
          />
        </>
      )}
    </div>
  );
}

function resolveTimeRange(
  preset: TimePreset,
  customFrom: string,
  customTo: string,
): TimeRangeParams {
  const now = Date.now();
  const ranges: Record<Exclude<TimePreset, 'all' | 'custom'>, number> = {
    hour: 60 * 60 * 1000,
    week: 7 * 24 * 60 * 60 * 1000,
    month: 30 * 24 * 60 * 60 * 1000,
  };

  if (preset === 'custom') {
    return {
      from: datetimeLocalToIso(customFrom),
      to: datetimeLocalToIso(customTo),
    };
  }

  if (preset === 'all') return {};

  return {
    from: new Date(now - ranges[preset]).toISOString(),
    to: new Date(now).toISOString(),
  };
}

function datetimeLocalToIso(value: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function graphTimeRangeKey(timeRange: TimeRangeParams): string {
  const from = timeRange.from || 'start';
  const to = timeRange.to || 'end';
  return from === 'start' && to === 'end' ? 'all' : `${from}_${to}`;
}

function graphSnapshotKey(layer: GraphLayer, timeRangeKey: string): string {
  return `${layer}:${timeRangeKey}`;
}

function layersForEnabledTypes(enabledTypes: Set<string>): GraphLayer[] {
  const layers = new Set<GraphLayer>();

  for (const type of enabledTypes) {
    const layer = layerForNodeType(type);
    if (layer) layers.add(layer);
  }

  return Array.from(layers);
}

function pickLayerGraphs(
  layers: Partial<Record<GraphLayer, GraphResponse>>,
  activeLayers: GraphLayer[],
): Partial<Record<GraphLayer, GraphResponse>> {
  const picked: Partial<Record<GraphLayer, GraphResponse>> = {};

  for (const layer of activeLayers) {
    if (layers[layer]) picked[layer] = layers[layer];
  }

  return picked;
}

function mergeGraphLayers(layers: Partial<Record<GraphLayer, GraphResponse>>): GraphResponse {
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  const alerts = new Map<string, Alert>();
  let generatedAt = emptyGraph.generated_at;

  for (const graph of Object.values(layers)) {
    if (!graph) continue;

    for (const node of graph.nodes) nodes.set(node.id, node);
    for (const alert of graph.alerts) alerts.set(alert.id, alert);
    if (new Date(graph.generated_at) > new Date(generatedAt)) {
      generatedAt = graph.generated_at;
    }
  }

  for (const graph of Object.values(layers)) {
    if (!graph) continue;
    for (const edge of graph.edges) {
      if (nodes.has(edge.source_node_id) && nodes.has(edge.target_node_id)) {
        edges.set(edge.id, edge);
      }
    }
  }

  return {
    nodes: Array.from(nodes.values()),
    edges: Array.from(edges.values()),
    alerts: Array.from(alerts.values()),
    generated_at: generatedAt,
  };
}

function splitGraphIntoLayers(graph: GraphResponse): Partial<Record<GraphLayer, GraphResponse>> {
  const layers: Partial<Record<GraphLayer, GraphResponse>> = {};
  const nodesByLayer = new Map<GraphLayer, Set<string>>();

  for (const node of graph.nodes) {
    const layer = layerForNodeType(node.node_type);
    if (!layer) continue;

    nodesByLayer.set(layer, nodesByLayer.get(layer) || new Set());
    nodesByLayer.get(layer)?.add(node.id);
  }

  for (const layer of graphLayers) {
    const nodeIds = nodesByLayer.get(layer);
    if (!nodeIds?.size) continue;

    const edges = graph.edges.filter(
      (edge) => nodeIds.has(edge.source_node_id) || nodeIds.has(edge.target_node_id),
    );
    const alertIds = new Set(edges.map((edge) => edge.alert_id).filter(Boolean));

    layers[layer] = {
      nodes: graph.nodes.filter((node) => nodeIds.has(node.id)),
      edges,
      alerts: graph.alerts.filter((alert) => nodeIds.has(alert.node_id) || alertIds.has(alert.id)),
      generated_at: graph.generated_at,
    };
  }

  return layers;
}

function layerForNodeType(type: string): GraphLayer | null {
  const layers: Record<string, GraphLayer> = {
    IP: 'ips',
    Domain: 'domains',
    Hash: 'hashes',
    Email: 'emails',
    CVE: 'cves',
    URL: 'urls',
    File: 'files',
    Malware: 'malware',
    Command: 'commands',
    Alert: 'alerts',
    'MITRE Technique': 'mitre',
    ASN: 'asns',
    Country: 'countries',
    Source: 'sources',
  };
  return layers[type] || null;
}

function isFreshIocDetails(details: IocDetails, cachedAt: number): boolean {
  const lastSeenMs = new Date(details.node.last_seen).getTime();
  const ageMs = Date.now() - cachedAt;
  const recentActivity = Date.now() - lastSeenMs < 60 * 60 * 1000;
  const ttlMs = recentActivity ? 5 * 60 * 1000 : 6 * 60 * 60 * 1000;

  return ageMs < ttlMs;
}

function filterGraph(
  graph: GraphResponse,
  enabledTypes: Set<string>,
  query: string,
  timeRange: TimeRangeParams,
): GraphResponse {
  const normalizedQuery = query.trim().toLowerCase();

  if (normalizedQuery) {
    return filterSearchNeighborhood(graph, enabledTypes, normalizedQuery, timeRange);
  }

  const nodes = graph.nodes.filter(
    (node) => isEnabledType(node, enabledTypes) && isInTimeRange(node, timeRange),
  );
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter(
    (edge) =>
      nodeIds.has(edge.source_node_id) &&
      nodeIds.has(edge.target_node_id) &&
      isInTimeRange(edge, timeRange),
  );
  return {
    ...graph,
    nodes,
    edges,
    alerts: filterVisibleAlerts(graph.alerts, edges, nodeIds, timeRange),
  };
}

function filterSearchNeighborhood(
  graph: GraphResponse,
  enabledTypes: Set<string>,
  normalizedQuery: string,
  timeRange: TimeRangeParams,
): GraphResponse {
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const adjacency = buildAdjacency(graph.edges);
  const seedIds = graph.nodes
    .filter(
      (node) =>
        isEnabledType(node, enabledTypes) &&
        isInTimeRange(node, timeRange) &&
        matchesQuery(node, normalizedQuery),
    )
    .map((node) => node.id);

  if (!seedIds.length) {
    return { ...graph, nodes: [], edges: [] };
  }

  const visibleNodeIds = new Set(seedIds);
  let frontier = seedIds;

  for (let depth = 0; depth < 2; depth += 1) {
    const nextFrontier: string[] = [];

    for (const nodeId of frontier) {
      const node = nodesById.get(nodeId);
      const incidentEdges = adjacency.get(nodeId) || [];
      if (depth > 0 && (!node || !canExpandSearchContext(node, incidentEdges.length))) {
        continue;
      }

      for (const edge of incidentEdges) {
        if (!isInTimeRange(edge, timeRange)) continue;
        const peerId = edge.source_node_id === nodeId ? edge.target_node_id : edge.source_node_id;
        const peer = nodesById.get(peerId);
        if (peer && isInTimeRange(peer, timeRange) && !visibleNodeIds.has(peerId)) {
          visibleNodeIds.add(peerId);
          nextFrontier.push(peerId);
        }
      }
    }

    frontier = nextFrontier;
  }

  const nodes = graph.nodes.filter((node) => visibleNodeIds.has(node.id));
  const edges = graph.edges.filter(
    (edge) =>
      visibleNodeIds.has(edge.source_node_id) &&
      visibleNodeIds.has(edge.target_node_id) &&
      isInTimeRange(edge, timeRange),
  );

  return {
    ...graph,
    nodes,
    edges,
    alerts: filterVisibleAlerts(graph.alerts, edges, visibleNodeIds, timeRange),
  };
}

function filterVisibleAlerts(
  alerts: Alert[],
  edges: GraphEdge[],
  visibleNodeIds: Set<string>,
  timeRange: TimeRangeParams,
): Alert[] {
  const edgeAlertIds = new Set(edges.map((edge) => edge.alert_id).filter(Boolean));
  return alerts.filter(
    (alert) =>
      isInTimeRange(alert, timeRange) &&
      (visibleNodeIds.has(alert.node_id) || edgeAlertIds.has(alert.id)),
  );
}

function isInTimeRange(
  item: Pick<GraphNode | GraphEdge | Alert, 'first_seen' | 'last_seen'>,
  timeRange: TimeRangeParams,
): boolean {
  const from = timeRange.from ? new Date(timeRange.from).getTime() : null;
  const to = timeRange.to ? new Date(timeRange.to).getTime() : null;
  const firstSeen = new Date(item.first_seen).getTime();
  const lastSeen = new Date(item.last_seen).getTime();

  if (Number.isNaN(firstSeen) || Number.isNaN(lastSeen)) return true;
  if (from !== null && lastSeen < from) return false;
  if (to !== null && firstSeen > to) return false;
  return true;
}

function buildAdjacency(edges: GraphEdge[]): Map<string, GraphEdge[]> {
  const adjacency = new Map<string, GraphEdge[]>();

  for (const edge of edges) {
    addAdjacentEdge(adjacency, edge.source_node_id, edge);
    addAdjacentEdge(adjacency, edge.target_node_id, edge);
  }

  return adjacency;
}

function addAdjacentEdge(adjacency: Map<string, GraphEdge[]>, nodeId: string, edge: GraphEdge) {
  const edges = adjacency.get(nodeId);
  if (edges) {
    edges.push(edge);
    return;
  }
  adjacency.set(nodeId, [edge]);
}

function isEnabledType(node: GraphNode, enabledTypes: Set<string>): boolean {
  return enabledTypes.has(node.node_type);
}

function matchesQuery(node: GraphNode, normalizedQuery: string): boolean {
  return (
    node.value.toLowerCase().includes(normalizedQuery) ||
    node.label.toLowerCase().includes(normalizedQuery) ||
    node.node_type.toLowerCase().includes(normalizedQuery)
  );
}

function canExpandSearchContext(node: GraphNode, edgeCount: number): boolean {
  if (edgeCount > 80) return false;
  return !['Alert', 'Source', 'MITRE Technique', 'Country'].includes(node.node_type);
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value));
}
