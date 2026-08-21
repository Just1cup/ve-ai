import { useEffect, useMemo, useRef, useState } from 'react';
import { MultiDirectedGraph } from 'graphology';
import Sigma from 'sigma';
import type { EdgeDisplayData, NodeDisplayData } from 'sigma/types';
import { Maximize2, ZoomIn, ZoomOut } from 'lucide-react';
import { graphResponseToCanonicalGraph, type CanonicalGraph } from './canonicalGraph';
import type { GraphResponse } from './types';

interface GraphCanvasProps {
  graph: GraphResponse;
  selectedNodeId: string | null;
  onSelectNode: (id: string | null) => void;
}

interface GraphologyNodeAttributes {
  label: string;
  shortLabel: string;
  nodeType: string;
  degree: number;
  size: number;
  color: string;
  x: number;
  y: number;
  value?: unknown;
  severity?: unknown;
  source?: unknown;
  description?: unknown;
  firstSeen?: unknown;
  lastSeen?: unknown;
  metadata?: unknown;
}

interface GraphologyEdgeAttributes {
  label: string;
  relation: string;
  weight: number;
  size: number;
  color: string;
  type: 'arrow';
  alertId?: unknown;
  firstSeen?: unknown;
  lastSeen?: unknown;
  metadata?: unknown;
}

type GraphModel = MultiDirectedGraph<GraphologyNodeAttributes, GraphologyEdgeAttributes>;
type GraphRenderer = Sigma<GraphologyNodeAttributes, GraphologyEdgeAttributes>;

interface FocusState {
  nodeId: string | null;
  nodeIds: Set<string>;
  edgeIds: Set<string>;
}

const DEFAULT_FOCUS: FocusState = {
  nodeId: null,
  nodeIds: new Set(),
  edgeIds: new Set(),
};

export default function GraphCanvas({ graph, selectedNodeId, onSelectNode }: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const rendererRef = useRef<GraphRenderer | null>(null);
  const onSelectNodeRef = useRef(onSelectNode);
  const topologyKeyRef = useRef('');
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [renderError, setRenderError] = useState<string | null>(null);

  const canonicalGraph = useMemo(() => graphResponseToCanonicalGraph(graph), [graph]);
  const graphModel = useMemo(() => canonicalGraphToGraphology(canonicalGraph), [canonicalGraph]);
  const topology = useMemo(() => topologyKey(canonicalGraph), [canonicalGraph]);
  const activeFocusNodeId = hoveredNodeId ?? selectedNodeId;
  const focusState = useMemo(
    () => collectFocusState(graphModel, activeFocusNodeId),
    [graphModel, activeFocusNodeId],
  );

  useEffect(() => {
    onSelectNodeRef.current = onSelectNode;
  }, [onSelectNode]);

  useEffect(() => {
    if (!containerRef.current) return;

    let renderer: GraphRenderer;

    try {
      renderer = new Sigma(graphModel, containerRef.current, {
        defaultEdgeColor: '#9aa4b5',
        defaultEdgeType: 'arrow',
        defaultNodeColor: '#6b7280',
        hideEdgesOnMove: graphModel.size > 1500,
        hideLabelsOnMove: true,
        labelFont: 'Inter, ui-sans-serif, system-ui, sans-serif',
        labelSize: 9,
        labelWeight: '600',
        labelColor: { color: '#111827' },
        labelDensity: graphModel.order > 1000 ? 0.12 : 0.42,
        labelGridCellSize: graphModel.order > 1000 ? 180 : 110,
        labelRenderedSizeThreshold: graphModel.order > 1000 ? 14 : 9,
        minCameraRatio: 0.04,
        minEdgeThickness: 0.25,
        maxCameraRatio: 8,
        renderEdgeLabels: false,
        zIndex: true,
      });
    } catch {
      setRenderError('Nao foi possivel iniciar o renderer WebGL do grafo neste navegador.');
      return;
    }

    setRenderError(null);

    renderer.on('clickNode', ({ node }) => {
      onSelectNodeRef.current(node);
      zoomToNodeContext(renderer, node);
    });
    renderer.on('clickStage', () => {
      onSelectNodeRef.current(null);
    });
    renderer.on('enterNode', ({ node }) => {
      setHoveredNodeId(node);
    });
    renderer.on('leaveNode', () => {
      setHoveredNodeId(null);
    });

    rendererRef.current = renderer;

    return () => {
      renderer.kill();
      rendererRef.current = null;
    };
  }, []);

  useEffect(() => {
    const renderer = rendererRef.current;
    if (!renderer) return;

    const topologyChanged = topologyKeyRef.current !== topology;
    renderer.setGraph(graphModel);
    renderer.setSettings({
      hideEdgesOnMove: graphModel.size > 1500,
      labelDensity: graphModel.order > 1000 ? 0.12 : 0.42,
      labelGridCellSize: graphModel.order > 1000 ? 180 : 110,
      labelRenderedSizeThreshold: graphModel.order > 1000 ? 14 : 9,
    });
    renderer.refresh();

    if (topologyChanged) {
      topologyKeyRef.current = topology;
      renderer.getCamera().animatedReset({ duration: 220 });
    }
  }, [graphModel, topology]);

  useEffect(() => {
    const renderer = rendererRef.current;
    if (!renderer) return;

    renderer.setSetting(
      'nodeReducer',
      createNodeReducer({
        renderer,
        totalNodes: graphModel.order,
        selectedNodeId,
        focusState,
      }),
    );
    renderer.setSetting(
      'edgeReducer',
      createEdgeReducer({
        focusState,
        selectedNodeId,
      }),
    );
    renderer.scheduleRefresh({ layoutUnchange: true });
  }, [focusState, graphModel.order, selectedNodeId]);

  const zoomIn = () => rendererRef.current?.getCamera().animatedZoom({ factor: 1.35, duration: 160 });
  const zoomOut = () =>
    rendererRef.current?.getCamera().animatedUnzoom({ factor: 1.35, duration: 160 });
  const fit = () => rendererRef.current?.getCamera().animatedReset({ duration: 220 });

  return (
    <div className="graph-canvas-wrap">
      <div className="graph-canvas" ref={containerRef} />
      {renderError ? (
        <div className="loading-state graph-render-error">{renderError}</div>
      ) : (
        <div className="graph-controls" aria-label="Controles do grafo">
          <button type="button" onClick={zoomIn} title="Aproximar">
            <ZoomIn size={16} />
          </button>
          <button type="button" onClick={zoomOut} title="Afastar">
            <ZoomOut size={16} />
          </button>
          <button type="button" onClick={fit} title="Ajustar na tela">
            <Maximize2 size={16} />
          </button>
        </div>
      )}
    </div>
  );
}

function canonicalGraphToGraphology(canonicalGraph: CanonicalGraph): GraphModel {
  const model = new MultiDirectedGraph<GraphologyNodeAttributes, GraphologyEdgeAttributes>();
  const edgeIds = new Set<string>();

  for (const node of canonicalGraph.nodes) {
    model.addNode(node.id, {
      label: node.label,
      shortLabel: node.shortLabel,
      nodeType: node.type,
      degree: Number(node.attributes.degree ?? 0),
      size: node.size,
      color: node.color,
      x: node.x,
      y: node.y,
      value: node.attributes.value,
      severity: node.attributes.severity,
      source: node.attributes.source,
      description: node.attributes.description,
      firstSeen: node.attributes.first_seen,
      lastSeen: node.attributes.last_seen,
      metadata: node.attributes.metadata,
    });
  }

  canonicalGraph.edges.forEach((edge, index) => {
    const edgeId = edgeIds.has(edge.id) ? `${edge.id}:${index}` : edge.id;
    edgeIds.add(edgeId);

    model.addDirectedEdgeWithKey(edgeId, edge.source, edge.target, {
      label: edge.label,
      relation: edge.type,
      weight: edge.weight,
      size: edge.size,
      color: edge.color,
      type: 'arrow',
      alertId: edge.attributes.alert_id,
      firstSeen: edge.attributes.first_seen,
      lastSeen: edge.attributes.last_seen,
      metadata: edge.attributes.metadata,
    });
  });

  return model;
}

function collectFocusState(model: GraphModel, nodeId: string | null): FocusState {
  if (!nodeId || !model.hasNode(nodeId)) return DEFAULT_FOCUS;

  const nodeIds = new Set<string>([nodeId]);
  const edgeIds = new Set<string>();

  model.forEachEdge(nodeId, (edge, _attributes, source, target) => {
    edgeIds.add(edge);
    nodeIds.add(source);
    nodeIds.add(target);
  });

  return {
    nodeId,
    nodeIds,
    edgeIds,
  };
}

function createNodeReducer({
  renderer,
  totalNodes,
  selectedNodeId,
  focusState,
}: {
  renderer: GraphRenderer;
  totalNodes: number;
  selectedNodeId: string | null;
  focusState: FocusState;
}) {
  return (nodeId: string, data: GraphologyNodeAttributes): Partial<NodeDisplayData> => {
    const isSelected = selectedNodeId === nodeId;
    const isFocusRoot = focusState.nodeId === nodeId;
    const isInFocus = focusState.nodeIds.has(nodeId);
    const ratio = renderer.getCamera().getState().ratio;
    const label = visibleNodeLabel(data, totalNodes, ratio);
    const position = { x: data.x, y: data.y };
    const size = displayNodeSize(data.size, totalNodes, ratio);

    if (focusState.nodeId && !isInFocus) {
      return {
        ...position,
        color: '#e0e5ed',
        label: null,
        size: Math.max(size * 0.45, 1.8),
        zIndex: 0,
      };
    }

    if (isSelected || isFocusRoot) {
      return {
        ...position,
        color: data.color,
        forceLabel: true,
        highlighted: true,
        label: data.label,
        size: size * 1.28,
        zIndex: 4,
      };
    }

    if (focusState.nodeId && isInFocus) {
      return {
        ...position,
        color: data.color,
        forceLabel: ratio < 1.2,
        label: ratio < 1.2 ? data.shortLabel : null,
        size: size * 1.08,
        zIndex: 3,
      };
    }

    return {
      ...position,
      color: data.color,
      label,
      size,
      zIndex: 1,
    };
  };
}

function createEdgeReducer({
  focusState,
  selectedNodeId,
}: {
  focusState: FocusState;
  selectedNodeId: string | null;
}) {
  return (edgeId: string, data: GraphologyEdgeAttributes): Partial<EdgeDisplayData> => {
    if (focusState.nodeId && !focusState.edgeIds.has(edgeId)) {
      return {
        color: '#e3e7ef',
        label: null,
        size: Math.max(data.size * 0.28, 0.2),
        zIndex: 0,
      };
    }

    const isFocused = focusState.edgeIds.has(edgeId);
    return {
      color: data.color,
      forceLabel: isFocused && !!selectedNodeId,
      label: isFocused && !!selectedNodeId ? data.label : null,
      size: isFocused ? data.size * 2.1 : data.size,
      zIndex: isFocused ? 2 : 1,
    };
  };
}

function displayNodeSize(size: number, totalNodes: number, cameraRatio: number): number {
  const densityScale = totalNodes > 2000 ? 0.58 : totalNodes > 900 ? 0.68 : totalNodes > 300 ? 0.82 : 1;
  const zoomScale = cameraRatio > 1.8 ? 0.74 : cameraRatio < 0.55 ? 1.05 : 1;
  return Math.max(1.9, size * densityScale * zoomScale);
}

function visibleNodeLabel(
  data: GraphologyNodeAttributes,
  totalNodes: number,
  cameraRatio: number,
): string | null {
  const isImportant = data.severity === 'critical' || data.severity === 'high' || data.degree > 10;

  if (cameraRatio > 1.9) return null;
  if (totalNodes > 2500) return cameraRatio < 0.42 && isImportant ? data.shortLabel : null;
  if (totalNodes > 1000) return cameraRatio < 0.58 && isImportant ? data.shortLabel : null;
  if (totalNodes > 300) return cameraRatio < 0.9 && isImportant ? data.shortLabel : null;
  return data.shortLabel;
}

function zoomToNodeContext(renderer: GraphRenderer, nodeId: string) {
  const model = renderer.getGraph();
  if (!model.hasNode(nodeId)) return;

  const attributes = model.getNodeAttributes(nodeId);
  const camera = renderer.getCamera();
  const nextRatio = Math.max(camera.getState().ratio * 0.72, 0.08);

  camera.animate(
    {
      x: attributes.x,
      y: attributes.y,
      ratio: nextRatio,
    },
    {
      duration: 220,
    },
  );
}

function topologyKey(graph: CanonicalGraph): string {
  return [
    graph.nodes.map((node) => node.id).join(','),
    graph.edges.map((edge) => edge.id).join(','),
  ].join('|');
}
