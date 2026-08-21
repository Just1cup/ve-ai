import { nodeTypeColor } from './graphTheme';
import type { GraphEdge, GraphNode, GraphResponse } from './types';

export interface CanonicalGraphNode {
  id: string;
  label: string;
  shortLabel: string;
  type: string;
  size: number;
  color: string;
  x: number;
  y: number;
  attributes: Record<string, unknown>;
}

export interface CanonicalGraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  weight: number;
  size: number;
  color: string;
  attributes: Record<string, unknown>;
}

export interface CanonicalGraph {
  nodes: CanonicalGraphNode[];
  edges: CanonicalGraphEdge[];
}

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

export function graphResponseToCanonicalGraph(graph: GraphResponse): CanonicalGraph {
  const degreeByNode = nodeDegrees(graph);
  const positions = graphLayoutPositions(graph, degreeByNode);
  const canonicalNodes = graph.nodes.map((node) => {
    const position = positions.get(node.id) ?? { x: 0, y: 0 };
    const label = node.label || node.value;
    const degree = degreeByNode.get(node.id) ?? 0;

    return {
      id: node.id,
      label,
      shortLabel: compactNodeLabel(label, node.node_type),
      type: node.node_type,
      size: nodeSize(node, degree),
      color: nodeTypeColor(node.node_type),
      x: position.x,
      y: position.y,
      attributes: {
        degree,
        value: node.value,
        severity: node.severity,
        source: node.source,
        description: node.description,
        first_seen: node.first_seen,
        last_seen: node.last_seen,
        metadata: node.metadata,
      },
    };
  });

  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const alertsById = new Map(graph.alerts.map((alert) => [alert.id, alert]));
  const canonicalEdges = graph.edges
    .filter((edge) => nodesById.has(edge.source_node_id) && nodesById.has(edge.target_node_id))
    .map((edge) => {
      const sourceNode = nodesById.get(edge.source_node_id);
      const weight = edgeWeight(edge.metadata?.count);
      return {
        id: edge.id,
        source: edge.source_node_id,
        target: edge.target_node_id,
        type: edge.relation,
        label: edgeLabel(edge, edge.alert_id ? alertsById.get(edge.alert_id)?.title : undefined),
        weight,
        size: Math.min(0.28 + Math.log1p(weight) * 0.18, 1.35),
        color: edgeColor(edge.relation, sourceNode?.node_type),
        attributes: {
          alert_id: edge.alert_id,
          first_seen: edge.first_seen,
          last_seen: edge.last_seen,
          metadata: edge.metadata,
        },
      };
    });

  return {
    nodes: canonicalNodes,
    edges: canonicalEdges,
  };
}

function nodeDegrees(graph: GraphResponse): Map<string, number> {
  const degrees = new Map<string, number>();
  for (const edge of graph.edges) {
    degrees.set(edge.source_node_id, (degrees.get(edge.source_node_id) ?? 0) + 1);
    degrees.set(edge.target_node_id, (degrees.get(edge.target_node_id) ?? 0) + 1);
  }
  return degrees;
}

function graphLayoutPositions(
  graph: GraphResponse,
  degreeByNode: Map<string, number>,
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const neighborsByNode = new Map<string, string[]>();

  for (const edge of graph.edges) {
    if (!nodesById.has(edge.source_node_id) || !nodesById.has(edge.target_node_id)) continue;
    pushNeighbor(neighborsByNode, edge.source_node_id, edge.target_node_id);
    pushNeighbor(neighborsByNode, edge.target_node_id, edge.source_node_id);
  }

  const anchors = graph.nodes
    .filter((node) => node.node_type === 'Alert')
    .sort((a, b) => compareNodesForLayout(a, b, degreeByNode));
  const fallbackAnchors = graph.nodes
    .filter((node) => node.node_type !== 'Alert')
    .sort((a, b) => compareNodesForLayout(a, b, degreeByNode))
    .slice(0, Math.max(8, Math.min(48, Math.ceil(Math.sqrt(graph.nodes.length)))));
  const layoutAnchors = anchors.length ? anchors : fallbackAnchors;
  const anchorIds = new Set(layoutAnchors.map((node) => node.id));
  const anchorSpacing = layoutAnchors.length > 500 ? 14 : layoutAnchors.length > 160 ? 20 : 30;

  layoutAnchors.forEach((node, index) => {
    positions.set(node.id, compactSpiral(index, anchorSpacing));
  });

  const buckets = new Map<string, GraphNode[]>();
  const orphans: GraphNode[] = [];

  for (const node of graph.nodes) {
    if (anchorIds.has(node.id)) continue;

    const anchorId = primaryAnchor(node, neighborsByNode, nodesById, anchorIds, degreeByNode);
    if (!anchorId) {
      orphans.push(node);
      continue;
    }

    const bucket = buckets.get(anchorId);
    if (bucket) bucket.push(node);
    else buckets.set(anchorId, [node]);
  }

  for (const [anchorId, bucket] of buckets) {
    const anchor = positions.get(anchorId);
    if (!anchor) continue;

    bucket.sort((a, b) => compareNodesForLayout(a, b, degreeByNode));
    const spacing = bucket.length > 240 ? 8 : bucket.length > 80 ? 11 : 16;

    bucket.forEach((node, index) => {
      const local = localSpiral(index, spacing, typeDistance(node.node_type));
      positions.set(node.id, {
        x: anchor.x + local.x,
        y: anchor.y + local.y,
      });
    });
  }

  const orphanBase = Math.max(220, Math.sqrt(graph.nodes.length) * 24);
  orphans
    .sort((a, b) => compareNodesForLayout(a, b, degreeByNode))
    .forEach((node, index) => {
      const position = compactSpiral(index, 24);
      const angle = hashRatio(node.id) * Math.PI * 2;
      positions.set(node.id, {
        x: position.x + Math.cos(angle) * orphanBase,
        y: position.y + Math.sin(angle) * orphanBase,
      });
    });

  return positions;
}

function pushNeighbor(neighborsByNode: Map<string, string[]>, nodeId: string, neighborId: string) {
  const neighbors = neighborsByNode.get(nodeId);
  if (neighbors) neighbors.push(neighborId);
  else neighborsByNode.set(nodeId, [neighborId]);
}

function primaryAnchor(
  node: GraphNode,
  neighborsByNode: Map<string, string[]>,
  nodesById: Map<string, GraphNode>,
  anchorIds: Set<string>,
  degreeByNode: Map<string, number>,
): string | null {
  let bestAnchor: string | null = null;
  let bestScore = -1;

  for (const neighborId of neighborsByNode.get(node.id) ?? []) {
    if (!anchorIds.has(neighborId)) continue;
    const neighbor = nodesById.get(neighborId);
    const score = severityScore(neighbor?.severity ?? null) * 1000 + (degreeByNode.get(neighborId) ?? 0);
    if (score > bestScore) {
      bestScore = score;
      bestAnchor = neighborId;
    }
  }

  return bestAnchor;
}

function compactSpiral(index: number, spacing: number): { x: number; y: number } {
  if (index === 0) return { x: 0, y: 0 };
  const radius = Math.sqrt(index) * spacing;
  const angle = index * GOLDEN_ANGLE;

  return {
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius,
  };
}

function localSpiral(index: number, spacing: number, baseRadius: number): { x: number; y: number } {
  const radius = baseRadius + Math.sqrt(index + 1) * spacing;
  const angle = index * GOLDEN_ANGLE;

  return {
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius,
  };
}

function compareNodesForLayout(
  first: GraphNode,
  second: GraphNode,
  degreeByNode: Map<string, number>,
): number {
  return (
    severityScore(second.severity) - severityScore(first.severity) ||
    (degreeByNode.get(second.id) ?? 0) - (degreeByNode.get(first.id) ?? 0) ||
    first.node_type.localeCompare(second.node_type) ||
    first.id.localeCompare(second.id)
  );
}

function typeDistance(type: string): number {
  const distances: Record<string, number> = {
    IP: 48,
    Domain: 58,
    URL: 68,
    Hash: 74,
    Email: 76,
    CVE: 78,
    File: 80,
    Command: 86,
    Malware: 54,
    'MITRE Technique': 92,
    ASN: 102,
    Country: 112,
    Source: 122,
  };

  return distances[type] ?? 72;
}

function nodeSize(node: GraphNode, degree: number): number {
  const severitySize: Record<string, number> = {
    critical: 7.2,
    high: 6.2,
    medium: 5.2,
    low: 4.2,
  };

  const typeBonus = node.node_type === 'Alert' ? 0.9 : node.node_type === 'IP' ? 0.4 : 0;
  const base = node.severity ? (severitySize[node.severity] ?? 4.8) : 4.2;
  return Math.min(base + typeBonus + Math.log1p(degree) * 0.55, 9.5);
}

function severityScore(severity: string | null): number {
  const scores: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };

  return severity ? (scores[severity] ?? 0) : 0;
}

export function edgeWeight(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? Math.min(Math.max(value, 1), 20) : 1;
}

function edgeColor(relation: string, sourceType?: string): string {
  if (relation === 'related_to') return '#c1c7d2';
  if (relation === 'seen_in') return '#9aa4b5';
  if (sourceType === 'IP') return '#6f8fe8';
  if (sourceType === 'Alert') return '#d59a76';
  if (sourceType === 'Domain' || sourceType === 'URL') return '#6aaea7';
  return '#9aa4b5';
}

export function edgeLabel(edge: GraphEdge, alertTitle?: string): string {
  const labels: Record<string, string> = {
    resolves_to: 'resolve para',
    hosts: 'hospeda',
    detected_as: 'detectado como',
    seen_in: 'visto em',
    related_to: 'mesmo alerta/contexto',
    belongs_to: 'pertence a',
    mapped_to: 'mapeado para',
    contacted: 'contatou',
    downloaded_from: 'baixado de',
  };

  if (edge.relation === 'related_to') {
    return alertTitle ? `mesmo alerta: ${compactLabel(alertTitle)}` : 'mesmo contexto';
  }

  const label = labels[edge.relation] || edge.relation;
  const count = edgeWeight(edge.metadata?.count);
  return count > 1 ? `${label} (${count}x)` : label;
}

function compactLabel(value: string): string {
  return value.length > 28 ? `${value.slice(0, 25)}...` : value;
}

function compactNodeLabel(value: string, type: string): string {
  const limit = type === 'Hash' ? 14 : type === 'Alert' ? 24 : 30;
  return value.length > limit ? `${value.slice(0, limit - 3)}...` : value;
}

function hashRatio(value: string): number {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) / 4294967295;
}
