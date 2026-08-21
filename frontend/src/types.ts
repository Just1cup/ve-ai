export interface GraphNode {
  id: string;
  node_type: string;
  value: string;
  label: string;
  severity: string | null;
  source: string | null;
  description: string | null;
  first_seen: string;
  last_seen: string;
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source_node_id: string;
  target_node_id: string;
  relation: string;
  alert_id: string | null;
  first_seen: string;
  last_seen: string;
  metadata: Record<string, unknown>;
}

export interface Alert {
  id: string;
  node_id: string;
  external_id: string;
  title: string;
  severity: string | null;
  source: string;
  description: string | null;
  first_seen: string;
  last_seen: string;
  raw: Record<string, unknown>;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  alerts: Alert[];
  generated_at: string;
}

export interface IocDetails {
  node: GraphNode;
  alerts: Alert[];
  edges: GraphEdge[];
}

export interface ExplorerCategory {
  node_type: string;
  total: number;
}

export interface ExplorerEntityRow extends GraphNode {
  alert_count: number;
  relationship_count: number;
  observation_count: number;
}

export interface ExplorerEntityPage {
  items: ExplorerEntityRow[];
  total: number;
  limit: number;
  offset: number;
}

export interface ExplorerEntityDetails {
  node: GraphNode;
  alerts: Alert[];
  edges: GraphEdge[];
  related_nodes: GraphNode[];
}

export interface TimeRangeParams {
  from?: string | null;
  to?: string | null;
}

export interface SocketMessage {
  type: 'graph_snapshot' | 'graph_updated';
  graph?: GraphResponse;
  revision?: string;
}

export type GraphLayer =
  | 'ips'
  | 'domains'
  | 'hashes'
  | 'emails'
  | 'cves'
  | 'urls'
  | 'files'
  | 'malware'
  | 'commands'
  | 'alerts'
  | 'mitre'
  | 'asns'
  | 'countries'
  | 'sources';
