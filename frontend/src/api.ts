import type {
  ExplorerCategory,
  ExplorerEntityDetails,
  ExplorerEntityPage,
  GraphLayer,
  GraphResponse,
  IocDetails,
  TimeRangeParams,
} from './types';

const apiBase = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '');

export async function fetchGraph(): Promise<GraphResponse> {
  const response = await fetch(`${apiBase}/api/graph`, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`Graph request failed: ${response.status}`);
  }
  return response.json();
}

export type GraphLayerFetchResult =
  | { status: 'not-modified'; etag: string | null }
  | { status: 'updated'; graph: GraphResponse; etag: string | null };

export async function fetchGraphLayer(
  layer: GraphLayer,
  etag?: string | null,
  timeRange: TimeRangeParams = {},
): Promise<GraphLayerFetchResult> {
  const headers: HeadersInit = { accept: 'application/json' };
  if (etag) headers['If-None-Match'] = etag;
  const query = timeRangeQuery(timeRange);
  const suffix = query ? `?${query}` : '';

  const response = await fetch(`${apiBase}/api/graph/${layer}${suffix}`, { headers });
  const nextEtag = response.headers.get('etag');

  if (response.status === 304) {
    return { status: 'not-modified', etag: nextEtag || etag || null };
  }

  if (!response.ok) {
    throw new Error(`Graph layer request failed: ${response.status}`);
  }

  return {
    status: 'updated',
    graph: await response.json(),
    etag: nextEtag,
  };
}

export async function fetchIocDetails(id: string): Promise<IocDetails> {
  const response = await fetch(`${apiBase}/api/graph/ioc/${id}`, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`IOC details request failed: ${response.status}`);
  }
  return response.json();
}

export interface ExplorerEntityParams {
  type?: string | null;
  search?: string;
  severity?: string;
  source?: string;
  from?: string | null;
  to?: string | null;
  limit?: number;
  offset?: number;
  sort?: string;
  direction?: 'asc' | 'desc';
}

export async function fetchExplorerCategories(
  params: TimeRangeParams = {},
): Promise<ExplorerCategory[]> {
  const query = timeRangeQuery(params);
  const suffix = query ? `?${query}` : '';

  const response = await fetch(`${apiBase}/api/explorer/categories${suffix}`, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`Explorer categories request failed: ${response.status}`);
  }
  return response.json();
}

export async function fetchExplorerEntities(
  params: ExplorerEntityParams,
): Promise<ExplorerEntityPage> {
  const query = new URLSearchParams();
  appendParam(query, 'type', params.type);
  appendParam(query, 'search', params.search);
  appendParam(query, 'severity', params.severity);
  appendParam(query, 'source', params.source);
  appendParam(query, 'from', params.from);
  appendParam(query, 'to', params.to);
  appendParam(query, 'limit', params.limit);
  appendParam(query, 'offset', params.offset);
  appendParam(query, 'sort', params.sort);
  appendParam(query, 'direction', params.direction);

  const response = await fetch(`${apiBase}/api/explorer/entities?${query.toString()}`, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`Explorer entities request failed: ${response.status}`);
  }
  return response.json();
}

export async function fetchExplorerEntity(id: string): Promise<ExplorerEntityDetails> {
  const response = await fetch(`${apiBase}/api/explorer/entities/${id}`, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`Explorer entity request failed: ${response.status}`);
  }
  return response.json();
}

export function websocketUrl(): string {
  const explicit = import.meta.env.VITE_WS_URL;
  if (explicit) return explicit;

  if (apiBase.startsWith('http://') || apiBase.startsWith('https://')) {
    const url = new URL(apiBase);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    url.pathname = '/api/ws';
    return url.toString();
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/api/ws`;
}

function appendParam(query: URLSearchParams, key: string, value: unknown) {
  if (value === null || value === undefined || value === '') return;
  query.set(key, String(value));
}

function timeRangeQuery(params: TimeRangeParams): string {
  const query = new URLSearchParams();
  appendParam(query, 'from', params.from);
  appendParam(query, 'to', params.to);
  return query.toString();
}
