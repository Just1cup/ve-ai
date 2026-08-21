import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, AlertTriangle, GitFork, Info, Rows3, X } from 'lucide-react';
import { displaySource } from './sourceDisplay';
import type { Alert, GraphEdge, GraphNode, IocDetails } from './types';

interface DetailsPanelProps {
  node: GraphNode | null;
  details: IocDetails | null;
  nodesById: Map<string, GraphNode>;
  onSelectNode: (id: string | null) => void;
  onOpenExplorer?: (id: string) => void;
}

interface RelationGroup {
  relation: string;
  edges: GraphEdge[];
  peers: RelationPeer[];
}

interface RelationPeer {
  edge: GraphEdge;
  node: GraphNode | null;
  direction: 'outgoing' | 'incoming';
}

export default function DetailsPanel({
  node,
  details,
  nodesById,
  onSelectNode,
  onOpenExplorer,
}: DetailsPanelProps) {
  const [openAlert, setOpenAlert] = useState<Alert | null>(null);
  const [selectedRelation, setSelectedRelation] = useState<string | null>(null);

  const relationGroups = useMemo(() => {
    if (!node || !details?.edges.length) return [];
    return buildRelationGroups(details.edges, node.id, nodesById);
  }, [details?.edges, node?.id, nodesById]);

  const alertsById = useMemo(() => {
    return new Map((details?.alerts || []).map((alert) => [alert.id, alert]));
  }, [details?.alerts]);

  const selectedGroup = relationGroups.find((group) => group.relation === selectedRelation) || null;

  useEffect(() => {
    setSelectedRelation(null);
    setOpenAlert(null);
  }, [node?.id]);

  if (!node) {
    return (
      <aside className="details-panel empty">
        <Info size={18} />
        <p>Selecione um no para ver detalhes, alertas e relacoes.</p>
      </aside>
    );
  }

  return (
    <aside className="details-panel">
      <div className="details-heading">
        <span className={`type-badge ${badgeClass(node.node_type)}`}>{node.node_type}</span>
        {node.severity && <span className={`severity-pill ${node.severity}`}>{node.severity}</span>}
        {onOpenExplorer && (
          <button
            type="button"
            className="details-action"
            onClick={() => onOpenExplorer(node.id)}
            title="Abrir no Explorer"
          >
            <Rows3 size={15} />
            <span>Abrir no Explorer</span>
          </button>
        )}
      </div>

      <h2>{node.label || node.value}</h2>
      <p className="node-value">{node.value}</p>

      <div className="detail-grid">
        <Detail label="Primeira observacao" value={formatDate(node.first_seen)} />
        <Detail label="Ultima observacao" value={formatDate(node.last_seen)} />
        <Detail label="Fonte" value={displaySource(node.source, node.metadata)} />
      </div>

      {node.description && <p className="description">{node.description}</p>}

      <section className="panel-section">
        <h3>
          <AlertTriangle size={16} />
          Alertas
        </h3>
        {details?.alerts.length ? (
          <div className="alert-list">
            {details.alerts.map((alert) => (
              <button
                type="button"
                className="alert-item"
                key={alert.id}
                onClick={() => setOpenAlert(alert)}
              >
                <div className="alert-title">
                  <span>{alert.title}</span>
                  {alert.severity && <span className={`severity-dot ${alert.severity}`} />}
                </div>
                <p>{displaySource(alert.source, alert.raw)}</p>
                <time>{formatDate(alert.last_seen)}</time>
              </button>
            ))}
          </div>
        ) : (
          <p className="muted">Nenhum alerta relacionado carregado.</p>
        )}
      </section>

      <section className="panel-section">
        <h3>
          <GitFork size={16} />
          Relacoes
        </h3>
        {relationGroups.length ? (
          <>
            <div className="relation-list">
              {relationGroups.map((group) => (
                <button
                  type="button"
                  className={group.relation === selectedRelation ? 'active' : ''}
                  key={group.relation}
                  onClick={() =>
                    setSelectedRelation((current) =>
                      current === group.relation ? null : group.relation,
                    )
                  }
                  title={relationSummary(group)}
                >
                  <span>{group.relation}</span>
                  <strong>{group.edges.length}</strong>
                </button>
              ))}
            </div>
            {selectedGroup && (
              <div className="relation-detail">
                <h4>{relationSummary(selectedGroup)}</h4>
                <div className="relation-peer-list">
                  {selectedGroup.peers.map((peer) => {
                    const context = relationContext(peer.edge, alertsById);
                    return (
                      <button
                        type="button"
                        key={peer.edge.id}
                        onClick={() => peer.node && onSelectNode(peer.node.id)}
                        disabled={!peer.node}
                      >
                        <span>{relationPhrase(selectedGroup.relation, peer.direction)}</span>
                        <strong>{peer.node?.label || peer.node?.value || shortId(peer.edge.id)}</strong>
                        {peer.node && <em>{peer.node.node_type}</em>}
                        {context && <small>{context}</small>}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </>
        ) : (
          <p className="muted">Sem relacoes visiveis.</p>
        )}
      </section>

      <section className="panel-section">
        <h3>
          <Activity size={16} />
          Metadados
        </h3>
        <pre>{JSON.stringify(node.metadata || {}, null, 2)}</pre>
      </section>
      {openAlert && <AlertModal alert={openAlert} onClose={() => setOpenAlert(null)} />}
    </aside>
  );
}

function AlertModal({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    closeButtonRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  return (
    <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className="alert-modal" role="dialog" aria-modal="true" aria-labelledby="alert-modal-title">
        <header>
          <div>
            <span className="modal-kicker">Alerta</span>
            <h2 id="alert-modal-title">{alert.title}</h2>
          </div>
          <button ref={closeButtonRef} type="button" onClick={onClose} title="Fechar" aria-label="Fechar detalhes do alerta">
            <X size={16} />
          </button>
        </header>
        <div className="modal-grid">
          <Detail label="Fonte" value={displaySource(alert.source, alert.raw)} />
          <Detail label="External ID" value={alert.external_id} />
          <Detail label="Primeira observacao" value={formatDate(alert.first_seen)} />
          <Detail label="Ultima observacao" value={formatDate(alert.last_seen)} />
          <Detail label="Severidade" value={alert.severity || '-'} />
        </div>
        {alert.description && <p className="description">{alert.description}</p>}
        <pre>{JSON.stringify(alert.raw || {}, null, 2)}</pre>
      </div>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'short',
    timeStyle: 'medium',
  }).format(new Date(value));
}

function badgeClass(type: string): string {
  return `badge-${type.replace(/\s+/g, '-')}`;
}

function buildRelationGroups(
  edges: GraphEdge[],
  nodeId: string,
  nodesById: Map<string, GraphNode>,
): RelationGroup[] {
  const groups = new Map<string, RelationGroup>();

  for (const edge of edges) {
    const direction = edge.source_node_id === nodeId ? 'outgoing' : 'incoming';
    const peerId = direction === 'outgoing' ? edge.target_node_id : edge.source_node_id;
    const group = groups.get(edge.relation) || {
      relation: edge.relation,
      edges: [],
      peers: [],
    };

    group.edges.push(edge);
    group.peers.push({
      edge,
      direction,
      node: nodesById.get(peerId) || null,
    });
    groups.set(edge.relation, group);
  }

  return Array.from(groups.values()).sort((left, right) => left.relation.localeCompare(right.relation));
}

function relationSummary(group: RelationGroup): string {
  const sample = group.peers[0];
  if (!sample) return `${group.relation} (${group.edges.length})`;
  return `${relationPhrase(group.relation, sample.direction)} (${group.edges.length})`;
}

function relationPhrase(relation: string, direction: 'outgoing' | 'incoming'): string {
  const outgoing: Record<string, string> = {
    resolves_to: 'resolve para',
    hosts: 'hospeda',
    detected_as: 'detectado como',
    seen_in: 'visto em',
    related_to: 'compartilha contexto com',
    belongs_to: 'pertence a',
    mapped_to: 'mapeado para',
    contacted: 'contatou',
    downloaded_from: 'baixado de',
  };
  const incoming: Record<string, string> = {
    resolves_to: 'recebe resolucao de',
    hosts: 'hospedado em',
    detected_as: 'detecta',
    seen_in: 'contem evidencia de',
    related_to: 'compartilha contexto com',
    belongs_to: 'agrupa',
    mapped_to: 'mapeia',
    contacted: 'contatado por',
    downloaded_from: 'origem de download para',
  };
  return (direction === 'outgoing' ? outgoing : incoming)[relation] || relation;
}

function shortId(value: string): string {
  return value.slice(0, 8);
}

function relationContext(edge: GraphEdge, alertsById: Map<string, Alert>): string | null {
  if (edge.alert_id) {
    const alert = alertsById.get(edge.alert_id);
    return alert ? `Motivo: mesmo alerta - ${alert.title}` : `Motivo: mesmo alerta ${shortId(edge.alert_id)}`;
  }

  const count = typeof edge.metadata?.count === 'number' ? edge.metadata.count : 0;
  if (edge.relation === 'related_to') {
    return count > 1
      ? `Motivo: contexto compartilhado (${count} ocorrencias)`
      : 'Motivo: contexto compartilhado';
  }

  return count > 1 ? `${count} ocorrencias nesta relacao` : null;
}
