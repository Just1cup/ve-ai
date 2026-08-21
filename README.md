# VÊ AÍ!

Visualização, correlação e investigação de indicadores de comprometimento em um grafo interativo.

O **VÊ AÍ!** nasceu como uma alternativa pessoal, menor e mais direta ao MISP para um fluxo específico de inteligência de ameaças. A aplicação transforma registros de IOC já produzidos por um dashboard em entidades relacionadas, persiste o histórico no PostgreSQL e oferece duas formas complementares de investigação: um grafo visual e um explorador tabular.

> O projeto não pretende implementar toda a superfície do MISP. Ele prioriza ingestão local, correlação, navegação visual e consulta operacional para um ambiente pessoal controlado.

## Por que o projeto existe

O MISP é uma plataforma completa de compartilhamento e gestão de threat intelligence, mas pode ser maior e mais complexa do que o necessário para um laboratório ou fluxo pessoal. O VÊ AÍ! concentra-se em um conjunto menor de necessidades:

- importar automaticamente os IOCs já coletados pelo projeto de dashboard;
- normalizar tipos e valores inconsistentes;
- deduplicar indicadores sem perder as observações de origem;
- construir relações úteis entre IOCs, alertas e contexto;
- navegar grandes conjuntos de entidades sem depender apenas de tabelas;
- acompanhar alterações da fonte em tempo real;
- manter uma base consultável para investigações posteriores.

## Funcionalidades

### Ingestão e correlação

- Leitura dos shards JSON ativos do dashboard montado em modo somente leitura.
- Suporte ao manifesto atômico `data/iocs-manifest.json` e compatibilidade com arquivos JSON legados.
- Normalização e deduplicação por `node_type + value`.
- IDs determinísticos para manter a identidade das entidades entre reprocessamentos.
- Persistência de arquivos ingeridos e observações de origem.
- Correlação entre IOCs, alertas, fontes e contexto técnico.
- Relações para IPs, domínios, URLs, hashes, e-mails, CVEs, arquivos, malware, comandos, técnicas MITRE, ASNs, países e fontes.
- Reprocessamento automático quando arquivos são criados, alterados ou removidos.

### Grafo de investigação

- Visualização interativa com Sigma.js e Graphology.
- Camadas carregadas por tipo de entidade.
- Busca textual e filtros por intervalo de tempo.
- Ativação seletiva de tipos de nós.
- Destaque do nó selecionado e de suas relações imediatas.
- Zoom, afastamento e ajuste automático do enquadramento.
- Painel de detalhes com alertas e relacionamentos da entidade.
- Atualizações sinalizadas pelo backend através de WebSocket.
- Cache HTTP por `ETag` para evitar transferências desnecessárias.
- Cache local do frontend e restauração do estado da visualização.

### Explorer

- Navegação por categorias e contagem de entidades.
- Busca, paginação, ordenação e filtros por severidade, fonte e período.
- Histórico de navegação entre entidades relacionadas.
- Visão detalhada com alertas, relações e observações associadas.

## Arquitetura

```text
Dashboard / shards JSON (somente leitura)
                  │
                  ▼
       watcher + parser em Rust
                  │
        normalização e correlação
                  │
                  ▼
             PostgreSQL
                  │
          API REST + WebSocket
                  │
                  ▼
      React + Sigma.js + Graphology
          Grafo          Explorer
```

### Backend

- Rust 2021
- Axum
- Tokio
- SQLx
- PostgreSQL
- `notify` para monitoramento dos arquivos
- Serde para parsing e serialização
- WebSocket para avisos de atualização

### Frontend

- React 19
- TypeScript
- Vite
- Sigma.js
- Graphology
- Lucide React
- Nginx no container de produção

## Estrutura do repositório

```text
.
├── backend/
│   ├── migrations/       # schema e índices PostgreSQL
│   ├── src/              # API, ingestão, banco e watcher
│   ├── tests/            # testes unitários e de integração
│   └── benches/          # benchmarks Criterion
├── frontend/
│   ├── nginx/            # proxy e servidor do build
│   └── src/              # grafo, explorer, API e cache
├── docker-compose.yml
└── README.md
```

## Requisitos

Para a execução recomendada:

- Docker;
- Docker Compose;
- o diretório irmão `../dashboard` contendo os dados JSON esperados.

Para desenvolvimento sem os containers da aplicação:

- Rust e Cargo;
- Node.js 22+ e npm;
- PostgreSQL 16+.

## Executando com Docker Compose

O Compose espera esta estrutura:

```text
programacao/
├── dashboard/
└── grafo/
```

Na raiz do projeto:

```bash
docker compose up --build
```

Abra:

```text
http://localhost:8088
```

Serviços iniciados:

| Serviço | Porta | Função |
|---|---:|---|
| `frontend` | `8088` | interface React servida pelo Nginx |
| `backend` | `3000` | API REST e WebSocket |
| `db` | interna | PostgreSQL 16 |

O volume `../dashboard:/dashboard:ro` impede que o backend modifique a fonte dos dados.

## Desenvolvimento local

### Backend

Com um PostgreSQL disponível:

```bash
cd backend
DATABASE_URL=postgres://ioc_graph:ioc_graph@localhost:5432/ioc_graph \
DASHBOARD_PATH=../../dashboard \
cargo run
```

Variáveis suportadas:

| Variável | Padrão | Descrição |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:3000` | endereço da API |
| `DATABASE_URL` | `postgres://ioc_graph:ioc_graph@localhost:5432/ioc_graph` | conexão PostgreSQL |
| `DASHBOARD_PATH` | `../dashboard` | diretório de entrada dos JSONs |
| `RUST_LOG` | definido pelo ambiente | filtro de logs |

### Frontend

```bash
cd frontend
npm ci
npm run dev
```

O Vite encaminha `/api` para `http://localhost:3000` durante o desenvolvimento.

## API

| Método | Endpoint | Finalidade |
|---|---|---|
| `GET` | `/api/health` | saúde da aplicação e do banco |
| `GET` | `/api/iocs` | listagem de IOCs |
| `GET` | `/api/iocs/{id}` | detalhes de um IOC |
| `GET` | `/api/alerts` | alertas, opcionalmente por IOC |
| `GET` | `/api/graph` | snapshot agregado do grafo |
| `GET` | `/api/graph/{layer}` | camada do grafo com suporte a `ETag` |
| `GET` | `/api/explorer/categories` | categorias e totais do Explorer |
| `GET` | `/api/explorer/entities` | entidades paginadas e filtradas |
| `GET` | `/api/explorer/entities/{id}` | detalhes e relações de uma entidade |
| `GET` | `/api/ws` | canal WebSocket de atualização |

Os endpoints de grafo e Explorer aceitam filtros conforme a rota, incluindo busca, tipos, severidade, fonte, paginação e intervalo temporal.

## Testes

### Suite padrão do backend

```bash
cd backend
cargo test
```

A suite padrão usa dados sintéticos e cobre parsing, construção do grafo, correlação, fingerprints, contratos HTTP, broadcast WebSocket e guardas de regressão.

### Testes com PostgreSQL real

Os testes baseados em Testcontainers são ignorados por padrão:

```bash
cd backend
cargo test --test database -- --ignored
cargo test --test api database_backed_endpoints_return_200_with_seeded_graph -- --ignored
```

### Frontend

```bash
cd frontend
npm ci
npm run build
```

### Benchmarks

```bash
cd backend
cargo bench
```

Há benchmarks para construção do grafo, parsing, correlação, WebSocket, memória, layout e busca. Consulte [`backend/tests/README.md`](backend/tests/README.md) para a documentação completa da estratégia de testes e regressão de desempenho.

## Modelo de dados resumido

- **GraphNode:** entidade normalizada, com tipo, valor, severidade, origem, período e metadados.
- **GraphEdge:** relação direcionada entre duas entidades.
- **Alert:** evento que conecta uma observação ao contexto operacional.
- **SourceObservation:** registro bruto e rastreável da fonte ingerida.
- **IngestedFile:** controle de arquivo, fingerprint e tamanho da entrada processada.

## Segurança e limites atuais

- O Compose usa credenciais locais previsíveis para facilitar o desenvolvimento. Troque-as antes de qualquer implantação compartilhada.
- A API atualmente não implementa autenticação ou autorização.
- O CORS permite origens amplas para desenvolvimento e deve ser restringido em produção.
- O projeto foi desenhado para uma fonte local confiável montada como somente leitura.
- Não exponha as portas do banco ou da API diretamente à internet sem proxy, TLS, autenticação e regras de rede.
- O VÊ AÍ! não implementa, neste momento, federação, taxonomias completas, sharing groups, feeds, sincronização entre organizações ou o ecossistema integral do MISP.

## Estado do projeto

O VÊ AÍ! é um projeto pessoal em desenvolvimento ativo. A base atual já cobre ingestão, persistência, correlação, atualização em tempo real, grafo, Explorer, testes e benchmarks. Evoluções futuras devem permanecer orientadas pelas necessidades reais do fluxo pessoal, evitando reproduzir complexidade do MISP que não seja necessária.

## Licença

Nenhuma licença de redistribuição foi definida ainda. Até que um arquivo de licença seja adicionado, permanecem reservados os direitos autorais do autor.
