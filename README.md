# VÊ AÍ! — Threat Intelligence Graph

<p align="center">
  <strong>Visualização, correlação e investigação de Indicadores de Comprometimento em um grafo interativo.</strong>
</p>

<p align="center">
  Transforme IOCs isolados em relações investigáveis.
</p>

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-Backend-black?logo=rust">
  <img alt="React" src="https://img.shields.io/badge/React-Frontend-20232A?logo=react">
  <img alt="PostgreSQL" src="https://img.shields.io/badge/PostgreSQL-Database-336791?logo=postgresql">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker">
</p>

---

## Sobre o projeto

**VÊ AÍ!** é uma aplicação de Threat Intelligence criada para transformar indicadores dispersos em entidades relacionadas e navegáveis.

A ferramenta recebe IOCs provenientes de diferentes observações, normaliza os dados, remove duplicidades sem perder o contexto original e constrói relações entre indicadores como:

* endereços IP;
* domínios;
* URLs;
* hashes;
* arquivos;
* CVEs;
* malwares;
* técnicas MITRE ATT&CK;
* ASNs;
* países;
* fontes;
* alertas;
* comandos;
* e-mails.

O resultado é um ambiente voltado para **investigação**, permitindo sair de um indicador isolado e explorar rapidamente tudo que está relacionado a ele.

O projeto nasceu como uma alternativa pessoal, mais enxuta e direta ao MISP para um fluxo específico de inteligência de ameaças.

> O objetivo não é reproduzir toda a superfície do MISP, mas oferecer ingestão, correlação, visualização e investigação de IOCs de maneira simples e operacional.

---

# Interface

O fluxo de investigação pode acontecer tanto visualmente através do **Grafo** quanto de forma estruturada através do **Explorer**.

## 1. Grafo

O Grafo oferece uma visão visual das relações existentes entre os indicadores.

É possível identificar rapidamente conexões entre IPs, domínios, arquivos, hashes, alertas, técnicas MITRE e outras entidades, permitindo que uma investigação parta de um único IOC e avance pelas relações encontradas.

![Grafo de Threat Intelligence](./Screenshot%202026-08-21%20at%2015-22-39%20IOC%20Graph%20%C2%B7%20Threat%20Intelligence.png)

### Recursos do Grafo

* visualização interativa com Sigma.js e Graphology;
* carregamento seletivo por tipo de entidade;
* busca textual;
* filtros temporais;
* seleção de tipos de nós;
* destaque das relações de um IOC;
* zoom e enquadramento automático;
* painel de detalhes;
* atualização sinalizada via WebSocket;
* cache HTTP utilizando `ETag`;
* cache local do estado da visualização.

---

## 2. Explorer

Nem toda investigação precisa começar pelo grafo.

O **Explorer** oferece uma visualização estruturada dos indicadores armazenados, permitindo pesquisar e navegar pela base de Threat Intelligence de maneira semelhante a um catálogo investigativo.

![IOC Explorer](./Screenshot%202026-08-21%20at%2015-44-52%20IOC%20Graph%20%C2%B7%20Threat%20Intelligence.png)

### Recursos do Explorer

* navegação por categorias de IOC;
* busca textual;
* filtros por período;
* filtros por severidade;
* filtros por fonte;
* ordenação;
* paginação;
* contagem de entidades;
* navegação entre indicadores relacionados;
* acesso direto aos detalhes de cada entidade.

---

## 3. IOC Overview

Ao selecionar um indicador, o VÊ AÍ! abre uma visão investigativa dedicada à entidade.

O **IOC Overview** concentra as principais informações conhecidas sobre o indicador e permite entender rapidamente seu contexto antes de aprofundar a análise.

![IOC Overview](./Screenshot%202026-08-21%20at%2015-45-12%20IOC%20Graph%20%C2%B7%20Threat%20Intelligence.png)

A partir dessa visão é possível analisar informações como:

* tipo do indicador;
* valor;
* score;
* severidade;
* confidence;
* threat level;
* primeira ocorrência;
* última ocorrência;
* quantidade de observações;
* relacionamentos;
* fontes;
* alertas associados;
* contexto técnico.

O histórico de navegação também permite avançar entre entidades relacionadas sem perder o caminho percorrido durante a investigação.

---

## 4. IOC Eventos

Além do estado atual do indicador, também é possível analisar os **eventos e observações associados ao IOC**.

![IOC Eventos](./Screenshot%202026-08-21%20at%2015-45-45%20IOC%20Graph%20%C2%B7%20Threat%20Intelligence.png)

Essa visualização ajuda a responder perguntas como:

* Onde esse indicador apareceu?
* Quando foi observado?
* Quantas vezes foi identificado?
* Qual fonte originou a observação?
* Quais alertas estão relacionados?
* Existe recorrência ao longo do tempo?
* Existem outros IOCs ligados ao mesmo contexto?

Dessa forma, o VÊ AÍ! mantém não apenas o indicador normalizado, mas também sua **rastreabilidade investigativa**.

---

# Fluxo de investigação

```text
                    ┌──────────────┐
                    │     IOC      │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    Grafo     │
                    │  Relações    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   Explorer   │
                    │ Busca/Filtro │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ IOC Overview │
                    │   Contexto   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ IOC Eventos  │
                    │ Observações  │
                    └──────────────┘
```

O investigador pode entrar no fluxo por qualquer uma dessas interfaces.

Por exemplo, um IP identificado em um alerta pode ser localizado no Explorer, aberto no IOC Overview e posteriormente enviado ao Grafo para visualizar suas relações com outros indicadores.

---

# Como funciona

```text
Dashboard / JSON shards
        │
        ▼
┌─────────────────────┐
│       Watcher       │
│       + Parser      │
│        Rust         │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Normalização        │
│ Deduplicação        │
│ Correlação          │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│     PostgreSQL      │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ REST API            │
│ WebSocket           │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────────────┐
│ React + Sigma + Graphology  │
├──────────────┬──────────────┤
│    Grafo     │   Explorer   │
└──────────────┴──────────────┘
```

---

# Funcionalidades

## Ingestão

* leitura automática dos shards JSON;
* suporte ao manifesto atômico `data/iocs-manifest.json`;
* compatibilidade com arquivos JSON legados;
* monitoramento de criação, alteração e remoção de arquivos;
* reprocessamento automático;
* persistência da origem da observação.

## Normalização

Indicadores provenientes de fontes diferentes nem sempre seguem o mesmo formato.

O backend normaliza essas entidades antes de armazená-las e correlacioná-las.

A deduplicação utiliza:

```text
node_type + value
```

IDs determinísticos são utilizados para preservar a identidade das entidades durante novos processamentos.

## Correlação

O VÊ AÍ! constrói relacionamentos entre diferentes entidades observadas no mesmo contexto.

Exemplos:

```text
IP ─────────────► Domain
│
├───────────────► ASN
│
├───────────────► Country
│
└───────────────► Alert
                    │
                    ├────► Malware
                    ├────► MITRE Technique
                    └────► Source
```

Isso permite transformar registros independentes em uma estrutura investigável.

---

# Stack

## Backend

| Tecnologia | Utilização                 |
| ---------- | -------------------------- |
| Rust 2021  | Backend                    |
| Axum       | API HTTP                   |
| Tokio      | Runtime assíncrono         |
| SQLx       | Integração com PostgreSQL  |
| PostgreSQL | Persistência               |
| notify     | Monitoramento dos arquivos |
| Serde      | Parsing e serialização     |
| WebSocket  | Atualizações em tempo real |

## Frontend

| Tecnologia   | Utilização                          |
| ------------ | ----------------------------------- |
| React 19     | Interface                           |
| TypeScript   | Desenvolvimento frontend            |
| Vite         | Build e ambiente de desenvolvimento |
| Sigma.js     | Renderização do grafo               |
| Graphology   | Estrutura e manipulação do grafo    |
| Lucide React | Iconografia                         |
| Nginx        | Servidor frontend em produção       |

---

# Estrutura do projeto

```text
.
├── backend/
│   ├── migrations/
│   │   └── schema e índices PostgreSQL
│   │
│   ├── src/
│   │   └── API, ingestão, banco e watcher
│   │
│   ├── tests/
│   │   └── testes unitários e integração
│   │
│   └── benches/
│       └── benchmarks Criterion
│
├── frontend/
│   ├── nginx/
│   │   └── configuração do servidor
│   │
│   └── src/
│       └── grafo, Explorer, API e cache
│
├── docker-compose.yml
└── README.md
```

---

# Executando o projeto

## Requisitos

Para executar utilizando containers:

* Docker;
* Docker Compose;
* diretório irmão `../dashboard` contendo os JSONs esperados.

Estrutura esperada:

```text
programacao/
├── dashboard/
└── grafo/
```

Na raiz do projeto:

```bash
docker compose up --build
```

Depois acesse:

```text
http://localhost:8088
```

### Serviços

| Serviço    |   Porta | Função                         |
| ---------- | ------: | ------------------------------ |
| `frontend` |  `8088` | React servido através do Nginx |
| `backend`  |  `3000` | REST API + WebSocket           |
| `db`       | interna | PostgreSQL 16                  |

O dashboard é montado como:

```text
../dashboard:/dashboard:ro
```

O modo `ro` impede que a aplicação altere os arquivos da fonte.

---

# Desenvolvimento local

## Backend

Requer Rust, Cargo e um PostgreSQL disponível.

```bash
cd backend

DATABASE_URL=postgres://ioc_graph:ioc_graph@localhost:5432/ioc_graph \
DASHBOARD_PATH=../../dashboard \
cargo run
```

### Variáveis de ambiente

| Variável         | Padrão                                                    | Descrição           |
| ---------------- | --------------------------------------------------------- | ------------------- |
| `BIND_ADDR`      | `0.0.0.0:3000`                                            | endereço da API     |
| `DATABASE_URL`   | `postgres://ioc_graph:ioc_graph@localhost:5432/ioc_graph` | PostgreSQL          |
| `DASHBOARD_PATH` | `../dashboard`                                            | diretório dos JSONs |
| `RUST_LOG`       | ambiente                                                  | filtro de logs      |

## Frontend

Requer Node.js 22+ e npm.

```bash
cd frontend
npm ci
npm run dev
```

Durante o desenvolvimento, o Vite encaminha:

```text
/api → http://localhost:3000
```

---

# API

| Método | Endpoint                      | Finalidade                  |
| ------ | ----------------------------- | --------------------------- |
| `GET`  | `/api/health`                 | status da aplicação e banco |
| `GET`  | `/api/iocs`                   | lista de IOCs               |
| `GET`  | `/api/iocs/{id}`              | detalhes de um IOC          |
| `GET`  | `/api/alerts`                 | consulta de alertas         |
| `GET`  | `/api/graph`                  | snapshot do grafo           |
| `GET`  | `/api/graph/{layer}`          | camada específica do grafo  |
| `GET`  | `/api/explorer/categories`    | categorias disponíveis      |
| `GET`  | `/api/explorer/entities`      | entidades do Explorer       |
| `GET`  | `/api/explorer/entities/{id}` | detalhes de uma entidade    |
| `GET`  | `/api/ws`                     | WebSocket de atualizações   |

Os endpoints do Grafo e Explorer suportam filtros como:

* busca;
* tipo;
* severidade;
* fonte;
* paginação;
* intervalo temporal.

---

# Testes

## Backend

```bash
cd backend
cargo test
```

A suíte padrão cobre:

* parsing;
* construção do grafo;
* correlação;
* fingerprints;
* contratos HTTP;
* WebSocket;
* regressões.

### PostgreSQL real

```bash
cargo test --test database -- --ignored

cargo test \
  --test api \
  database_backed_endpoints_return_200_with_seeded_graph \
  -- --ignored
```

## Frontend

```bash
cd frontend
npm ci
npm run build
```

## Benchmarks

```bash
cd backend
cargo bench
```

Existem benchmarks para construção de grafo, parsing, correlação, WebSocket, memória, layout e busca.

---

# Modelo de dados

### GraphNode

Representa uma entidade normalizada.

Contém informações como:

* tipo;
* valor;
* severidade;
* origem;
* período;
* metadados.

### GraphEdge

Representa uma relação direcionada entre duas entidades.

### Alert

Evento que relaciona uma observação com seu contexto operacional.

### SourceObservation

Preserva o registro bruto e a origem do indicador.

### IngestedFile

Mantém informações sobre arquivos processados, fingerprint e tamanho.

---

# Segurança

O projeto atualmente foi desenvolvido para utilização em um ambiente pessoal/controlado.

Antes de qualquer exposição em produção:

* altere as credenciais padrão do Compose;
* implemente autenticação e autorização;
* restrinja o CORS;
* utilize HTTPS;
* coloque a aplicação atrás de um reverse proxy;
* aplique regras de firewall;
* não exponha diretamente o PostgreSQL;
* não exponha diretamente a API backend à Internet.

A fonte de dados é montada como somente leitura para impedir modificações acidentais pelo backend.

---

# Escopo

O VÊ AÍ! não pretende substituir integralmente plataformas como o MISP.

Atualmente não estão no escopo:

* federação entre organizações;
* sharing groups;
* feeds externos completos;
* taxonomias completas;
* sincronização entre organizações;
* ecossistema integral do MISP.

A prioridade é manter uma ferramenta **rápida, investigativa e adequada ao fluxo operacional que motivou sua criação**.

---

# Status

> **Em desenvolvimento ativo**

A aplicação atualmente possui:

* ingestão automática;
* normalização;
* deduplicação;
* persistência;
* correlação;
* atualização em tempo real;
* Grafo interativo;
* Explorer;
* IOC Overview;
* histórico/eventos;
* testes;
* benchmarks.

---

## Autor

Desenvolvido por **Just1cup**.

Threat Intelligence • Detection Engineering • Cybersecurity

---

## Licença

Nenhuma licença de redistribuição foi definida até o momento.

Até que um arquivo de licença seja adicionado, permanecem reservados os direitos autorais do autor.
