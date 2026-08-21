# Testes do backend ioc-graph

Todos os testes usam dados sinteticos e nao dependem do diretorio real `../dashboard`.

## Suite padrao

```bash
cd backend
cargo test
```

Executa testes unitarios e de integracao deterministico sem Docker:

- parser de JSON do dashboard;
- construcao e invariantes do grafo;
- correlacao de IOCs;
- fingerprints e atualizacoes de snapshot;
- contratos HTTP que nao exigem banco real;
- broadcast WebSocket via `tokio::sync::broadcast`;
- guardas de regressao sem baseline externo.

## Testes com PostgreSQL real

Os testes que usam Testcontainers ficam ignorados por padrao.
Execute somente quando o Docker estiver disponivel:

```bash
cargo test --test database -- --ignored
cargo test --test api database_backed_endpoints_return_200_with_seeded_graph -- --ignored
```

Esses testes sobem PostgreSQL temporario, executam migrations e validam insert,
update/upsert, delete, transacao, rollback, constraints, integridade referencial
e endpoints REST com dados persistidos.

## Teste de carga

```bash
cargo test --test performance_regression load_test_100k_iocs_remains_bounded_and_completes -- --ignored
```

Esse teste gera 100.000 IOCs sinteticos e valida que o snapshot resultante
contem os IOCs, relacoes e alertas esperados sem depender de fixtures externas.

## Benchmarks

Compile todos os benchmarks sem executa-los:

```bash
cargo bench --no-run
```

Execute todos:

```bash
cargo bench
```

Execute uma categoria especifica:

```bash
cargo bench --bench graph_build
cargo bench --bench parser
cargo bench --bench correlation
cargo bench --bench websocket
cargo bench --bench memory
cargo bench --bench layout
cargo bench --bench search
```

Os benchmarks cobrem construcao do grafo, parser por tamanho de arquivo,
correlacao, deduplicacao, broadcast WebSocket, RSS aproximado, topologia de
layout e busca por tipo/valor.

## Regressao de desempenho

Os testes de regressao aceitam um baseline JSON via variavel de ambiente:

```bash
IOC_GRAPH_PERF_BASELINE=./perf-baseline.json cargo test --test performance_regression
```

Formato esperado:

```json
{
  "graph_build_ms": 120.0,
  "memory_growth_bytes": 104857600,
  "single_change_update_ms": 80.0,
  "indexed_query_ms": 5.0
}
```

Limites aplicados:

- `graph_build_ms`: falha acima de 15% do baseline;
- `memory_growth_bytes`: falha acima de 20% do baseline;
- `single_change_update_ms`: falha acima de 25% do tempo baseline, equivalente a queda maior que 20% na velocidade;
- `indexed_query_ms`: falha acima de 25% do tempo baseline, equivalente a queda maior que 20% na velocidade.

Criterion tambem pode manter historico local:

```bash
cargo bench -- --save-baseline main
cargo bench -- --baseline main
```
