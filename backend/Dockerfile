FROM rust:1-bookworm AS build

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY benches ./benches
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin app

USER app
COPY --from=build /app/target/release/ioc-graph-backend /usr/local/bin/ioc-graph-backend

EXPOSE 3000
CMD ["ioc-graph-backend"]
