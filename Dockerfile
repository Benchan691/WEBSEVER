FROM rust:1.91-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/webserver-rust /usr/local/bin/webserver-rust
COPY templates ./templates
COPY static ./static
COPY config ./config
EXPOSE 9100
CMD ["webserver-rust"]
