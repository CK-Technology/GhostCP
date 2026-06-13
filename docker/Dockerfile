# GhostCP development / test image.
# Builds the API and runs it with auto-reload via cargo-watch.
# Edition 2024 requires Rust >= 1.85.
FROM rust:1.88-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-watch

# Prime the dependency cache as a separate layer.
COPY Cargo.toml Cargo.lock ./
COPY api/Cargo.toml ./api/Cargo.toml
COPY ui/Cargo.toml ./ui/Cargo.toml

COPY docker/scripts/wait-for-postgres.sh /usr/local/bin/wait-for-postgres
RUN chmod +x /usr/local/bin/wait-for-postgres

EXPOSE 8080

# Source is bind-mounted by compose; rebuild + reload on change.
CMD ["cargo", "watch", "-w", "api/src", "-x", "run -p ghostcp-api"]
