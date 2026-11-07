# One image for the whole website: the built pages + the Rust API that serves them and
# /api from the same address (first-party cookies, no proxy in between).
#
#   docker build -t toniebee .                       # live build: refuses while the owner's
#                                                    # details are missing (launch check)
#   docker build --build-arg PREVIEW=1 -t toniebee . # a preview to show her (noindex)
#
# Render builds this from render.yaml.

# ---- 1. The website ----------------------------------------------------------
FROM node:24-bookworm-slim AS site
ARG PREVIEW=0
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN if [ "$PREVIEW" = "1" ]; then npm run build; else npm run build:live; fi \
    && rm -rf dist/_dev

# ---- 2. The API ---------------------------------------------------------------
FROM rust:1.90-bookworm AS api
WORKDIR /app/backend
COPY backend/ ./
RUN cargo build --release --locked && strip target/release/toniebee-api

# ---- 3. What runs: the binary, the pages, nothing else ------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home toniebee
COPY --from=api /app/backend/target/release/toniebee-api /usr/local/bin/toniebee-api
COPY --from=site /app/frontend/dist /srv/site
ENV SITE_DIR=/srv/site \
    HOST=0.0.0.0 \
    PORT=10000 \
    RUST_LOG=toniebee_api=info,tower_http=info
USER toniebee
EXPOSE 10000
CMD ["toniebee-api"]
