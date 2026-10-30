# Desktroo Remote — © 2026 Mdm-services.fr. Tous droits réservés.
# Serveur RustDesk (AGPL-3.0, voir /usr/share/doc/rustdesk-server/NOTICE dans l'image) :
#   - hbbr : programme officiel, vérifié par son empreinte ;
#   - hbbs : compilé ici depuis le source officiel du même tag, avec notre modification (hbbs-patch/).

FROM alpine:3.20 AS rustdesk
ARG TARGETARCH
ARG RUSTDESK_SERVER_VERSION=1.1.16
ARG SHA256_AMD64=0565c41affe6c3f409b0bddfaf5a24ccbf3f64f5f8e3fec250b69a0d5f6bdbcf
ARG SHA256_ARM64=6a4ae3c5ca257a4278ded72fd17eb2ca4eeb0356a5425e63a3e7fcb0ec6c155c
RUN set -eu; apk add --no-cache curl unzip >/dev/null; \
    case "$TARGETARCH" in amd64) A=amd64; S=$SHA256_AMD64;; arm64) A=arm64v8; S=$SHA256_ARM64;; *) echo "architecture non prise en charge : $TARGETARCH"; exit 1;; esac; \
    curl -fsSL -o /tmp/rd.zip "https://github.com/rustdesk/rustdesk-server/releases/download/${RUSTDESK_SERVER_VERSION}/rustdesk-server-linux-${A}.zip"; \
    echo "$S  /tmp/rd.zip" | sha256sum -c -; \
    unzip -q /tmp/rd.zip -d /tmp/rd; mkdir /out; cp "/tmp/rd/$A/hbbr" /out/; chmod 755 /out/*

# Compilé pour l'architecture de l'image (amd64 et arm64 sont construits chacun sur une machine de leur type).
# Rust sous Alpine produit un programme statique (musl) : il tourne tel quel dans l'image finale.
FROM rust:1-alpine AS hbbs
ARG RUSTDESK_SERVER_VERSION=1.1.16
ARG RUSTDESK_SERVER_COMMIT=73523b31cfd25d77dee862e6fc9f5e1fb5e485ef
RUN apk add --no-cache build-base git linux-headers >/dev/null
RUN set -eu; git clone -q --branch "$RUSTDESK_SERVER_VERSION" --depth 1 --recurse-submodules --shallow-submodules \
      https://github.com/rustdesk/rustdesk-server /src; \
    test "$(git -C /src rev-parse HEAD)" = "$RUSTDESK_SERVER_COMMIT"
WORKDIR /src
COPY hbbs-patch/ /patch/
RUN git apply /patch/*.patch && cargo build --release --locked --bin hbbs && \
    install -m 755 target/release/hbbs /hbbs && /hbbs --help >/dev/null

FROM node:22-alpine
ARG RUSTDESK_SERVER_VERSION=1.1.16
ARG APP_VERSION=dev
LABEL org.opencontainers.image.title="Desktroo Remote" \
      org.opencontainers.image.vendor="Mdm-services.fr" \
      org.opencontainers.image.source="https://github.com/Nabief/desktroo-remote" \
      org.opencontainers.image.licenses="LicenseRef-Desktroo AND AGPL-3.0-only"
# tzdata : les journaux du serveur RustDesk à l'heure du NAS (TZ posé par Desktroo)
RUN apk add --no-cache tzdata >/dev/null
COPY --from=rustdesk /out/hbbr /usr/local/bin/
COPY --from=hbbs /hbbs /usr/local/bin/
COPY hbbs-patch/ /usr/share/doc/rustdesk-server/patches/
COPY NOTICE /usr/share/doc/rustdesk-server/NOTICE
WORKDIR /app
COPY server.js ./
COPY public ./public
ENV NODE_ENV=production DATA_DIR=/data RD_BIN_DIR=/usr/local/bin \
    RD_SERVER_VERSION=${RUSTDESK_SERVER_VERSION} APP_VERSION=${APP_VERSION}
# 8080 : panneau (derrière Desktroo) · 8081 : API des postes (port 21114 du NAS, public)
# 8082 : API des techniciens (port 21120 du NAS, réseau local seulement) · 21115-21117 : serveur RustDesk
EXPOSE 8080 8081 8082 21115 21116 21116/udp 21117
# Desktroo Apps lance le conteneur sous l'utilisateur 568 (apps de TrueNAS), en lecture seule hors de /data et /tmp.
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
