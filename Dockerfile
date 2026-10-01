# syntax=docker/dockerfile:1
#
# Image de synco-cdn (cf. docs/deploiement-docker.md).
#
# Images de base épinglées par empreinte : publiées depuis au moins 7 jours
# (règle du projet) et immuables. Pour les mettre à jour, reprendre une
# empreinte d'au moins 7 jours sur Docker Hub.

# rust:1.98.1-slim-bookworm (2026-09-19) — même compilateur que rust-toolchain.toml
ARG RUST_IMAGE=rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730
# debian:trixie-20260918-slim (2026-09-19)
ARG RUNTIME_IMAGE=debian:trixie-20260918-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS build
WORKDIR /src

# 1. Dépendances seules, avec des sources factices : cette couche n'est
#    reconstruite que si Cargo.toml / Cargo.lock changent.
#    rust-toolchain.toml n'est pas copié : l'image fixe déjà le compilateur,
#    et rustup téléchargerait sinon clippy et rustfmt pour rien.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && touch src/lib.rs \
 && cargo build --release --locked \
 && rm -rf src

# 2. Le service.
COPY src ./src
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --locked \
 && strip target/release/synco-cdn

# ---------------------------------------------------------------------------
# Exécution
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE}

# Utilisateur sans privilèges. L'UID/GID réellement utilisé se règle dans
# docker-compose.yml (CDN_UID/CDN_GID) pour correspondre au propriétaire du
# stockage partagé avec synco_api.
RUN groupadd --gid 10001 synco \
 && useradd --uid 10001 --gid synco --no-create-home --shell /usr/sbin/nologin synco-cdn

COPY --from=build /src/target/release/synco-cdn /usr/local/bin/synco-cdn
COPY docker/config.toml /etc/synco-cdn/config.toml

USER 10001:10001
EXPOSE 9100 9101
VOLUME ["/data"]
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/synco-cdn", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/synco-cdn"]
CMD ["--config", "/etc/synco-cdn/config.toml"]
