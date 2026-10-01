#!/usr/bin/env bash
# Installe ce qu'il faut pour fuzzer, aux versions de fuzz/versions.env :
# rustup (s'il manque), la toolchain nightly datée, cargo-fuzz, et vérifie
# la présence d'un compilateur C++ (libFuzzer est compilé depuis ses sources).
# Idempotent : ne réinstalle rien de déjà présent à la bonne version.
set -euo pipefail

cd "$(dirname "$0")"
# shellcheck source=versions.env
source ./versions.env

log() { printf '\033[1m[fuzz/setup]\033[0m %s\n' "$*"; }

if ! command -v rustup >/dev/null 2>&1; then
  ../ci/ensure-rustup.sh
  export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
fi

if ! rustup toolchain list | grep -q "^${FUZZ_TOOLCHAIN}"; then
  log "installation de ${FUZZ_TOOLCHAIN}"
  rustup toolchain install "${FUZZ_TOOLCHAIN}" --profile minimal
fi

installed="$(cargo "+${FUZZ_TOOLCHAIN}" fuzz --version 2>/dev/null | awk '{print $2}' || true)"
if [[ "${installed}" != "${CARGO_FUZZ_VERSION}" ]]; then
  log "installation de cargo-fuzz ${CARGO_FUZZ_VERSION}"
  cargo "+${FUZZ_TOOLCHAIN}" install cargo-fuzz --version "${CARGO_FUZZ_VERSION}" --locked
fi

if ! command -v c++ >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    log "installation d'un compilateur C++"
    SUDO=""; [[ "$(id -u)" != 0 ]] && SUDO="sudo"
    $SUDO apt-get update -qq && $SUDO apt-get install -y -qq build-essential >/dev/null
  else
    echo "Compilateur C++ introuvable (paquet build-essential / gcc-c++)." >&2
    exit 1
  fi
fi

log "prêt : $(cargo "+${FUZZ_TOOLCHAIN}" --version), cargo-fuzz ${CARGO_FUZZ_VERSION}"
