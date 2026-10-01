#!/usr/bin/env bash
# Installe rustup s'il est absent (images de runner Gitea sans Rust). La
# version de Rust elle-même est fixée par rust-toolchain.toml (service) ou
# fuzz/versions.env (fuzzing) : rustup l'installe à la première commande.
set -euo pipefail

if command -v rustup >/dev/null 2>&1; then
  exit 0
fi

echo "[ci] installation de rustup"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path

# Rend cargo visible aux étapes suivantes (Gitea et GitHub Actions).
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${CARGO_HOME:-$HOME/.cargo}/bin" >> "${GITHUB_PATH}"
fi
