#!/usr/bin/env bash
# Lance le fuzzing.
#
#   fuzz/run.sh <cible|all> [secondes par cible]   (défaut : 300)
#   fuzz/run.sh --minimize <cible|all>             réduit le corpus accumulé
#   fuzz/run.sh --reproduce <cible> <fichier>      rejoue une entrée
#
# Variables : FUZZ_JOBS (processus libFuzzer en parallèle par cible, défaut 1).
#
# Corpus : fuzz/seeds/<cible> (versionné, lecture seule) + fuzz/corpus/<cible>
# (découvertes, non versionné, gardé en cache par la CI). En cas de
# plantage, l'entrée fautive est dans fuzz/artifacts/<cible>/ et affichée
# en base64 dans la sortie pour être reproductible même sans artefact.
set -euo pipefail

# cargo-fuzz s'exécute depuis la racine du dépôt (répertoire parent de fuzz/).
cd "$(dirname "$0")/.."
# shellcheck source=versions.env
source fuzz/versions.env

TARGETS=(ticket ticket_claims range path config session_record)

# Taille maximale d'une entrée : un peu au-delà des bornes du service.
max_len() {
  case "$1" in
    ticket) echo 3000 ;;        # ticket : 2 048 octets maximum
    ticket_claims) echo 2048 ;;
    range) echo 300 ;;          # en-tête ignoré au-delà de 256 octets
    path) echo 512 ;;
    config) echo 16384 ;;
    session_record) echo 8192 ;;
  esac
}

cargo_fuzz() { cargo "+${FUZZ_TOOLCHAIN}" fuzz "$@"; }

# libFuzzer n'accepte dans un dictionnaire que les échappements \\, \" et
# \xHH : on refuse tôt un dictionnaire invalide plutôt qu'après la compilation.
check_dicts() {
  local bad
  bad="$(grep -nE '^[^#].*\\[^\\"x]' fuzz/dicts/*.dict || true)"
  if [[ -n "${bad}" ]]; then
    echo "Échappement invalide dans un dictionnaire (utiliser \\xHH) :" >&2
    echo "${bad}" >&2
    exit 2
  fi
}
check_dicts

report_crashes() {
  local target="$1" found=0
  shopt -s nullglob
  for input in fuzz/artifacts/"${target}"/*; do
    found=1
    echo "::error title=fuzzing ${target}::entrée fautive ${input}"
    echo "--- ${input} (base64) ---"
    base64 -w0 "${input}"; echo
    echo "Reproduire : echo '<base64>' | base64 -d > crash && fuzz/run.sh --reproduce ${target} crash"
  done
  return "${found}"
}

run_target() {
  local target="$1" seconds="$2"
  mkdir -p "fuzz/corpus/${target}"
  local args=(
    "-max_total_time=${seconds}"
    "-timeout=10"             # une entrée qui prend plus de 10 s est un bug
    "-rss_limit_mb=2048"
    "-max_len=$(max_len "${target}")"
    "-print_final_stats=1"
  )
  [[ -f "fuzz/dicts/${target}.dict" ]] && args+=("-dict=fuzz/dicts/${target}.dict")
  local jobs="${FUZZ_JOBS:-1}"
  if (( jobs > 1 )); then args+=("-fork=${jobs}"); fi

  echo "=== ${target} : ${seconds} s ==="
  local status=0
  cargo_fuzz run "${target}" "fuzz/corpus/${target}" "fuzz/seeds/${target}" -- "${args[@]}" || status=$?
  if (( status != 0 )); then
    report_crashes "${target}" || true
    return "${status}"
  fi
}

case "${1:-}" in
  --minimize)
    for target in $([[ "${2:-all}" == all ]] && echo "${TARGETS[@]}" || echo "$2"); do
      mkdir -p "fuzz/corpus/${target}"
      echo "=== minimisation ${target} ($(ls "fuzz/corpus/${target}" | wc -l) entrées) ==="
      cargo_fuzz cmin "${target}" "fuzz/corpus/${target}" -- "-max_len=$(max_len "${target}")"
    done
    ;;
  --reproduce)
    [[ $# -eq 3 ]] || { echo "usage : $0 --reproduce <cible> <fichier>" >&2; exit 2; }
    cargo_fuzz run "$2" "$3"
    ;;
  ""|-h|--help)
    sed -n '2,14p' "fuzz/run.sh"; exit 2 ;;
  *)
    seconds="${2:-300}"
    failed=()
    for target in $([[ "$1" == all ]] && echo "${TARGETS[@]}" || echo "$1"); do
      run_target "${target}" "${seconds}" || failed+=("${target}")
    done
    if (( ${#failed[@]} > 0 )); then
      echo "Cibles en échec : ${failed[*]}" >&2
      exit 1
    fi
    ;;
esac
