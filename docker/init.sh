#!/usr/bin/env bash
# Prépare un déploiement Docker de synco-cdn. Idempotent : ne remplace
# jamais un secret ou une clé existants.
#
#   docker/init.sh [kid]      (kid par défaut : AAAA-MM, ex. 2026-10)
#
# Crée :
#   .env                              depuis .env.example, clé publique remplie
#   secrets/cdn_internal_secret       secret HMAC API ↔ CDN (hexadécimal)
#   secrets/ticket_private_key.pem    clé privée Ed25519, POUR synco_api seulement
#
# Puis affiche les variables à reporter dans la configuration de synco_api.
set -euo pipefail

cd "$(dirname "$0")/.."
KID="${1:-$(date +%Y-%m)}"

command -v openssl >/dev/null || { echo "openssl est requis" >&2; exit 1; }
[[ "${KID}" =~ ^[a-z0-9-]{1,32}$ ]] || { echo "kid invalide (a-z, 0-9, -, 32 caractères max)" >&2; exit 1; }

umask 077
mkdir -p secrets

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "• .env créé depuis .env.example"
fi

if [[ ! -s secrets/cdn_internal_secret ]]; then
  openssl rand -hex 32 > secrets/cdn_internal_secret
  echo "• secret interne généré"
fi
# Monté en lecture dans le conteneur, qui ne tourne pas sous votre UID :
# le fichier doit être lisible ; le répertoire secrets/ (700) protège l'hôte.
chmod 0444 secrets/cdn_internal_secret

if [[ ! -s secrets/ticket_private_key.pem ]]; then
  openssl genpkey -algorithm ed25519 -out secrets/ticket_private_key.pem 2>/dev/null
  chmod 0400 secrets/ticket_private_key.pem
  echo "• paire de clés Ed25519 générée (kid ${KID})"
fi

# Clé publique brute (32 derniers octets du DER) en base64.
PUBLIC_KEY="$(openssl pkey -in secrets/ticket_private_key.pem -pubout -outform DER | tail -c 32 | base64 -w0)"

current="$(grep -E '^CDN_TICKET_PUBLIC_KEYS=' .env | cut -d= -f2- || true)"
if [[ -z "${current}" ]]; then
  line="CDN_TICKET_PUBLIC_KEYS={ \"${KID}\" = \"${PUBLIC_KEY}\" }"
  if grep -qE '^CDN_TICKET_PUBLIC_KEYS=' .env; then
    # Remplacement sans sed (la valeur contient des caractères spéciaux).
    awk -v line="${line}" '/^CDN_TICKET_PUBLIC_KEYS=/{print line; next} {print}' .env > .env.tmp && mv .env.tmp .env
  else
    echo "${line}" >> .env
  fi
  echo "• clé publique ajoutée à .env"
elif [[ "${current}" != *"${PUBLIC_KEY}"* ]]; then
  echo "! CDN_TICKET_PUBLIC_KEYS de .env ne contient pas la clé de secrets/ticket_private_key.pem :" >&2
  echo "  vérifier la configuration (rotation en cours ?)." >&2
fi

# SELinux en mode enforcing : le stockage doit être étiqueté pour les
# conteneurs (option de montage z), sinon « Permission denied » sur /data.
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]] \
   && grep -qE '^CDN_DATA_MOUNT_OPTIONS=rw$' .env; then
  awk '/^CDN_DATA_MOUNT_OPTIONS=/{print "CDN_DATA_MOUNT_OPTIONS=z"; next} {print}' .env > .env.tmp && mv .env.tmp .env
  echo "• SELinux actif : CDN_DATA_MOUNT_OPTIONS=z"
fi
chmod 0600 .env

cat <<INFO

Prochaines étapes :
  1. Relire .env : CDN_DATA_DIR, CDN_UID/CDN_GID (propriétaire du stockage),
     CDN_CORS_ALLOWED_ORIGINS, CDN_API_INTERNAL_URL.
  2. docker compose up -d --build

Variables à reporter dans synco_api (cf. docs/plan/06-integration-synco-api.md) :
  CDN_URL=https://cdn.synco.one
  CDN_INTERNAL_URL=http://127.0.0.1:${CDN_INTERNAL_PORT:-9101}
  CDN_INTERNAL_SECRET=$(cat secrets/cdn_internal_secret)
  CDN_TICKET_KID=${KID}
  CDN_TICKET_PRIVATE_KEY_FILE=$(pwd)/secrets/ticket_private_key.pem
  CDN_CALLBACK_LISTEN=172.17.0.1:9002

secrets/ticket_private_key.pem ne doit être donné qu'à synco_api : le CDN
n'a besoin que de la clé publique.
INFO
