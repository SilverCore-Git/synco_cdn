# Déploiement avec Docker Compose

Le CDN tourne dans un conteneur, sur la même machine que synco_api, avec
qui il partage le répertoire de stockage des fichiers (`FM_DATA_DIR`).
nginx, sur l'hôte, publie `https://cdn.synco.one` vers le conteneur.

```
Internet ──▶ nginx (hôte, TLS) ──▶ 127.0.0.1:9100 ──▶ conteneur synco-cdn
synco_api (hôte) ──────────────▶ 127.0.0.1:9101 ──▶ (écouteur interne)
conteneur ──▶ host.docker.internal:9000 ──▶ synco_api (rappels de fin d'envoi)
                  │
                  └── /data ⇄ CDN_DATA_DIR (= FM_DATA_DIR de synco_api)
```

## Prérequis

- Docker avec Compose v2 (`docker compose version`), ou Podman.
- `openssl` (génération des clés).
- Le répertoire de stockage de synco_api, et son propriétaire (`ls -nd`).

## Installation

```sh
git clone … synco_cdn && cd synco_cdn
docker/init.sh                 # crée .env, le secret HMAC et la paire de clés Ed25519
$EDITOR .env                   # relire les valeurs ci-dessous
docker compose up -d --build
docker compose ps              # STATUS doit indiquer « (healthy) »
```

`docker/init.sh` peut être relancé sans risque : il ne remplace jamais un
secret ou une clé existants.

### Valeurs à relire dans `.env`

| Variable | À mettre |
|----------|----------|
| `CDN_DATA_DIR` | Le `FM_DATA_DIR` de synco_api (chemin absolu sur l'hôte) |
| `CDN_UID`, `CDN_GID` | Propriétaire de ce répertoire (`ls -nd $CDN_DATA_DIR`) : le CDN y crée, l'API y lit, déplace et supprime |
| `CDN_CORS_ALLOWED_ORIGINS` | Origines de synco_app (web, Tauri, Capacitor), tableau TOML |
| `CDN_API_INTERNAL_URL` | Adresse de synco_api vue du conteneur. Par défaut l'hôte, port 9000 : synco_api doit alors écouter sur une adresse joignable depuis le pont Docker (pas seulement 127.0.0.1) |
| `CDN_DATA_MOUNT_OPTIONS` | `rw`, ou `z` sur un hôte SELinux (Fedora, RHEL, Rocky) ; `init.sh` le détecte |

Les autres variables (limites, mode de téléchargement, journaux) ont des
valeurs par défaut adaptées ; elles sont commentées dans `.env.example`.

### Brancher synco_api

`docker/init.sh` affiche les valeurs à reporter dans la configuration de
synco_api (cf. [plan 06](plan/06-integration-synco-api.md)) :

```
CDN_URL=https://cdn.synco.one
CDN_INTERNAL_URL=http://127.0.0.1:9101
CDN_INTERNAL_SECRET=<contenu de secrets/cdn_internal_secret>
CDN_TICKET_KID=<kid>
CDN_TICKET_PRIVATE_KEY=<contenu de secrets/ticket_private_key.pem>
```

`secrets/ticket_private_key.pem` est la clé qui signe les tickets : elle
ne va **que** dans synco_api. Le conteneur du CDN ne reçoit que la clé
publique.

### nginx

Reprendre [`deploy/nginx.conf`](../deploy/nginx.conf) : `proxy_pass` vers
`127.0.0.1:9100`, sans mise en tampon des requêtes ni des réponses. En mode
`CDN_DOWNLOAD_MODE=accel`, l'`alias` de `location /_cdn_files/` doit
pointer vers `CDN_DATA_DIR` sur l'hôte.

## Vérifications

```sh
curl -s http://127.0.0.1:9100/healthz            # ok
curl -s http://127.0.0.1:9101/readyz             # ok (stockage accessible, espace suffisant)
curl -s http://127.0.0.1:9101/metrics | head     # métriques Prometheus
docker compose logs -f                           # journaux JSON
```

## Exploitation

| Action | Commande |
|--------|----------|
| Mise à jour | `git pull && docker compose up -d --build` |
| Redémarrage | `docker compose restart` |
| Arrêt | `docker compose down` (les requêtes en cours se terminent, 30 s max) |
| Valider une configuration | `docker compose run --rm cdn --config /etc/synco-cdn/config.toml --check-config` |

Un redémarrage coupe brièvement le service. Les envois en cours ne sont pas
perdus : leurs sessions sont sur disque, et le client renvoie seulement les
parts interrompues.

### Rotation des clés de tickets

1. Générer une nouvelle paire (`openssl genpkey -algorithm ed25519`) et
   ajouter sa clé publique dans `CDN_TICKET_PUBLIC_KEYS`, à côté de
   l'ancienne : `{ "2026-10" = "…", "2027-01" = "…" }`.
2. `docker compose up -d` (le conteneur est recréé avec la nouvelle liste).
3. Faire signer synco_api avec la nouvelle clé.
4. Une heure plus tard, retirer l'ancienne clé et refaire `docker compose up -d`.

## Sécurité du conteneur

- Utilisateur sans privilèges, système de fichiers en lecture seule (seul
  `/data` est inscriptible), toutes les capacités retirées,
  `no-new-privileges`, limite mémoire (`CDN_MEMORY_LIMIT`).
- Ports publiés sur la boucle locale uniquement par défaut. L'écouteur
  interne (`CDN_INTERNAL_BIND`) ne doit jamais être exposé sur Internet.
- `.env` et `secrets/` sont exclus de git et de l'image.
- Images de base épinglées par empreinte, publiées depuis au moins 7 jours
  (cf. en-tête du `Dockerfile` pour les mettre à jour).

## Dépannage

| Symptôme | Cause probable |
|----------|----------------|
| `Permission denied` sur `/data` ou `/run/secrets/…` | Mauvais `CDN_UID`/`CDN_GID`, ou SELinux : `CDN_DATA_MOUNT_OPTIONS=z` |
| `public_keys : au moins une clé…` | `CDN_TICKET_PUBLIC_KEYS` vide : lancer `docker/init.sh` |
| Envois finalisés mais `503 api_unavailable` | `CDN_API_INTERNAL_URL` injoignable depuis le conteneur (synco_api écoute-t-elle sur le pont Docker ?) ; le CDN réessaie toutes les minutes |
| Conteneur `unhealthy` | `/readyz` échoue : stockage plein (réserve `CDN_MIN_FREE_*` atteinte) ou illisible |
| `401 ticket_unknown_key` | La clé (`kid`) qui signe côté API n'est pas dans `CDN_TICKET_PUBLIC_KEYS` |
