# Déploiement avec Docker Compose

Le CDN tourne dans un conteneur, sur la même machine que synco_api, avec
qui il partage le répertoire de stockage des fichiers (`FM_DATA_DIR`).
nginx, sur l'hôte, publie `https://cdn.synco.one` vers le conteneur.

```
Internet ──▶ nginx (hôte, TLS) ──▶ 127.0.0.1:9100 ──▶ conteneur synco-cdn
synco_api (hôte) ──────────────▶ 127.0.0.1:9101 ──▶ (écouteur interne)
conteneur ──▶ host.docker.internal:9002 ──▶ synco_api (écouteur des rappels, 172.17.0.1)
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
| `CDN_API_INTERNAL_URL` | Écouteur des rappels de synco_api vu du conteneur. Par défaut `http://host.docker.internal:9002`, c'est-à-dire `CDN_CALLBACK_LISTEN=172.17.0.1:9002` côté API (adresse de `docker0`) |
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
CDN_TICKET_PRIVATE_KEY_FILE=<chemin>/secrets/ticket_private_key.pem
CDN_CALLBACK_LISTEN=172.17.0.1:9002
FM_DATA_DIR=<CDN_DATA_DIR>
```

`secrets/ticket_private_key.pem` est la clé qui signe les tickets : elle
ne va **que** dans synco_api (l'utilisateur qui exécute l'API doit pouvoir
la lire). Le conteneur du CDN ne reçoit que la clé publique. À la place
des variables `*_FILE`, `CDN_INTERNAL_SECRET` et `CDN_TICKET_PRIVATE_KEY`
acceptent la valeur elle-même (PEM sur une ligne avec des `\n`).

synco_api refuse de démarrer si l'une de ces variables manque : tous les
fichiers passent par le CDN.

**Rappels du CDN vers l'API.** Le conteneur joint l'écouteur dédié de
synco_api (`CDN_CALLBACK_LISTEN`), séparé de l'API publique : nginx ne le
publie pas. Sur un hôte avec pare-feu (ufw, firewalld), autoriser les
réseaux Docker vers `172.17.0.1:9002`, par exemple
`ufw allow from 172.16.0.0/12 to 172.17.0.1 port 9002 proto tcp`.

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

## Poste de développement avec Podman sans root

Deux différences avec Docker :

- **Utilisateur** : `CDN_UID=0` et `CDN_GID=0`. Sans root, l'uid 0 du
  conteneur est votre propre utilisateur sur l'hôte : synco_api, lancée par
  vous, peut lire et supprimer les blobs.
- **Réseau** : le conteneur ne joint l'hôte que par son IP réseau (pasta),
  ce qui obligerait synco_api à écouter sur le réseau local. Une surcharge
  locale, `docker-compose.override.yml` (non versionnée, fusionnée
  automatiquement), fait partager au conteneur le réseau de l'hôte, en
  restant sur la boucle locale :

  ```yaml
  services:
    cdn:
      network_mode: host
      ports: !reset []
      extra_hosts: !reset []
      sysctls: !reset {}
      environment:
        SYNCO_CDN_LISTEN__PUBLIC: 127.0.0.1:9100
        SYNCO_CDN_LISTEN__INTERNAL: 127.0.0.1:9101
        SYNCO_CDN_API__INTERNAL_URL: http://127.0.0.1:9002
  ```

  Côté synco_api : `CDN_URL=http://localhost:9100` (autorisé par la CSP de
  développement de synco_app) et `CDN_CALLBACK_LISTEN=127.0.0.1:9002`.

Commandes : `podman compose up -d --build` (service utilisateur
`podman.socket` démarré).

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
| Envois finalisés mais `503 api_unavailable` | `CDN_API_INTERNAL_URL` injoignable depuis le conteneur : `CDN_CALLBACK_LISTEN` de synco_api, pare-feu ; le CDN réessaie toutes les minutes |
| Conteneur `unhealthy` | `/readyz` échoue : stockage plein (réserve `CDN_MIN_FREE_*` atteinte) ou illisible |
| `401 ticket_unknown_key` | La clé (`kid`) qui signe côté API n'est pas dans `CDN_TICKET_PUBLIC_KEYS` |
