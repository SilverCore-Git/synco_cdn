# synco_cdn

Service de transport de fichiers de Synco, écrit en Rust. Il reçoit et sert
les morceaux (chunks) des fichiers chiffrés de bout en bout, en utilisant
tous les cœurs de la machine. Il ne décide de rien : l'autorisation, le
quota et les métadonnées restent dans **synco_api**, qui délivre des
**tickets signés** que le CDN vérifie localement.

```
             ┌────────────── api.synco.one (synco_api, Bun) ──────────────┐
  client ──▶ │ droits, quota, métadonnées → délivre un ticket Ed25519      │
    │        └─────────────────────────────▲──────────────────────────────┘
    │                                      │ rappel interne (fin d'envoi)
    │        ┌─────────────── cdn.synco.one (synco_cdn, Rust) ────────────┐
    └──────▶ │ vérifie le ticket, écrit/lit les octets, rien d'autre       │
             └──────────────────────────┬─────────────────────────────────┘
                                        ▼
                         FM_DATA_DIR/<id>.enc  (disque partagé)
```

L'objectif de performance : **seules la vitesse du disque et celle du réseau
limitent le débit**. L'objectif de robustesse : **aucun plantage**, quelles
que soient les entrées, la charge ou l'état du disque.

## Utilisation

```sh
cargo build --release                       # binaire : target/release/synco-cdn
cargo test                                  # unitaires, vecteurs Node, bout en bout
cargo clippy --all-targets -- -D warnings   # lints « zéro panique »
cargo run --release --example bench         # débit envoi + téléchargement (variables BENCH_*)
node tests/vectors/generate.mjs             # régénère les vecteurs de tickets

synco-cdn --config deploy/config.example.toml --check-config
synco-cdn --config /etc/synco-cdn/config.toml
```

Signaux : `SIGTERM`/`SIGINT` arrêt propre, `SIGHUP` rechargement des clés
de tickets et des origines CORS. Exemples de déploiement dans
[`deploy/`](deploy/) (configuration commentée, service systemd, vhost nginx).

## Organisation du code

| Module | Rôle |
|--------|------|
| `ticket`, `range` | Analyse des entrées non fiables, sans E/S (testées par entrées aléatoires, fuzzées) |
| `storage::session` | Session d'envoi : état atomique des parts, phases, persistance |
| `storage::writer` | Réception d'une part : lots de fragments écrits par `pwritev`, SHA-256 |
| `storage::reader` | Téléchargement : `pread` par blocs de 1 Mio, lecture anticipée bornée |
| `storage::recovery` | Reprise des sessions au démarrage |
| `storage` | Ouverture (préallocation), finalisation (`fdatasync`, renommage sans écrasement), annulation |
| `http` | Écouteurs, isolation des paniques par requête, routes publiques et internes, CORS |
| `server` | Assemblage, balayage périodique, arrêt propre |
| `limits`, `metrics`, `revocation`, `internal_auth`, `api_client`, `config` | Budget mémoire, Prometheus, révocations, HMAC, rappels vers synco_api, configuration |

Garanties vérifiées à la compilation : `unsafe` interdit ; `unwrap`,
`expect`, `panic!`, indexation directe, arithmétique non vérifiée et
conversions `as` refusées (cf. `Cargo.toml`, section `[lints]`).

## État

Étapes 0 à 3 de la [feuille de route](docs/plan/10-feuille-de-route.md)
réalisées : le service est complet de son côté. Il reste à brancher
synco_api (émission des tickets, rappel de fin d'envoi) et synco_app
(étapes 4 et 5). Mesures sur la machine de développement :
[04 — Mesures](docs/plan/04-moteur-io.md#mesures-première-version).

## Plans

| # | Document | Contenu |
|---|----------|---------|
| 01 | [Architecture](docs/plan/01-architecture.md) | Rôle du CDN, découpage en modules, modèle de threads, cycle de vie d'un transfert |
| 02 | [Tickets](docs/plan/02-tickets.md) | Format, signature Ed25519, champs, durée de vie, renouvellement, révocation |
| 03 | [Protocole HTTP](docs/plan/03-protocole.md) | Routes publiques et internes, en-têtes, codes d'erreur, CORS |
| 04 | [Moteur d'E/S et performance](docs/plan/04-moteur-io.md) | Écriture positionnelle, budget mémoire, contre-pression, HTTP/2, réglages |
| 05 | [Robustesse et sécurité](docs/plan/05-robustesse-securite.md) | Zéro panique, bornes, modèle de menace, reprise après redémarrage |
| 06 | [Intégration synco_api](docs/plan/06-integration-synco-api.md) | Émission des tickets, quota en base, rappel de fin d'envoi, révocations |
| 07 | [Intégration synco_app](docs/plan/07-integration-synco-app.md) | Ce qui change dans le gestionnaire de transferts, CSP, bascule progressive |
| 08 | [Exploitation](docs/plan/08-exploitation.md) | nginx, supervision, réglages noyau, métriques, rotation des clés |
| 09 | [Tests et benchmarks](docs/plan/09-tests-benchmarks.md) | Tests unitaires, fuzzing, intégration, charge, chaos, objectifs chiffrés |
| 10 | [Feuille de route](docs/plan/10-feuille-de-route.md) | Étapes, livrables et critères d'acceptation |

## Décisions prises dans ces plans

1. **E2EE uniquement.** Le CDN ne transporte que des octets déjà chiffrés par
   le client (format E2EE v2 par morceaux). Il ne détient aucune clé de
   chiffrement de contenu. Les anciens fichiers chiffrés côté serveur (SSE)
   restent servis par synco_api.
2. **Stockage partagé.** Le CDN écrit dans le même répertoire que synco_api
   (`FM_DATA_DIR`, un fichier `<id>.enc` par fichier), sur la même machine.
   synco_api garde la suppression et les éditions.
3. **Un seul processus multi-thread** (runtime tokio), pas de cluster.
4. **Tickets Ed25519 à format maison**, signés par l'API avec `node:crypto`
   (aucune dépendance côté API), vérifiés par le CDN sans appel réseau.
5. **La fin d'un envoi passe par le CDN**, qui connaît l'état réel des
   octets, puis appelle l'API pour créer l'entrée en base.

## Décisions encore ouvertes

| Sujet | Options | Tranché par |
|-------|---------|-------------|
| Service des téléchargements | Rust en direct, ou délégation à nginx (`X-Accel-Redirect`, `sendfile`) | Benchmark, étape 3 |
| Terminaison TLS | nginx devant, ou `rustls` dans le CDN | Choix d'exploitation, étape 7 |
| Taille des morceaux E2EE | 4 Mio (actuel) ou 8 Mio | Benchmark, étape 6 |
| Supervision | systemd ou PM2 (mode fork, 1 instance) | Choix d'exploitation, étape 7 |
