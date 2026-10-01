# 10 — Feuille de route

Chaque étape se termine par un livrable utilisable et des critères
vérifiables.

**État (30/09/2026)** : étapes 0 à 3 réalisées dans ce dépôt (le choix du
mode de téléchargement par défaut attend la mesure sur la machine de
production). Fuzzing en place (6 cibles, CI Gitea), cf. `fuzz/README.md`.
`cargo deny` et `cargo audit` ne sont pas encore dans la CI. Étapes 4 à 8
à faire.

Les étapes 1 à 5 se font dans synco_cdn ; les étapes 4 et 5 touchent aussi
synco_api et synco_app.

## Étape 0 — Squelette

- Projet Cargo, `rust-toolchain.toml`, profil de publication, lints de
  [05](05-robustesse-securite.md), CI (format, lints, tests, `cargo deny`).
- Chargement et validation de la configuration, journaux JSON, runtime
  tokio configurable, deux écouteurs, `/healthz`, `/readyz`, arrêt propre.

**Critère** : le binaire démarre, refuse une configuration invalide avec un
message clair, s'arrête proprement sur `SIGTERM`, CI verte.

## Étape 1 — Tickets

- `ticket.rs` : format, vérification, révocations.
- `tests/vectors/tickets.json` : vecteurs partagés.
- Signature côté synco_api (`cdnTickets.ts`, `node:crypto`), mêmes vecteurs
  exécutés dans ses tests.
- Cible de fuzzing.

**Critère** : tous les vecteurs passent des deux côtés ; fuzzing 1 h sans
panique.

## Étape 2 — Envois

- Sessions, table des parts, écriture positionnelle avec coalescence et
  double tampon, budget mémoire, préallocation, persistance et reprise au
  démarrage.
- Routes `POST/PUT/GET/DELETE /v1/uploads…` et `complete`, avec un faux
  serveur API pour le rappel.

**Critère** : tests d'intégration et de propriétés verts ; `kill -9` pendant
100 envois puis reprise sans perte ; débit ≥ 90 % de la référence disque en
local.

## Étape 3 — Téléchargements

- `range.rs`, lecture positionnelle en streaming avec lecture anticipée,
  contrôle `size`/`mtime`.
- Mode `accel` (délégation à nginx) derrière une option.
- Benchmark direct vs `accel` : **choix du mode par défaut**.

**Critère** : tests verts, débit ≥ 90 % de la référence, mémoire constante
avec des lecteurs lents.

## Étape 4 — Intégration synco_api ✅

Fait (synco_api, branche `feat/cdn`), cf. [06](06-integration-synco-api.md).
Décision en cours de route : pas de cohabitation. Les données existantes
sont réinitialisées, tout fichier passe en E2EE par le CDN, l'ancien
système (chiffrement serveur, routes de transfert de l'API, OnlyOffice) est
supprimé.

- Table `CdnTransfer`, quota en base (transaction `Serializable`).
- Routes `transfers/uploads` (+ `replace` pour l'édition), `renew`, ticket
  dans `/meta`.
- Écouteur dédié des rappels (`complete`, `abort`), client HMAC vers le CDN
  (révocations, annulations), entretien (transferts expirés, blobs
  orphelins).

**Critère** : test de bout en bout API + CDN avec le vrai binaire
(`cdnE2e.test.ts`) ✅ ; tests existants verts, hors 3 tests P20 déjà en
échec sur `recipe/papaye` (import manquant dans `routes/tasks.ts`).

## Étape 5 — Intégration synco_app

- `chunkedUpload.ts`, `chunkedDownload.ts`, `http.ts` : cibles CDN, gestion
  du ticket (renouvellement), nouveaux codes d'erreur, action « Reprendre ».
- CSP (`index.html`, `tauri.conf.json`).
- Test de bout en bout avec le chiffrement v2 réel.

**Critère** : envoi et téléchargement de fichiers de 1 Mo à 10 Go depuis le
navigateur et depuis l'app bureau, coupure réseau de 30 s absorbée sans
action de l'utilisateur.

## Étape 6 — Durcissement et réglages

- Tests de chaos, fuzzing long, benchmarks complets de [09](09-tests-benchmarks.md).
- **Choix de la taille des parts** et des niveaux de parallélisme du client.
- Profilage et optimisations justifiées par les mesures.

**Critère** : tous les objectifs chiffrés de [04](04-moteur-io.md#objectifs-chiffrés)
atteints, ou écart expliqué et accepté.

## Étape 7 — Mise en production

- **Choix nginx vs `rustls`** et **systemd vs PM2**.
- Configuration nginx, service, réglages système, métriques et alertes.
- Déploiement : CDN, puis API et app ensemble (l'API exige le CDN, l'app
  doit parler le nouveau protocole). Surveillance des métriques pendant une
  semaine.
- Retour arrière : version précédente de l'API et de l'app (pas de
  cohabitation des deux systèmes).

**Critère** : une semaine en production sans panique ni erreur de rappel non
résolue.

## Étape 8 — Nettoyage

- ~~Retrait de `uploadSessions.ts`, `storageQuota.ts` et de la route E2EE
  par morceaux de synco_api~~ : fait à l'étape 4.
- Documentation d'exploitation à jour dans ce dépôt.
