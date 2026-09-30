# 09 — Tests et benchmarks

## Tests unitaires

Pour chaque module pur ou presque :

- `ticket.rs` : vecteurs partagés, bornes de chaque champ, tolérance
  d'horloge, séparation de domaine (une signature du même payload sans le
  préfixe de domaine est refusée).
- `range.rs` : toutes les formes (`a-b`, `a-`, `-n`), plages vides,
  inversées, hors fichier, fichier vide, entiers géants, espaces, plages
  multiples.
- `storage/session.rs` : table des parts (transitions atomiques
  absente → en cours → reçue), comptage, sérialisation des plages reçues.
- `storage/writer.rs` : coalescence (fragments de toutes tailles, part de
  0 octet, part plus longue ou plus courte que prévu), empreinte.

## Tests par propriétés (`proptest`)

- Pour toute taille de fichier et de part valides : l'union des plages des
  parts couvre exactement le fichier, sans chevauchement.
- Pour tout ordre d'arrivée des parts (permutations, doublons,
  interruptions) : le fichier final est identique à la source.
- Pour toute plage demandée : la réponse est exactement la tranche
  correspondante, ou `416`.

## Fuzzing (`cargo fuzz`)

Cibles : analyse des tickets, analyse de `Range`, analyse du corps JSON
interne, rechargement de `<tid>.session` / `<tid>.parts` corrompus.
Critère : aucune panique, aucun dépassement de temps, après au moins
1 heure par cible en CI de nuit.

## Tests d'intégration

Serveur réel lancé sur un répertoire temporaire, clé de test, faux serveur
synco_api (qui enregistre les rappels) :

- envoi complet, parts en parallèle et dans le désordre, puis
  téléchargement par plages parallèles : octets identiques ;
- réessais : même part deux fois, part coupée au milieu, part de mauvaise
  taille ;
- tickets : expiré, mauvais `tid`, mauvaise opération, révoqué, clé
  inconnue, rotation de clé ;
- finalisation : parts manquantes, API injoignable puis rétablie, API qui
  refuse, finalisation rappelée deux fois ;
- téléchargements : fichier modifié (`409`), supprimé pendant la lecture,
  plages invalides ;
- CORS : préflight accepté pour une origine autorisée, rien pour une autre ;
- arrêt propre pendant des envois, puis reprise.

## Test de bout en bout avec le vrai client

Réutilise le principe du test fait pour la route d'envoi par morceaux de
synco_api : le code de `chunkedCryptoCore.ts` (chiffrement v2 réel) envoie
un fichier au CDN, le télécharge, le déchiffre et le compare à l'original.
Lancé dans la CI de synco_app contre un binaire CDN construit en CI.

## Tests de chaos

| Scénario | Attendu |
|----------|---------|
| `kill -9` au milieu de 100 envois, redémarrage | Toutes les sessions reprennent, fichiers identiques après fin |
| Disque plein (tmpfs de petite taille) | `507` à l'ouverture, aucun fichier corrompu, service toujours disponible |
| 10 000 connexions qui n'envoient rien (slowloris) | Fermées par délai, clients légitimes servis |
| Client qui lit un téléchargement à 1 Ko/s | Mémoire du CDN inchangée (2 blocs en vol) |
| synco_api arrêtée pendant les finalisations | `503`, puis succès après redémarrage de l'API |
| `ulimit -n` bas, épuisement des descripteurs | Aucun arrêt, reprise dès que des connexions se ferment |

## Benchmarks

### Référence matérielle, mesurée d'abord

- Disque : `fio` en écriture séquentielle et aléatoire par blocs de 1 Mio,
  profondeur 8, sur le volume de `FM_DATA_DIR`.
- Réseau : `iperf3` entre le client de test et le serveur, 8 flux.

Le résultat du CDN s'exprime en **pourcentage de la référence** :
min(disque, réseau). C'est ce qui rend l'objectif « limité par le disque et
le réseau » vérifiable.

### Outil

Un binaire `bench/` (Rust, hyper) qui simule des clients : nombre de
fichiers, taille, parts en parallèle, ticket de test. Il mesure le débit,
la latence par part (p50, p95, p99) et le taux d'erreurs. Les
téléchargements sont aussi mesurés avec `oha` (requêtes Range).

### Scénarios

| Scénario | Mesure |
|----------|--------|
| 1 fichier de 10 Gio, 8 parts en parallèle | Débit vs référence |
| 1 000 fichiers de 4 Mio, 64 en parallèle | Fichiers/s, latence p99 |
| 1 000 envois simultanés de 100 Mio | Débit total, mémoire, erreurs |
| Téléchargements : mode direct vs `accel` | Débit, CPU par Go/s |
| Parts de 4, 8 et 16 Mio sur un lien à 50 ms de RTT | Débit, choix de la taille par défaut |
| Mixte 50 % envois / 50 % téléchargements | Équité, aucune famine |

### Profilage

`perf record` + flamegraph sur les scénarios, `tokio-console` en
développement pour repérer les tâches bloquées. Tout résultat sous
l'objectif doit être expliqué par le profil avant d'être accepté.

## CI

| Étape | Outil |
|-------|-------|
| Format | `cargo fmt --check` |
| Lints (règles de [05](05-robustesse-securite.md)) | `cargo clippy --all-targets -- -D warnings` |
| Tests | `cargo nextest run` |
| Dépendances | `cargo deny check`, `cargo audit` |
| Fuzzing court | 5 min par cible à chaque PR, 1 h la nuit |
| Benchmark de non-régression | scénario court à chaque PR sur `main`, alerte si −10 % |
