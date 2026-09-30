# 05 — Robustesse et sécurité

## Zéro panique : règles de code

Une panique dans un service réseau est un bug. Elles sont interdites à la
compilation, pas seulement par convention :

```rust
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::indexing_slicing,        // t[i] peut paniquer : .get(i)
    clippy::arithmetic_side_effects, // débordements : checked_* / saturating_*
    clippy::as_conversions,          // troncatures silencieuses : try_from
    clippy::string_slice,
)]
```

- **Arithmétique des tailles** : toujours en `u64`, toujours vérifiée. Un
  offset de part se calcule par `index.checked_mul(part_size)`, et un
  dépassement est une erreur `400`, jamais un plantage ni un offset faux.
- **Erreurs** : une seule énumération `CdnError`, convertie en réponse HTTP
  à un seul endroit. Les fonctions renvoient `Result`, l'opérateur `?` fait
  remonter.
- **Exceptions** : seul `main.rs` peut s'autoriser un `expect`, pour une
  configuration invalide au démarrage (le service refuse alors de démarrer,
  avec un message clair). Chaque exception porte un `#[allow]` justifié en
  commentaire.
- **Défense en profondeur** : même avec ces règles, une panique dans une
  dépendance reste possible. `CatchPanicLayer` la transforme en `500` pour
  cette requête seulement, la journalise et incrémente une métrique
  d'alerte. Le processus continue.
- `unsafe` est interdit dans le code du CDN. Les dépendances qui en
  contiennent (tokio, hyper…) sont des bibliothèques largement auditées ;
  l'appel système `fallocate` passe par `rustix`, qui expose une API sûre.

## Tout est borné

| Ressource | Borne | Au-delà |
|-----------|-------|---------|
| Connexions simultanées | 10 000 (config) | Acceptation suspendue, reprise dès qu'une se ferme |
| Mémoire des tampons | 512 Mio (config) | Contre-pression (cf. [04](04-moteur-io.md)) |
| Parts en écriture par transfert | 8 | `429` + `Retry-After` |
| Sessions d'envoi ouvertes | 20 000 | `503` |
| Taille d'une part | 64 Mio | Refusée dès le ticket |
| Taille d'un fichier | config (10 Gio par défaut) | Refusée dès le ticket |
| Longueur d'un ticket | 2 048 octets | `401` avant décodage |
| En-têtes d'une requête | 16 Kio | `431` |
| Durée de lecture des en-têtes | 10 s | Connexion fermée |
| Inactivité d'un corps de requête | 30 s | Connexion fermée, part non marquée reçue |
| Espace disque libre | réserve de 5 % ou 20 Gio (config) | `507`, aucune écriture commencée |
| Descripteurs de fichiers épuisés (`EMFILE`) | — | Boucle d'acceptation en attente 100 ms, pas d'arrêt |

## Pannes prévues et comportement

| Situation | Comportement |
|-----------|--------------|
| Disque plein pendant une écriture | Impossible pour un envoi (préalloué). Pour les fichiers de session : `507`, session intacte |
| Erreur d'E/S sur une part | `500` pour cette part, pas marquée reçue ; le client la renvoie |
| Client qui coupe au milieu d'une part | Part non marquée reçue, tampons libérés |
| Même part envoyée deux fois en parallèle | La seconde reçoit `409 part_in_progress` (état de la part changé par comparaison atomique) |
| synco_api injoignable à la finalisation | Fichier conservé, état persisté, `503` au client, rappel repris au prochain `complete` |
| synco_api refuse la finalisation | Fichier supprimé, `409` au client avec le message de l'API |
| Fichier supprimé par l'API pendant un téléchargement | Linux garde l'inode ouvert : la réponse en cours se termine ; les requêtes suivantes reçoivent `404` |
| Fichier remplacé pendant un téléchargement | `409 file_changed` (contrôle `size`/`mtime` du ticket) |
| `SIGTERM` | Plus de nouvelles connexions, requêtes en cours terminées (délai 30 s), état déjà persisté |
| `kill -9`, coupure de courant | Reprise au démarrage (ci-dessous) |

## Reprise après redémarrage

Au démarrage, le CDN parcourt `.cdn-uploads/` :

- session dont le ticket a expiré depuis plus de 24 h : fichiers supprimés ;
- sinon, session rechargée depuis `<tid>.session` et `<tid>.parts`.

`<tid>.parts` contient un octet par part, écrit **après** l'écriture des
données de la part. Après un arrêt brutal du processus, le cache disque du
noyau conserve les deux, donc une part marquée reçue l'est vraiment. Après
une coupure de courant, une part marquée reçue peut être incomplète : ce
cas rare est détecté par le client (le déchiffrement AES-GCM du morceau
échoue au téléchargement) ; pour l'exclure, `complete` refait un
`fdatasync` avant toute annonce à l'API, et une option `strict_durability`
fait un `fdatasync` du fichier de données avant chaque marquage de part.

Le client, lui, reprend par `GET /v1/uploads/{tid}` et renvoie seulement
les parts manquantes.

## Modèle de menace

| Menace | Parade |
|--------|--------|
| Ticket forgé | Signature Ed25519, clé privée uniquement sur l'API |
| Ticket volé (journaux, extension de navigateur) | Jamais dans une URL, jamais journalisé ; durée de vie courte ; limité à un `tid`/`fid` et une opération |
| Ticket rejoué sur un autre fichier | `fid`/`tid` du ticket comparés au chemin |
| Réécriture de parts par un détenteur du ticket | Parts figées dès `complete` ; les données étant chiffrées côté client, une altération est détectée au déchiffrement |
| Traversée de chemin | Les chemins sont construits à partir de `Uuid` typés, jamais de chaînes reçues |
| Écrasement d'un fichier existant | `RENAME_NOREPLACE` à la finalisation |
| Lecture d'un fichier non terminé | Seul `FM_DATA_DIR/<fid>.enc` est servi, jamais `.cdn-uploads/` |
| Saturation du disque | Taille fixée par le ticket, quota vérifié par l'API, préallocation, réserve d'espace libre |
| Saturation de la mémoire | Budget des tampons + contre-pression |
| Slowloris, connexions fantômes | Délais d'en-têtes et d'inactivité, plafond de connexions |
| Requêtes internes forgées | Écouteur sur `127.0.0.1`, HMAC avec horodatage |
| Compromission du CDN | Aucune clé de contenu, aucune clé de signature, aucun accès à la base : l'attaquant obtient des octets chiffrés |
| Sniffing du navigateur | Toujours `application/octet-stream`, `nosniff`, `attachment` |

## Journaux

- Format JSON (tracing), une ligne par requête : route, `tid`/`fid`, `sub`,
  statut, octets, durée.
- Jamais : ticket, en-tête `Authorization`, contenu, nom de fichier en clair
  (il n'est d'ailleurs jamais transmis au CDN).

## Chaîne d'approvisionnement

- `Cargo.lock` versionné, `cargo deny` en CI (licences, doublons, sources)
  et `cargo audit` (vulnérabilités connues).
- Toute nouvelle dépendance, ou nouvelle version, doit être publiée depuis
  au moins 7 jours.
- Version minimale de Rust fixée (`rust-toolchain.toml`).
