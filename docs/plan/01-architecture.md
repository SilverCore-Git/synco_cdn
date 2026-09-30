# 01 — Architecture

## Rôle et frontières

Le CDN fait exactement quatre choses :

1. vérifier un ticket signé par synco_api ;
2. recevoir les parts d'un envoi et les écrire à leur position dans le fichier ;
3. servir des plages d'octets d'un fichier stocké ;
4. à la fin d'un envoi, prévenir synco_api.

Il ne fait **jamais** : vérifier des droits, lire la base de données, calculer
un quota, chiffrer ou déchiffrer un contenu, émettre des événements socket.
Tout ce qui demande une décision métier est déjà tranché au moment où l'API
signe le ticket.

Conséquence : le CDN n'a besoin ni de la base, ni de Keycloak, ni de la clé
maîtresse `FM_ENCRYPT_KEY`. Une compromission du CDN expose des octets
chiffrés, pas des clés.

## Cycle de vie d'un envoi

```
client                      synco_api                        synco_cdn
  │ POST /api/cdn/transfers/uploads │                              │
  │ (espace, taille, clé emballée)  │                              │
  │────────────────────────────────▶│ droits, quota réservé        │
  │                                 │ (ligne CdnTransfer en base)  │
  │◀──── { cdnUrl, ticket, tid } ───│                              │
  │                                                                │
  │ POST /v1/uploads   (Bearer ticket)  ─────────────────────────▶ │ session créée,
  │                                                                │ fichier préalloué
  │ PUT /v1/uploads/{tid}/part  × N, en parallèle  ──────────────▶ │ pwrite à l'offset
  │                                                                │
  │ POST /v1/uploads/{tid}/complete  ────────────────────────────▶ │ toutes les parts ?
  │                                                                │ fdatasync, rename
  │                                 │◀── POST /internal/cdn/uploads/{tid}/complete
  │                                 │ StoredFile créé, quota libéré,
  │                                 │ socket « file-added »
  │                                 │──── métadonnées ────────────▶│
  │◀──────────────────────────── métadonnées du fichier ───────────│
```

## Cycle de vie d'un téléchargement

```
client                      synco_api                        synco_cdn
  │ GET /api/cdn/meta/{id}           │                              │
  │─────────────────────────────────▶│ droits (canAccessStoredFile) │
  │◀── métadonnées + { cdnUrl, ticket } (fichier E2EE v2)           │
  │                                                                 │
  │ GET /v1/files/{fid}  Range: bytes=a-b  × N, en parallèle  ────▶ │ pread, streaming
  │◀──────────────────────────────── 206 Partial Content ───────────│
```

Le ticket de téléchargement est joint à la réponse `/meta`, qui est déjà
appelée aujourd'hui : aucun aller-retour de plus.

## Modules

```
src/
├── main.rs            démarrage : config, journaux, runtime, écouteurs, arrêt propre
├── config.rs          chargement et validation de la configuration (échec au démarrage, jamais après)
├── error.rs           CdnError : une seule énumération, correspondance vers les codes HTTP
├── ticket.rs          analyse et vérification des tickets — pur, sans E/S, fuzzé
├── range.rs           analyse de l'en-tête Range — pur, fuzzé
├── limits.rs          sémaphores : connexions, budget mémoire, parts par transfert
├── metrics.rs         compteurs et histogrammes Prometheus
├── api_client.rs      rappel vers synco_api (signé HMAC, délais, réessais)
├── http/
│   ├── mod.rs         routeur, couches (délais, capture de panique, journaux)
│   ├── cors.rs        CORS strict, origines en liste blanche
│   ├── uploads.rs     POST/PUT/GET/DELETE des sessions d'envoi
│   ├── downloads.rs   GET/HEAD des fichiers, Range
│   ├── internal.rs    écouteur interne : métriques, révocations, annulations
│   └── health.rs      /healthz, /readyz
└── storage/
    ├── mod.rs         trait Storage (permet une implémentation io_uring plus tard)
    ├── layout.rs      chemins : identifiants typés (Uuid), jamais de chaîne libre
    ├── session.rs     état d'une session d'envoi, table des parts, persistance
    ├── writer.rs      écriture d'une part : coalescence, pwrite, SHA-256
    ├── reader.rs      lecture positionnelle en streaming, lecture anticipée
    ├── recovery.rs    rechargement des sessions au démarrage
    └── space.rs       espace disque libre, préallocation
```

`ticket.rs` et `range.rs` ne font aucune E/S : ce sont les deux points où des
octets non fiables sont analysés, ils sont isolés pour être testés
exhaustivement et fuzzés.

## Modèle de threads

Un seul processus, deux familles de threads :

| Pool | Taille | Travail |
|------|--------|---------|
| Workers tokio | 1 par cœur | Sockets, HTTP/1.1 et HTTP/2, vérification des tickets, routage |
| Pool bloquant tokio | ~2 × cœurs (réglable) | `pwrite`, `pread`, `fdatasync`, SHA-256 |

Pourquoi un pool séparé pour le disque : les appels disque de Linux sont
bloquants (hors io_uring). Les faire sur un worker figerait toutes les
connexions de ce cœur. Dans le pool bloquant, un disque lent ralentit
seulement les transferts qui l'attendent.

La vérification Ed25519 (~50 µs) reste sur les workers : elle n'a lieu
qu'une fois par requête et ne justifie pas un changement de thread.

Le SHA-256 d'une part est calculé dans la même tâche bloquante que son
écriture, pendant que les données sont encore dans le cache du processeur.

## État partagé

Tous les threads partagent la même mémoire : l'état des sessions vit dans une
table concurrente (`DashMap<Tid, Arc<UploadSession>>`). Pas de verrou global,
et les compteurs chauds (parts reçues, parts en cours) sont atomiques.

L'état est aussi **persisté sur disque**, pour survivre à un redémarrage
(détails dans [05](05-robustesse-securite.md#reprise-après-redémarrage)) :

```
FM_DATA_DIR/
├── <fid>.enc                    fichiers terminés (partagés avec synco_api)
└── .cdn-uploads/
    ├── <tid>.data               fichier en cours, préalloué à sa taille finale
    ├── <tid>.session            contenu du ticket d'ouverture (JSON, fsync)
    └── <tid>.parts              1 octet par part (0 = absente, 1 = reçue) + SHA-256 de chaque part
```

`.cdn-uploads` est sur le même système de fichiers que les fichiers
terminés (vérifié au démarrage), pour que la finalisation soit un simple
`rename`.

## Ce que le CDN ne sait pas faire, volontairement

- **Anciens fichiers SSE** : servis par synco_api, qui détient la clé.
- **Envois sans chiffrement de bout en bout** (utilisateur sans code PIN
  déverrouillé) : restent sur la route d'envoi par morceaux de synco_api,
  qui chiffre côté serveur.
- **Aperçus par URL** (`<img src>`) : impossibles avec un ticket en en-tête,
  et inutiles pour des fichiers E2EE, déjà déchiffrés en `blob:` côté client.
