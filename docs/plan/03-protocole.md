# 03 — Protocole HTTP

Deux écouteurs :

| Écouteur | Adresse par défaut | Exposé | Usage |
|----------|--------------------|--------|-------|
| Public | `127.0.0.1:9100` (derrière nginx) | `https://cdn.synco.one` | Clients |
| Interne | `127.0.0.1:9101` | Jamais | synco_api, Prometheus |

Toutes les routes publiques exigent `Authorization: Bearer <ticket>`, sauf
`OPTIONS` et `/healthz`.

## Routes publiques

### `POST /v1/uploads` — ouvrir (ou reprendre) une session d'envoi

Ticket `op=up`. Idempotent : rappeler la route pour un `tid` existant renvoie
l'état courant au lieu d'en créer un nouveau.

À l'ouverture, le CDN :
- vérifie l'espace libre (taille + réserve minimale), sinon `507` ;
- crée `<tid>.data` et le **préalloue** à sa taille finale (`fallocate`) :
  pas de fragmentation, et pas de disque plein au milieu de l'envoi ;
- écrit `<tid>.session` et `<tid>.parts`.

Réponse `201` (création) ou `200` (reprise) :

```json
{ "tid": "…", "size": 1073741840, "partSize": 4194320, "partCount": 256,
  "receivedParts": [[0, 41], [57, 57]], "expiresAt": 1759230000 }
```

`receivedParts` est une liste de plages inclusives : compacte même pour des
dizaines de milliers de parts.

### `PUT /v1/uploads/{tid}/part` — envoyer une part

| En-tête | Obligatoire | Sens |
|---------|-------------|------|
| `X-Part-Index` | oui | Index de la part (0 à `partCount - 1`) |
| `Content-Length` | oui en HTTP/1.1 | Doit valoir la taille attendue de cette part |
| `X-Part-Sha256` | non | Empreinte des octets ; vérifiée si présente |

Corps : octets bruts (`application/octet-stream`).

**Pourquoi l'index est dans un en-tête et pas dans l'URL** : le navigateur met
en cache la réponse CORS préalable (`OPTIONS`) par URL. Avec l'index dans
l'URL, chaque part déclencherait une requête `OPTIONS` de plus, soit deux
fois plus de requêtes. Avec une URL fixe par envoi, une seule suffit.

Réponses :
- `204` : part écrite (ou déjà reçue : le corps est ignoré sans réécrire le
  disque, ce qui rend les réessais gratuits) ;
- `400 bad_part_length` : taille différente de celle attendue (la part n'est
  pas marquée reçue) ;
- `409 part_in_progress` : la même part est déjà en cours d'écriture ;
- `409 upload_completing` : la finalisation a commencé ;
- `422 part_checksum_mismatch` : `X-Part-Sha256` ne correspond pas ;
- `429 too_many_parts_in_flight` avec `Retry-After` : plus de 8 parts de ce
  transfert en cours d'écriture (contre-pression, pas une limite de débit).

### `GET /v1/uploads/{tid}` — état de la session

Même corps que la réponse d'ouverture. Sert à la reprise après une coupure.

### `POST /v1/uploads/{tid}/complete` — finaliser

1. Vérifie que toutes les parts sont reçues et qu'aucune n'est en cours.
2. `fdatasync` du fichier, puis `rename` vers `FM_DATA_DIR/<fid>.enc` **sans
   écrasement** (`RENAME_NOREPLACE`), puis `fsync` du répertoire.
3. Appelle synco_api (`POST /internal/cdn/uploads/{tid}/complete`) avec la
   taille et l'empreinte du fichier.
4. Renvoie tel quel le JSON de métadonnées renvoyé par l'API.

Idempotent : si la finalisation a déjà réussi, le résultat mémorisé est
renvoyé. Si l'API est injoignable, le fichier reste en place, l'état
« rappel en attente » est persisté, et le client reçoit `503` avec
`Retry-After` ; un nouvel appel reprend au rappel, sans refaire les étapes
disque.

Empreinte du fichier : `sha256p:` suivi du SHA-256 de la concaténation des
SHA-256 de chaque part. Calculée sans relire le fichier, puisque chaque
empreinte de part est calculée à l'écriture.

### `DELETE /v1/uploads/{tid}` — abandonner

Supprime les fichiers de la session et prévient l'API (libération du quota
réservé). `204`.

### `GET` et `HEAD /v1/files/{fid}` — lire un fichier

Ticket `op=down` dont `fid` correspond.

- Pas de `Range` : `200`, fichier complet.
- Une plage (`bytes=a-b`, `bytes=a-`, `bytes=-n`) : `206` avec
  `Content-Range`.
- Plusieurs plages : `416`. Le client n'en demande jamais, et une réponse
  `multipart/byteranges` n'apporterait rien.
- Plage hors du fichier : `416` avec `Content-Range: bytes */<taille>`.
- Fichier modifié depuis l'émission du ticket (`size` ou `mtime` différents) :
  `409 file_changed`.

En-têtes de réponse :

```
Content-Type: application/octet-stream
Content-Disposition: attachment
Accept-Ranges: bytes
ETag: "<fid>-<size>-<mtime>"
Cache-Control: private, no-store
X-Content-Type-Options: nosniff
```

Le contenu est toujours du chiffré opaque : jamais de type MIME réel, jamais
d'affichage `inline`.

### `GET /healthz`

`200 ok` si le processus répond. Sans authentification, sans détail.

## Routes internes (écouteur `127.0.0.1:9101`)

Authentifiées par HMAC-SHA256 avec un secret partagé API ↔ CDN (au moins
32 octets, en hexadécimal dans la configuration). Chaque requête, dans les
deux sens, porte :

| En-tête | Valeur |
|---------|--------|
| `X-Synco-Timestamp` | secondes Unix ; refusé au-delà de ±60 s (anti-rejeu) |
| `X-Synco-Signature` | HMAC-SHA256 hexadécimal de `MÉTHODE "\n" CHEMIN "\n" HORODATAGE "\n" CORPS` |

`CHEMIN` est le chemin sans paramètres (`/internal/v1/revocations`),
`CORPS` les octets exacts du corps (vide pour un `DELETE`). La comparaison
se fait en temps constant. Une signature invalide renvoie `403 bad_signature`.

| Route | Appelant | Effet |
|-------|----------|-------|
| `POST /internal/v1/revocations` | synco_api | Révoque les tickets d'un `sub` émis avant `until` |
| `DELETE /internal/v1/uploads/{tid}` | synco_api | Annule une session d'envoi |
| `GET /readyz` | supervision | `200` si le stockage est accessible en écriture et que l'espace libre dépasse la réserve |
| `GET /metrics` | Prometheus | Métriques (cf. [08](08-exploitation.md#métriques)) |

## Routes appelées par le CDN sur synco_api

Toutes signées avec le même schéma HMAC.

`POST {API_INTERNAL_URL}/internal/cdn/uploads/{tid}/abort` (corps `{}`) :
le client a abandonné l'envoi, ou la session a expiré ; l'API libère le
quota réservé. Au mieux : un échec est seulement journalisé.

`POST {API_INTERNAL_URL}/internal/cdn/uploads/{tid}/complete` :

```json
{ "tid": "…", "fid": "…", "size": 1073741840, "hash": "sha256p:…" }
```

Réponses attendues : `201` ou `200` avec les métadonnées ; `4xx` (hors
`429`) si l'API refuse (transfert inconnu, expiré ou droits retirés) : le
CDN supprime alors le fichier. `5xx`, `429` ou absence de réponse : trois
tentatives (délais 200 ms et 800 ms), puis `503` au client ; le balayage
périodique rappelle ensuite l'API toutes les minutes jusqu'à une réponse
définitive. Détails côté API dans [06](06-integration-synco-api.md).

## CORS

- Origines autorisées : liste blanche en configuration, reprise de
  `allowedOrigins` de synco_api (web, Tauri, Capacitor).
- En-têtes autorisés : `Authorization`, `Content-Type`, `Range`,
  `X-Part-Index`, `X-Part-Sha256`.
- En-têtes exposés : `Content-Range`, `Content-Length`, `Accept-Ranges`,
  `ETag`, `Retry-After`.
- `Access-Control-Max-Age: 7200` (plafond de Chromium).
- Pas de cookies (`credentials` inutiles : le ticket est dans un en-tête).
- Origine non autorisée : réponse sans en-têtes CORS, le navigateur bloque.

## Codes d'erreur

| Statut | `error` | Cas |
|--------|---------|-----|
| 400 | `bad_part_index`, `bad_part_length`, `bad_part_checksum`, `body_error` | Part invalide ou interrompue ; non marquée reçue |
| 401 | `ticket_missing`, `ticket_invalid`, `ticket_unknown_key`, `ticket_expired`, `ticket_revoked` | Ticket refusé |
| 403 | `ticket_wrong_operation`, `ticket_wrong_target`, `cors_forbidden` | Ticket valide mais hors périmètre, origine refusée |
| 404 | `upload_not_found`, `file_not_found`, `not_found` | Ressource inconnue |
| 405 | `method_not_allowed` | Méthode non acceptée |
| 408 | `body_timeout` | Plus aucun octet reçu pendant `timeouts.body_idle` |
| 409 | `part_in_progress`, `parts_in_progress`, `parts_missing` | À réessayer plus tard |
| 409 | `upload_completing`, `upload_finalized`, `upload_mismatch`, `upload_rejected`, `file_exists`, `file_changed` | Conflit d'état, définitif |
| 416 | `range_not_satisfiable` | Plage hors du fichier (`Content-Range: bytes */<taille>`) |
| 422 | `part_checksum_mismatch` | `X-Part-Sha256` ne correspond pas |
| 429 | `too_many_parts_in_flight` | Contre-pression, avec `Retry-After` |
| 503 | `api_unavailable`, `upload_initializing`, `too_many_sessions`, `not_ready` | Transitoire, avec `Retry-After` |
| 507 | `insufficient_storage` | Réserve d'espace disque atteinte |

## Format des erreurs

```json
{ "error": "ticket_expired", "message": "Le ticket a expiré." }
```

`error` est un code stable, utilisé par le client ; `message` est lisible et
ne contient jamais de chemin, de nom de fichier ni de détail interne.
