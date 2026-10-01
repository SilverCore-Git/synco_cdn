# 06 — Intégration synco_api

> **Implémenté** dans synco_api (branche `feat/cdn`), code dans `src/cdn/`.

synco_api garde toutes les décisions : droits, quota, métadonnées,
événements. Le contenu des fichiers ne transite plus jamais par l'API.

**Tout fichier est chiffré de bout en bout** (format v2 par morceaux) et
transféré par le CDN. L'ancien système est supprimé : chiffrement serveur
(`FileCrypto`, `FM_ENCRYPT_KEY`), envoi en une requête et par morceaux via
l'API, `/download`, `/content`, `/content-e2ee`, `/disable-e2ee`,
OnlyOffice, jeton d'authentification en query string.

## Modèle de données

`StoredFile` :
- `blobId` (UUID, unique) : le contenu est dans `<FM_DATA_DIR>/<blobId>.enc`.
  Distinct de `id` : remplacer le contenu (édition) écrit un nouveau blob
  puis bascule `blobId`, sans changer l'identité du fichier (liens, tâches,
  références `<file:ID>`) ;
- `encryptedFileKey`, `keyVersion`, `iv` obligatoires ;
- retirés : `isEncrypted`, `isE2EE`, `encoding`, `forceDownload`,
  `onlyOfficeKey`.

`CdnTransfer` (`cdn_transfers`) : un envoi en cours.

| Champ | Rôle |
|-------|------|
| `id` | `tid` du ticket |
| `blobId` | `fid` du ticket : nom du blob sur disque |
| `fileId`, `replace` | Création : id du `StoredFile` à créer, fixé dès l'ouverture (finalisation idempotente). Remplacement : fichier existant |
| `ownerId`, `orgId`, destination | Rejoués par `resolveUploadTarget` à la finalisation |
| `size`, `partSize` | Taille exacte du chiffré (compte dans le quota) |
| `originalName`, `mimeType`, `encryptedFileKey`, `keyVersion`, `iv` | Recopiés dans `StoredFile` |
| `status` | `OPEN` → `COMPLETED` ou `ABORTED` |
| `expiresAt` | Expiration du ticket courant (renouvelable) |

## Quota

Espace utilisé = `Σ StoredFile.size` + `Σ CdnTransfer.size` (transferts
`OPEN`). Contrôle et création du transfert dans une transaction Prisma
interactive `Serializable`, rejouée sur conflit (`P2034`) : deux ouvertures
simultanées ne dépassent jamais la limite ensemble, même avec plusieurs
processus. Au plus 16 envois ouverts (non expirés) par utilisateur. Aucune
requête SQL brute.

## Routes clientes (`/api/cdn`)

| Route | Effet |
|-------|-------|
| `POST /transfers/uploads` | Nouveau fichier : `resolveUploadTarget`, validation du format v2, quota, ticket `up` |
| `POST /transfers/uploads/replace/:fileId` | Nouveau contenu d'un fichier : propriétaire, ou WRITE + UPLOAD |
| `POST /transfers/uploads/:tid/renew` | Propriétaire ; droits rejoués (retirés : `403`, transfert annulé ici et au CDN) ; nouveau ticket |
| `DELETE /transfers/uploads/:tid` | Abandon (annulé ici et au CDN) |
| `GET /meta/:id` | Métadonnées + `download: { url, ticket, expiresAt }` |
| `PATCH /meta/:id` | Renommage, déplacement |
| `DELETE /:id` | Ligne et blob |

Corps d'ouverture : `orgId`, destination (`workspaceId`, `folderId`,
`messageId`, `dmMessageId`, `taskId`), `fileName`, `mimeType`, `size`,
`partSize`, `encryptedFileKey`, `keyVersion`, `iv`. Refusé (`400`) si :
- `iv` n'est pas `v2:<chunkSize>:<préfixe de nonce de 8 octets>` ;
- `partSize` n'est pas un multiple de `chunkSize + 16` ;
- `size` n'est pas la taille d'un chiffré possible ;
- la géométrie sort des bornes du CDN ou de `CDN_MAX_FILE_BYTES`.

Réponse : `{ tid, fileId, cdnUrl, ticket, expiresAt, size, partSize,
partCount }`.

Le ticket de téléchargement (15 min) porte la taille et le `mtime` (ns) du
blob, lus par `fs.stat({ bigint: true })` au moment de `/meta`.

## Rappels du CDN : écouteur dédié

Sur un port à part, `CDN_CALLBACK_LISTEN` (par défaut `127.0.0.1:9002` ;
avec le CDN dans Docker, `172.17.0.1:9002`, joint via
`host.docker.internal`). Hors de l'API publique : jamais publié par nginx,
ni limiteurs de requêtes ni authentification utilisateur. Chaque requête est
signée HMAC (cf. [03](03-protocole.md)), vérifiée sur les octets exacts du
corps. Un filtre sur l'adresse source est impossible avec Docker (le
conteneur arrive par son réseau) : la signature est la protection.

`POST /internal/cdn/uploads/:tid/complete` `{ tid, fid, size, hash }`,
idempotent sur `tid` :

1. Transfert inconnu ou `ABORTED` : `409` (le CDN supprime le blob).
2. Déjà `COMPLETED` : `200` avec le fichier.
3. `fid` ou `size` différents du transfert : `409`, transfert annulé.
4. Droits rejoués (`resolveUploadTarget` ; pour un remplacement, fichier
   existant et droit d'écriture) : refus = `409`.
5. Transaction : `OPEN` → `COMPLETED` puis création du `StoredFile` (id
   fixé, `hash` du CDN). Pour un remplacement : bascule conditionnelle de
   `blobId` (sur l'ancien blob, rejouée si une autre édition est passée
   entre-temps), puis suppression de l'ancien blob.
6. Socket `file-added` (ou `file-updated`) ; `201` (ou `200`) avec les
   métadonnées, que le CDN transmet telles quelles au client.

Un transfert expiré mais encore `OPEN` est accepté : après une panne de
l'API, le CDN rappelle jusqu'à une réponse définitive, et refuser ferait
supprimer un fichier entièrement reçu.

Une erreur interne (base indisponible…) renvoie `500` : le CDN réessaie.

`POST /internal/cdn/uploads/:tid/abort` : `OPEN` → `ABORTED` (quota libéré).
`204`, ou `404` si inconnu.

## Appels de l'API vers le CDN

`src/cdn/cdnClient.ts`, HMAC, au mieux (échec journalisé seulement) :

| Événement | Appel |
|-----------|-------|
| Bannissement, suppression de compte, expulsion d'une organisation | `POST /internal/v1/revocations { sub, until: now }` |
| Renouvellement refusé, abandon par le client | `DELETE /internal/v1/uploads/:tid` |

## Entretien

Toutes les 10 minutes (idempotent, plusieurs processus possibles) :
- transferts `OPEN` expirés depuis plus de 3 h → `ABORTED` ;
- transferts terminés depuis plus de 7 jours : supprimés ;
- blobs orphelins (`<uuid>.enc` référencé ni par un `StoredFile` ni par un
  transfert `OPEN`, inchangé depuis 6 h) : supprimés. Couvre les
  suppressions en cascade (message, organisation, compte).

## Configuration

| Variable | Exemple |
|----------|---------|
| `CDN_URL` | `https://cdn.synco.one` |
| `CDN_INTERNAL_URL` | `http://127.0.0.1:9101` |
| `CDN_INTERNAL_SECRET` / `_FILE` | 32 octets aléatoires, hex |
| `CDN_TICKET_KID` | `2026-10` (`[a-z0-9-]`) |
| `CDN_TICKET_PRIVATE_KEY` / `_FILE` | PEM Ed25519 |
| `CDN_CALLBACK_LISTEN` | `172.17.0.1:9002` |
| `CDN_MAX_FILE_BYTES` | `10737418240` (≤ `limits.max_file_bytes` du CDN) |
| `FM_DATA_DIR` | Répertoire des blobs, partagé avec le CDN |

Toutes obligatoires (sauf les deux dernières) : l'API refuse de démarrer
sans.

## Tests

- `cdnTickets.test.ts` : les vecteurs de `tests/vectors/tickets.json`
  (copiés dans `src/cdn/testdata/`) sont re-signés à l'identique.
- `internalAuth.test.ts` : vecteur HMAC commun avec `internal_auth.rs`.
- `cdnTransfers.test.ts` : routes, rappels, quota concurrent, entretien.
- `cdnE2e.test.ts` : avec le vrai binaire (`CDN_E2E_BIN`).
