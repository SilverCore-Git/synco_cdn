# 06 — Intégration synco_api

synco_api garde toutes les décisions : droits, quota, métadonnées,
événements. Ce document liste ce qui change de son côté.

## Nouvelle table : `CdnTransfer`

Remplace les sessions et les réservations de quota gardées en mémoire
(`src/cdn/uploadSessions.ts`, `src/cdn/storageQuota.ts`), qui ne survivent
pas à un redémarrage et ne tiendraient pas avec plusieurs processus.

```prisma
model CdnTransfer {
  id          String   @id              // tid, porté par le ticket
  fileId      String   @unique          // fid : id du futur StoredFile
  ownerId     String
  orgId       String
  size        BigInt                    // taille stockée, compte dans le quota
  partSize    Int
  // Contexte de rangement et E2EE, recopié tel quel dans StoredFile
  workspaceId      String?
  folderId         String?
  messageId        String?
  dmMessageId      String?
  taskId           String?
  originalName     String   /// @encrypted
  mimeType         String
  encryptedFileKey String   @db.Text
  keyVersion       Int
  iv               String
  status      CdnTransferStatus @default(OPEN)   // OPEN | COMPLETED | ABORTED
  expiresAt   DateTime
  createdAt   DateTime @default(now())

  @@index([orgId, status])
  @@index([expiresAt])
  @@map("cdn_transfers")
}
```

## Quota

Espace utilisé d'une organisation = `SUM(StoredFile.size)` +
`SUM(CdnTransfer.size WHERE status = OPEN AND expiresAt > now)`.

Le contrôle et la création du `CdnTransfer` se font dans une transaction
Prisma interactive en isolation `Serializable`, rejouée sur conflit
(`P2034`). Deux ouvertures simultanées ne peuvent donc plus dépasser la
limite ensemble, même après un redémarrage et même avec plusieurs
processus. Aucune requête SQL brute.

## Routes clientes

### `POST /api/cdn/transfers/uploads`

Corps : celui de l'actuel `POST /api/cdn/uploads` (org, espace, dossier,
nom, type, taille, taille des parts, `encryptedFileKey`, `keyVersion`,
`iv`), avec `isE2EE` obligatoirement vrai.

1. `resolveUploadTarget` (déjà factorisé) : droits, module Fichiers,
   conteneur de destination.
2. Transaction quota + création du `CdnTransfer`.
3. Signature d'un ticket `up`.

Réponse : `{ cdnUrl, ticket, tid, expiresAt }`.

### `POST /api/cdn/transfers/uploads/:tid/renew`

Propriétaire du transfert uniquement ; `resolveUploadTarget` rejoué (droits
retirés entre-temps = `403`, et annulation côté CDN). Prolonge `expiresAt`
et renvoie un nouveau ticket.

### `GET /api/cdn/meta/:id` (existante, enrichie)

Pour un fichier E2EE au format v2 (`iv` commençant par `v2:`), ajoute :

```json
"download": { "cdnUrl": "https://cdn.synco.one", "ticket": "sct1.…", "expiresAt": … }
```

`size` et `mtime` du ticket viennent d'un `fs.stat` du fichier (même
machine). Aucun aller-retour supplémentaire pour le client.

## Route interne appelée par le CDN

`POST /internal/cdn/uploads/:tid/complete`, montée **avant**
`authMiddleware`, protégée par :
- vérification HMAC (secret `CDN_INTERNAL_SECRET`) et horodatage ±60 s ;
- accessible uniquement depuis l'adresse locale.

Traitement, idempotent sur `tid` :
1. `CdnTransfer` introuvable, expiré ou annulé : `409` (le CDN supprime le
   fichier).
2. Déjà `COMPLETED` : renvoie le `StoredFile` existant.
3. Taille reçue différente de `CdnTransfer.size` : `409`.
4. `resolveUploadTarget` rejoué (droits retirés pendant l'envoi : `409`).
5. Transaction : création du `StoredFile` (id = `fileId`, `isE2EE = true`,
   `hash` reçu du CDN) et passage du transfert en `COMPLETED`.
6. Émission socket `file-added`, réponse `201` avec les métadonnées.

## Appels de l'API vers le CDN

Client HMAC minimal (`src/cdn/cdnClient.ts`) vers l'écouteur interne :

| Événement côté API | Appel |
|--------------------|-------|
| Bannissement d'un compte (`banService`) | `POST /internal/v1/revocations { sub, until: now }` |
| Renouvellement refusé, droits retirés | `DELETE /internal/v1/uploads/:tid` |

En cas d'échec, l'appel est journalisé et n'échoue pas l'opération de
l'API : les tickets expirent de toute façon en 1 h au plus.

## Nettoyage

Tâche périodique (toutes les 10 min) : les `CdnTransfer` `OPEN` expirés
passent en `ABORTED` (quota libéré). Le CDN supprime de son côté les
sessions expirées.

## Signature des tickets

`src/cdn/cdnTickets.ts`, avec `node:crypto` uniquement :
- clé privée Ed25519 en PEM, dans `CDN_TICKET_PRIVATE_KEY` et
  `CDN_TICKET_KID` ; démarrage refusé si absente quand `CDN_URL` est définie ;
- exécution de la suite de vecteurs de test partagée
  (`synco_cdn/tests/vectors/tickets.json`) dans les tests de l'API.

## Configuration ajoutée

| Variable | Exemple |
|----------|---------|
| `CDN_URL` | `https://cdn.synco.one` (absente = CDN désactivé, comportement actuel) |
| `CDN_INTERNAL_URL` | `http://127.0.0.1:9101` |
| `CDN_INTERNAL_SECRET` | 32 octets aléatoires, hex |
| `CDN_TICKET_KID` | `2026-10` |
| `CDN_TICKET_PRIVATE_KEY` | PEM Ed25519 |

## Ce qui reste inchangé

- Anciens fichiers SSE : `GET /api/cdn/download/:id`, déchiffrement serveur.
- Envois non E2EE : route d'envoi par morceaux actuelle
  (`/api/cdn/uploads`), chiffrement serveur.
- Suppression, déplacement, renommage, édition de contenu, OnlyOffice.
- `canAccessStoredFile`, `resolveUploadTarget` : réutilisés tels quels.

## Retrait

Une fois le CDN en production et stable : suppression de
`uploadSessions.ts`, `storageQuota.ts` (remplacé par le quota en base) et
de la route E2EE par morceaux de l'API. La route reste pour les envois non
E2EE.
