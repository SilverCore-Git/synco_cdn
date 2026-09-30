# 07 — Intégration synco_app

Le gestionnaire de transferts actuel (`src/services/transfers/`) reste en
place : file d'attente, sémaphore de parts, réessais, annulation, panneau,
pool de workers de chiffrement. Seules les **cibles réseau** changent.

## Envoi (`chunkedUpload.ts`)

| Étape | Aujourd'hui | Avec le CDN |
|-------|-------------|-------------|
| Ouverture | `POST /api/cdn/uploads` | `POST /api/cdn/transfers/uploads` → ticket, puis `POST {cdnUrl}/v1/uploads` |
| Part | `PUT /api/cdn/uploads/:id/parts/:i` (jeton Keycloak) | `PUT {cdnUrl}/v1/uploads/:tid/part` + `X-Part-Index` (ticket) |
| Finalisation | `POST /api/cdn/uploads/:id/complete` | `POST {cdnUrl}/v1/uploads/:tid/complete` |
| Abandon | `DELETE /api/cdn/uploads/:id` | `DELETE {cdnUrl}/v1/uploads/:tid` |

Nouveau : un petit gestionnaire de ticket par transfert, qui :
- renouvelle 5 min avant `expiresAt` (un seul renouvellement à la fois,
  partagé par toutes les parts en vol) ;
- sur `401 ticket_expired`, renouvelle une fois puis rejoue la part.

`http.ts` : `putUploadPart` prend l'URL et le ticket au lieu du jeton
Keycloak. Le jeton Keycloak n'est plus envoyé au CDN.

Codes à traiter dans `withRetry` :
- `429 too_many_parts_in_flight` et `503` : réessai après `Retry-After` ;
- `409 part_in_progress` : réessai ;
- `507` : erreur définitive, message « espace de stockage du serveur
  insuffisant ».

Reprise : si l'envoi échoue au milieu (réseau coupé plus longtemps que les
réessais), le transfert passe en erreur avec une action « Reprendre » dans
le panneau, qui appelle `GET /v1/uploads/:tid` et renvoie les parts
manquantes. (Aujourd'hui, un échec abandonne la session.)

## Téléchargement (`chunkedDownload.ts`)

- `fetchMetadata` renvoie désormais `download.cdnUrl` et `download.ticket`
  pour les fichiers v2.
- `fetchFileRange` interroge `{cdnUrl}/v1/files/:fid` avec le ticket.
- `409 file_changed` : nouveau `GET /api/cdn/meta`, puis reprise du
  téléchargement depuis le début (les morceaux déjà lus viennent de
  l'ancienne version).

Les fichiers v1 et SSE restent sur l'API, sans changement.

## Fichiers non E2EE

Quand aucune clé d'espace n'est disponible, `prepareE2EE` renvoie `null` :
l'envoi reste sur la route de l'API (chiffrement serveur), comme
aujourd'hui.

## Politique de sécurité du contenu (CSP)

Ajouter `https://cdn.synco.one` à `connect-src` dans les deux copies de la
politique :
- `index.html` (web) ;
- `src-tauri/tauri.conf.json` (bureau).

Sans cette modification, le navigateur bloque silencieusement toutes les
requêtes vers le CDN.

## Bascule progressive

- `VITE_CDN_ENABLED` côté app, et `CDN_URL` côté API. Tant que l'API ne
  renvoie pas de ticket, le client garde les routes actuelles : les deux
  chemins coexistent.
- Mise en production : CDN d'abord, puis API (qui commence à délivrer des
  tickets), puis app. Retour arrière : retirer `CDN_URL` de l'API, les
  clients repassent sur l'ancien chemin sans redéploiement.

## Parts par fichier

Avec HTTP/2 (connexion unique multiplexée) vers le CDN, la limite de 6
connexions par domaine du navigateur ne s'applique plus. Les valeurs
actuelles (4 parts par fichier, 6 en vol au total) seront réévaluées au
benchmark de l'étape 6 ; point de départ envisagé : 6 par fichier, 12 au
total.
