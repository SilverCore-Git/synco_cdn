# 02 — Tickets

Un ticket est une autorisation courte, signée par synco_api, pour **une
opération sur un transfert**. Le CDN le vérifie avec la clé publique de
l'API, sans appel réseau ni base de données.

## Pourquoi pas un JWT

- Pas de champ `alg` à négocier : pas de confusion d'algorithme possible
  (`none`, HS256 signé avec la clé publique…).
- Signature et vérification disponibles nativement : `node:crypto`
  (Ed25519) côté API, `ed25519-dalek` côté Rust. Aucune bibliothèque JWT à
  maintenir des deux côtés.
- Format fixe, court, analysable en quelques lignes et facile à fuzzer.

## Pourquoi Ed25519 plutôt qu'un secret partagé

Avec un secret partagé (HMAC), le CDN pourrait fabriquer des tickets. Avec
Ed25519, il ne détient que la clé publique : une compromission du CDN ne
permet pas de s'autoriser d'autres fichiers.

## Format

```
sct1.<kid>.<payload>.<signature>
```

| Partie | Contenu |
|--------|---------|
| `sct1` | Version du format. Tout autre préfixe est refusé. |
| `kid` | Identifiant de la clé de signature (`[a-z0-9-]{1,32}`), pour la rotation. |
| `payload` | JSON compact encodé en base64url sans remplissage. |
| `signature` | Ed25519 (64 octets), base64url sans remplissage. |

Octets signés (séparation de domaine, pour qu'une signature de ticket ne
soit jamais valable dans un autre contexte) :

```
"synco-cdn-ticket\x00" || "sct1." || kid || "." || payload
```

Longueur maximale d'un ticket : 2 048 octets. Au-delà, refus avant tout
décodage.

## Champs

Communs :

| Champ | Type | Sens |
|-------|------|------|
| `op` | `"up"` \| `"down"` | Opération autorisée |
| `tid` | UUID | Identifiant du transfert |
| `fid` | UUID | Fichier concerné (à créer pour `up`, à lire pour `down`) |
| `sub` | chaîne ≤ 64 | Utilisateur, pour les journaux et les révocations |
| `iat` | entier (s) | Émission |
| `exp` | entier (s) | Expiration |

Envoi (`up`) :

| Champ | Type | Sens |
|-------|------|------|
| `size` | entier | Taille exacte du fichier stocké, en octets |
| `psz` | entier | Taille d'une part (la dernière est plus courte) |

Téléchargement (`down`) :

| Champ | Type | Sens |
|-------|------|------|
| `size` | entier | Taille du fichier au moment de l'émission |
| `mtime` | chaîne décimale (ns) | Date de modification du fichier au moment de l'émission. Chaîne et non nombre : les nanosecondes dépassent la précision des nombres JSON en JavaScript. Côté API : `fs.statSync(p, { bigint: true }).mtimeNs.toString()` |

`size` et `mtime` permettent au CDN de détecter un fichier modifié entre
l'émission du ticket et la lecture (édition, réenvoi) : les plages lues
viendraient sinon de deux versions différentes. En cas d'écart, le CDN
répond `409 file_changed` et le client redemande un ticket.

Désérialisation stricte : champs inconnus refusés, types exacts, UUID
validés, `psz` dans [64 Kio, 64 Mio], `size` ≤ limite de configuration,
nombre de parts ≤ 100 000.

## Vérification (ordre)

1. Longueur ≤ 2 048, quatre parties, préfixe `sct1`.
2. `kid` connu (sinon `401 unknown_key`).
3. Signature valide, **avant** tout décodage du JSON.
4. JSON strict.
5. `iat - 30 s ≤ maintenant < exp + 30 s` (tolérance d'horloge).
6. `op` correspond à la route ; `tid`/`fid` correspondent au chemin.
7. `sub` et `tid` absents de la liste de révocation.

Chaque échec renvoie `401` avec un code machine (`ticket_expired`,
`ticket_invalid`…), jamais le détail interne.

## Durée de vie et renouvellement

| Ticket | Durée | Renouvellement |
|--------|-------|----------------|
| Envoi | 1 h | `POST /api/cdn/transfers/uploads/{tid}/renew` : l'API revérifie les droits et signe un nouveau ticket pour le même `tid` |
| Téléchargement | 15 min | Nouveau `GET /api/cdn/meta/{id}` |

Le client renouvelle 5 minutes avant `exp`, ou sur un `401 ticket_expired`
(une seule fois, puis erreur). Un envoi de plusieurs heures reste donc
couvert, et une perte de droits prend effet au plus tard au renouvellement
suivant.

## Révocation

Pour les cas qui ne peuvent pas attendre l'expiration :

- **Bannissement d'un compte** : l'API envoie
  `POST /internal/v1/revocations { sub, until }`. Le CDN refuse tout ticket
  de ce `sub` émis avant `until`.
- **Annulation d'un envoi par l'API** : `DELETE /internal/v1/uploads/{tid}`.

La liste de révocation est en mémoire, bornée, et chaque entrée expire
après la durée de vie maximale d'un ticket. Elle est persistée dans
`.cdn-uploads/revocations.json` pour survivre à un redémarrage.

## Rotation des clés

Le CDN charge un ensemble de clés publiques (`kid → clé`). Procédure :

1. Générer une nouvelle paire et ajouter la clé publique au CDN (rechargement
   sans redémarrage via `SIGHUP`).
2. Faire signer l'API avec la nouvelle clé.
3. Après la durée de vie maximale d'un ticket (1 h), retirer l'ancienne clé.

## Implémentation de référence côté API

[`tests/vectors/generate.mjs`](../../tests/vectors/generate.mjs) signe des
tickets avec `node:crypto` seul : c'est le code à reprendre dans
`synco_api/src/cdn/cdnTickets.ts`. Une clé privée Ed25519 brute de 32
octets s'importe en la préfixant de l'en-tête PKCS#8
`302e020100300506032b657004220420`.

## Vecteurs de test partagés

`tests/vectors/tickets.json` contient des tickets valides et invalides
(signature altérée, `kid` inconnu, expiré, champ inconnu, trop long…) avec
le résultat attendu. La même suite est exécutée par le CDN (Rust) et par
synco_api (TypeScript), ce qui garantit que les deux implémentations
restent compatibles.
