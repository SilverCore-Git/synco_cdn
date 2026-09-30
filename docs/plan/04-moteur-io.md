# 04 — Moteur d'E/S et performance

Objectif : le débit n'est limité que par le disque et le réseau, avec une
mémoire bornée et prévisible quelle que soit la charge.

## Principes

1. **Écriture positionnelle.** Chaque part est écrite directement à sa place
   dans le fichier final (`pwrite`, via `FileExt::write_at` de la
   bibliothèque standard). Pas de fichier temporaire par part, pas
   d'assemblage, pas de copie finale. Plusieurs threads écrivent des parts
   différentes du même fichier en même temps sans verrou : `write_at` prend
   `&File` et Linux garantit des écritures positionnelles indépendantes.
2. **Coalescence.** Le réseau livre le corps par petits fragments (16 à 64
   Kio). Ils sont accumulés dans un tampon de 1 Mio avant chaque `pwrite` :
   un appel système par Mio au lieu d'un par fragment.
3. **Double tampon.** Pendant qu'un tampon est écrit dans le pool bloquant,
   le suivant se remplit depuis le socket. Réseau et disque travaillent en
   parallèle, avec au plus deux tampons par part en vol.
4. **Aucune copie inutile.** Les fragments sont des `Bytes` (comptés par
   référence) ; seule la coalescence copie, une fois, dans le tampon
   d'écriture.
5. **Préallocation.** `fallocate` à l'ouverture : les blocs sont réservés
   d'un coup, contigus autant que possible, et un disque plein est détecté
   avant le premier octet.

## Budget mémoire et contre-pression

Un sémaphore global représente le budget mémoire des tampons (par défaut
512 Mio, soit 512 jetons de 1 Mio). Pour remplir un tampon, une tâche doit
prendre un jeton.

Quand le disque est plus lent que le réseau :
1. les écritures s'accumulent, les jetons s'épuisent ;
2. les tâches arrêtent de lire leur socket en attendant un jeton ;
3. le contrôle de flux TCP (ou HTTP/2) ralentit l'émetteur.

Le client ralentit donc naturellement au rythme du disque, sans erreur et
sans que la mémoire du CDN augmente. C'est ce qui permet d'accepter des
milliers de transferts simultanés sans risque de manque de mémoire.

Même mécanisme pour les téléchargements : la lecture anticipée (deux blocs
de 1 Mio par réponse) prend des jetons, et un client lent n'immobilise que
deux blocs.

## Téléchargements

Chemin par défaut, entièrement en Rust :
1. ouverture du fichier une fois par requête, `fstat` (contrôle `size` et
   `mtime` du ticket) ;
2. lecture positionnelle (`read_at`) de blocs de 1 Mio dans le pool
   bloquant, deux blocs d'avance ;
3. envoi en streaming dans le corps de la réponse.

Variante à mesurer : **délégation à nginx**. Le CDN vérifie le ticket puis
répond avec `X-Accel-Redirect: /_cdn_files/<fid>.enc` ; nginx sert le
fichier par `sendfile` (du disque au socket dans le noyau, zéro copie,
`Range` géré nativement). Le benchmark de l'étape 3 tranche : si le chemin
Rust atteint la vitesse du réseau, il est gardé (moins de configuration
nginx) ; sinon la délégation devient le mode par défaut, activable par
configuration.

## Réglages HTTP

| Paramètre | Valeur | Raison |
|-----------|--------|--------|
| HTTP/2, fenêtre de flux | adaptative (BDP) | Les fenêtres par défaut (64 Kio) plafonnent le débit sur un lien à forte latence : à 50 ms de RTT, 64 Kio donnent ~1,3 Mo/s par flux |
| HTTP/2, flux simultanés max | 256 | Assez pour tous les morceaux d'un client |
| HTTP/2, taille de trame max | 256 Kio | Moins d'en-têtes de trame par Mio |
| HTTP/1.1, keep-alive | oui | Une connexion réutilisée pour toutes les parts |
| Délai de lecture des en-têtes | 10 s | Anti-slowloris |
| Délai d'inactivité du corps | 30 s | Libère les envois bloqués |

Si nginx termine le TLS, ses propres réglages s'appliquent au lien client
(cf. [08](08-exploitation.md#nginx)) ; nginx parle ensuite HTTP/1.1 avec
keep-alive au CDN.

## Réglages du binaire

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "unwind"      # capture des paniques par requête (cf. 05)
debug = "line-tables-only"  # traces lisibles, profilage perf
```

- Allocateur `mimalloc` : moins de contention entre threads que l'allocateur
  système sur les allocations de tampons.
- SHA-256 via `sha2` avec instructions SHA-NI si présentes (≥ 1,5 Go/s par
  cœur) : jamais le goulot devant le disque.
- Ed25519 via `ed25519-dalek` : ~20 000 vérifications/s par cœur, négligeable
  (une par requête de 4 Mio).

## Taille des parts

La taille est choisie par le client et fixée dans le ticket. Le format E2EE
v2 utilise 4 Mio de clair (4 Mio + 16 octets chiffrés). Plus grand = moins
de requêtes et d'en-têtes, mais une part perdue coûte plus cher à renvoyer
et la progression est moins fine. Le benchmark de l'étape 6 compare 4, 8 et
16 Mio sur un lien réel ; le format accepte n'importe quelle valeur entre
64 Kio et 64 Mio.

## Évolution possible : io_uring

Le stockage passe par un trait `Storage`. Si les mesures montrent que le
pool bloquant devient le goulot (ce qui n'arrive en pratique qu'au-delà de
plusieurs Go/s sur NVMe), une implémentation io_uring pourra le remplacer
sans toucher au reste. Elle n'est pas prévue dans la première version :
elle ajoute de la complexité et les bibliothèques tokio + io_uring sont
moins mûres.

## Objectifs chiffrés

Mesurés selon la méthode décrite dans [09](09-tests-benchmarks.md#benchmarks) :

| Mesure | Objectif |
|--------|----------|
| Débit d'envoi (8 parts en parallèle, un client) | ≥ 90 % de min(débit disque `fio`, débit réseau `iperf3`) |
| Débit de téléchargement | ≥ 90 % de min(lecture disque, réseau) |
| 1 000 envois simultanés | aucune erreur, mémoire ≤ budget + 64 Mio |
| Latence de traitement d'une part de 4 Mio (hors réseau), p99 | ≤ temps d'écriture disque de 4 Mio + 5 ms |
| CPU | ≤ 1 cœur par Go/s transféré |
