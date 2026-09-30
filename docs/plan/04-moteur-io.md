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
2. **Écriture vectorielle, sans copie.** Le réseau livre le corps par
   fragments (`Bytes` de hyper, comptés par référence). Ils sont regroupés
   en lots d'environ 1 Mio, écrits par un seul `pwritev` : un appel système
   par Mio, et aucun octet recopié en espace utilisateur. (Une première
   version copiait les fragments dans un tampon ; le profil montrait 40 %
   du temps CPU en `memmove`.)
3. **Double lot.** Pendant qu'un lot est écrit dans le pool bloquant, le
   suivant se remplit depuis le socket. Réseau et disque travaillent en
   parallèle, avec au plus deux lots par part en vol.
4. **Lecture sans mise à zéro.** Les téléchargements lisent (`pread`)
   directement dans la capacité libre du tampon, sans l'initialiser
   (15 % du temps CPU dans la première version).
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
2. lecture positionnelle (`pread`) de blocs de 1 Mio dans le pool
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

## Mesures (première version)

`cargo run --release --example bench` : client et serveur dans le même
processus, boucle TCP locale, parts de 4 Mio + 16 octets.
Machine : Ryzen 5 5600X (12 threads), NVMe Crucial P3, btrfs.

| Scénario | Envoi | Téléchargement |
|----------|-------|----------------|
| Référence disque (`dd`, 2 Gio, `fdatasync`) | 2,7 Gio/s | — |
| 16 fichiers × 256 Mio, 8 parts en vol, HTTP/1.1, NVMe | 1,8 Gio/s | 4,0 Gio/s |
| 8 fichiers × 256 Mio, 4 parts en vol, HTTP/2, NVMe | 1,7 Gio/s | 1,4 Gio/s |
| 8 fichiers × 256 Mio, 8 parts en vol, HTTP/1.1, en RAM (tmpfs) | 2,9 Gio/s | 4,5 Gio/s |

Pendant ces mesures, 84 % du temps CPU est dans le noyau (boucle TCP
locale des deux côtés, système de fichiers) et le processus n'occupe que
5 cœurs sur 12 : le moteur du CDN n'est pas le facteur limitant. En
production, derrière une carte 10 Gbit/s (≈ 1,16 Gio/s), le débit sera
borné par le réseau. Le reste du temps CPU utilisateur est surtout le
SHA-256 des parts (accéléré SHA-NI).

À refaire sur la machine de production, avec un client distant, pour les
objectifs ci-dessous.

## Objectifs chiffrés

Mesurés selon la méthode décrite dans [09](09-tests-benchmarks.md#benchmarks) :

| Mesure | Objectif |
|--------|----------|
| Débit d'envoi (8 parts en parallèle, un client) | ≥ 90 % de min(débit disque `fio`, débit réseau `iperf3`) |
| Débit de téléchargement | ≥ 90 % de min(lecture disque, réseau) |
| 1 000 envois simultanés | aucune erreur, mémoire ≤ budget + 64 Mio |
| Latence de traitement d'une part de 4 Mio (hors réseau), p99 | ≤ temps d'écriture disque de 4 Mio + 5 ms |
| CPU | ≤ 1 cœur par Go/s transféré |
