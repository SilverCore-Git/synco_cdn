# Fuzzing de synco_cdn

Le fuzzing envoie des millions d'entrées générées au code qui analyse des
données non fiables et vérifie qu'il ne plante jamais. Le fuzzer
(libFuzzer, via `cargo fuzz`) mute les entrées en suivant la couverture du
code : il garde celles qui atteignent de nouveaux chemins et les fait
évoluer.

## Cibles

| Cible | Code visé | Propriété vérifiée |
|-------|-----------|--------------------|
| `ticket` | `TicketVerifier::verify` sur une chaîne quelconque | Jamais de panique |
| `ticket_claims` | Désérialisation et validation des champs d'un ticket **correctement signé** | Tout ticket accepté respecte les bornes (tailles, parts, durée de vie, horloge) |
| `range` | Analyse de l'en-tête `Range` | Une plage acceptée est non vide et dans le fichier |
| `path` | Routage des chemins d'URL publics et internes | Seul un identifiant canonique est accepté |
| `config` | Chargement d'un fichier de configuration | Erreur explicite, jamais de panique |
| `session_record` | Relecture au démarrage d'un fichier de session corrompu | Ni panique ni allocation démesurée ; géométrie dans les bornes des tickets |

`ticket_claims` existe parce que `ticket` ne peut pas forger de signature :
sans elle, le fuzzer ne dépasserait jamais la vérification Ed25519 et ne
testerait pas le désérialiseur JSON.

## Utilisation locale

```sh
fuzz/setup.sh                                  # nightly + cargo-fuzz (versions de versions.env)
fuzz/run.sh all 300                            # 5 min par cible
fuzz/run.sh ticket_claims 3600                 # 1 h sur une cible
FUZZ_JOBS=8 fuzz/run.sh range 600              # 8 processus en parallèle
fuzz/run.sh --minimize all                     # réduit le corpus accumulé
fuzz/run.sh --reproduce ticket <fichier>       # rejoue une entrée
```

Prérequis : `curl`, un compilateur C++ (`build-essential` / `gcc-c++`).
`setup.sh` installe rustup s'il manque.

## Fichiers

| Chemin | Versionné | Rôle |
|--------|-----------|------|
| `versions.env` | oui | Toolchain nightly et version de cargo-fuzz, figées |
| `fuzz_targets/` | oui | Les cibles |
| `seeds/<cible>/` | oui | Corpus de départ, généré par `generate-seeds.mjs` à partir des vecteurs de tickets et de `deploy/config.example.toml` |
| `dicts/<cible>.dict` | oui | Jetons utiles au fuzzer (`"sct1"`, `"bytes="`, noms de sections…) ; échappements `\\`, `\"`, `\xHH` seulement |
| `corpus/<cible>/` | non | Découvertes du fuzzer, gardées en cache par la CI |
| `artifacts/<cible>/` | non | Entrées qui font planter |

## En CI (Gitea Actions)

`.gitea/workflows/fuzz.yml` :

| Déclencheur | Durée par cible | Processus |
|-------------|-----------------|-----------|
| Pull request touchant `src/`, `fuzz/`, `Cargo.*` | 3 min | 1 |
| Chaque nuit à 2 h 17 (branche par défaut) | 30 min, puis minimisation du corpus | 2 |
| Manuel (onglet Actions → Fuzzing → Run workflow) | au choix | au choix |

Les 6 cibles tournent en parallèle (matrice). Le corpus est gardé en cache
d'une exécution à l'autre : chaque nuit repart de tout ce qui a été
découvert avant.

**En cas de plantage**, le job échoue et :
- le journal contient une annotation `::error`, l'entrée fautive en base64
  et la commande pour la rejouer ;
- l'entrée est publiée en artefact `crash-<cible>` (30 jours).

Pour la rejouer en local :

```sh
echo '<base64 du journal>' | base64 -d > crash
fuzz/run.sh --reproduce <cible> crash
```

Une fois corrigée, ajouter l'entrée au corpus de départ (dans
`generate-seeds.mjs`) pour qu'elle serve de test de non-régression.

Pour qu'un plantage **bloque la fusion** d'une PR : Paramètres du dépôt →
Branches → règle de protection → « Vérifications d'état requises » →
ajouter les jobs `Fuzzing / fuzz (…)`.

### Runner Gitea

Le fuzzing occupe les cœurs pendant toute sa durée : un runner dédié, ou
au moins une machine qui n'héberge pas la production, est préférable.

1. Installer `act_runner` et l'enregistrer (Paramètres du dépôt ou de
   l'organisation → Actions → Runners → jeton d'enregistrement) :

   ```sh
   act_runner register --instance https://<gitea> --token <jeton> \
     --labels "ubuntu-latest:docker://docker.gitea.com/runner-images:ubuntu-latest"
   ```

   Le label doit correspondre au `runs-on: ubuntu-latest` des workflows
   (sinon adapter l'un ou l'autre).

2. Dans la configuration du runner (`act_runner generate-config`) :
   - `runner.capacity` : nombre de jobs simultanés. 6 permet de lancer les
     6 cibles en même temps (compter 2 cœurs et ~2,5 Gio de RAM par job la
     nuit) ;
   - `cache.enabled: true` : indispensable pour conserver le corpus et les
     outils entre deux exécutions ;
   - `runner.timeout` ≥ 3 h.

3. Activer Actions sur le dépôt (Paramètres → Actions) si ce n'est pas
   déjà fait.

Sans cache disponible, le fuzzing fonctionne quand même, mais chaque
exécution repart du corpus de départ et réinstalle nightly et cargo-fuzz
(≈ 3 min de plus).

## Mettre à jour les versions

Éditer `versions.env` en respectant la règle du projet : **toute version
publiée depuis au moins 7 jours**.

- Toolchain : une nightly datée, par exemple `nightly-AAAA-MM-JJ`, publiée
  il y a au moins 7 jours.
- cargo-fuzz : une version de crates.io publiée il y a au moins 7 jours
  (`https://crates.io/crates/cargo-fuzz/versions`).

Le changement invalide le cache des outils : la CI réinstalle au prochain
passage.

## Ajouter une cible

1. `fuzz_targets/<nom>.rs` et une section `[[bin]]` dans `Cargo.toml`.
2. Ajouter `<nom>` à `TARGETS` et à `max_len` dans `run.sh`, et à la
   matrice de `.gitea/workflows/fuzz.yml`.
3. Des entrées de départ dans `generate-seeds.mjs`, et un dictionnaire si
   l'entrée a une syntaxe.
