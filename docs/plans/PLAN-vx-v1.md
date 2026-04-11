# Plan: VX Security Scanner v1.0

## Spec Summary

VX est un scanner de sécurité Go (black-box + white-box) déjà fonctionnel avec 12 modules réseau, 5 modules locaux, 6 formats de sortie, CI/CD intégré.

**Objectif v1.0** : corriger les faux positifs critiques, atteindre la parité VICE, ajouter les tests, préparer la release.

## Codebase Findings

- **42 fichiers Go, 6948 lignes** — bien structuré, patterns clairs
- **Faux positifs critiques** : `xss.go` et `httpmethods.go` ne filtrent pas les catch-all SPA (Next.js/React/Vue)
- **`isRealAPIResponse()`** existe déjà dans `webservice.go` mais n'est pas partagée
- **0 tests** — aucun `*_test.go`
- **Modules VICE manquants** : SQLi remote, open redirect, path traversal, DKIM, JS endpoint discovery, WebSocket
- **Aucun linter** configuré

## Architecture

```
cmd/           ← Cobra commands (scan, audit, full, history, interactive)
pkg/engine/    ← Core: Module interface, Config, Finding, Score
pkg/modules/   ← 12 remote scan modules (each implements engine.Module)
pkg/local/     ← 5 local audit modules (each implements local.LocalModule)
pkg/report/    ← 5 output formats (terminal, html, sarif, badge, markdown)
pkg/config/    ← YAML config parser
pkg/history/   ← Scan history persistence
```

### Key Decisions

### Decision: Partager isRealAPIResponse()
**Options**: A) Copier dans chaque module B) Extraire dans `pkg/modules/module.go` comme helper partagé
**Pick**: B
**Why**: Un seul point de maintenance. Déjà 3 modules en ont besoin (webservice, xss, httpmethods).
**One-way door?**: non

### Decision: Structure des tests
**Options**: A) Tests unitaires par fichier module B) Tests d'intégration avec serveur HTTP mock C) Les deux
**Pick**: C — tests unitaires pour le scoring/parsing, mock server pour les modules réseau
**Why**: Les modules réseau testent du HTTP — un httptest.Server est le pattern Go standard.
**One-way door?**: non

### Decision: Modules VICE manquants — scope
**Options**: A) Tout implémenter B) Prioriser les plus utiles (SQLi, open redirect, DKIM, JS discovery) C) Minimum viable
**Pick**: B — SQLi remote, open redirect, path traversal, DKIM, JS endpoint discovery. WebSocket et SSRF en v1.1.
**Why**: SQLi/redirect/traversal sont des classiques OWASP. DKIM complète le DNS check existant. JS discovery est un différenciateur. WebSocket/SSRF sont niches.
**One-way door?**: non

## Waves

### Wave 1 (parallel) — Fix False Positives & Shared Infra

#### M1: Extract shared HTTP helpers
- **Goal**: `isRealAPIResponse()` et `isSPACatchAll()` disponibles pour tous les modules
- **Files owned**: `pkg/modules/module.go` (modify)
- **Tasks**:
  - [ ] Déplacer `isRealAPIResponse()` de `webservice.go` vers `module.go`
  - [ ] Ajouter `isSPACatchAll(body []byte) bool` — détecte Next.js, React, Vue, Angular, Nuxt catch-all
  - [ ] Ajouter `probeDetailed()` comme méthode publique dans `module.go`
  - [ ] Ajouter `doRequest(client, method, url, ua) probeResult` pour GET/PUT/DELETE/etc.
  - [ ] Mettre à jour `webservice.go` pour utiliser les helpers de `module.go` au lieu de ses copies locales
- **Tests**: `pkg/modules/module_test.go` — test `isSPACatchAll` avec HTML Next.js, React, Vue, page HTML normale
- **Done when**: helpers partagés compilent, webservice.go refactorisé

#### M2: Fix XSS false positives
- **Goal**: Le module XSS ne reporte plus de faux positifs sur les apps SPA/Next.js
- **Files owned**: `pkg/modules/xss.go` (modify)
- **Tasks**:
  - [ ] Dans `testReflectedXSS()` : avant chaque payload check, vérifier que la réponse n'est pas un catch-all SPA via `isSPACatchAll()`
  - [ ] Dans `testParamXSS()` : même vérification sur les error pages
  - [ ] Améliorer `getInjectionContext()` : distinguer "dans un string JS" vs "dans le DOM HTML"
  - [ ] Ajouter détection de faux positif pour l'attribute breakout : si `&quot;` est présent → pas exploitable
  - [ ] Dédupliquer les findings par `Title + CWE` (déjà partiellement fait, vérifier)
- **Tests**: `pkg/modules/xss_test.go` — mock server avec page Next.js catch-all, page vulnérable réelle, page avec encoding correct
- **Done when**: scan iautos.fr ne reporte plus de XSS HIGH faux positifs

#### M3: Fix HTTPMethods false positives
- **Goal**: PUT/DELETE ne sont plus flaggés HIGH sur les catch-all SPA
- **Files owned**: `pkg/modules/httpmethods.go` (modify)
- **Tasks**:
  - [ ] Dans `testWriteMethods()` : utiliser `doRequest()` + `isSPACatchAll()` pour filtrer les 200 qui sont juste des pages HTML
  - [ ] Ajouter vérification Content-Type : si `text/html` sur PUT/DELETE → probablement catch-all, réduire à INFO
  - [ ] TRACE check : vérifier que le body contient bien l'écho de la requête (pas juste un 200)
- **Tests**: `pkg/modules/httpmethods_test.go` — mock server catch-all vs serveur qui accepte vraiment PUT
- **Done when**: scan iautos.fr ne reporte plus PUT/DELETE comme HIGH

#### M4: Linter & CI quality
- **Goal**: golangci-lint configuré, go vet clean
- **Files owned**: `.golangci.yml` (new), `Makefile` (new)
- **Tasks**:
  - [ ] Créer `.golangci.yml` avec errcheck, gosimple, govet, staticcheck, unused
  - [ ] Créer `Makefile` : `build`, `test`, `lint`, `scan-test` (scan localhost:8080)
  - [ ] Fix tous les warnings golangci-lint existants
  - [ ] Mettre à jour `.github/workflows/ci.yml` pour inclure lint + test
- **Tests**: `make lint` passe sans erreur
- **Done when**: CI verte avec lint + vet + test

### Wave 2 (after Wave 1) — New Remote Modules

#### M5: SQLi Remote Testing
- **Depends on**: M1
- **Goal**: Détecter les injections SQL via les paramètres URL et formulaires
- **Files owned**: `pkg/modules/sqli.go` (new)
- **Tasks**:
  - [ ] Créer module `SQLi` implémentant `engine.Module`
  - [ ] Payloads : `'`, `' OR 1=1--`, `" OR 1=1--`, `1; DROP TABLE--`, `' UNION SELECT NULL--`
  - [ ] Détecter les réponses d'erreur SQL (MySQL, PostgreSQL, MSSQL, SQLite, Oracle patterns)
  - [ ] Tester sur les mêmes endpoints que XSS (search forms, common params)
  - [ ] Time-based detection : `' OR SLEEP(3)--` avec mesure du temps de réponse
  - [ ] Filtrer les catch-all SPA via `isSPACatchAll()`
- **Tests**: `pkg/modules/sqli_test.go` — mock avec page erreur MySQL, page safe, catch-all
- **Done when**: module détecte une SQLi error-based sur un mock vulnérable

#### M6: Open Redirect & Path Traversal
- **Depends on**: M1
- **Goal**: Détecter les redirections ouvertes et les traversées de chemin
- **Files owned**: `pkg/modules/redirect.go` (new), `pkg/modules/traversal.go` (new)
- **Tasks**:
  - [ ] **Open Redirect** : tester `?url=https://evil.com`, `?redirect=//evil.com`, `?next=/\evil.com`, `?return_to=https://evil.com` sur les pages login/logout/callback
  - [ ] Détecter si la réponse 3xx redirige vers le domaine evil
  - [ ] **Path Traversal** : tester `/../etc/passwd`, `..%2f..%2fetc/passwd`, `....//....//etc/passwd`
  - [ ] Détecter les patterns `root:x:` dans la réponse
  - [ ] Tester aussi sur les endpoints de download/fichiers
- **Tests**: mock servers pour les deux modules
- **Done when**: redirect détecte une 302 → evil.com, traversal détecte root:x:

#### M7: DKIM & DNS Enhancement
- **Depends on**: M1
- **Goal**: Compléter l'analyse DNS avec DKIM (12 selectors) et dangling CNAME
- **Files owned**: `pkg/modules/discovery.go` (modify — section `dnsChecks`)
- **Tasks**:
  - [ ] DKIM : tester 12 selectors courants (default, google, selector1, selector2, k1, k2, k3, mail, dkim, s1, s2, brevo)
  - [ ] Reporter les selectors trouvés comme INFO, les absences comme LOW
  - [ ] Dangling CNAME : pour chaque sous-domaine trouvé, checker si le CNAME pointe vers un service mort (GitHub Pages, Heroku, AWS, etc.)
  - [ ] Ajouter la vérification CAA records
- **Tests**: `pkg/modules/discovery_test.go` — mock DNS responses
- **Done when**: scan chronovet.fr trouve les DKIM selectors Sendinblue

#### M8: JS Endpoint Discovery
- **Depends on**: M1
- **Goal**: Extraire les endpoints API depuis les bundles JavaScript
- **Files owned**: `pkg/modules/jsdiscovery.go` (new)
- **Tasks**:
  - [ ] Parser le HTML pour trouver tous les `<script src="...">` (JS bundles)
  - [ ] Télécharger chaque bundle JS
  - [ ] Regex pour extraire les URLs/paths : `/api/...`, `fetch("..."`, `axios.get("..."`, `"/v1/..."`
  - [ ] Dédupliquer et classifier (API interne, externe, CDN)
  - [ ] Tester l'accessibilité de chaque endpoint découvert
  - [ ] Reporter les endpoints non-authentifiés comme MEDIUM
- **Tests**: mock avec faux JS bundle contenant des endpoints
- **Done when**: découvre les endpoints API dans les bundles JS de iautos.fr

### Wave 3 (after Wave 2) — Tests & Polish

#### M9: Test Suite Core
- **Depends on**: M5, M6, M7, M8
- **Goal**: Couverture de tests pour le core engine et le scoring
- **Files owned**: `pkg/engine/score_test.go` (new), `pkg/engine/finding_test.go` (new), `pkg/engine/engine_test.go` (new)
- **Tasks**:
  - [ ] `score_test.go` : tester ComputeScore avec 0 findings, all severities, edge cases (score négatif → 0)
  - [ ] `finding_test.go` : tester Severity.String(), Severity.Points(), Finding.String()
  - [ ] `engine_test.go` : tester module registration, shouldRun filter, parallel execution
- **Tests**: `go test ./pkg/engine/... -v`
- **Done when**: 100% coverage sur pkg/engine/

#### M10: Test Suite Modules (mock HTTP server)
- **Depends on**: M9
- **Goal**: Tests d'intégration pour tous les modules réseau avec httptest.Server
- **Files owned**: `pkg/modules/testutil_test.go` (new), compléter les `*_test.go` de Wave 1/2
- **Tasks**:
  - [ ] Créer `testutil_test.go` avec helper `newMockServer()` qui sert différents scénarios (vulnérable, safe, catch-all)
  - [ ] Tests pour headers, cookies, cors, tls (au minimum)
  - [ ] Tests pour webservice avec faux endpoints XML PrestaShop
  - [ ] Tests pour info avec page contenant des tokens/secrets
- **Tests**: `go test ./pkg/modules/... -v -race`
- **Done when**: `go test ./... -race` passe sans erreur, >60% coverage modules

#### M11: Test Suite Local
- **Depends on**: M9
- **Goal**: Tests pour les modules d'audit local
- **Files owned**: `pkg/local/secrets_test.go` (new), `pkg/local/codevulns_test.go` (new), `pkg/local/module_test.go` (new)
- **Tasks**:
  - [ ] `module_test.go` : tester DetectLanguages, ShannonEntropy, WalkFiles
  - [ ] `secrets_test.go` : tester avec fichiers fixtures contenant des secrets connus
  - [ ] `codevulns_test.go` : tester chaque pattern de vulnérabilité par langage
- **Tests**: `go test ./pkg/local/... -v`
- **Done when**: >70% coverage local

#### M12: Release & Distribution
- **Depends on**: M9, M10, M11
- **Goal**: v1.0.0 prête à publier
- **Files owned**: `cmd/root.go` (modify — version), `Dockerfile` (new), `.goreleaser.yml` (new)
- **Tasks**:
  - [ ] Bumper la version à v1.0.0 dans root.go et engine.go
  - [ ] Créer `Dockerfile` multi-stage (build + scratch)
  - [ ] Créer `.goreleaser.yml` pour cross-compile (linux/darwin/windows × amd64/arm64)
  - [ ] Mettre à jour `action.yml` pour utiliser le Docker image ou le binaire pre-built
  - [ ] Tag git v1.0.0
- **Tests**: `docker build .` + `goreleaser check`
- **Done when**: `goreleaser check` passe, Docker image build OK

## must_haves Verification

| must_have Truth | Verified by | Milestone |
|---|---|---|
| Pas de faux positif XSS sur Next.js/React | `vx scan iautos.fr` → 0 HIGH XSS | M2 |
| Pas de faux positif PUT/DELETE sur SPA | `vx scan iautos.fr` → 0 HIGH httpmethods | M3 |
| SQLi remote détecté | test mock vulnérable | M5 |
| Open redirect détecté | test mock redirect | M6 |
| Path traversal détecté | test mock traversal | M6 |
| DKIM selectors trouvés | `vx scan chronovet.fr` | M7 |
| JS endpoints extraits | `vx scan iautos.fr` → endpoints /api/ | M8 |
| Tests passent | `go test ./... -race` | M9, M10, M11 |
| Lint clean | `make lint` | M4 |
| Release binaries multi-platform | `goreleaser check` | M12 |

## Deviation Rules

| Level | Trigger | Permission |
|---|---|---|
| 1. Bug in existing code | Blocks progress | Auto-fix, note in plan |
| 2. Missing validation/security | Critical gap | Auto-fix, note in plan |
| 3. Blocking dependency | Can't continue | Auto-fix, note in plan |
| 4. Architecture change | Structural shift | **STOP — ask user** |

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| isSPACatchAll rate-limits des faux négatifs (vrais vulns ignorées) | M | H | Checker Content-Type + body ensemble, pas l'un ou l'autre |
| Time-based SQLi trop lent (SLEEP payloads) | M | L | Timeout court (5s), max 3 payloads time-based |
| JS bundles trop gros à télécharger | L | M | Limiter à 5MB par bundle, max 20 bundles |
| golangci-lint casse le build existant | M | L | Fix progressif, pas tout d'un coup |
| OSV.dev API down pendant les tests | L | M | Mock les réponses HTTP dans les tests |

## Scope Summary

| Wave | Milestones | Files | Complexity |
|---|---|---|---|
| 1 — Fix FP & Infra | M1, M2, M3, M4 | 7 modified + 6 new test files + 2 config | M |
| 2 — New Modules | M5, M6, M7, M8 | 4 new + 1 modified + 4 test files | L |
| 3 — Tests & Release | M9, M10, M11, M12 | 8 new test files + 3 new config + 1 modified | M |
| **Total** | **12 milestones** | **~36 files** | **L** |
