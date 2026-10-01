# django-gates-demo

A small Django notes app (login, per-user notes, CSRF, security headers)
built to go through every DevSecOps gate (G1–G6) for real: a build
pipeline (CI) per commit, then a release pipeline that deploys the same
signed digest to dev, staging and prod and tests each environment **after**
the new digest is deployed to it. The evidence for each decision is kept.

```
GET  /healthz                 {"status": "ok"}
GET  /accounts/login/         login form
GET  /notes/                  your notes (login required); POST adds one
POST /notes/<id>/delete/      delete one of your notes (anyone else's → 404)
GET  /api/notes/              your notes as JSON; POST adds one
GET  /api/notes/<id>/         one of your notes; DELETE removes it
```

Run locally:

```
uv sync
DJANGO_DEBUG=1 uv run python manage.py migrate
DJANGO_DEBUG=1 uv run python manage.py runserver
```

Run the unit tests with `uv run pytest tests/unit`. The other suites test
a running app, so the release pipeline runs them against dev, staging and
prod right after each deploy:

| suite | what it checks | runs in |
|---|---|---|
| `tests/live/test_smoke.py` (`-m smoke`) | read-only: health, TLS redirect, headers, login page, static files, anonymous access refused | dev · staging · prod |
| `tests/live/test_integration.py` | ingress + sessions + auth + API + pages together, validation, persistence | dev |
| `tests/live/test_e2e.py` | user journeys through the pages and their forms (login, add, delete, logout, two users) | staging |
| `tests/live/test_regression.py` | fixed or decided behaviour: no CORS on static, note limit, method allow-lists, body size, caching | dev · staging |
| `tests/live/test_security.py` | authenticated DAST (OWASP Top 10): IDOR, CSRF, open redirect, session fixation, logout, enumeration, cookies, headers, injection | dev · staging |
| `tests/perf/load.js` (k6) | p95 latency SLO, error rate | staging |
| nuclei · testssl.sh · trivy | unauthenticated DAST, TLS, the deployed digest's dependencies | dev/staging · staging · dev |

To run a suite against any running instance (for example `docker run` of
the image behind `tests/env/Caddyfile`), use its make target, e.g.
`make regression` or `make security-tests`. All but `make smoke` need two
users (`manage.py ensure_user`):

```
BASE_URL=https://localhost:18443 HTTP_URL=http://localhost:18480 REQUESTS_CA_BUNDLE=ca.crt \
USER_A=... PASSWORD_A=... USER_B=... PASSWORD_B=... make e2e
```

## Build & unit tests (`devsecops-pipeline.yml`, CI)

`.github/workflows/devsecops-pipeline.yml` runs on PRs, reviews, pushes to
`main` and manual dispatch. Nothing in it runs the application: every
dynamic test runs in the release pipeline, against the environment the
new digest was just deployed to.

```
1 build ──────── checkout · build twice (reproducible?) · unit tests + coverage
                 · code quality (ruff)
2 static ─────── SAST (semgrep) · gitleaks · trufflehog · trivy SCA (uv.lock)
                 · checkov · reviewers · signed commits
2 image ──────── trivy image scan · syft SBOM · dockle · manage.py check --deploy
3 package ────── (main only) push by digest · cosign sign · SBOM + SLSA attestations
   └─ G2 Control Gate ── build successful · all tests passed · code quality
                         threshold met · no blocking findings · signed
4 evidence ───── bundle + sha256 manifest → artifact `evidence` (90 days);
                 on main, cosign-attested to the image digest
5 release ────── (main, G2 passed) starts devsecops-release for this commit
```

Each control is its own job, and every one of them runs even when another
fails. Each job ends in `.github/scripts/verdict.py`, which applies that
control's threshold and writes `verdict.json` next to the raw report in
the `report-<control>` artifact. A red job means a failed control.
`.github/scripts/gate.py` maps controls to gate criteria.

A control can only report `skipped` when it could not be evaluated in
this context (for example, a PR image isn't published or signed). Skipped
never counts as a pass. It is allowed only where the gate explicitly
permits it: `artifact_signed_attested` on PRs.

Gate results go to the security dashboard as `gate-result-G<n>`
artifacts (`gate-result-G<n>-<env>` from the release pipeline). G1 is
recorded on PRs and G2 on pushes to `main` (on PRs it appears as
`gate-preview-G2`). The `evidence` bundle also feeds
DefectDojo: the dashboard's collector reimports every report listed in
`manifest.json`.

### When a control fails

verdict.py records every finding in the same shape, whatever the tool:
severity, id, title, file and line or package and version, the fix, and a
link. `.github/scripts/findings.py` turns those findings into:

- **The job summary** (open the red job). It says why the control failed:
  - *findings*: the tool reported something that blocks.
  - *tool*: nothing was checked, and the tool's output is shown.
  - *policy*: a threshold such as coverage wasn't met.

  Under the verdict comes **the tool's own report**, as developers know it
  from running the tool:
  - trivy's table (SCA and image), rendered from the same JSON with
    `trivy convert`, without the accepted risks;
  - checkov's markdown; semgrep's text; dockle's list;
  - `check --deploy`'s output; testssl.sh's console report.

  The report is also in the step log and in the artifact, and it's
  collapsed when the control passed. Tools without a readable report of
  their own (the secret scanners, tests, governance, nuclei) get a table
  of blocking findings instead, sorted by severity. trufflehog's own
  output would print the secret. SCA and image findings also get an
  upgrade plan with one row per package: the version that fixes all of
  that package's findings. Accepted risks, with their reason and expiry,
  are in a collapsed section, because the tools don't know about the
  register. The summary ends with the `make` command that reproduces the
  failure, which prints the same report.
- **Annotations**: the first 9 blocking findings that have a file and line
  appear on the PR's Files tab.
- **Code scanning** (public repos only; private ones need GitHub Advanced
  Security). Each control uploads its own `findings.sarif` (semgrep,
  gitleaks, trivy SCA, checkov) or trivy's SARIF (image scan), so alerts
  open and close per control. A control whose tool failed uploads nothing,
  so that failure can't close real alerts.
- **One PR comment**, edited in place on every run. It lists every control
  and marks the blocking findings that are new compared with the latest
  `main` run. A finding counts as the same if the control, id and file or
  package match; line numbers are ignored. Fork PRs get no comment,
  because their token is read-only. Their job summaries carry the same
  information.
- **`findings.json`** in each `report-<control>` artifact: every finding,
  uncapped. It is also part of the evidence bundle.

The same scans run locally with the pipeline's pinned images, arguments
and thresholds. The Makefile reads the image pins from the workflow, so
the two can't drift:

```
make scan            # semgrep · gitleaks · trufflehog · trivy SCA · checkov
make scan-image      # docker build, then trivy image · dockle · check --deploy
make sca-trivy       # any single control, by its pipeline name
pre-commit install --hook-type pre-commit --hook-type pre-push
```

The pre-commit hooks are defined in `.pre-commit-config.yaml`:
- On commit: gitleaks on the staged changes; trivy when `uv.lock` or
  `pyproject.toml` changes; checkov when `Dockerfile` or `deploy/` changes.
- On push: semgrep.

### Checking the evidence later

```
cosign verify-attestation \
  --type https://github.com/usfali-ke/django-gates-demo/evidence/v1 \
  --certificate-identity https://github.com/usfali-ke/django-gates-demo/.github/workflows/devsecops-pipeline.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/usfali-ke/django-gates-demo@sha256:<digest> \
  | jq '.payload | @base64d | fromjson | .predicate'
```

Then run `sha256sum -c SHA256SUMS` inside the downloaded `evidence`
artifact.

### Accepted risks

`security/accepted-risks.json` is the only way to let a finding through.
Each entry names the control, the finding id and a reason, and has an
expiry date. Once it expires, the finding blocks again. Every acceptance
that was applied is listed in the verdict and in the manifest.

## Release pipeline (`devsecops-release.yml`)

The digest the build pipeline signed moves dev → staging → prod in **one
run**, and is never rebuilt. Each stage is `devsecops-stage.yml` for one
environment, and every test in it runs against that environment after the
digest is deployed there:

```
1 Build & unit tests (devsecops-pipeline) ── G2 Control Gate ── starts ↓

2 Deploy to Dev ──── R1 verify → G5(dev) → deploy/dev → G6(dev)
                     → G3 in dev: smoke · integration · regression tests
                       · DAST (nuclei + authenticated security tests)
                       · dependency re-check of the deployed digest
   Approval Gate ─── staging-approval: dev's test results + security scans,
                     release notes (in the run summary)
3 Deploy to Staging  R1 verify → G5(staging) → deploy/staging → G6(staging)
                     → G3 in staging: smoke · end-to-end · regression tests
                       · performance (k6) · DAST (nuclei + testssl.sh
                       + authenticated security tests) → UAT (change request told)
   Approval Gate ─── release-approval + G4: UAT sign-off (uat-approved),
                     test results, Go/No-Go (readiness-approved), change window
4 Deploy to Prod ─── R1 verify → G5(prod) → deploy/prod (canary) → G6(prod)
                     → post-deploy smoke tests · health watch (5 min of
                       /healthz probes, latency SLO, no restarts)
                     · rollback plan verified before the deploy; a failure
                       after it starts the rollback automatically

Monitoring, logging & feedback: run summary per stage, a comment on the
change request and the pull requests, the rollback command if a deployed
stage failed; gate results, deployment events and release evidence to the
security dashboard; Argo CD notifications for every sync and canary.
```

A stage starts only when the previous one deployed **and passed its
tests**; a failed stage stops the run there. Staging and prod also refuse
to run if the previous environment has moved on to a newer release while
this one waited for approval.

- **R1 verify**, every stage: signature + SBOM + SLSA provenance for the
  commit that built the digest; the evidence attestation (the pipeline's
  Control Gate passed); the target overlay is schema-valid and
  checkov-clean, and only its digest changes. Also:
  - *previous environment's tests*: staging and prod verify the release
    record the previous stage attested to the digest, and need its G3 to
    have passed against the deployed environment;
  - *release notes*: the pull requests and commits since the digest the
    target environment runs now (job summary and `release-notes.md`);
  - *rollback plan*: the digest running now (or, on a redeploy, the one it
    replaced) is still signed and still in the registry. The deploy
    commit records it as `Rollback-Digest`.
- **Approval Gates**: `staging-approval` and `release-approval`. The
  approver can't be whoever started or re-ran the run, nor whoever
  authored the change (the commit or its pull request). G4 also needs the
  change request labelled `change-approved`, `readiness-approved` and
  `uat-approved`, and the dashboard's own decision on it.
- **Deploy** is a commit to `deploy/<env>/kustomization.yaml`. Its
  trailers (`Environment`, `Image-Digest`, `Source-Commit`,
  `Rollback-Digest`, `Rollback-Source`) are what the next stage's R1
  reads, together with the `security-dashboard/G6/<env>` status on that
  commit.
- **Evidence:** every stage leaves a `release-evidence-<env>` bundle,
  attested to the digest once it was deployed.

How to release:

1. Open a **Change request** issue whose change window covers the
   release. Someone other than you adds `change-approved`.
2. Merge to main, and put the merge commit's SHA (or the release run's
   URL) in the change request's **Release** field. When **devsecops-pipeline**'s Control Gate passes, it
   starts **devsecops-release** for that commit, which deploys to dev and
   tests it there.
3. Someone who didn't start the run or write the change approves
   `staging-approval`. Staging is deployed and tested; the change request
   gets a comment that UAT can start.
4. The tester adds `uat-approved`; the Go/No-Go review adds
   `readiness-approved`. Inside the change window, someone who didn't
   start the run or write the change approves `release-approval`. Prod is
   deployed, smoke-tested and watched.

A run can also start at any stage (Actions → devsecops-release → Run
workflow): `start: staging` promotes what dev runs, `start: prod` what
staging runs (pass `change` if no change request names the commit). A
push that only touches `deploy/**` or `*.md` doesn't build; to deploy an
older published commit, use `start: dev` and `commit: <sha>`.

To roll back, run with `start: <env>` and `kind: rollback`. It redeploys
the environment's recorded `Rollback-Digest` through the same gates (for
prod, the same change and approval) and stops there. The dashboard counts
it as a rollback. When prod fails after its deploy (smoke tests, health
watch or G6), the run starts that rollback itself; it still waits for a
`release-approval` reviewer. For dev and staging, the feedback job prints
the command.

A stage refuses to run when:
- the previous environment's last deploy wasn't made by this workflow;
- that deploy's G6 isn't green, or its G3 didn't pass;
- the previous environment now runs a newer digest than this run deployed
  there (a newer release overtook it);
- `deploy/base` or the target overlay changed on main after it verified them.

## One-time cluster setup (run by an operator)

The Rollout reads `DJANGO_SECRET_KEY` from a Secret, which this repo never
contains. Each environment needs its own:

```
for ns in django-gates-demo-dev django-gates-demo-stg django-gates-demo-prod; do
  kubectl -n "$ns" create secret generic django-gates-demo \
    --from-literal=secret-key="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
done
```

The namespaces, the Argo CD Applications (`django-gates-demo-{dev,staging,prod}`)
and the environment tester's RBAC are in the security dashboard's
`pipeline/k8s/kind/platform`.

### Environment test runner

The tests after each deploy (G3 in dev and staging, the smoke tests and
health watch in prod) run on a self-hosted runner, because GitHub-hosted runners can't
reach the cluster. It is one job per stage, so one runner registration,
and each suite in it is its own step, control (`report-<env>-env-tests`)
and G3/G6 criterion source. The job:
- finds the pod running the promoted digest;
- port-forwards it to `127.0.0.1:18000`;
- outside prod, creates two random-password users in it
  (`manage.py ensure_user`, with the password on stdin);
- puts a Caddy TLS proxy on `https://localhost:18443` in front of it
  (`tests/env/Caddyfile`).

The runner needs docker, kubectl, git, jq, python3 and curl. `uv` is
installed by the job. It runs as the `env-tester` ServiceAccount
(`django-gates-demo-tools`), which can list pods and port-forward in
`django-gates-demo-{dev,stg,prod}` and exec only in dev and stg.

`bash tests/env/env-runner.sh [runner dir]` does the setup: it mints a 2-hour
token for `env-tester`, writes a kubeconfig with it (mode 0600), registers
the runner as **ephemeral** (one registration serves one job) with the
label `django-gates-demo-env`, and runs it. It needs `GH_TOKEN` with
admin rights on the repo, for the registration token. One release run has
up to three environment test jobs (one per stage), so keep it in a loop
while a release is running.

This repo is public, so a pull request from a fork could try to run on a
self-hosted runner. To prevent that:
- keep the runner registered only while a release runs;
- keep *Settings → Actions → Fork pull request workflows → Require
  approval for all external contributors* on. The pipeline itself never
  targets this label.
