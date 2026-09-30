# django-gates-demo

A small Django notes app (login, per-user notes, CSRF, security headers)
built to go through every DevSecOps gate (G1–G6) for real, in **one
pipeline run per commit**, keeping the evidence for each decision.

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

Run the tests with `uv run pytest tests/unit`. The functional, perf and
DAST suites run against the preprod stack (`tests/preprod/compose.yaml`:
the image behind a TLS proxy), which the pipeline starts.

## One run, every gate

`.github/workflows/devsecops-pipeline.yml` runs on PRs, reviews, pushes to
`main` and manual dispatch:

```
1 build ──────── build twice (reproducible?) · unit tests + coverage
2 static ─────── semgrep · gitleaks · trufflehog · trivy SCA (uv.lock) · checkov
                 reviewers · signed commits
2 image ──────── trivy image scan · syft SBOM · dockle · manage.py check --deploy
3 publish ────── (main only) push by digest · cosign sign · SBOM + SLSA attestations
   └─ G2 artifact gate ── a failed G2 stops here ──┐
4 preprod ────── functional · k6 performance       │  (full_scan=true on a
5 dast ───────── nuclei · testssl                  │   manual run overrides)
   └─ G3 pre-production gate
6 evidence ───── bundle + sha256 manifest → artifact `evidence` (90 days);
                 on main, cosign-attested to the image digest
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
artifacts. G1 is recorded on PRs; G2 and G3 on pushes to `main` (on PRs
they appear as `gate-preview-*`). The `evidence` bundle also feeds
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

## Promoting (`devsecops-release.yml`, one run per environment)

The digest the pipeline built and signed moves dev → staging → prod. It is
never rebuilt. Each environment gets its gates around its own deploy:

```
Build & unit tests (devsecops-pipeline, every push)
  G1 build · unit tests · SAST · code quality (ruff) · package
  G2/G3 on the image → publish → evidence → dispatches the dev release
dev ───── R1 this commit's image · rollback plan → G5(dev) → deploy/dev
          → G6(dev) → G3 in dev (integration · nuclei · dependency re-check)
staging ─ R1 the digest G6 verified in dev · dev's G3 passed · release notes
          · rollback plan → staging-approval → G5(staging) → deploy/staging
          → G6(staging) → G3 in staging (functional · k6 · nuclei · testssl)
prod ──── R1 the digest G6 verified in staging · staging's G3 passed
          · release notes · rollback plan → G4 (release-approval · change
          window · UAT sign-off · Go/No-Go) → G5(prod) → deploy/prod
          (canary) → G6(prod) + smoke tests
```

- **R1** for every environment: signature + SBOM + SLSA provenance for the
  commit that built the digest; the evidence attestation (the pipeline's G2
  and preprod G3 passed); the target overlay is schema-valid and
  checkov-clean, and only its digest changes. Also:
  - *previous environment's tests*: staging and prod verify the release
    record the previous environment's run attested to the digest, and
    need its G3 to have passed;
  - *release notes*: the pull requests and commits since the digest the
    target environment runs now (job summary and `release-notes.md`);
  - *rollback plan*: the digest running now (or, on a redeploy, the one it
    replaced) is still signed and still in the registry. The deploy
    commit records it as `Rollback-Digest`.
- **Staging approval**: the `staging-approval` environment. The approver
  can't be whoever started or re-ran the run.
- **G4** (prod only): the `release-approval` environment (same rule), and
  the dashboard's decision on the change. That decision includes *G3
  passed in staging for this digest* and *UAT signed off after it*.
- **Deploy** is a commit to `deploy/<env>/kustomization.yaml`. Its
  trailers (`Environment`, `Image-Digest`, `Source-Commit`,
  `Rollback-Digest`, `Rollback-Source`) are what the next environment's R1
  reads, together with the `security-dashboard/G6/<env>` status on that
  commit.
- **Evidence:** every run leaves a `release-evidence` bundle, attested to
  the digest once something was deployed.

How to promote:

1. Push to main. When **devsecops-pipeline** publishes, it starts the dev
   release for that commit. A push that only touches `deploy/**` or `*.md`
   doesn't build; after one, run the pipeline on main by hand. To redeploy
   an older published commit to dev, run the release with
   `environment: dev` and `commit: <sha>`.
2. Once dev's G6 and G3 are green: `environment: staging`. Someone who
   neither started nor re-ran the run approves `staging-approval`.
3. For prod, open a **Change request** issue whose change window covers the
   release. Once staging's tests passed, the tester adds `uat-approved`.
   Someone other than you adds `change-approved` and `readiness-approved`
   (Go/No-Go). Then run with `environment: prod` and the issue (`7`, `#7`
   or `CHG-7`). Someone who neither started nor re-ran the run approves
   `release-approval`.

To roll back, run with `kind: rollback`. It deploys the environment's
recorded `Rollback-Digest` through the same gates (and, for prod, the same
change and approval). The dashboard counts it as a rollback.

A promotion refuses to run when:
- the previous environment's last deploy wasn't made by this workflow;
- that deploy's G6 isn't green, or its G3 didn't pass;
- `deploy/base` or the target overlay changed on main after the run started.

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

The tests after each deploy (G3 in dev and staging, the smoke tests in
prod) run on a self-hosted runner, because GitHub-hosted runners can't
reach the cluster. The job:
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
admin rights on the repo, for the registration token. Start it before each
release run, or keep it in a loop while you promote.

This repo is public, so a pull request from a fork could try to run on a
self-hosted runner. To prevent that:
- keep the runner registered only while a promotion runs;
- keep *Settings → Actions → Fork pull request workflows → Require
  approval for all external contributors* on. The pipeline itself never
  targets this label.
