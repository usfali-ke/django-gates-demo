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

## Releasing (same shape: `devsecops-release.yml`)

```
R1 resolve ── the change is an open `change` issue with both approval labels
R1 verify ─── signature + SBOM + SLSA (this commit) · evidence attestation
              (G2 + G3 passed for this digest) · target config
R2 G4 ─────── `release-approval` environment (approver ≠ whoever started or
              re-ran the run) + dashboard decision on the change
R3 deploy ─── digest committed to deploy/kind → G5 gate
R4 verify ─── wait for the dashboard's `security-dashboard/G6` (Argo CD)
R5 evidence ─ `release-evidence` bundle, attested to the digest
```

1. Open a **Change request** issue, with a change window that covers the
   release. Someone other than you adds `change-approved` and
   `readiness-approved`.
2. Actions → **devsecops-release** → Run workflow, giving the issue
   (`7`, `#7` or `CHG-7`).
3. Someone other than whoever started the run approves the
   `release-approval` deployment. If G4 is re-run, it needs a fresh
   approval from someone who neither started nor re-ran the run.
4. The release runs on main's HEAD, which needs a published image. Pushes
   that only touch `deploy/**` or `*.md` don't run the pipeline, so after
   one, run **devsecops-pipeline** on main by hand before releasing.

## One-time cluster setup (run by an operator)

The Rollout reads `DJANGO_SECRET_KEY` from a Secret, which this repo never
contains:

```
kubectl -n django-gates-demo create secret generic django-gates-demo \
  --from-literal=secret-key="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
```
