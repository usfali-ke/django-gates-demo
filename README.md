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
2 static ─────── semgrep · bandit · zizmor+actionlint · gitleaks · trufflehog
                 osv-scanner · checkov · hadolint · reviewers · signed commits
2 image ──────── trivy · syft SBOM · dockle · manage.py check --deploy
3 publish ────── (main only) push by digest · cosign sign · SBOM + SLSA attestations
   └─ G2 artifact gate ── a failed G2 stops here ──┐
4 preprod ────── functional · k6 performance       │  (full_scan=true on a
5 dast ───────── ZAP (authenticated) · nuclei · testssl   manual run overrides)
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
R1 verify ─── signature + SBOM + SLSA (this commit) · evidence attestation
              (G2 + G3 passed for this digest) · target config
R2 G4 ─────── `release-approval` environment + dashboard decision on the change
R3 deploy ─── digest committed to deploy/kind → G5 gate
R4 verify ─── wait for the dashboard's `security-dashboard/G6` (Argo CD)
R5 evidence ─ `release-evidence` bundle, attested to the digest
```

1. Open a **Change request** issue. Someone other than you adds
   `change-approved` and `readiness-approved`.
2. Actions → **devsecops-release** → Run workflow, giving the issue number.
3. Approve the `release-approval` deployment when GitHub asks.

## One-time cluster setup (run by an operator)

The Rollout reads `DJANGO_SECRET_KEY` from a Secret, which this repo never
contains:

```
kubectl -n django-gates-demo create secret generic django-gates-demo \
  --from-literal=secret-key="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
```
