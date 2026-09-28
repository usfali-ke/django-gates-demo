# The pipeline's scans, locally: same pinned images (read from the
# workflow, so they can't drift), same arguments, same verdict.py
# thresholds and accepted-risk register. Reports land in reports/<control>/
# (findings.json has everything); blocking findings print.
#
#   make scan          static controls (no image build)
#   make scan-image    builds the image, then image-scan · image-compliance · django-deploy-check
#   make sca-trivy     any single control, by its pipeline name
#
# Differences from CI: the image is a local `docker build` (not the
# reproducible OCI artifact), and trufflehog verifies candidates against
# their providers from your machine, as it does from the runner.

SHELL   := /bin/bash
WF      := .github/workflows/devsecops-pipeline.yml
pin      = $(shell sed -n 's/^  $(1): //p' $(WF))
SEMGREP    := $(call pin,SEMGREP)
GITLEAKS   := $(call pin,GITLEAKS)
TRUFFLEHOG := $(call pin,TRUFFLEHOG)
TRIVY      := $(call pin,TRIVY)
CHECKOV    := $(call pin,CHECKOV)
DOCKLE     := $(call pin,DOCKLE)
IMAGE_TAG  := django-gates-demo:local

# As you, so reports aren't root-owned; tools that want a home get /tmp.
RUN     := docker run --rm --user $(shell id -u):$(shell id -g) -e HOME=/tmp
VERDICT  = CONTROL=$@ VERDICT_FILE=reports/$@/verdict.json TOOL="$(1) (make)" python3 .github/scripts/verdict.py

STATIC := sast-semgrep secrets-gitleaks secrets-trufflehog sca-trivy iac-checkov
IMAGE  := image-scan image-compliance django-deploy-check

.PHONY: scan scan-image image pre-commit-secrets $(STATIC) $(IMAGE)

# Every control runs; the exit code says whether any failed.
scan:
	@rc=0; for t in $(STATIC); do $(MAKE) --no-print-directory $$t || rc=1; done; exit $$rc

scan-image: image
	@rc=0; for t in $(IMAGE); do $(MAKE) --no-print-directory $$t || rc=1; done; exit $$rc

sast-semgrep:
	@mkdir -p reports/$@
	@$(RUN) -v "$(CURDIR):/src:ro" -v "$(CURDIR)/reports/$@:/out" -w /src $(SEMGREP) semgrep scan \
	  --config p/default --config p/python --config p/django --config p/dockerfile --config p/github-actions \
	  --metrics=off --json-output=/out/semgrep.json -q || true
	@$(call VERDICT,semgrep) semgrep reports/$@/semgrep.json

secrets-gitleaks:
	@mkdir -p reports/$@
	@$(RUN) -v "$(CURDIR):/repo" -w /repo $(GITLEAKS) git /repo --redact --no-banner --log-level warn \
	  --report-format json --report-path /repo/reports/$@/gitleaks.json --exit-code 0 || true
	@SCOPE="every commit reachable from HEAD" $(call VERDICT,gitleaks) gitleaks reports/$@/gitleaks.json

secrets-trufflehog:
	@mkdir -p reports/$@
	@$(RUN) -v "$(CURDIR):/repo:ro" $(TRUFFLEHOG) git file:///repo --json --no-update \
	  --results=verified,unknown,unverified 2>/dev/null \
	  | jq -c 'select(.DetectorName) | del(.Raw, .RawV2) | .ExtraData = null' > reports/$@/trufflehog.jsonl; \
	  RC=$${PIPESTATUS[0]} $(call VERDICT,trufflehog) trufflehog reports/$@/trufflehog.jsonl

sca-trivy:
	@mkdir -p reports/$@
	@$(RUN) -v "$(CURDIR):/src:ro" -v "$(CURDIR)/reports/$@:/out" -v trivy-cache:/tmp/trivy $(TRIVY) \
	  fs --cache-dir /tmp/trivy --scanners vuln --list-all-pkgs --include-dev-deps --format json \
	  --output /out/trivy-fs.json --exit-code 0 -q /src || true
	@$(call VERDICT,trivy) trivy-fs reports/$@/trivy-fs.json

iac-checkov:
	@mkdir -p reports/$@/input
	@cp Dockerfile reports/$@/input/Dockerfile
	@kubectl kustomize deploy/kind | uv run -q --no-project --with pyyaml==6.0.3 python .github/scripts/scan_view.py > reports/$@/input/kind.yaml
	@$(RUN) -v "$(CURDIR)/reports/$@:/work" $(CHECKOV) -f /work/input/kind.yaml -f /work/input/Dockerfile \
	  --framework kubernetes dockerfile -o json --output-file-path /work --soft-fail --quiet > /dev/null || true
	@mv reports/$@/results_json.json reports/$@/checkov.json 2>/dev/null || true
	@$(call VERDICT,checkov) checkov reports/$@/checkov.json

image:
	docker build -t $(IMAGE_TAG) .

image-scan:
	@mkdir -p reports/$@
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(CURDIR)/reports/$@:/out" -v trivy-cache:/root/.cache/trivy $(TRIVY) \
	  image --scanners vuln,secret --severity CRITICAL,HIGH --format json --output /out/trivy.json --exit-code 0 -q $(IMAGE_TAG) || true
	@BASE_IMAGE="$(call pin,BASE_IMAGE)" $(call VERDICT,trivy) trivy reports/$@/trivy.json

image-compliance:
	@mkdir -p reports/$@
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(CURDIR)/reports/$@:/out" $(DOCKLE) \
	  -f json -o /out/dockle.json --exit-code 0 $(IMAGE_TAG) || true
	@$(call VERDICT,dockle) dockle reports/$@/dockle.json

django-deploy-check:
	@mkdir -p reports/$@
	@DJANGO_SECRET_KEY=$$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))') \
	  docker run --rm --read-only --tmpfs /tmp -e DJANGO_SECRET_KEY -e DJANGO_ALLOWED_HOSTS=app.example.invalid \
	  $(IMAGE_TAG) python manage.py check --deploy --fail-level WARNING > reports/$@/check-deploy.txt 2>&1; \
	  RC=$$? $(call VERDICT,django check --deploy) django-check reports/$@/check-deploy.txt

# pre-commit: only what's staged, so it's fast (.pre-commit-config.yaml).
pre-commit-secrets:
	@mkdir -p reports/secrets-gitleaks
	@$(RUN) -v "$(CURDIR):/repo" -w /repo $(GITLEAKS) git /repo --pre-commit --staged --redact --no-banner --log-level warn \
	  --report-format json --report-path /repo/reports/secrets-gitleaks/gitleaks-staged.json --exit-code 0 || true
	@SCOPE="the staged changes" CONTROL=secrets-gitleaks TOOL="gitleaks (pre-commit)" \
	  python3 .github/scripts/verdict.py gitleaks reports/secrets-gitleaks/gitleaks-staged.json
