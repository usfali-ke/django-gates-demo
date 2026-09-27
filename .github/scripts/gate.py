"""Assemble one gate decision from the control verdicts of this run.

Every control is its own job ending in verdict.py; a gate criterion is
answered by one or more of them (SAST = semgrep + bandit + the workflow
audit). This file is the single list of which job answers which dashboard
criterion (keys: the dashboard's docs/GATE_INGEST_API.md).

    NEEDS='${{ toJSON(needs) }}' python3 .github/scripts/gate.py G1 out.json

A criterion is:
  fail     if any of its controls failed, or didn't leave a verdict (a
           crashed, cancelled or skipped job is never an implicit pass);
  skipped  if a control reported `skipped` (couldn't be evaluated in this
           context, e.g. no signature on a pull request) — not a pass;
  pass     only when every control passed.
The gate passes only when every criterion passes, except the keys in
ALLOW_SKIPPED (comma-separated) which may be `skipped` — used on pull
requests, where the image is built and tested but never published.

Writes gate-result.json (a GateEvaluationIn body), the job summary, and
`status=pass|fail` to $GITHUB_OUTPUT.
"""

import datetime as dt
import json
import os
import sys

# gate → [(criterion key, category, [(job id, output name)])]
GATES = {
    "G1": [
        ("required_reviewers_approved", "governance", [("reviewers", "result")]),
        ("unit_tests_pass", "quality", [("unit-tests", "result")]),
        ("sast_clean", "security", [("sast-semgrep", "result"), ("sast-bandit", "result"), ("workflow-audit", "result")]),
        ("secrets_clean", "security", [("secrets-gitleaks", "result"), ("secrets-trufflehog", "result")]),
        ("commits_signed", "security", [("commits-signed", "result")]),
    ],
    "G2": [
        ("reproducible_build_config_controlled", "delivery", [("build", "result")]),
        ("sca_clean", "security", [("sca-osv", "result")]),
        ("iac_clean", "security", [("iac-checkov", "result"), ("iac-hadolint", "result")]),
        ("container_image_scan_hardened_base", "security", [("image-scan", "result")]),
        ("artifact_signed_attested", "security", [("publish", "result")]),
        ("sbom_present", "security", [("sbom", "result")]),
    ],
    "G3": [
        ("functional_integration_regression_pass", "quality", [("functional", "result")]),
        ("performance_within_slo", "quality", [("performance", "result")]),
        ("coverage_threshold_met", "quality", [("unit-tests", "coverage")]),
        ("dast_scan_clean", "security", [("dast-zap", "result"), ("dast-nuclei", "result"), ("dast-tls", "result")]),
        ("compliance_scan_clean", "security", [("image-compliance", "result"), ("django-deploy-check", "result")]),
    ],
    "G5": [
        ("artifact_provenance_verified", "security", [("provenance", "result")]),
        ("target_env_config_controlled", "delivery", [("config", "result")]),
        ("approved_gitops_pipeline_path", "governance", [("deploy", "result")]),
    ],
}


def verdict(needs, job, output):
    j = needs.get(job) or {}
    try:
        v = json.loads((j.get("outputs") or {}).get(output) or "")
    except ValueError:
        v = None
    if not isinstance(v, dict) or v.get("status") not in ("pass", "fail", "skipped"):
        v = {"status": "fail", "detail": f"control did not complete (job {job}: {j.get('result', 'not run')})"}
    return job, v


def criterion(needs, key, category, sources, evidence_url):
    parts = [verdict(needs, job, output) for job, output in sources]
    statuses = {v["status"] for _, v in parts}
    status = "fail" if "fail" in statuses else "skipped" if "skipped" in statuses else "pass"
    if len(parts) == 1:
        detail = parts[0][1].get("detail", "")
    else:
        detail = " | ".join(f"{job} {v['status']}: {v.get('detail', '')}" for job, v in parts)
    metrics = {}
    for job, v in parts:
        for name, value in (v.get("metrics") or {}).items():
            if isinstance(value, (int, float)):
                metrics[name if len(parts) == 1 else f"{job}.{name}"] = value
    out = {"key": key, "category": category, "status": status, "detail": detail[:1000], "evidence_url": evidence_url}
    if metrics:
        out["metrics"] = metrics
    return out


def main():
    gate, path = sys.argv[1], sys.argv[2]
    e = os.environ.get
    needs = json.loads(e("NEEDS") or "{}")
    run_url = f"{e('GITHUB_SERVER_URL')}/{e('GITHUB_REPOSITORY')}/actions/runs/{e('GITHUB_RUN_ID')}"
    allow_skipped = {k for k in (e("ALLOW_SKIPPED") or "").split(",") if k}
    # Every report is in the run's artifacts (report-<control>, and the
    # signed `evidence` bundle).
    criteria = [criterion(needs, *c, evidence_url=f"{run_url}#artifacts") for c in GATES[gate]]
    ok = all(c["status"] == "pass" or (c["status"] == "skipped" and c["key"] in allow_skipped) for c in criteria)
    status = "pass" if ok else "fail"
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    body = {
        # product/source/run_url are overwritten by the dashboard from the
        # run it downloads this from; here so the file reads standalone.
        "product": e("PRODUCT") or e("GITHUB_REPOSITORY", "/").split("/")[-1],
        "gate": gate,
        "status": status,
        "source": "github-actions",
        "subject": e("SUBJECT"),
        "external_id": f"gh-{e('GITHUB_RUN_ID')}-{e('GITHUB_RUN_ATTEMPT')}-{gate}",
        "commit_sha": e("COMMIT_SHA") or e("GITHUB_SHA"),
        "artifact_digest": e("DIGEST") or None,
        "environment": e("ENVIRONMENT") or None,
        "run_url": run_url,
        "started_at": e("STARTED_AT") or now,
        "finished_at": now,
        "criteria": criteria,
    }
    with open(path, "w") as f:
        json.dump(body, f, indent=2)
    icon = {"pass": "✅", "fail": "❌", "skipped": "⏭️"}
    with open(e("GITHUB_STEP_SUMMARY"), "a") as f:
        f.write(f"### {gate}: {status}\n\n| | criterion | detail |\n|---|---|---|\n")
        f.write("".join(f"| {icon[c['status']]} {c['status']} | `{c['key']}` | {c['detail'].replace('|', '/')} |\n" for c in criteria))
        if allow_skipped:
            f.write(f"\n_Skipped allowed in this context: {', '.join(sorted(allow_skipped))}_\n")
    for c in criteria:
        print(f"{c['status']:>7}  {c['key']}: {c['detail']}")
    with open(e("GITHUB_OUTPUT"), "a") as f:
        f.write(f"status={status}\n")


if __name__ == "__main__":
    main()
