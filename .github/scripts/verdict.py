"""One verdict per control.

Reads a tool's report, applies the threshold, writes `<output>=<json>`
({status, detail, tool, metrics, accepted}) to $GITHUB_OUTPUT for the gate
and evidence jobs, copies it to $VERDICT_FILE (inside the control's report
artifact, so each artifact is self-describing), and exits 1 on fail so the
control's own job goes red:

    python3 .github/scripts/verdict.py <check> [args...]

A report that is missing or unreadable is a fail — a scanner that didn't
run is not a clean scan. Tools always run with "don't fail on findings"
(their exit codes mean different things: findings vs. crashed), so this
script is the one place a threshold is decided. Settings come from env,
never from ${{ }} inside a script.

Accepted risks (security/accepted-risks.json) are applied here and listed
in the verdict; an expired entry no longer applies.
"""

import datetime as dt
import glob
import json
import os
import re
import sys

# The only XML parsed here is JUnit/coverage output from this job's own
# pytest run. The runner's Python links expat >= 2.4.1, so ElementTree
# resolves no external entities and refuses entity-expansion bombs — the
# risks semgrep's use-defused-xml-parse rule is about.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

env = os.environ.get
CONTROL = env("CONTROL", "")
_applied = []


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def load_jsonl(path):
    try:
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]
    except (OSError, ValueError):
        return None


def missing(tool):
    return False, f"{tool} did not produce a report", None


def accepted(finding_id, text=""):
    """True if the register accepts this finding for this control (and the
    entry hasn't expired). Records every entry used."""
    register = load(env("ACCEPTED_RISKS", "security/accepted-risks.json")) or {}
    today = dt.date.today().isoformat()
    for entry in register.get("accepted", []):
        if entry.get("control") != CONTROL or entry.get("id") != finding_id:
            continue
        if entry.get("match") and entry["match"] not in text:
            continue
        if entry.get("expires", "") < today:
            continue
        if finding_id not in _applied:
            _applied.append(finding_id)
        return True
    return False


def summarize(items, key, limit=8):
    return ", ".join(sorted({key(i) for i in items})[:limit])


# --- G1 ---------------------------------------------------------------------


def reviewers(path):
    """Latest review per reviewer, author excluded; only approvals of the
    current head count — an approval of an older revision didn't review
    what's actually being merged."""
    author, head, required = env("AUTHOR"), env("HEAD_SHA"), int(env("REQUIRED_APPROVALS", "1"))
    latest = {}
    for r in load_jsonl(path) or []:
        if r["user"]["login"] != author and r["state"] not in ("COMMENTED", "PENDING"):
            latest[r["user"]["login"]] = r
    approvals = sorted(u for u, r in latest.items() if r["state"] == "APPROVED" and r["commit_id"] == head)
    blocking = sorted(u for u, r in latest.items() if r["state"] == "CHANGES_REQUESTED")
    detail = f"{len(approvals)} of {required} required approval(s) on head {head[:7]} (author {author} excluded)"
    if blocking:
        detail += f"; changes requested by {', '.join(blocking)}"
    return len(approvals) >= required and not blocking, detail, {"approvals": len(approvals), "required": required}


def commits(path):
    """commits.tsv: short sha, GitHub's verified flag, reason."""
    with open(path) as f:
        rows = [line.rstrip("\n").split("\t") for line in f if line.strip()]
    unsigned = [f"{sha} ({reason})" for sha, verified, reason in rows if verified != "true"]
    detail = f"{len(unsigned)} of {len(rows)} commit(s) unsigned/unverified" + (f": {', '.join(unsigned[:6])}" if unsigned else "")
    return bool(rows) and not unsigned, detail, None


def tests(pattern):
    """JUnit files → passed/total. A skipped test is excluded from the
    total, and zero tests is a fail, so skipping everything can't pass.
    RC is the test command's exit code (also catches collection errors)."""
    passed = total = 0
    for path in glob.glob(pattern, recursive=True):
        for case in ET.parse(path).getroot().iter("testcase"):  # nosemgrep: python.lang.security.use-defused-xml-parse.use-defused-xml-parse
            tags = {child.tag for child in case}
            if "skipped" in tags:
                continue
            total += 1
            passed += not tags & {"failure", "error"}
    ok = env("RC") == "0" and total > 0 and passed == total
    return ok, f"{passed}/{total} passed ({env('LABEL', pattern)})", {"tests_passed": passed, "tests_total": total}


def coverage(path):
    threshold = float(env("COVERAGE_THRESHOLD"))
    try:
        rate = ET.parse(path).getroot().get("line-rate")  # nosemgrep: python.lang.security.use-defused-xml-parse.use-defused-xml-parse
    except (OSError, ET.ParseError):
        rate = None
    if rate is None:
        return False, "no coverage report", {"coverage_pct": 0.0, "threshold_pct": threshold}
    cov = float(rate) * 100
    return cov >= threshold, f"{cov:.1f}% line coverage vs threshold {threshold:.0f}% (pytest-cov, unit tests)", {"coverage_pct": round(cov, 2), "threshold_pct": threshold}


def semgrep(path):
    """ERROR (High) and WARNING (Medium) block; INFO is reported."""
    report = load(path)
    if report is None:
        return missing("semgrep")
    results = [r for r in report.get("results", []) if not accepted(r["check_id"], r.get("path", ""))]
    blocking = [r for r in results if r["extra"].get("severity") in ("ERROR", "WARNING")]
    errors = report.get("errors") or []
    rules = summarize(blocking, lambda r: f"{r['check_id'].rsplit('.', 1)[-1]} ({r['path']}:{r['start']['line']})", 6)
    detail = f"{len(blocking)} High/Medium of {len(results)} findings, {len(errors)} scan error(s){': ' + rules if rules else ''}"
    return not blocking, detail, {"findings": len(results), "blocking": len(blocking)}


def bandit(path):
    """Medium+ severity at Medium+ confidence blocks."""
    report = load(path)
    if report is None:
        return missing("bandit")
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    results = [r for r in report.get("results", []) if not accepted(r["test_id"], r.get("filename", ""))]
    blocking = [r for r in results if rank.get(r["issue_severity"], 0) >= 1 and rank.get(r["issue_confidence"], 0) >= 1]
    ids = summarize(blocking, lambda r: f"{r['test_id']} ({r['filename'].lstrip('./')}:{r['line_number']})", 6)
    files = report.get("metrics", {}).get("_totals", {}).get("loc", 0)
    detail = f"{len(blocking)} Medium+/Medium+ of {len(results)} findings over {files} LOC{': ' + ids if ids else ''}"
    return not blocking and files > 0, detail, {"findings": len(results), "blocking": len(blocking)}


def gitleaks(path):
    report = load(path)
    if report is None:
        return missing("gitleaks")
    leaks = [r for r in report if not accepted(r.get("RuleID", ""), r.get("File", ""))]
    where = summarize(leaks, lambda r: f"{r['RuleID']} ({r['File']}:{r['StartLine']} @{r.get('Commit', '')[:7]})", 6)
    return not leaks, f"{len(leaks)} leak(s) in {env('SCOPE', 'the repository')} (values redacted){': ' + where if where else ''}", {"leaks": len(leaks)}


def trufflehog(path):
    """Verified (live) credentials block; unverified candidates are
    reported, since most are test fixtures or dead keys."""
    rows = load_jsonl(path)
    if rows is None:
        return missing("trufflehog")
    rows = [r for r in rows if "DetectorName" in r and not accepted(r["DetectorName"])]
    verified = [r for r in rows if r.get("Verified")]
    where = summarize(verified, lambda r: f"{r['DetectorName']} ({((r.get('SourceMetadata') or {}).get('Data') or {}).get('Git', {}).get('file', '?')})", 6)
    detail = f"{len(verified)} verified live credential(s), {len(rows) - len(verified)} unverified candidate(s) in full git history{': ' + where if where else ''}"
    return env("RC") == "0" and not verified, detail, {"verified": len(verified), "unverified": len(rows) - len(verified)}


# --- G2 ---------------------------------------------------------------------


def build(dockerfile):
    """Config controlled (every base ref digest-pinned) and reproducible
    (cached build == --no-cache build, env D1/D2)."""
    refs, bad = [], []
    with open(dockerfile) as f:
        for line in f:
            m = re.match(r"\s*#\s*syntax=(\S+)", line) or re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)", line, re.I)
            if m and not re.fullmatch(r"[a-z][\w-]*", m.group(1)):  # FROM <earlier stage> isn't a base ref
                refs.append(m.group(1))
                if not re.search(r"@sha256:[0-9a-f]{64}$", m.group(1)):
                    bad.append(m.group(1))
    pins = f"{len(refs) - len(bad)}/{len(refs)} base refs digest-pinned" + (f" (unpinned: {', '.join(bad)})" if bad else "")
    d1, d2 = env("D1"), env("D2")
    if env("RC") != "0" or not d1 or not d2:
        ok, repro = False, "build failed"
    elif d1 != d2:
        ok, repro = False, f"NOT reproducible: {d1[:19]} vs {d2[:19]} (cached vs --no-cache)"
    else:
        ok, repro = True, f"reproducible: cached and --no-cache builds both {d1[:19]} (same runner)"
    return ok and bool(refs) and not bad, f"{repro}; {pins}", None


def osv(path):
    """High/Critical (CVSS >= 7) block, and so does a vulnerability with no
    severity at all — unknown isn't low. Zero packages scanned is a fail
    (the lockfile wasn't understood)."""
    report = load(path)
    if report is None:
        return missing("osv-scanner")
    packages = [p for r in report.get("results") or [] for p in r.get("packages") or []]
    blocking, lower = [], 0
    for p in packages:
        for group in p.get("groups") or []:
            ids = group.get("ids") or []
            if any(accepted(i) for i in ids):
                continue
            sev = group.get("max_severity") or ""
            name = f"{ids[0] if ids else '?'} ({p['package']['name']} {p['package']['version']})"
            if sev == "" or float(sev) >= 7.0:
                blocking.append(name + (" no severity" if sev == "" else f" {sev}"))
            else:
                lower += 1
    detail = f"{len(blocking)} High/Critical-or-unrated, {lower} lower, across {len(packages)} packages ({env('LOCKFILE', 'lockfile')}){': ' + ', '.join(sorted(blocking)[:8]) if blocking else ''}"
    return bool(packages) and not blocking, detail, {"packages": len(packages), "blocking": len(blocking)}


def checkov(path):
    """Open-source checkov has no severities, so every failed check blocks;
    exceptions are inline `checkov.io/skipN` annotations, counted here."""
    reports = load(path)
    if reports is None:
        return missing("checkov")
    reports = reports if isinstance(reports, list) else [reports]
    passed = sum(r.get("summary", {}).get("passed", 0) for r in reports)
    failed = [c for r in reports for c in r.get("results", {}).get("failed_checks", [])]
    skipped = sorted({c["check_id"] for r in reports for c in r.get("results", {}).get("skipped_checks", [])})
    ids = summarize(failed, lambda c: f"{c['check_id']} ({c['resource']})")
    detail = (f"{len(failed)} failed, {passed} passed, {len(skipped)} skipped with inline justification"
              f"{' (' + ', '.join(skipped) + ')' if skipped else ''} — {', '.join(r.get('check_type', '?') for r in reports)}"
              f"{': ' + ids if ids else ''}")
    return not failed and passed > 0, detail, {"failed": len(failed), "passed": passed}


def hadolint(path):
    """error and warning block; info/style are reported."""
    report = load(path)
    if report is None:
        return missing("hadolint")
    findings = [r for r in report if not accepted(r["code"])]
    blocking = [r for r in findings if r["level"] in ("error", "warning")]
    ids = summarize(blocking, lambda r: f"{r['code']} (line {r['line']})")
    return not blocking, f"{len(blocking)} error/warning of {len(findings)} findings on Dockerfile{': ' + ids if ids else ''}", None


def zizmor_where(finding):
    try:
        loc = finding["locations"][0]
        local = loc["symbolic"]["key"]["Local"]
        path = local.get("given_path") or local.get("verbatim_path") or "?"
        return f"{path.removeprefix('/repo/')}:{loc['concrete']['location']['start_point']['row'] + 1}"
    except (KeyError, IndexError, TypeError):
        return "?"


def workflows(zizmor_path, actionlint_path):
    """zizmor Medium+ and every actionlint error block."""
    z = load(zizmor_path)
    a = load(actionlint_path)
    if z is None or a is None:
        return missing("zizmor" if z is None else "actionlint")
    zf = [f for f in z if not accepted(f.get("ident", ""))]
    zb = [f for f in zf if (f.get("determinations") or {}).get("severity", "").lower() in ("medium", "high")]
    ids = summarize(zb, lambda f: f"{f['ident']} ({zizmor_where(f)})", 6)
    detail = f"zizmor: {len(zb)} Medium/High of {len(zf)} findings{': ' + ids if ids else ''}; actionlint: {len(a)} error(s)"
    if a:
        detail += ": " + summarize(a, lambda e: f"{e['filepath']}:{e['line']} {e['kind']}", 4)
    return not zb and not a, detail, {"zizmor_blocking": len(zb), "actionlint_errors": len(a)}


def trivy(path):
    """Critical/High with a released fix block; ones with no upstream fix
    are reported but don't block (BLOCK_UNFIXED=true to block them too).
    Any embedded secret blocks. Plus "hardened base": a non-root USER."""
    report = load(path)
    if report is None:
        return missing("trivy")
    vulns = [v for r in report.get("Results") or [] for v in r.get("Vulnerabilities") or [] if not accepted(v["VulnerabilityID"])]
    secrets = [s for r in report.get("Results") or [] for s in r.get("Secrets") or [] if not accepted(s.get("RuleID", ""))]
    block_unfixed = env("BLOCK_UNFIXED") == "true"
    blocking = vulns if block_unfixed else [v for v in vulns if v.get("FixedVersion")]
    unfixed = [v for v in vulns if not v.get("FixedVersion")]
    top = summarize(blocking, lambda v: f"{v['VulnerabilityID']} ({v['PkgName']})")
    user = ((report.get("Metadata") or {}).get("ImageConfig") or {}).get("config", {}).get("User", "").strip()
    root = user.split(":")[0] in ("", "0", "root")
    detail = (f"{len(blocking)} fixable Critical/High{': ' + top if top else ''}; {len(unfixed)} without an upstream fix "
              f"({'blocking' if block_unfixed else 'reported, not blocking'}); {len(secrets)} embedded secret(s); "
              f"runs as {user or 'root (no USER)'}; base {env('BASE_IMAGE', '?')[:40]}")
    return not blocking and not secrets and not root, detail, {"blocking": len(blocking), "unfixed": len(unfixed)}


def sbom(path):
    bom = load(path)
    if bom is None:
        return missing("syft")
    n = len(bom.get("components") or [])
    return bom.get("bomFormat") == "CycloneDX" and n > 0, f"CycloneDX {bom.get('specVersion')} with {n} components (syft, from the built image)", {"components": n}


def signed():
    """A signature is the statement "this passed every static control":
    only signed when they all passed (NOT_READY lists the ones that
    didn't), and a pass means the pushed digest is the built one and the
    signature and attestations verify (VERIFY_FAILED)."""
    if env("NOT_READY"):
        return False, f"not published or signed: controls failed ({env('NOT_READY')})", None
    if env("VERIFY_FAILED"):
        return False, f"publish/sign ran but verification failed:{env('VERIFY_FAILED')}", None
    return True, ("pushed digest == built digest; cosign keyless signature + CycloneDX SBOM and SLSA v1 provenance "
                  f"attestations verified for {env('CERT_IDENTITY', '').split('/', 5)[-1]} (public Rekor); GitHub build provenance attested"), None


# --- G3 ---------------------------------------------------------------------


def dockle(path):
    """FATAL and WARN block; INFO is reported."""
    report = load(path)
    if report is None:
        return missing("dockle")
    details = report.get("details") or []
    kept = [d for d in details if not all(accepted(d["code"], a) for a in (d.get("alerts") or [""]))]
    blocking = [d for d in kept if d["level"] in ("FATAL", "WARN")]
    ids = summarize(blocking, lambda d: f"{d['code']} {d['title']}")
    return not blocking, f"{len(blocking)} FATAL/WARN of {len(kept)} findings (CIS Docker Benchmark + dockle checks){': ' + ids if ids else ''}", None


def django_check(path):
    """`manage.py check --deploy --fail-level WARNING` inside the built
    image, with production settings. RC is its exit code."""
    try:
        with open(path) as f:
            out = f.read()
    except OSError:
        return missing("django check --deploy")
    issues = re.findall(r"^\?: \((\S+)\)|^\S+: \((\S+)\)", out, re.M)
    ids = sorted({a or b for a, b in issues})
    ok = env("RC") == "0" and "System check identified no issues" in out
    return ok, f"{len(ids)} deployment check issue(s){': ' + ', '.join(ids[:8]) if ids else ''} (manage.py check --deploy --fail-level WARNING, production settings, in the image)", None


def k6(path):
    summary = load(path)
    if summary is None:
        return missing("k6")
    m = summary.get("metrics", {})
    val = lambda name, stat: (m.get(name, {}).get("values") or {}).get(stat)  # noqa: E731
    p95, failed, checks, slo = val("http_req_duration", "p(95)"), val("http_req_failed", "rate") or 0, val("checks", "rate") or 0, float(env("SLO_P95_MS"))
    reqs = val("http_reqs", "count") or 0
    if p95 is None:
        return False, "k6 summary has no http_req_duration", None
    ok = p95 <= slo and failed < 0.01 and checks >= 0.99
    detail = f"p95 {p95:.0f} ms vs SLO {slo:.0f} ms; {100 * failed:.2f}% failed of {reqs} requests, {100 * checks:.1f}% checks ok (authenticated, via TLS proxy)"
    return ok, detail, {"p95_ms": round(p95, 1), "slo_ms": slo, "requests": reqs}


def zap(path):
    """High and Medium block (after accepted risks). RC is zap.sh's exit
    code: the plan fails on errors and warnings, e.g. the seeded API
    requests not being authenticated — then the scan proves nothing."""
    report = load(path)
    if report is None:
        return missing("ZAP")
    alerts = [a for s in report.get("site", []) for a in s.get("alerts", [])
              if str(a.get("confidence")) != "0" and not accepted(a.get("pluginid", ""), a.get("name", ""))]  # 0 = marked false positive
    high = [a for a in alerts if str(a.get("riskcode")) == "3"]
    medium = [a for a in alerts if str(a.get("riskcode")) == "2"]
    low = [a for a in alerts if str(a.get("riskcode")) == "1"]
    names = summarize(high + medium, lambda a: f"{a.get('name', '?')} [{a.get('pluginid')}]", 6)
    plan_ok = env("RC") == "0"
    detail = (f"{len(high)} High, {len(medium)} Medium, {len(low)} Low alert types — ZAP authenticated spider + active scan"
              f"{'' if plan_ok else f' (automation plan FAILED, rc {env(chr(82) + chr(67))}: see zap.log)'}{': ' + names if names else ''}")
    return plan_ok and not high and not medium, detail, {"high": len(high), "medium": len(medium), "low": len(low)}


def nuclei(path):
    """Medium+ block; low is reported."""
    rows = load_jsonl(path)
    if rows is None:
        return missing("nuclei")
    rows = [r for r in rows if not accepted(r.get("template-id", ""))]
    blocking = [r for r in rows if (r.get("info") or {}).get("severity") in ("medium", "high", "critical")]
    ids = summarize(blocking, lambda r: f"{r['template-id']} ({r['info']['severity']})")
    detail = f"{len(blocking)} Medium+ of {len(rows)} findings — nuclei {env('TEMPLATES', '')} (dos/fuzz/intrusive excluded){': ' + ids if ids else ''}"
    return env("RC") == "0" and not blocking, detail, {"findings": len(rows), "blocking": len(blocking)}


def testssl(path):
    """HIGH and CRITICAL block; certificate-issuance findings caused by the
    ephemeral internal CA are accepted in the register (by id)."""
    report = load(path)
    if report is None:
        return missing("testssl.sh")
    scans = report.get("scanResult") or []
    findings = []
    for scan in scans:
        for section, items in scan.items():
            if isinstance(items, list):
                findings += [i for i in items if isinstance(i, dict) and "severity" in i]
    # Per-certificate ids carry a suffix ("intermediate_cert_notAfter <#1>").
    kept = [f for f in findings if not accepted(re.sub(r"\s*<#\d+>$", "", f.get("id", "")))]
    blocking = [f for f in kept if f["severity"] in ("HIGH", "CRITICAL")]
    fatal = [f for f in kept if f["severity"] == "FATAL"]
    ids = summarize(blocking + fatal, lambda f: f"{f['id']} ({f['severity']})")
    detail = f"{len(blocking)} High/Critical of {len(findings)} TLS checks (testssl.sh: protocols, ciphers, vulnerabilities, headers){': ' + ids if ids else ''}"
    return bool(scans) and bool(findings) and not blocking and not fatal, detail, {"checks": len(findings), "blocking": len(blocking)}


# --- G5 ---------------------------------------------------------------------


def kubeconform(path):
    """Render valid against schemas (-strict) AND the only change vs git
    is the image digest (CHANGED, space-separated paths)."""
    summary = (load(path) or {}).get("summary", {})
    valid = summary.get("valid", 0)
    total = sum(summary.get(k, 0) for k in ("valid", "invalid", "errors", "skipped"))
    changed = (env("CHANGED") or "").split()
    ok = env("RC") == "0" and total > 0 and valid == total and changed == [env("KUSTOMIZATION", "deploy/kind/kustomization.yaml")]
    return ok, f"deploy/kind render: {valid}/{total} resources valid (kubeconform -strict); change vs git: {', '.join(changed) or 'none'} (image digest only)", None


# --- generic ----------------------------------------------------------------


def result(status, detail):
    """For controls decided in shell (API checks, verification commands).
    `skipped` = not evaluated in this context (says why in detail); it
    never counts as a pass — gate.py decides whether it may be skipped."""
    return ("skipped" if status == "skipped" else status == "pass"), detail, None


CHECKS = {f.__name__.replace("_", "-"): f for f in (
    reviewers, commits, tests, coverage, semgrep, bandit, gitleaks, trufflehog,
    build, osv, checkov, hadolint, workflows, trivy, sbom, signed,
    dockle, django_check, k6, zap, nuclei, testssl, kubeconform, result,
)}


def main():
    check, args = sys.argv[1], sys.argv[2:]
    try:
        ok, detail, metrics = CHECKS[check](*args)
    except (OSError, ValueError, KeyError, TypeError, IndexError, ET.ParseError) as exc:
        ok, detail, metrics = False, f"{check}: could not evaluate ({type(exc).__name__}: {exc})", None
    out = {"status": "skipped" if ok == "skipped" else "pass" if ok else "fail", "detail": detail[:1000]}
    if env("TOOL"):
        out["tool"] = env("TOOL")
    if metrics:
        out["metrics"] = metrics
    if _applied:
        out["accepted"] = _applied
        out["detail"] = (out["detail"] + f"; accepted risks applied: {', '.join(_applied)}")[:1000]
    print(f"{out['status']}: {out['detail']}")
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"{env('OUTPUT', 'result')}={json.dumps(out)}\n")
    if env("VERDICT_FILE"):
        os.makedirs(os.path.dirname(env("VERDICT_FILE")) or ".", exist_ok=True)
        with open(env("VERDICT_FILE"), "w") as f:
            json.dump({"control": CONTROL, "check": check, **out}, f, indent=2)
    if out["status"] == "fail":
        print(f"::error title={CONTROL or check}::{out['detail'][:500]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
