"""Hermes AI security review as a G1 pipeline control (`ai-review` job).

    python3 .github/scripts/hermes_review.py

1. Forward: on pull_request events, send this run's PR event to the Hermes
   gateway, signed exactly like a GitHub webhook (X-Hub-Signature-256 HMAC
   over the body). The gateway is on the lab network, which is why the job
   runs on the self-hosted `lab-runner`. Review events (an approval) don't
   re-request a review — they reuse the one for the same head commit.
2. Wait: for Hermes's PR comment for THIS head commit — the one ending
   "Automated review by Hermes on commit <sha>", posted after this run asked
   (or, on review events, any time), by HERMES_COMMENTER when set.
3. Verdict: fail on any Critical/High finding (the same bar as SAST and
   secrets); Medium/Low are advisory and reported in the detail.
4. Report: parse each finding block (see PARSE_HEADER / PARSE_FIELD below —
   the route prompt in hermes-route.yaml writes this exact shape) into
   DefectDojo's Generic Findings Import schema and write it to
   $OUT/hermes-findings.json, so this control's findings reach DefectDojo
   through the same `defectdojo-upload` job as every other scanner's
   report (file-name rule in defectdojo_upload.py: hermes-findings.json ->
   "Generic Findings Import"). Written even when there are zero findings,
   so a clean run still shows as an imported, empty test rather than
   nothing happening.

Writes `result=<json>` ({status, detail, metrics}) to $GITHUB_OUTPUT like
verdict.py (and to $VERDICT_FILE when set), and exits 1 on fail, so a red
job is a failed control. Stdlib only. Source of truth:
security-dashboard/pipeline/github/hermes-pr-review/.

Env: HERMES_URL, HERMES_SECRET, GH_TOKEN, PR_NUMBER, HEAD_SHA,
GITHUB_REPOSITORY, GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_RUN_ID,
GITHUB_RUN_ATTEMPT; optional HERMES_COMMENTER, WAIT_SECONDS (default 1500),
VERDICT_FILE, OUT (directory for hermes-findings.json).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, NoReturn

MARKER = re.compile(r"Automated review by Hermes on commit ([0-9a-f]{7,40})")
BLOCKING = {"critical", "high"}
POLL_SECONDS = 20
# The comment this is parsed from is only as trustworthy as HERMES_COMMENTER
# makes it (see review_for()); these are a second, independent backstop so a
# single comment can't inject unbounded text into DefectDojo's findings
# table regardless of whose identity it carries. Found by Hermes reviewing
# this file's own diff (2026-11-05): Low, CWE-74.
MAX_FINDINGS = 50
MAX_FIELD_CHARS = 2000
MAX_TITLE_CHARS = 200

# One finding block, written by the route prompt's OUTPUT FORMAT section
# (hermes-route.yaml) as:
#   ### [F1] <title> (Severity: Critical)
#   - CWE: 89
#   - Location: path/to/file.py:42
#   - Description: ...
#   - Impact: ...
#   - Mitigation: ...
# Each field is one line (the prompt requires it), which is what makes this
# reliably parseable without a markdown table.
FINDING_HEADER = re.compile(r"^###\s*\[(?P<id>F\d+)\]\s*(?P<title>.+?)\s*\(Severity:\s*(?P<severity>Critical|High|Medium|Low)\)\s*$", re.M)
FIELD_LINE = re.compile(r"^-\s*(?P<label>CWE|Location|Description|Impact|Mitigation)\s*:\s*(?P<value>.*)$", re.I | re.M)
FILE_LINE = re.compile(r"^(?P<path>.+?):(?P<line>\d+)$")
SECTION_END = re.compile(r"^(---\s*$|##\s)", re.M)


def _http_url(url: str) -> str:
    """Only http(s): a file://, ftp:// or data: URL is never opened."""
    if urllib.parse.urlsplit(url).scheme.lower() not in ("https", "http"):
        raise ValueError(f"refusing non-HTTP(S) URL: {url!r}")
    return url


def _opener() -> urllib.request.OpenerDirector:
    opener = urllib.request.OpenerDirector()
    for h in (urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPDefaultErrorHandler(),
              urllib.request.HTTPErrorProcessor(), urllib.request.HTTPRedirectHandler(), urllib.request.UnknownHandler()):
        opener.add_handler(h)
    return opener


_HTTP = _opener()


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def finish(status: str, detail: str, **metrics) -> NoReturn:
    out = {"status": status, "detail": detail[:1000], "metrics": metrics}
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"result={json.dumps(out)}\n")
    if env("VERDICT_FILE"):
        os.makedirs(os.path.dirname(env("VERDICT_FILE")) or ".", exist_ok=True)
        with open(env("VERDICT_FILE"), "w") as f:
            json.dump({"control": "ai-review", **out}, f, indent=2)
    if env("GITHUB_STEP_SUMMARY"):
        with open(env("GITHUB_STEP_SUMMARY"), "a") as f:
            f.write(f"### AI security review (Hermes): {status}\n\n{detail}\n")
    print(f"{status}: {detail}")
    if status != "pass":
        print(f"::error::{detail[:500]}")
    sys.exit(0 if status == "pass" else 1)  # a verdict is final


def forward(body: bytes) -> str:
    secret = env("HERMES_SECRET")
    if not secret:
        finish("fail", "HERMES_WEBHOOK_SECRET is not set for this repository — the review can't be requested")
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    delivery = f"gha-{env('GITHUB_RUN_ID')}-{env('GITHUB_RUN_ATTEMPT', '1')}"
    req = urllib.request.Request(_http_url(env("HERMES_URL")), data=body, method="POST", headers={
        "Content-Type": "application/json", "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery, "X-Hub-Signature-256": sig,
    })
    try:
        with _HTTP.open(req, timeout=30) as resp:
            return f"HTTP {resp.status} {resp.read().decode()[:200]}"
    except urllib.error.HTTPError as exc:
        hint = {401: "signature rejected — HERMES_WEBHOOK_SECRET doesn't match the route secret",
                404: "no such route — check HERMES_WEBHOOK_URL", 429: "Hermes rate limit hit — re-run in a minute"}
        finish("fail", f"Hermes refused the review request: HTTP {exc.code} ({hint.get(exc.code, exc.reason)})")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        finish("fail", f"Hermes gateway unreachable at {env('HERMES_URL')}: {exc}")
    return ""


def comments(since: dt.datetime | None) -> list[dict]:
    repo, pr = env("GITHUB_REPOSITORY"), env("PR_NUMBER")
    url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments?per_page=100"
    if since:
        url += "&since=" + urllib.parse.quote(since.strftime("%Y-%m-%dT%H:%M:%SZ"))
    out: list[dict] = []
    while url:
        req = urllib.request.Request(_http_url(url), headers={"Authorization": f"Bearer {env('GH_TOKEN')}", "Accept": "application/vnd.github+json"})
        with _HTTP.open(req, timeout=30) as resp:
            out.extend(json.loads(resp.read()))
            nxt = [p for p in resp.headers.get("Link", "").split(",") if 'rel="next"' in p]
            url = nxt[0].split(";")[0].strip(" <>") if nxt else ""
    return out


def review_for(head: str, asked_at: dt.datetime | None) -> dict | None:
    # HERMES_COMMENTER is required, not optional: this comment is the only
    # thing verdict() trusts (G1's ai_security_review_clean criterion), so
    # without an identity check anyone who can comment on the PR can post a
    # fake "Automated review by Hermes on commit <sha> ... no blocking
    # issues" and the control passes. Caught live by Hermes reviewing this
    # very diff (2026-11-05): High, CWE-345. main() enforces this is set
    # before ever reaching here.
    commenter = env("HERMES_COMMENTER")
    for c in reversed(comments(asked_at)):  # newest first
        m = MARKER.search(c.get("body") or "")
        if not m or not head.startswith(m.group(1)) and not m.group(1).startswith(head):
            continue
        if (c.get("user") or {}).get("login") != commenter:
            continue
        created = dt.datetime.fromisoformat(c["created_at"].replace("Z", "+00:00"))
        if asked_at and created < asked_at:
            continue
        return c
    return None


def _findings_section(body: str) -> str:
    """The text between '## Security findings' and the next '---'/'## ...'
    heading — never the Schema/Dependency/Other-notes sections below it."""
    start = body.find("## Security findings")
    if start == -1:
        return ""
    rest = body[start + len("## Security findings"):]
    end = SECTION_END.search(rest)
    return rest[: end.start()] if end else rest


def _clean(text: str, max_chars: int) -> str:
    """Strip control characters (CWE-74 backstop: this text lands in a
    JSON file DefectDojo parses) and cap length so one block can't inject
    unbounded content into the findings record."""
    text = "".join(ch for ch in text if ch == "\n" or ch >= " ")
    return text[:max_chars]


def parse_findings(body: str) -> list[dict[str, Any]]:
    """Each '### [F1] <title> (Severity: X)' block in the findings section,
    as a DefectDojo Generic Findings Import finding. A field the model
    omitted is left out rather than guessed; CWE "N/A" is dropped, not
    coerced to a number. Capped at MAX_FINDINGS blocks, each field capped
    and control-character-stripped (see MAX_* above) — this comment's
    trustworthiness rests entirely on HERMES_COMMENTER (review_for()), and
    these are an independent backstop regardless of that."""
    section = _findings_section(body)
    headers = list(FINDING_HEADER.finditer(section))[:MAX_FINDINGS]
    out: list[dict[str, Any]] = []
    today = dt.datetime.now(dt.UTC).date().isoformat()
    for i, m in enumerate(headers):
        block = section[m.end(): headers[i + 1].start() if i + 1 < len(headers) else len(section)]
        fields: dict[str, str] = {}
        for fm in FIELD_LINE.finditer(block):
            fields[fm.group("label").lower()] = fm.group("value").strip()
        severity = m.group("severity").title()
        finding: dict[str, Any] = {
            "title": _clean(f"[{m.group('id')}] {m.group('title')}", MAX_TITLE_CHARS),
            "severity": severity,
            "description": _clean(fields.get("description") or m.group("title"), MAX_FIELD_CHARS),
            "static_finding": True,
            "dynamic_finding": False,
            "date": today,
        }
        if fields.get("mitigation"):
            finding["mitigation"] = _clean(fields["mitigation"], MAX_FIELD_CHARS)
        if fields.get("impact"):
            finding["impact"] = _clean(fields["impact"], MAX_FIELD_CHARS)
        cwe = fields.get("cwe", "")
        cwe_digits = re.search(r"\d+", cwe)
        if cwe_digits and cwe.strip().upper() != "N/A":
            finding["cwe"] = int(cwe_digits.group())
        loc = fields.get("location", "")
        fl = FILE_LINE.match(loc)
        if fl:
            finding["file_path"] = _clean(fl.group("path"), MAX_TITLE_CHARS)
            finding["line"] = int(fl.group("line"))
        elif loc and loc.strip().upper() != "N/A":
            finding["file_path"] = _clean(loc, MAX_TITLE_CHARS)
        out.append(finding)
    return out


def write_findings_file(findings: list[dict[str, Any]], comment_url: str) -> None:
    out_dir = env("OUT")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    for f in findings:
        refs = f"Hermes AI security review — {comment_url}" if comment_url else "Hermes AI security review"
        f["references"] = refs
    with open(os.path.join(out_dir, "hermes-findings.json"), "w") as fh:
        json.dump({"findings": findings}, fh, indent=2)


def verdict(comment: dict) -> None:
    body = comment.get("body") or ""
    first = body.strip().splitlines()[0] if body.strip() else ""
    link = comment.get("html_url", "")
    if first.strip().startswith("Security review: NOT COMPLETED"):
        # The route prompt's own fail-safe section is explicit that this must
        # never read as a pass: Hermes couldn't get the diff (or confirm it
        # was non-empty), so there is no review to have findings in. Counting
        # zero severity rows here is "nothing was checked", not "nothing was
        # found" — pre-existing gap (the old table-row count had the same
        # empty-counts-means-pass hole), closed here since a correctness
        # check on this control's verdict is exactly in scope.
        finish("fail", f"Hermes could not complete the review (see {link}) — no automated security assurance for this PR; manual review required", findings=0, blocking=0, verdict_line=first)
    findings = parse_findings(body)
    write_findings_file(findings, link)
    counts: dict[str, int] = {}
    for f in findings:
        sev = f["severity"].lower()
        counts[sev] = counts.get(sev, 0) + 1
    blocking = sum(n for s, n in counts.items() if s in BLOCKING)
    summary = ", ".join(f"{n} {s.title()}" for s, n in sorted(counts.items(), key=lambda kv: ["critical", "high", "medium", "low"].index(kv[0]))) or "no findings"
    if blocking:
        finish("fail", f"Hermes: {summary} — Critical/High block the merge; see {link}", findings=len(findings), blocking=blocking, verdict_line=first)
    finish("pass", f"Hermes: {first or 'review posted'} ({summary}; Medium/Low are advisory) — {link}", findings=len(findings), blocking=0, verdict_line=first)


def main() -> None:
    if not env("HERMES_COMMENTER"):
        finish("fail", "HERMES_COMMENTER is not set for this repository — without it any PR comment matching "
                       "the marker text would be trusted as Hermes's own verdict. Set the repo variable to the "
                       "GitHub login Hermes's gh is authenticated as on the gateway host.")
    head = env("HEAD_SHA")
    event_name = env("GITHUB_EVENT_NAME")
    asked_at = None
    if event_name == "pull_request":
        with open(env("GITHUB_EVENT_PATH"), "rb") as f:
            event = json.load(f)
        if (event.get("pull_request") or {}).get("draft"):
            finish("fail", "draft PR — the AI review runs when the PR is marked ready for review")
        asked_at = dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(seconds=5)
        print("review requested:", forward(json.dumps(event, separators=(",", ":")).encode()))
    deadline = time.monotonic() + int(env("WAIT_SECONDS", "1500"))
    while True:
        try:
            found = review_for(head, asked_at)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"::warning::GitHub comments API: {exc}; retrying")
            found = None
        if found:
            verdict(found)
        if time.monotonic() > deadline:
            what = "for this head commit" if asked_at is None else "since this run requested it"
            finish("fail", f"no Hermes review {what} within {env('WAIT_SECONDS', '1500')}s (commit {head[:7]}) — check the gateway log")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
