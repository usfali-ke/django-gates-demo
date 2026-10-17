# The AI review report

Every pull request gets a Hermes Agent review, posted as a comment and read by
the `ai-review` control of the Develop phase (G1 criterion
`ai_security_review_clean`). Any Critical/High finding fails the control; the
rest is advisory.

The comment has a fixed structure so it can be read at a glance:

1. a one-line verdict — `Security review: no blocking issues` or
   `Security review: N finding(s)`;
2. `## Security findings` — the severity table (Critical/High/Medium/Low,
   `file:line`, issue, suggested fix), or `No findings.`;
3. `## Schema / database changes` — new or changed queries, and index or
   constraint changes (`file:line`, what changed, what to watch);
4. `## Dependency / library changes` — added, removed, re-pinned or swapped
   libraries, including the behaviour delta of a swap;
5. `## Other notes` — non-security correctness and clarity points.

Sections 3 and 4 are report-only: their tables lead with a `Kind`, never a
severity, so they cannot fail a build. A change that is also a real security
problem is raised again in section 2 under the existing class (unparameterized
SQL as injection, TLS verification disabled as insecure crypto, an unpinned or
typosquat dependency as a dependency finding). When a diff touches neither
area, the section says so (`None in this diff.`) rather than disappearing.
