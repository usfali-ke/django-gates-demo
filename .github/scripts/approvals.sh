#!/usr/bin/env bash
# Separation of duties for a protected environment's review:
#
#     GH_TOKEN=... [SOURCE_SHA=<commit>] bash .github/scripts/approvals.sh <environment>
#
# Reads the review of <environment> in this run back from GitHub. Whoever
# started the run — or re-ran it — can't be its approver, and neither can
# whoever authored the change being released or opened its pull request: at
# least one approval must come from someone who did none of those.
# Writes started=, authors= and approved= (JSON arrays of logins) and
# detail= to $GITHUB_OUTPUT; exits 1 when nobody approved, or when every
# approval came from someone excluded.
#
# Two things used to reject the only person who could approve:
#
#   * the change's "author" was read from the commit on main, which for a
#     merged pull request is a merge commit GitHub attributes to whoever
#     merged it — the releaser, not the author — barring them from
#     approving the merge they made;
#   * triggering_actor was excluded even on the first attempt, where a
#     run the pipeline starts has github-actions as its actor and
#     triggering_actor is only the human whose push or merge set that
#     pipeline going — a case the change check already covers.
#
# So the change is resolved from the pull request (its author and its
# commits' authors), and triggering_actor is excluded only on a re-run,
# where it really is the person who clicked re-run.
set -euo pipefail

environment=$1
run=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}")
approvals=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/approvals")

started=$(jq -c '[.actor.login, (if (.run_attempt // 1) > 1 then .triggering_actor.login else empty end)]
                 | map(select(.)) | unique' <<<"$run")

authors='[]'
if [ -n "${SOURCE_SHA:-}" ]; then
  commit=$(gh api "repos/${GITHUB_REPOSITORY}/commits/${SOURCE_SHA}")
  prs=$(gh api "repos/${GITHUB_REPOSITORY}/commits/${SOURCE_SHA}/pulls" 2>/dev/null || echo '[]')
  pr_authors='[]'
  for n in $(jq -r '.[]?.number' <<<"$prs"); do
    cs=$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${n}/commits" 2>/dev/null || echo '[]')
    pr_authors=$(jq -nc --argjson a "$pr_authors" --argjson c "$cs" '$a + [$c[]?.author.login]')
  done
  # web-flow commits GitHub's own merges; bots can't approve anyway.
  authors=$(jq -nc --argjson c "$commit" --argjson p "$prs" --argjson pa "$pr_authors" \
    '((if ($p | length) > 0 then [$p[]?.user.login] else [$c.author.login] end) + $pa)
     | map(select(. and . != "web-flow" and (endswith("[bot]") | not))) | unique')
fi

excluded=$(jq -nc --argjson s "$started" --argjson a "$authors" '$s + $a | unique')
approved=$(jq -c --arg e "$environment" \
  '[.[] | select(.state == "approved" and any(.environments[]?; .name == $e)) | .user.login] | unique' <<<"$approvals")
# self: approvals from someone excluded. eligible: approvals from someone
# who did none of those — one of these has to exist for the review to count.
self=$(jq -rn --argjson a "$approved" --argjson e "$excluded" '($a - ($a - $e)) | join(", ")')
eligible=$(jq -rn --argjson a "$approved" --argjson e "$excluded" '($a - $e) | join(", ")')
{ echo "started=$started"; echo "authors=$authors"; echo "approved=$approved"; } >> "$GITHUB_OUTPUT"

summary=$(jq -rn --argjson s "$started" --argjson a "$authors" --argjson ap "$approved" \
  '"started by " + ($s | join(", "))
   + (if ($a | length) > 0 then ", change by " + ($a | join(", ")) else "" end)
   + ", approved by " + ($ap | join(", "))')

if [ "$approved" = "[]" ]; then
  detail="no ${environment} approval recorded for this run"
elif [ -n "$eligible" ]; then
  detail="$summary"
  echo "detail=$detail" >> "$GITHUB_OUTPUT"
  echo "$detail" | tee -a "$GITHUB_STEP_SUMMARY"
  exit 0
else
  # Every approval came from someone excluded. Report which, and — the case
  # that makes this unpassable — whether the environment has nobody left who
  # could approve at all.
  reviewers=$(gh api "repos/${GITHUB_REPOSITORY}/environments/${environment}" 2>/dev/null \
    | jq -c '[.protection_rules[]? | select(.type == "required_reviewers") | .reviewers[]?
              | (.reviewer.login // .reviewer.name)] | map(select(.)) | unique' || echo '[]')
  reviewers=${reviewers:-[]}
  remaining=$(jq -cn --argjson r "$reviewers" --argjson e "$excluded" '$r - $e')
  if [ "$reviewers" != "[]" ] && [ "$remaining" = "[]" ]; then
    detail="no eligible ${environment} approver exists: every reviewer of this environment (${reviewers} minus the run's starter, re-runner and change authors) is excluded, so nobody could approve. Add a reviewer who did none of those, or opt into the documented single-operator exception — for a run the pipeline starts, set the ALLOW_SELF_APPROVAL repository variable; a manual run can pass allow-self-approval"
  else
    detail="${environment} approved only by ${self}, who started or re-ran this run or authored the change — someone who did neither must approve"
  fi
  # Documented single-operator exception (opt-in per run): a two-person team
  # where one account starts the pipeline and the other authors the change
  # has no eligible approver left under the doc's strict rule. When
  # ALLOW_SELF_APPROVAL is set, the exclusion is waived — but the waiver is
  # written into the verdict detail, which the dashboard records verbatim
  # on the checklist evidence, so the exception is always visible.
  if [ "${ALLOW_SELF_APPROVAL:-}" = "true" ] || [ "${ALLOW_SELF_APPROVAL:-}" = "1" ]; then
    detail="SEGREGATION-OF-DUTIES EXCEPTION (single-operator mode): ${summary} — exclusion waived by ALLOW_SELF_APPROVAL"
    echo "detail=$detail" >> "$GITHUB_OUTPUT"
    echo "::warning::$detail"
    echo "$detail" | tee -a "$GITHUB_STEP_SUMMARY"
    exit 0
  fi
fi
echo "detail=$detail" >> "$GITHUB_OUTPUT"
echo "::error::$detail"
exit 1
