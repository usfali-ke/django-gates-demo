#!/usr/bin/env bash
# Separation of duties for a protected environment's review:
#
#     GH_TOKEN=... [SOURCE_SHA=<commit>] bash .github/scripts/approvals.sh <environment>
#
# Reads the review of <environment> in this run back from GitHub. Whoever
# started the run or re-ran it can't be its approver, so a re-run of the
# job needs someone who did neither. With SOURCE_SHA, neither can whoever
# authored or committed the change being released, or opened its pull
# request: a release run the pipeline starts by itself is started by
# github-actions, so the human behind the change is the author. Writes
# started= and approved= (JSON arrays of logins) and detail= to
# $GITHUB_OUTPUT; exits 1 when nobody approved or an excluded login did.
set -euo pipefail

environment=$1
run=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}")
approvals=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/approvals")
started=$(jq -c '[.actor.login, .triggering_actor.login] | map(select(.)) | unique' <<<"$run")
authors='[]'
if [ -n "${SOURCE_SHA:-}" ]; then
  commit=$(gh api "repos/${GITHUB_REPOSITORY}/commits/${SOURCE_SHA}")
  prs=$(gh api "repos/${GITHUB_REPOSITORY}/commits/${SOURCE_SHA}/pulls" 2>/dev/null || echo '[]')
  # web-flow commits GitHub's own merges; bots can't approve anyway.
  authors=$(jq -nc --argjson c "$commit" --argjson p "$prs" \
    '[$c.author.login, $c.committer.login, ($p[]?.user.login)] | map(select(. and . != "web-flow" and (endswith("[bot]") | not))) | unique')
fi
excluded=$(jq -nc --argjson s "$started" --argjson a "$authors" '$s + $a | unique')
approved=$(jq -c --arg e "$environment" \
  '[.[] | select(.state == "approved" and any(.environments[]?; .name == $e)) | .user.login] | unique' <<<"$approvals")
self=$(jq -rn --argjson s "$excluded" --argjson a "$approved" '$a - ($a - $s) | join(", ")')
{ echo "started=$started"; echo "authors=$authors"; echo "approved=$approved"; } >> "$GITHUB_OUTPUT"
if [ "$approved" = "[]" ]; then
  detail="no ${environment} approval recorded for this run"
elif [ -n "$self" ]; then
  # Documented single-operator exception (opt-in per run): a two-person team
  # where one account starts the pipeline and the other authors the change
  # has no eligible approver left under the doc's strict rule. When
  # ALLOW_SELF_APPROVAL is set, the exclusion is waived — but the waiver is
  # written into the verdict detail, which the dashboard records verbatim
  # on the checklist evidence, so the exception is always visible.
  if [ "${ALLOW_SELF_APPROVAL:-}" = "true" ] || [ "${ALLOW_SELF_APPROVAL:-}" = "1" ]; then
    detail="SEGREGATION-OF-DUTIES EXCEPTION (single-operator mode): ${environment} approved by ${self}, who started/re-ran this run or authored the change — exclusion waived by ALLOW_SELF_APPROVAL"
    echo "detail=$detail" >> "$GITHUB_OUTPUT"
    echo "::warning::$detail"
    echo "$detail" | tee -a "$GITHUB_STEP_SUMMARY"
    exit 0
  fi
  detail="${environment} approved by ${self}, who started or re-ran this run or authored the change — someone who did neither must approve"
else
  detail="${environment}: started by $(jq -r 'join(", ")' <<<"$started")"
  [ "$authors" = "[]" ] || detail="${detail}, change by $(jq -r 'join(", ")' <<<"$authors")"
  detail="${detail}, approved by $(jq -r 'join(", ")' <<<"$approved")"
  echo "detail=$detail" >> "$GITHUB_OUTPUT"
  echo "$detail" | tee -a "$GITHUB_STEP_SUMMARY"
  exit 0
fi
echo "detail=$detail" >> "$GITHUB_OUTPUT"
echo "::error::$detail"
exit 1
