#!/usr/bin/env bash
# Separation of duties for a protected environment's review:
#
#     GH_TOKEN=... bash .github/scripts/approvals.sh <environment>
#
# Reads the review of <environment> in this run back from GitHub. Whoever
# started the run or re-ran it can't be its approver, so a re-run of the
# job needs someone who did neither. Writes started= and approved= (JSON
# arrays of logins) and detail= to $GITHUB_OUTPUT; exits 1 when nobody
# approved or an initiator did.
set -euo pipefail

environment=$1
run=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}")
approvals=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/approvals")
started=$(jq -c '[.actor.login, .triggering_actor.login] | map(select(.)) | unique' <<<"$run")
approved=$(jq -c --arg e "$environment" \
  '[.[] | select(.state == "approved" and any(.environments[]?; .name == $e)) | .user.login] | unique' <<<"$approvals")
self=$(jq -rn --argjson s "$started" --argjson a "$approved" '$a - ($a - $s) | join(", ")')
{ echo "started=$started"; echo "approved=$approved"; } >> "$GITHUB_OUTPUT"
if [ "$approved" = "[]" ]; then
  detail="no ${environment} approval recorded for this run"
elif [ -n "$self" ]; then
  detail="${environment} approved by ${self}, who also started or re-ran this run — someone who did neither must approve"
else
  detail="${environment}: started by $(jq -r 'join(", ")' <<<"$started"), approved by $(jq -r 'join(", ")' <<<"$approved")"
  echo "detail=$detail" >> "$GITHUB_OUTPUT"
  echo "$detail" | tee -a "$GITHUB_STEP_SUMMARY"
  exit 0
fi
echo "detail=$detail" >> "$GITHUB_OUTPUT"
echo "::error::$detail"
exit 1
