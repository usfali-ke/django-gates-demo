#!/usr/bin/env bash
# Records which change request a release belongs to:
#
#     GH_TOKEN=... [CHANGE=<7|#7|CHG-7>] [RELEASE=<sha|run-url>] [NOTE=...] \
#       bash .github/scripts/pick-change.sh
#
# Writes the `/release <value>` comment on the chosen open change request —
# the pick devsecops-stage's change.sh reads before prod asks for its
# approval. RELEASE defaults to the newest commit on main. With no CHANGE it
# lists the open change requests and fails, so running it bare is how you see
# what there is to choose.
set -euo pipefail

if [ -z "${RELEASE:-}" ]; then
  RELEASE=$(gh api "repos/${GITHUB_REPOSITORY}/commits/main" | jq -r .sha)
  echo "No release given: using the newest commit on main (${RELEASE:0:7})."
fi

if [ -z "${CHANGE:-}" ]; then
  echo "No change request given. Open change requests:"
  gh api --paginate "repos/${GITHUB_REPOSITORY}/issues?labels=change&state=open&per_page=100" \
    | jq -s -r 'add // [] | .[] | select(.pull_request == null)
        | "- CHG-\(.number) \(.title) [\([.labels[].name] | join(", "))] \(.html_url)"'
  echo "::error::pass the change request number (change: 7) to record the pick"
  exit 1
fi

n=$(sed -E 's/^[[:space:]]*(#|[Cc][Hh][Gg]-)?//; s/[[:space:]]*$//' <<<"$CHANGE")
[[ "$n" =~ ^[0-9]+$ ]] || { echo "::error::'${CHANGE}' isn't a change request number (7, #7 or CHG-7)"; exit 1; }
issue=$(gh api "repos/${GITHUB_REPOSITORY}/issues/${n}") \
  || { echo "::error::CHG-${n}: issue #${n} doesn't exist — open one with the Change request form"; exit 1; }
[ "$(jq -r .state <<<"$issue")" = open ] \
  || { echo "::error::CHG-${n} is $(jq -r .state <<<"$issue"), not open — reopen it or pick another"; exit 1; }
jq -e '.pull_request == null' <<<"$issue" > /dev/null || { echo "::error::#${n} is a pull request, not a change request"; exit 1; }

body="/release ${RELEASE}"$'\n\n'"Picked by ${GITHUB_ACTOR:-the workflow} with **Pick the change request for a release**${NOTE:+ — ${NOTE}}"
url=$(gh api "repos/${GITHUB_REPOSITORY}/issues/${n}/comments" -f body="$body" | jq -r .html_url)
echo "Picked CHG-${n} ($(jq -r .title <<<"$issue")) for ${RELEASE:0:7} — ${url}"
echo "A waiting prod stage resolves its pick within 30 seconds; a later run reads it straight away."
