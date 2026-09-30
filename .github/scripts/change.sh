#!/usr/bin/env bash
# Finds the change request a release run is for:
#
#     GH_TOKEN=... SOURCE_SHA=<commit> [CHANGE=<7|#7|CHG-7>] [REQUIRE=true] bash .github/scripts/change.sh
#
# CHANGE if given; otherwise the one open `change` issue whose Release
# field (.github/ISSUE_TEMPLATE/change-request.yml) names SOURCE_SHA (the
# full SHA or a prefix of at least 7) or this run's URL. Writes id=CHG-<n>,
# number=, url=, state= and labels= (JSON array) to $GITHUB_OUTPUT. Finding
# none, or more than one, leaves id empty; with REQUIRE=true it's an error.
set -euo pipefail

run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
none() {
  if [ "${REQUIRE:-}" = true ]; then echo "::error::$1"; exit 1; fi
  echo "::notice::$1"; exit 0
}
if [ -n "${CHANGE:-}" ]; then
  n=$(sed -E 's/^[[:space:]]*(#|[Cc][Hh][Gg]-)?//; s/[[:space:]]*$//' <<<"$CHANGE")
  [[ "$n" =~ ^[0-9]+$ ]] || none "'${CHANGE}' isn't a change request number (7, #7 or CHG-7)"
  issue=$(gh api "repos/${GITHUB_REPOSITORY}/issues/${n}" 2>/dev/null) \
    || none "CHG-${n}: issue #${n} doesn't exist — open one with the Change request form"
  jq -e '.pull_request == null' <<<"$issue" > /dev/null || none "#${n} is a pull request, not a change request"
else
  matches=$(gh api --paginate "repos/${GITHUB_REPOSITORY}/issues?labels=change&state=open&per_page=100" \
    | jq -s --arg sha "$SOURCE_SHA" --arg run "$run_url" '[add // [] | .[] | select(.pull_request == null)
        | (((.body // "") | capture("### Release[ \t]*[\r\n]+(?<v>[^\r\n]*)").v) // "" | gsub("^\\s+|\\s+$"; "") | rtrimstr("/")) as $r
        | select($r == $run or (($r | test("^[0-9a-f]{7,40}$")) and ($sha | startswith($r))))]')
  count=$(jq length <<<"$matches")
  [ "$count" = 1 ] || none "$([ "$count" = 0 ] && echo "no" || echo "${count}") open change requests name ${SOURCE_SHA:0:7} or this run in their Release field$([ "$count" = 0 ] || echo "; pass the one meant as input change")"
  issue=$(jq '.[0]' <<<"$matches")
fi
n=$(jq -r .number <<<"$issue")
{ echo "id=CHG-${n}"; echo "number=${n}"; echo "url=$(jq -r .html_url <<<"$issue")"
  echo "state=$(jq -r .state <<<"$issue")"; echo "labels=$(jq -c '[.labels[].name]' <<<"$issue")"; } >> "$GITHUB_OUTPUT"
echo "Change request: CHG-${n} ($(jq -r .title <<<"$issue"))"
