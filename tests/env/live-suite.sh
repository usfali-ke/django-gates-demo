#!/usr/bin/env bash
# Runs one tests/live suite against a running environment and records it
# for verdict.py:
#
#     OUT=reports [ENV_FILE=...] bash tests/env/live-suite.sh <control> <pytest args...>
#
# ENV_FILE (the runner's 0600 file: BASE_URL, HTTP_URL, REQUESTS_CA_BUNDLE,
# USER_*/PASSWORD_*) is sourced if given; otherwise they come from the
# environment. Writes $OUT/<control>/junit.xml, and rc=<pytest's exit code>
# to $GITHUB_OUTPUT when there is one. Always exits 0: the verdict decides.
set -uo pipefail
control=$1; shift
out="${OUT:-reports}/${control}"
mkdir -p "$out"
if [ -n "${ENV_FILE:-}" ]; then
  set -a
  # shellcheck source=/dev/null
  . "$ENV_FILE"
  set +a
fi
rc=0
uv sync --frozen --quiet || rc=$?
[ "$rc" != 0 ] || uv run --frozen pytest "$@" -p no:cacheprovider -q -rfE --junitxml="$out/junit.xml" || rc=$?
echo "rc=$rc" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "$rc" > "$out/rc"
