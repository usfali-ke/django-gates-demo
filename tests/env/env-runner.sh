#!/usr/bin/env bash
# Registers and runs the environment test runner for one job
# (README: "Environment test runner"):
#
#     GH_TOKEN=... bash tests/env/env-runner.sh [runner dir]
#
# The runner dir holds an unpacked actions/runner release (default
# ~/actions-runner-env). The runner runs as the env-tester ServiceAccount,
# with a 2-hour token in a kubeconfig only this user can read; GH_TOKEN
# (repo admin) is used for the registration token and not passed on.
set -euo pipefail

repo=usfali-ke/django-gates-demo
dir=${1:-$HOME/actions-runner-env}
kubeconfig=$HOME/.kube/env-tester.json

[ -x "$dir/config.sh" ] || { echo "no actions runner in $dir" >&2; exit 1; }

mkdir -p "$(dirname "$kubeconfig")"
token=$(kubectl -n django-gates-demo-tools create token env-tester --duration=2h)
# umask in a subshell only: the runner's checkouts must stay readable by
# the tool containers (cap-drop ALL: root there can't override modes).
(umask 077; kubectl config view --minify --raw -o json \
  | jq --arg t "$token" '.users[0].user = {token: $t} | .contexts[0].context.namespace = "django-gates-demo-tools"' \
  > "$kubeconfig")
unset token

registration=$(curl -fsS -X POST -H "Authorization: Bearer ${GH_TOKEN:?GH_TOKEN is not set}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${repo}/actions/runners/registration-token" | jq -r .token)

cd "$dir"
./config.sh --unattended --replace --ephemeral --url "https://github.com/${repo}" \
  --name "env-$(hostname -s)" --labels django-gates-demo-env --token "$registration"
unset registration
# Node tries each address of a host for only 250 ms by default (happy
# eyeballs). On a slow link, or with DNS handing out an unroutable NAT64
# address, every attempt times out and the artifact upload fails with
# ETIMEDOUT; 2 s per address still falls back between IPv6 and IPv4.
exec env -u GH_TOKEN KUBECONFIG="$kubeconfig" NODE_OPTIONS=--network-family-autoselection-attempt-timeout=2000 ./run.sh
