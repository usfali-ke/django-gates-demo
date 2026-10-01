#!/usr/bin/env bash
# Self-hosted GitHub Actions runners for this repo, as Docker containers on
# this host (README: "Self-hosted runners"):
#
#     GH_TOKEN=... [SLOTS=6] [ENV_SLOTS=1] bash ci/runners/runners.sh
#
# Each slot loops: ask GitHub for a just-in-time runner config (one job,
# then the runner deregisters), run it in a fresh container, wipe the
# slot's work directory, repeat. GH_TOKEN (repo admin) stays in this
# script: a job only ever sees its own one-time runner config.
#
#   SLOTS      generic runners, label django-gates-demo-docker: the jobs
#              that would run on ubuntu-latest (vars.CI_RUNS_ON)
#   ENV_SLOTS  environment test runners, label django-gates-demo-env: the
#              release's post-deploy tests, as the env-tester ServiceAccount
#              (a 2-hour token, minted per job)
#
# The containers use this host's Docker daemon (its image cache is what
# makes them fast) and its network (the env tests port-forward into kind
# and put a proxy in front). Anything a job runs can therefore control
# this host: only this repo's own workflows may target these labels, and
# fork pull requests stay on GitHub-hosted runners.
#
# While it runs, the repo variable CI_RUNS_ON names the generic label, so
# the workflows use these runners; on exit it is deleted and they fall
# back to ubuntu-latest.
set -euo pipefail

repo=usfali-ke/django-gates-demo
api="https://api.github.com/repos/${repo}"
here=$(cd "$(dirname "$0")" && pwd)
root=${RUNNERS_HOME:-$HOME/.local/share/django-gates-demo-runners}
image=django-gates-demo-runner:local
prefix="$(hostname -s)-docker"
generic_label=django-gates-demo-docker
: "${GH_TOKEN:?GH_TOKEN is not set (repo admin, for runner registration)}"

gh_api() {
  curl -fsS -H "Authorization: Bearer ${GH_TOKEN}" -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}

log() { echo "$(date -u +%H:%M:%SZ) $*"; }

# Clears (and creates) a slot's work directory as root, since tool
# containers leave root-owned files, and hands it to the runner user.
reset_dir() {
  # shellcheck disable=SC2016 # $0 expands in the container's shell
  docker run --rm --user 0 --entrypoint sh -v "$1:$1" "$image" \
    -c 'rm -rf "$0/_work" "$0/kubeconfig" && mkdir -p "$0/_work" && chown 1001:1001 "$0/_work"' "$1"
}

# A token for env-tester, in a kubeconfig only the runner user can read.
env_kubeconfig() {
  local dir=$1 token
  token=$(kubectl -n django-gates-demo-tools create token env-tester --duration=2h)
  (umask 077; kubectl config view --minify --raw -o json \
    | jq --arg t "$token" '.users[0].user = {token: $t} | .contexts[0].context.namespace = "django-gates-demo-tools"' \
    > "$dir/kubeconfig")
  docker run --rm --user 0 --entrypoint chown -v "$dir:$dir" "$image" 1001:1001 "$dir/kubeconfig"
}

slot() {
  local kind=$1 n=$2 label dir name jit extra
  label=$([ "$kind" = env ] && echo django-gates-demo-env || echo "$generic_label")
  dir="$root/${kind}-${n}"
  mkdir -p "$dir"
  while :; do
    reset_dir "$dir"
    name="${prefix}-${kind}-${n}-$(date +%s)"
    jit=$(gh_api -X POST "${api}/actions/runners/generate-jitconfig" \
      -d "$(jq -nc --arg n "$name" --arg l "$label" --arg w "$dir/_work" \
            '{name: $n, runner_group_id: 1, labels: ["self-hosted", "linux", "x64", $l], work_folder: $w}')" \
      | jq -r .encoded_jit_config) || { log "${kind}-${n}: no runner config from GitHub, retrying in 30 s"; sleep 30; continue; }
    extra=()
    if [ "$kind" = env ]; then
      env_kubeconfig "$dir" || { log "${kind}-${n}: no env-tester token, retrying in 30 s"; sleep 30; continue; }
      extra=(-v "$dir/kubeconfig:/home/runner/.kube/config:ro" -e KUBECONFIG=/home/runner/.kube/config)
    fi
    log "${kind}-${n}: ${name} waiting for a job"
    # This network's DNS also returns NAT64 (64:ff9b::) addresses, which
    # don't route. Node races IPv6 against IPv4 with a 250 ms limit per
    # attempt (2 s isn't enough when several jobs pull images at once), and
    # uploads fail with ETIMEDOUT. IPv4 first, no racing: the OS timeout.
    ACTIONS_RUNNER_INPUT_JITCONFIG=$jit docker run --rm --name "$name" --label "$prefix=$kind" \
      --network host --group-add "$(stat -c %g /var/run/docker.sock)" \
      -v /var/run/docker.sock:/var/run/docker.sock -v "$dir/_work:$dir/_work" \
      -e ACTIONS_RUNNER_INPUT_JITCONFIG -e TRIVY_CACHE_VOLUME="trivy-cache-${kind}-${n}" \
      -e NODE_OPTIONS="--dns-result-order=ipv4first --no-network-family-autoselection" \
      "${extra[@]}" "$image" /home/runner/run.sh > "$dir/runner.log" 2>&1 || true
    log "${kind}-${n}: ${name} done ($(grep -m1 -o 'completed with result: [A-Za-z]*' "$dir/runner.log" || echo "no job"))"
    jit=""
  done
}

stop() {
  trap - EXIT INT TERM
  log "stopping: workflows fall back to ubuntu-latest"
  gh_api -X DELETE "${api}/actions/variables/CI_RUNS_ON" > /dev/null || true
  docker ps -q --filter "label=${prefix}" | xargs -r docker rm -f > /dev/null
  # Runners that never got a job stay registered (offline) otherwise.
  gh_api "${api}/actions/runners?per_page=100" \
    | jq -r --arg p "$prefix-" '.runners[] | select(.name | startswith($p)) | .id' \
    | while read -r id; do gh_api -X DELETE "${api}/actions/runners/${id}" > /dev/null || true; done
  kill 0 2> /dev/null || true
}

mkdir -p "$root"
log "building ${image}"
docker build -q -t "$image" "$here" > /dev/null
trap stop EXIT INT TERM
for i in $(seq "${SLOTS:-6}"); do slot generic "$i" & done
for i in $(seq "${ENV_SLOTS:-1}"); do slot env "$i" & done
sleep 5
gh_api -X PATCH "${api}/actions/variables/CI_RUNS_ON" -d "{\"value\": \"${generic_label}\"}" > /dev/null 2>&1 \
  || gh_api -X POST "${api}/actions/variables" -d "{\"name\": \"CI_RUNS_ON\", \"value\": \"${generic_label}\"}" > /dev/null
log "CI_RUNS_ON=${generic_label}: workflows now run here (Ctrl-C or SIGTERM to stop)"
wait
