#!/usr/bin/env bash
set -euo pipefail

DEPLOY_PATH="${DEPLOY_PATH:-/root/zcomm}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"
BACKEND_SERVICE="${BACKEND_SERVICE:-backend}"
NGINX_SERVICE="${NGINX_SERVICE:-nginx}"

log() {
  printf "[remote-deploy] %s\n" "$1"
}

log "Deploy path: ${DEPLOY_PATH}"
cd "${DEPLOY_PATH}"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: Remote repo has uncommitted changes. Commit/stash/reset before deploy."
  exit 1
fi

log "Checking out ${DEPLOY_BRANCH}"
git checkout "${DEPLOY_BRANCH}"

log "Fetching latest ${DEPLOY_BRANCH}"
git fetch origin "${DEPLOY_BRANCH}"

log "Rebasing local branch on origin/${DEPLOY_BRANCH}"
git pull --rebase origin "${DEPLOY_BRANCH}"

log "Rebuilding backend and ensuring nginx service is up"
docker compose up -d --build "${BACKEND_SERVICE}" "${NGINX_SERVICE}" --remove-orphans

log "Reloading nginx"
docker compose exec -T "${NGINX_SERVICE}" nginx -s reload >/dev/null 2>&1 || true

log "Backend health check"
curl -fsS http://localhost:8080/health >/dev/null

log "Deploy complete"
docker compose ps
