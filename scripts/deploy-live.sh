#!/usr/bin/env bash
set -euo pipefail

DEPLOY_HOST="${DEPLOY_HOST:-ubuntu-zcomm}"
DEPLOY_USER="${DEPLOY_USER:-root}"
DEPLOY_PATH="${DEPLOY_PATH:-/root/zcomm}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"
BACKEND_SERVICE="${BACKEND_SERVICE:-backend}"
NGINX_SERVICE="${NGINX_SERVICE:-nginx}"
NPM_INSTALL_CMD="${NPM_INSTALL_CMD:-ci}"
ALLOW_DIRTY="${ALLOW_DIRTY:-false}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: Required command not found: $1"
    exit 1
  fi
}

require_cmd npm
require_cmd rsync
require_cmd ssh
require_cmd bash
require_cmd git

log() {
  printf "[deploy-live] %s\n" "$1"
}

log "Repo root: ${REPO_ROOT}"
cd "${REPO_ROOT}"

if [[ "${ALLOW_DIRTY}" != "true" ]] && [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: Working tree is dirty. Commit or stash changes first."
  echo "Set ALLOW_DIRTY=true to bypass this check."
  exit 1
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
log "Current branch: ${CURRENT_BRANCH}"
if [[ "${CURRENT_BRANCH}" != "${DEPLOY_BRANCH}" ]]; then
  log "Warning: current branch (${CURRENT_BRANCH}) differs from DEPLOY_BRANCH (${DEPLOY_BRANCH})"
fi

log "Building frontend"
cd frontend
if [[ "${NPM_INSTALL_CMD}" == "ci" ]]; then
  npm ci
else
  npm install
fi
npm run build
cd "${REPO_ROOT}"

if [[ ! -d "frontend/build" ]]; then
  echo "ERROR: frontend/build was not generated."
  exit 1
fi

log "Syncing frontend build to ${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}/frontend/build/"
rsync -az --delete frontend/build/ "${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}/frontend/build/"

log "Running remote deploy steps"
ssh "${DEPLOY_USER}@${DEPLOY_HOST}" \
  DEPLOY_PATH="${DEPLOY_PATH}" \
  DEPLOY_BRANCH="${DEPLOY_BRANCH}" \
  BACKEND_SERVICE="${BACKEND_SERVICE}" \
  NGINX_SERVICE="${NGINX_SERVICE}" \
  'bash -s' < "${SCRIPT_DIR}/remote-deploy.sh"

log "Done"
