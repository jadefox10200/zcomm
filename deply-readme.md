# Live Deploy Workflow (Simple)

This project is deployed directly from `main`.
No PR flow required.

## One-time Setup

1. Ensure these scripts exist and are executable locally:
   - `scripts/deploy-live.sh`
   - `scripts/remote-deploy.sh`

2. Make them executable:

```bash
chmod +x scripts/deploy-live.sh scripts/remote-deploy.sh
```

3. Ensure SSH login works to server without interactive password prompts for automation.

## Daily Deploy Command

Run this from repo root on your local machine:

```bash
bash ./scripts/deploy-live.sh
```

This does all required steps:

1. Builds frontend locally (`npm ci` + `npm run build`).
2. Syncs `frontend/build/` to server using `rsync`.
3. SSHes to server and runs remote deploy:
   - checks out `main`
   - pulls latest with rebase
   - rebuilds backend container
   - ensures nginx container is up
   - reloads nginx
   - runs backend health check

The script is preconfigured for:

1. Host: `ubuntu-zcomm`
2. User: `root`
3. Server path: `/root/zcomm`

## Optional Overrides

- Use a different branch target:

```bash
make deploy-live DEPLOY_HOST=your-server DEPLOY_BRANCH=main
```

- If local working tree is dirty and you still want to deploy:

```bash
make deploy-live DEPLOY_HOST=your-server ALLOW_DIRTY=true
```

- If `npm ci` is temporarily blocked by lock mismatch:

```bash
make deploy-live DEPLOY_HOST=your-server NPM_INSTALL_CMD=install
```

## Safety Rules

1. Do not run `npm install` on server for deploys.
2. Do not commit `node_modules` or `frontend/build`.
3. Keep deploys from local machine only; server should mostly `git pull` + containers.

## Troubleshooting

### Deploy fails with "Remote repo has uncommitted changes"

On server:

```bash
cd /root/zcomm
git status
```

Commit/stash/reset the changes, then rerun deploy.

### Nginx fails to start (upstream lookup)

Ensure upstream host in `nginx.conf` points to Compose service name `backend`, not container name.

### Admin button not visible

1. Confirm account role in browser console:

```js
JSON.parse(localStorage.getItem("account")).role
```

2. Sign out and back in after backend role changes.
3. Hard refresh browser cache.
