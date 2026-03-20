# HTTPS Deployment Guide

## Overview

TLS termination is handled by Nginx. The backend Go server runs on plain HTTP
(port 8080) inside the Docker network and is never exposed directly to the
internet. Nginx listens on ports 80 and 443, redirects all plain-HTTP traffic
to HTTPS, and proxies API requests to the backend.

Certificates are managed by [Let's Encrypt](https://letsencrypt.org/) via the
`certbot/certbot` Docker image included in `docker-compose.yml`. Certbot checks
for renewal every 12 hours and renews automatically when the cert is within
30 days of expiry.

---

## Initial Certificate Issuance (first deploy)

Before starting the full stack for the first time you need to obtain a
certificate. The steps below use the **webroot** method so Nginx can keep
running while certbot verifies domain ownership.

### 1. Start Nginx on HTTP only

Temporarily bring up only the nginx container. It will answer on port 80,
create the `certbot-webroot` Docker volume, and serve the ACME challenge files
that certbot needs.

```sh
docker-compose up -d nginx
```

### 2. Issue the certificate

Replace `your@email.com` with your real address. This command issues a
certificate covering both the bare domain and the `www` subdomain.

> **Note:** Step 1 (`docker-compose up -d nginx`) creates the `certbot-webroot`
> volume automatically. The `docker run` command below reuses that same volume.

```sh
docker run --rm \
  -v /etc/letsencrypt:/etc/letsencrypt \
  -v certbot-webroot:/var/www/certbot \
  certbot/certbot certonly \
    --webroot \
    --webroot-path /var/www/certbot \
    --email your@email.com \
    --agree-tos \
    --no-eff-email \
    -d zcommapp.com \
    -d www.zcommapp.com
```

This writes the certificate chain and private key to:

```
/etc/letsencrypt/live/zcommapp.com/fullchain.pem
/etc/letsencrypt/live/zcommapp.com/privkey.pem
```

These paths are already configured in `nginx.conf`.

### 3. Start the full stack

```sh
docker-compose up -d
```

---

## Automatic Renewal

The `certbot` service in `docker-compose.yml` runs `certbot renew` every 12
hours. Certbot skips renewal unless the certificate will expire within 30 days.

After each successful renewal you should reload Nginx so it picks up the new
certificate:

```sh
docker exec zcomm-nginx nginx -s reload
```

To automate the reload, add a certbot post-renewal deploy hook on the host.
Create the file `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh`:

```sh
#!/bin/sh
docker exec zcomm-nginx nginx -s reload
```

Make it executable:

```sh
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

Certbot runs this script automatically after each successful renewal. If you
prefer a cron-based approach (less precise but simpler), add the following to
the host crontab (`crontab -e`):

```cron
0 */12 * * * docker exec zcomm-nginx nginx -s reload
```

Nginx reloads are graceful (no dropped connections), so running them
periodically even when no renewal occurred is acceptable.

---

## Troubleshooting

### "Certificate did not pass validation" / domain mismatch

This usually means the cert was issued only for one form of the domain (e.g.,
`zcommapp.com` but **not** `www.zcommapp.com`). Re-issue with **both** `-d`
flags as shown in step 2 above.

To inspect which names are covered by the current certificate:

```sh
sudo openssl x509 -in /etc/letsencrypt/live/zcommapp.com/fullchain.pem \
  -noout -text | grep -A1 "Subject Alternative Name"
```

### Expired certificate

Run the renewal manually:

```sh
docker-compose run --rm certbot renew --webroot -w /var/www/certbot
docker exec zcomm-nginx nginx -s reload
```

### Nginx fails to start (cert files missing)

If `/etc/letsencrypt/live/zcommapp.com/` does not yet exist, Nginx cannot load
its TLS config. Complete the **Initial Certificate Issuance** steps above
first.

---

## Local / Development (self-signed certificate)

For local testing you can generate a self-signed certificate with OpenSSL:

```sh
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

Place `server.crt` and `server.key` in the `backend/` directory. Browsers will
show a warning for self-signed certs; this is expected in development.

To run the backend directly over HTTPS (bypassing Nginx), edit `backend/main.go`:

```go
func main() {
    server := api.NewServer()
    log.Println("Starting zcomm backend server on :8443 (HTTPS)")
    if err := server.RunTLS(":8443", "server.crt", "server.key"); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}
```

> **Note:** In production, always use a certificate from a trusted CA. Never
> use self-signed certificates in production.

