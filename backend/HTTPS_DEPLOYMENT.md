# HTTPS Deployment Instructions for Missiv Backend

## 1. Generate a Self-Signed Certificate (for local/dev)

You can use OpenSSL to generate a self-signed certificate and private key:

```sh
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
```

This will create `server.crt` (certificate) and `server.key` (private key) in your current directory.

## 2. Move Certificates to Backend Directory

Place both `server.crt` and `server.key` in your backend directory (e.g., `backend/`).

## 3. Update Go Server to Use HTTPS

Edit `backend/internal/api/server.go` and `backend/main.go` to use `ListenAndServeTLS`:

- Change the `Run` method to accept cert and key paths, and use `s.router.RunTLS(addr, certFile, keyFile)`.
- Update `main.go` to pass the cert and key file paths.

## 4. Example Usage in main.go

```go
func main() {
    server := api.NewServer()
    log.Println("Starting Missiv backend server on :8443 (HTTPS)")
    if err := server.RunTLS(":8443", "server.crt", "server.key"); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}
```

## 5. Production

For production, use a certificate from a trusted CA (e.g., Let's Encrypt) and update the cert/key file paths accordingly.

## 6. Update Frontend API URLs

Ensure your frontend points to `https://` URLs and accepts the new port (e.g., 8443).

---

**Note:** Browsers may warn about self-signed certs in development. For real deployments, always use a trusted certificate authority.
