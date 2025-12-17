package main

import (
	"log"

	"github.com/jadefox10200/missiv/backend/internal/api"
)

func main() {
	server := api.NewServer()

	// For HTTPS, use port 8443 and cert/key files (see HTTPS_DEPLOYMENT.md)
	log.Println("Starting Missiv backend server on :8443 (HTTPS)")
	if err := server.RunTLS(":8443", "server.crt", "server.key"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
