package main

import (
	"log"
	"os"

	"github.com/jadefox10200/missiv/backend/internal/api"
)

func main() {
	server := api.NewServer()

	if os.Getenv("GIN_MODE") == "release" {
		// Production: use HTTPS (TLS)
		log.Println("Starting Missiv backend server on :8443 (HTTPS)")
		if err := server.RunTLS(":8443", "server.crt", "server.key"); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	} else {
		// Development: use plain HTTP
		log.Println("Starting Missiv backend server on :8080 (HTTP; no TLS)")
		if err := server.Run(":8080"); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}
}