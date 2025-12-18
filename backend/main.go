package main

import (
	"log"

	"github.com/jadefox10200/missiv/backend/internal/api"
)

func main() {
	server := api.NewServer()

	log.Println("Starting zcomm backend server on :8080 (HTTP)")
	if err := server.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}