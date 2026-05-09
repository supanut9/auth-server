package main

import (
	"log"

	_ "github.com/joho/godotenv/autoload"

	"github.com/supanut9/auth-server/httpserver"
)

func main() {
	router, cfg, err := httpserver.NewRouterFromEnv()
	if err != nil {
		log.Fatalf("bootstrap auth server: %v", err)
	}

	if err := router.Run(cfg.HTTPAddr); err != nil {
		log.Fatalf("run server: %v", err)
	}
}
