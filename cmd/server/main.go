package main

import (
	"log"

	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/adapter/in/http"
	"github.com/supanut9/auth-server/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	http.RegisterRoutes(router, cfg)

	if err := router.Run(cfg.HTTPAddr); err != nil {
		log.Fatalf("run server: %v", err)
	}
}
