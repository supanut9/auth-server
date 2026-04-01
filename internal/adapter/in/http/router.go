package http

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/config"
)

func RegisterRoutes(router *gin.Engine, cfg config.Config) {
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":   "ok",
			"app_name": cfg.AppName,
		})
	})
}
