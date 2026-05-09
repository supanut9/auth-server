package httpserver

import (
	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/config"
	internalhttpserver "github.com/supanut9/auth-server/internal/httpserver"
)

func NewRouterFromEnv() (*gin.Engine, config.Config, error) {
	return internalhttpserver.NewRouterFromEnv()
}
