package handler

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/httpserver"
)

var (
	handlerOnce sync.Once
	handlerErr  error
	router      *gin.Engine
)

func Handler(w http.ResponseWriter, r *http.Request) {
	handlerOnce.Do(func() {
		router, _, handlerErr = httpserver.NewRouterFromEnv()
	})

	if handlerErr != nil {
		http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
		return
	}

	if routePath := r.URL.Query().Get("__vercel_path"); routePath != "" {
		r.URL.Path = routePath
		query := r.URL.Query()
		query.Del("__vercel_path")
		r.URL.RawQuery = query.Encode()
	}

	router.ServeHTTP(w, r)
}
