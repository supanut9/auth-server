package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestStructuredLoggerOmitsQueryString(t *testing.T) {
	const path = "/v1/oauth2/authorize"
	const requestID = "request-123"

	for _, tt := range []struct {
		name       string
		missingURL bool
	}{
		{name: "request URL path"},
		{name: "fallback path", missingURL: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			previousWriter := gin.DefaultWriter
			gin.DefaultWriter = &output
			logger := StructuredLogger()
			gin.DefaultWriter = previousWriter

			router := gin.New()
			router.Use(RequestIDMiddleware(), logger)
			router.GET(path, func(c *gin.Context) {
				if tt.missingURL {
					c.Request.URL = nil
				}
				c.Status(http.StatusNoContent)
			})

			req := httptest.NewRequest(http.MethodGet, path+"?client_id=x&state=secret&email=a@b.c", nil)
			req.Header.Set("X-Request-Id", requestID)
			router.ServeHTTP(httptest.NewRecorder(), req)

			line := output.String()
			if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
				t.Fatalf("expected one newline-terminated log entry, got %q", line)
			}
			for _, value := range []string{"state=", "secret", "a@b.c"} {
				if strings.Contains(line, value) {
					t.Errorf("log contains query data %q: %s", value, line)
				}
			}

			var entry struct {
				Path      string `json:"path"`
				RequestID string `json:"request_id"`
				Method    string `json:"method"`
				Status    int    `json:"status"`
			}
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatalf("decode request log: %v", err)
			}
			if entry.Path != path || entry.RequestID != requestID || entry.Method != http.MethodGet || entry.Status != http.StatusNoContent {
				t.Fatalf("unexpected request log: %+v", entry)
			}
		})
	}
}
