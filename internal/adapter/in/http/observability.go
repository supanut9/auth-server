package http

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const requestIDContextKey = "request_id"

func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := normalizeRequestID(c.GetHeader("X-Request-Id"))
		if requestID == "" {
			requestID = normalizeRequestID(c.GetHeader("X-Request-ID"))
		}
		if requestID == "" {
			requestID = uuid.NewString()
		}

		c.Set(requestIDContextKey, requestID)
		c.Writer.Header().Set("X-Request-Id", requestID)
		c.Next()
	}
}

func StructuredLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		requestID := "-"
		if param.Keys != nil {
			if value, ok := param.Keys[requestIDContextKey]; ok {
				if id, ok := value.(string); ok && id != "" {
					requestID = id
				}
			}
		}

		entry := map[string]any{
			"time":       param.TimeStamp.UTC().Format(time.RFC3339Nano),
			"status":     param.StatusCode,
			"latency_ms": param.Latency.Milliseconds(),
			"client_ip":  param.ClientIP,
			"method":     param.Method,
			"path":       param.Path,
			"request_id": requestID,
		}
		if param.ErrorMessage != "" {
			entry["error"] = strings.TrimSpace(param.ErrorMessage)
		}

		payload, err := json.Marshal(entry)
		if err != nil {
			return fmt.Sprintf("{\"error\":\"logger_marshal_failed\",\"request_id\":\"%s\"}\n", requestID)
		}

		return string(payload) + "\n"
	})
}

func requestIDFromContext(c *gin.Context) string {
	if value, ok := c.Get(requestIDContextKey); ok {
		if requestID, ok := value.(string); ok {
			return requestID
		}
	}

	return ""
}

func normalizeRequestID(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 128 {
		return ""
	}

	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return ""
		}
	}

	return value
}
