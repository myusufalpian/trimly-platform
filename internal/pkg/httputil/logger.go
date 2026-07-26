package httputil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const RequestIDKey contextKey = "requestId"

// GenerateRequestID creates a random 16-byte hex string
func GenerateRequestID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return time.Now().Format("20060102150405999999")
	}
	return hex.EncodeToString(bytes)
}

// GetClientIP extracts real client IP considering X-Forwarded-For & X-Real-IP headers
func GetClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	return r.RemoteAddr
}

// RequestLoggerMiddleware logs incoming HTTP requests using slog and injects X-Request-ID
func RequestLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = GenerateRequestID()
		}

		ctx := context.WithValue(r.Context(), RequestIDKey, reqID)
		r = r.WithContext(ctx)

		w.Header().Set("X-Request-ID", reqID)

		rw := &responseWriterInterceptor{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		// Skip access log for health/readiness probe paths to avoid log noise
		path := r.URL.Path
		if path == "/healthz" || path == "/readyz" || path == "/health" {
			return
		}

		duration := time.Since(start)

		slog.Info("http request",
			slog.String("request_id", reqID),
			slog.String("method", r.Method),
			slog.String("path", path),
			slog.Int("status", rw.statusCode),
			slog.Duration("duration", duration),
			slog.String("ip", GetClientIP(r)),
		)
	})
}

type responseWriterInterceptor struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterInterceptor) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
