package httputil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
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

// GetRemoteIP returns the untrusted socket peer IP (RemoteAddr without port).
// It must not reflect client-supplied headers, so it is safe to use as a rate-limit key.
func GetRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
			slog.String("ip", GetRemoteIP(r)),
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
