package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trimly-platform/internal/pkg/httputil"
)

func TestRequestLoggerMiddleware(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Context().Value(httputil.RequestIDKey)
		if reqID == nil || reqID == "" {
			t.Errorf("expected request_id in context, got nil")
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := httputil.RequestLoggerMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/v1/links", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	reqIDHeader := rec.Header().Get("X-Request-ID")
	if reqIDHeader == "" {
		t.Errorf("expected X-Request-ID header in response")
	}
}

func TestRequestLoggerMiddlewareCustomID(t *testing.T) {
	customID := "custom-req-id-12345"
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Context().Value(httputil.RequestIDKey).(string)
		if reqID != customID {
			t.Errorf("expected request_id %s, got %s", customID, reqID)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	wrapped := httputil.RequestLoggerMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", customID)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Header().Get("X-Request-ID") != customID {
		t.Errorf("expected X-Request-ID header %s, got %s", customID, rec.Header().Get("X-Request-ID"))
	}
}

func TestGenerateRequestID(t *testing.T) {
	id := httputil.GenerateRequestID()
	if id == "" {
		t.Error("expected non-empty request ID")
	}
	if len(id) != 32 {
		t.Errorf("expected request ID length 32, got %d", len(id))
	}
}

func TestRequestLoggerMiddlewareSkipsHealthPath(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := httputil.RequestLoggerMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}
