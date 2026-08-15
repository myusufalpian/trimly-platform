package httputil_test

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trimly-platform/internal/pkg/httputil"
)

func TestRespondJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"foo": "bar"}

	httputil.RespondJSON(rr, http.StatusOK, data)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var resp httputil.ResponseEnvelope
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response envelope: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success true, got false")
	}
}

func TestRespondError(t *testing.T) {
	rr := httptest.NewRecorder()
	httputil.RespondError(rr, http.StatusBadRequest, "INVALID_PARAM", "Parameter is missing")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	var resp httputil.ResponseEnvelope
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response envelope: %v", err)
	}

	if resp.Success {
		t.Errorf("expected success false, got true")
	}

	if resp.Error == nil || resp.Error.Code != "INVALID_PARAM" {
		t.Errorf("expected error code INVALID_PARAM, got %v", resp.Error)
	}
}

func TestSecurityHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rr := httptest.NewRecorder()

	httputil.SecurityHeaders(next).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("expected X-Content-Type-Options nosniff, got %q", got)
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("expected X-Frame-Options DENY, got %q", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("expected Cache-Control no-store, got %q", got)
	}
}

func TestLimitRequestBodyRejectsOversizedBody(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr := io.Copy(io.Discard, r.Body)
		if readErr != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	body := strings.NewReader(strings.Repeat("a", 2<<20))
	rr := httptest.NewRecorder()

	httputil.LimitRequestBody(next).ServeHTTP(rr, httptest.NewRequest("POST", "/", body))

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 Request Entity Too Large, got %d", rr.Code)
	}
}

func TestLimitRequestBodyAllowsSmallBody(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	body := strings.NewReader("small")
	rr := httptest.NewRecorder()

	httputil.LimitRequestBody(next).ServeHTTP(rr, httptest.NewRequest("POST", "/", body))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for small body, got %d", rr.Code)
	}
}

func TestIPRateLimiterBurstThenBlock(t *testing.T) {
	limiter := httputil.NewIPRateLimiter(1, 2)

	allowed := 0
	for i := 0; i < 5; i++ {
		if limiter.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("expected 2 requests allowed within burst, got %d", allowed)
	}

	if !limiter.Allow("5.6.7.8") {
		t.Error("expected a different IP to be unaffected by another IP's limit")
	}
}

func TestIPRateLimiterMiddlewareReturns429(t *testing.T) {
	limiter := httputil.NewIPRateLimiter(0.0001, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	first := httptest.NewRecorder()
	limiter.Middleware(next).ServeHTTP(first, httptest.NewRequest("GET", "/", nil))
	if first.Code != http.StatusOK {
		t.Errorf("expected 200 for first request, got %d", first.Code)
	}

	second := httptest.NewRecorder()
	limiter.Middleware(next).ServeHTTP(second, httptest.NewRequest("GET", "/", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for request exceeding burst, got %d", second.Code)
	}
}

func TestIPRateLimiterMiddlewareGroupsByIPNotPort(t *testing.T) {
	limiter := httputil.NewIPRateLimiter(0.0001, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	first := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "10.0.0.1:1111"
	limiter.Middleware(next).ServeHTTP(first, req1)
	if first.Code != http.StatusOK {
		t.Errorf("expected 200 for first request, got %d", first.Code)
	}

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.1:2222"
	limiter.Middleware(next).ServeHTTP(second, req2)
	if second.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 when same IP uses a different source port, got %d", second.Code)
	}
}

func TestGetRemoteIPIgnoresForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.7:4000"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("X-Real-IP", "203.0.113.100")

	if got := httputil.GetRemoteIP(req); got != "198.51.100.7" {
		t.Errorf("expected RemoteAddr IP, got %q", got)
	}
}

func TestGetRemoteIPWithoutPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.7"

	if got := httputil.GetRemoteIP(req); got != "198.51.100.7" {
		t.Errorf("expected bare RemoteAddr IP, got %q", got)
	}
}

func TestIPRateLimiterIgnoresForwardedFor(t *testing.T) {
	limiter := httputil.NewIPRateLimiter(0.0001, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	first := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "10.0.0.1:1111"
	req1.Header.Set("X-Forwarded-For", "203.0.113.9")
	limiter.Middleware(next).ServeHTTP(first, req1)
	if first.Code != http.StatusOK {
		t.Errorf("expected 200 for first request, got %d", first.Code)
	}

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.1:2222"
	req2.Header.Set("X-Forwarded-For", "203.0.113.10")
	limiter.Middleware(next).ServeHTTP(second, req2)
	if second.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429: spoofed X-Forwarded-For must not bypass the shared quota, got %d", second.Code)
	}
}

func TestTrustedProxyExtractorTrustsForwardedForFromTrustedPeer(t *testing.T) {
	extractor, err := httputil.NewTrustedProxyExtractor([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("failed to build extractor: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:1111"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Real-IP", "203.0.113.10")

	if got := extractor.ClientIP(req); got != "203.0.113.9" {
		t.Errorf("expected X-Forwarded-For value from trusted proxy, got %q", got)
	}
}

func TestTrustedProxyExtractorIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	extractor, err := httputil.NewTrustedProxyExtractor([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("failed to build extractor: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.50:1111"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")

	if got := extractor.ClientIP(req); got != "203.0.113.50" {
		t.Errorf("expected RemoteAddr IP for untrusted peer, got %q", got)
	}
}

func TestTrustedProxyExtractorInvalidCIDR(t *testing.T) {
	if _, err := httputil.NewTrustedProxyExtractor([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestTrustedProxyExtractorAcceptsSingleIP(t *testing.T) {
	extractor, err := httputil.NewTrustedProxyExtractor([]string{"192.168.1.10"})
	if err != nil {
		t.Fatalf("expected single IP to be accepted, got %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.10:2222"
	req.Header.Set("X-Real-IP", "172.16.0.7")

	if got := extractor.ClientIP(req); got != "172.16.0.7" {
		t.Errorf("expected X-Real-IP value from trusted single IP, got %q", got)
	}
}

func TestTrustedProxyExtractorAcceptsSingleIPv6(t *testing.T) {
	extractor, err := httputil.NewTrustedProxyExtractor([]string{"::1"})
	if err != nil {
		t.Fatalf("expected single IPv6 to be accepted, got %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:2222"
	req.Header.Set("X-Forwarded-For", "2001:db8::9")

	if got := extractor.ClientIP(req); got != "2001:db8::9" {
		t.Errorf("expected X-Forwarded-For value from trusted single IPv6 proxy, got %q", got)
	}
}

func TestTrustedProxyExtractorStripsPortFromForwardedHeaders(t *testing.T) {
	extractor, err := httputil.NewTrustedProxyExtractor([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("failed to build extractor: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:1111"
	req.Header.Set("X-Forwarded-For", "203.0.113.9:54321")

	if got := extractor.ClientIP(req); got != "203.0.113.9" {
		t.Errorf("expected forwarded IP without port, got %q", got)
	}
}

func TestIPRateLimiterUsesExtractorKey(t *testing.T) {
	extractor, err := httputil.NewTrustedProxyExtractor([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("failed to build extractor: %v", err)
	}
	limiter := httputil.NewIPRateLimiter(0.0001, 1)
	limiter.SetKeyFunc(extractor.ClientIP)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	first := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "10.0.0.5:1111"
	req1.Header.Set("X-Forwarded-For", "203.0.113.9")
	limiter.Middleware(next).ServeHTTP(first, req1)
	if first.Code != http.StatusOK {
		t.Errorf("expected 200 for first request, got %d", first.Code)
	}

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.6:2222"
	req2.Header.Set("X-Forwarded-For", "203.0.113.9")
	limiter.Middleware(next).ServeHTTP(second, req2)
	if second.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429: same client behind trusted proxy must share quota, got %d", second.Code)
	}
}

func TestIPRateLimiterEvictsIdleEntries(t *testing.T) {
	limiter := httputil.NewIPRateLimiterWithIdleTTL(1, 1, 50*time.Millisecond)

	if !limiter.Allow("1.2.3.4") {
		t.Fatal("expected first request to be allowed")
	}
	if limiter.Allow("1.2.3.4") {
		t.Fatal("expected second request to exceed burst")
	}

	time.Sleep(60 * time.Millisecond)

	if !limiter.Allow("1.2.3.4") {
		t.Error("expected fresh burst after idle eviction")
	}
}

func TestRequestScheme(t *testing.T) {
	t.Run("defaults to http", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/path", nil)
		if got := httputil.RequestScheme(req); got != "http" {
			t.Errorf("expected http, got %q", got)
		}
	})

	t.Run("respects X-Forwarded-Proto", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/path", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		if got := httputil.RequestScheme(req); got != "https" {
			t.Errorf("expected https, got %q", got)
		}
	})

	t.Run("respects TLS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://example.com/path", nil)
		req.TLS = &tls.ConnectionState{}
		if got := httputil.RequestScheme(req); got != "https" {
			t.Errorf("expected https, got %q", got)
		}
	})
}

func TestBaseURL(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/path", nil)
	if got := httputil.BaseURL(req); got != "http://example.com" {
		t.Errorf("expected http://example.com, got %q", got)
	}
}
