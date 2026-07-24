package httputil_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
