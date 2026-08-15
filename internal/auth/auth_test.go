package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trimly-platform/internal/auth"
)

type envelope struct {
	Success bool `json:"success"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func TestHashTokenDeterministic(t *testing.T) {
	token := "sample_token_string_123"
	hash1 := auth.HashToken(token)
	hash2 := auth.HashToken(token)

	if hash1 == "" {
		t.Fatalf("expected non-empty hash string")
	}

	if hash1 != hash2 {
		t.Errorf("expected deterministic hash output, got %s vs %s", hash1, hash2)
	}
}

func TestRequireVerifiedEmailMiddleware(t *testing.T) {
	handler := auth.NewHandler(nil, true)
	middleware := handler.RequireVerifiedEmailMiddleware

	now := time.Now()

	tests := []struct {
		name           string
		user           *auth.User
		expectedStatus int
	}{
		{
			name:           "Unverified User Blocked",
			user:           &auth.User{ID: "user-1", Email: "unverified@example.com", EmailVerifiedAt: nil},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Verified User Permitted",
			user:           &auth.User{ID: "user-2", Email: "verified@example.com", EmailVerifiedAt: &now},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Nil User Blocked",
			user:           nil,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/links", nil)
			if tt.user != nil {
				ctx := context.WithValue(req.Context(), auth.UserContextKey, tt.user)
				req = req.WithContext(ctx)
			}

			rr := httptest.NewRecorder()
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware(nextHandler).ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestAuthMiddlewareTokenExtraction(t *testing.T) {
	handler := auth.NewHandler(nil, true)
	middleware := handler.AuthMiddleware

	req := httptest.NewRequest("GET", "/v1/auth/me", nil)
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got %d", rr.Code)
	}
}

func TestAuthMiddlewareValidSession(t *testing.T) {
	mailer := &stubMailSender{}
	repo := &stubAuthRepo{}
	svc := auth.NewService(repo, mailer)
	handler := auth.NewHandler(svc, true)
	middleware := handler.AuthMiddleware

	req := httptest.NewRequest("GET", "/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "valid-token"})
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(auth.UserContextKey).(*auth.User)
		if user.ID != "user-1" {
			t.Errorf("expected user-1, got %s", user.ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
}

func TestAuthMiddlewareInvalidSession(t *testing.T) {
	mailer := &stubMailSender{}
	repo := &stubAuthRepo{}
	svc := auth.NewService(repo, mailer)
	handler := auth.NewHandler(svc, true)
	middleware := handler.AuthMiddleware

	req := httptest.NewRequest("GET", "/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "invalid-token"})
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
	}
}

func TestRegisterValidation(t *testing.T) {
	svc := auth.NewService(nil, nil)

	_, errShort := svc.Register(context.Background(), auth.RegisterRequest{Email: "user@example.com", Password: "short"})
	if errShort == nil {
		t.Fatalf("expected error for short password, got nil")
	}

	if errShort.Error() != "password must be at least 8 characters long" {
		t.Errorf("expected password length error, got %q", errShort.Error())
	}

	_, errEmpty := svc.Register(context.Background(), auth.RegisterRequest{Email: "", Password: "validpassword123"})
	if errEmpty == nil {
		t.Fatalf("expected error for empty email, got nil")
	}
}

type stubAuthService struct {
	registerUser *auth.User
	registerErr  error
	loginToken   string
	loginUser    *auth.User
	loginErr     error
	verifyErr    error
}

func (s *stubAuthService) Register(ctx context.Context, req auth.RegisterRequest) (*auth.User, error) {
	return s.registerUser, s.registerErr
}

func (s *stubAuthService) VerifyEmail(ctx context.Context, req auth.VerifyEmailRequest) error {
	return s.verifyErr
}

func (s *stubAuthService) Login(ctx context.Context, req auth.LoginRequest) (string, *auth.User, error) {
	return s.loginToken, s.loginUser, s.loginErr
}

func (s *stubAuthService) Logout(ctx context.Context, sessionToken string) error {
	return nil
}

func (s *stubAuthService) GetUserFromSession(ctx context.Context, sessionToken string) (*auth.User, error) {
	return nil, nil
}

func registerRequest(body string) *http.Request {
	return httptest.NewRequest("POST", "/v1/auth/register", strings.NewReader(body))
}

func TestRegisterHandlerEmailTaken(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{registerErr: auth.ErrEmailTaken}, true)
	rr := httptest.NewRecorder()

	handler.Register(rr, registerRequest(`{"email":"taken@test.com","password":"Password123"}`))

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict, got %d", rr.Code)
	}

	var resp envelope
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == nil || resp.Error.Message != "an account with this email already exists" {
		t.Errorf("expected generic email taken message, got %+v", resp.Error)
	}
}

func TestRegisterHandlerGenericErrorIsOpaque(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{registerErr: errors.New("ERROR: duplicate key value violates unique constraint (SQLSTATE 23505)")}, true)
	rr := httptest.NewRecorder()

	handler.Register(rr, registerRequest(`{"email":"x@test.com","password":"Password123"}`))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}

	var resp envelope
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == nil || resp.Error.Message == "ERROR: duplicate key value violates unique constraint (SQLSTATE 23505)" {
		t.Errorf("raw database error must not be leaked to the client, got %+v", resp.Error)
	}
}

func TestRegisterHandlerInvalidJSON(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{}, true)
	rr := httptest.NewRecorder()

	handler.Register(rr, registerRequest("{not-json"))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
}

func TestLoginSetsSecureCookie(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{
		loginToken: "tok-123",
		loginUser:  &auth.User{ID: "user-1", Email: "a@test.com"},
	}, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"email":"a@test.com","password":"Password123"}`))

	handler.Login(rr, req)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 session cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "session_token" {
		t.Errorf("expected cookie name session_token, got %q", c.Name)
	}
	if c.Value != "tok-123" {
		t.Errorf("expected cookie value tok-123, got %q", c.Value)
	}
	if !c.HttpOnly {
		t.Error("expected HttpOnly cookie")
	}
	if !c.Secure {
		t.Error("expected Secure cookie")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite Lax, got %v", c.SameSite)
	}
}

func TestLoginHandlerInvalidCredentials(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{loginErr: errors.New("invalid email or password")}, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"email":"a@test.com","password":"wrong"}`))

	handler.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
	}
}

func TestLoginHandlerOmitsTokenFromBody(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{
		loginToken: "tok-123",
		loginUser:  &auth.User{ID: "user-1", Email: "a@test.com"},
	}, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"email":"a@test.com","password":"Password123"}`))

	handler.Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "tok-123") {
		t.Error("session token must not be exposed in the response body")
	}
}

func TestRegisterHandlerKeepsValidationMessage(t *testing.T) {
	handler := auth.NewHandler(auth.NewService(&stubAuthRepo{}, &stubMailSender{}), true)
	rr := httptest.NewRecorder()

	handler.Register(rr, registerRequest(`{"email":"a@test.com","password":"short"}`))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
	var resp envelope
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == nil || resp.Error.Code != "INVALID_INPUT" {
		t.Errorf("expected INVALID_INPUT error code, got %+v", resp.Error)
	}
	if resp.Error == nil || resp.Error.Message != "password must be at least 8 characters long" {
		t.Errorf("expected validation message preserved, got %+v", resp.Error)
	}
}

func TestLoginHandlerInvalidInput(t *testing.T) {
	handler := auth.NewHandler(auth.NewService(&stubAuthRepo{}, &stubMailSender{}), true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"email":"","password":""}`))

	handler.Login(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid input, got %d", rr.Code)
	}
}

func TestLoginHandlerOpaqueOnRepoError(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{loginErr: errors.New("connection refused")}, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"email":"a@test.com","password":"Password123"}`))

	handler.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
	}
	var resp envelope
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == nil || resp.Error.Message == "connection refused" {
		t.Errorf("raw repo error must not leak, got %+v", resp.Error)
	}
}

func TestVerifyEmailHandlerInvalidInput(t *testing.T) {
	handler := auth.NewHandler(auth.NewService(&stubAuthRepo{}, &stubMailSender{}), true)
	rr := httptest.NewRecorder()

	handler.VerifyEmail(rr, httptest.NewRequest("POST", "/v1/auth/verify-email", strings.NewReader(`{"token":""}`)))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
	var resp envelope
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == nil || resp.Error.Code != "INVALID_INPUT" {
		t.Errorf("expected INVALID_INPUT code, got %+v", resp.Error)
	}
}

func TestVerifyEmailHandlerInvalidJSON(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{}, true)
	rr := httptest.NewRecorder()

	handler.VerifyEmail(rr, httptest.NewRequest("POST", "/v1/auth/verify-email", strings.NewReader("{not-json")))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
	var resp envelope
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == nil || resp.Error.Code != "INVALID_INPUT" {
		t.Errorf("expected INVALID_INPUT code for invalid JSON, got %+v", resp.Error)
	}
}

func TestVerifyEmailHandlerOpaqueOnRepoError(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{verifyErr: errors.New("connection refused")}, true)
	rr := httptest.NewRecorder()

	handler.VerifyEmail(rr, httptest.NewRequest("POST", "/v1/auth/verify-email", strings.NewReader(`{"token":"tok"}`)))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
	var resp envelope
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Error == nil || resp.Error.Message == "connection refused" {
		t.Errorf("raw repo error must not leak, got %+v", resp.Error)
	}
	if resp.Error == nil || resp.Error.Message != "invalid or expired verification token" {
		t.Errorf("expected generic verification message, got %+v", resp.Error)
	}
}

func TestVerifyEmailHandlerSuccess(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{}, true)
	rr := httptest.NewRecorder()

	handler.VerifyEmail(rr, httptest.NewRequest("POST", "/v1/auth/verify-email", strings.NewReader(`{"token":"valid-token"}`)))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
}

func TestLogoutClearsSessionCookie(t *testing.T) {
	handler := auth.NewHandler(&stubAuthService{}, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "tok-123"})

	handler.Logout(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 clearing cookie, got %d", len(cookies))
	}
	if cookies[0].Value != "" || cookies[0].MaxAge != -1 {
		t.Errorf("expected empty cookie with MaxAge -1, got value=%q maxAge=%d", cookies[0].Value, cookies[0].MaxAge)
	}
}
