package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trimly-platform/internal/pkg/httputil"
)

type contextKey string

const UserContextKey contextKey = "user"

const sessionCookieName = "session_token"

type authService interface {
	Register(ctx context.Context, req RegisterRequest) (*User, error)
	VerifyEmail(ctx context.Context, req VerifyEmailRequest) error
	Login(ctx context.Context, req LoginRequest) (string, *User, error)
	Logout(ctx context.Context, sessionToken string) error
	GetUserFromSession(ctx context.Context, sessionToken string) (*User, error)
}

type Handler struct {
	service      authService
	cookieSecure bool
}

func NewHandler(service authService, cookieSecure bool) *Handler {
	return &Handler{service: service, cookieSecure: cookieSecure}
}

func sessionCookie(token string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	user, err := h.service.Register(r.Context(), req)
	if err != nil {
		if errors.Is(err, ErrEmailTaken) {
			httputil.RespondError(w, http.StatusConflict, "EMAIL_TAKEN", "an account with this email already exists")
			return
		}
		if errors.Is(err, ErrInvalidInput) {
			httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusBadRequest, "REGISTRATION_FAILED", "unable to register, please try again")
		return
	}

	httputil.RespondJSON(w, http.StatusCreated, map[string]interface{}{
		"user":    user,
		"message": "User registered successfully. Please check your email for verification.",
	})
}

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	err := h.service.VerifyEmail(r.Context(), req)
	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusBadRequest, "VERIFICATION_FAILED", "invalid or expired verification token")
		return
	}

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Email verified successfully",
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid JSON payload")
		return
	}

	token, user, err := h.service.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			httputil.RespondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
			return
		}
		httputil.RespondError(w, http.StatusUnauthorized, "LOGIN_FAILED", "invalid email or password")
		return
	}

	http.SetCookie(w, sessionCookie(token, 0, h.cookieSecure))

	httputil.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"user": user,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	token := h.extractToken(r)
	_ = h.service.Logout(r.Context(), token)

	http.SetCookie(w, sessionCookie("", -1, h.cookieSecure))

	httputil.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := h.extractToken(r)
		if token == "" {
			httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
			return
		}

		if h.service == nil {
			httputil.RespondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Auth service unavailable")
			return
		}

		user, err := h.service.GetUserFromSession(r.Context(), token)
		if err != nil {
			httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Invalid or expired session")
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handler) RequireVerifiedEmailMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(UserContextKey).(*User)
		if !ok || user == nil {
			httputil.RespondError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
			return
		}

		if user.EmailVerifiedAt == nil {
			httputil.RespondError(w, http.StatusForbidden, "EMAIL_NOT_VERIFIED", "Email verification is required before performing this action")
			return
		}

		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

func (h *Handler) extractToken(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}
