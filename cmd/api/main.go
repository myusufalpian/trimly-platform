package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"trimly-platform/internal/admin"
	"trimly-platform/internal/apikey"
	"trimly-platform/internal/auth"
	"trimly-platform/internal/bio"
	"trimly-platform/internal/config"
	"trimly-platform/internal/link"
	"trimly-platform/internal/pkg/httputil"
	"trimly-platform/internal/pkg/mail"
	"trimly-platform/internal/security"
	"trimly-platform/internal/workspace"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"
)

const (
	loginRateLimit          rate.Limit = 1
	loginRateBurst                     = 5
	registerRateLimit       rate.Limit = 0.2
	registerRateBurst                  = 3
	verifyEmailRateLimit    rate.Limit = 1
	verifyEmailRateBurst               = 10
	logoutRateLimit         rate.Limit = 1
	logoutRateBurst                    = 20
	createAPIKeyRateLimit   rate.Limit = 0.5
	createAPIKeyRateBurst              = 3
	workspaceRateLimit      rate.Limit = 1
	workspaceRateBurst                 = 5
	serverReadHeaderTimeout            = 5 * time.Second
	serverReadTimeout                  = 15 * time.Second
	serverWriteTimeout                 = 15 * time.Second
	serverIdleTimeout                  = 60 * time.Second
	dbPingTimeout                      = 10 * time.Second
	readinessPingTimeout               = 2 * time.Second
	shutdownTimeout                    = 10 * time.Second
)

type workspaceMembershipAdapter struct {
	repo workspace.Repository
}

func (w *workspaceMembershipAdapter) IsMember(ctx context.Context, workspaceID, userID string) bool {
	role, err := w.repo.GetMemberRole(ctx, workspaceID, userID)
	return err == nil && role != ""
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("Configuration error", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbPingTimeout)
	defer cancel()

	dbPool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("Unable to connect to database", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if err := dbPool.Ping(ctx); err != nil {
		slog.Warn("Database ping warning", slog.String("error", err.Error()))
	} else {
		slog.Info("Successfully connected to PostgreSQL database")
	}

	mailAdapter := mail.NewMailHogAdapter(cfg.SMTPHost, cfg.SMTPPort)

	authRepo := auth.NewRepository(dbPool)
	authService := auth.NewService(authRepo, mailAdapter)
	authHandler := auth.NewHandler(authService, cfg.CookieSecure)

	workspaceRepo := workspace.NewRepository(dbPool)
	workspaceService := workspace.NewService(workspaceRepo)
	workspaceHandler := workspace.NewHandler(workspaceService)

	adminRepo := admin.NewRepository(dbPool)
	adminService := admin.NewService(adminRepo)
	adminHandler := admin.NewHandler(adminService)

	apiKeyRepo := apikey.NewRepository(dbPool)
	apiKeyService := apikey.NewService(apiKeyRepo)
	apiKeyHandler := apikey.NewHandler(apiKeyService)

	linkRepo := link.NewRepository(dbPool)
	linkService := link.NewService(linkRepo, adminService)
	linkService.SetURLScanner(security.NewMockURLScanner(cfg.ThreatDomains...))
	linkService.SetWorkspaceChecker(&workspaceMembershipAdapter{repo: *workspaceRepo})
	linkHandler := link.NewHandler(linkService)

	bioRepo := bio.NewRepository(dbPool)
	bioService := bio.NewService(bioRepo)
	bioHandler := bio.NewHandler(bioService)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httputil.RespondJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "trimly-platform",
		})
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		httputil.RespondJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "trimly-platform",
		})
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		pingCtx, pingCancel := context.WithTimeout(r.Context(), readinessPingTimeout)
		defer pingCancel()

		if err := dbPool.Ping(pingCtx); err != nil {
			slog.Error("Readiness check failed - DB ping error", slog.String("error", err.Error()))
			httputil.RespondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Database connection unhealthy")
			return
		}

		httputil.RespondJSON(w, http.StatusOK, map[string]string{
			"status":   "ready",
			"database": "connected",
		})
	})

	mux.HandleFunc("GET /r/{slug}", linkHandler.PublicRedirect)

	proxyExtractor, err := httputil.NewTrustedProxyExtractor(cfg.TrustedProxies)
	if err != nil {
		slog.Error("Invalid TRUSTED_PROXIES configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}
	loginLimiter := httputil.NewIPRateLimiter(loginRateLimit, loginRateBurst)
	registerLimiter := httputil.NewIPRateLimiter(registerRateLimit, registerRateBurst)
	verifyEmailLimiter := httputil.NewIPRateLimiter(verifyEmailRateLimit, verifyEmailRateBurst)
	logoutLimiter := httputil.NewIPRateLimiter(logoutRateLimit, logoutRateBurst)
	createAPIKeyLimiter := httputil.NewIPRateLimiter(createAPIKeyRateLimit, createAPIKeyRateBurst)
	workspaceLimiter := httputil.NewIPRateLimiter(workspaceRateLimit, workspaceRateBurst)
	for _, l := range []*httputil.IPRateLimiter{loginLimiter, registerLimiter, verifyEmailLimiter, logoutLimiter, createAPIKeyLimiter, workspaceLimiter} {
		l.SetKeyFunc(proxyExtractor.ClientIP)
	}
	mux.Handle("POST /v1/auth/register", registerLimiter.Middleware(http.HandlerFunc(authHandler.Register)))
	mux.Handle("POST /v1/auth/verify-email", verifyEmailLimiter.Middleware(http.HandlerFunc(authHandler.VerifyEmail)))
	mux.Handle("POST /v1/auth/login", loginLimiter.Middleware(http.HandlerFunc(authHandler.Login)))
	mux.Handle("POST /v1/auth/logout", logoutLimiter.Middleware(http.HandlerFunc(authHandler.Logout)))

	authChain := func(handler http.HandlerFunc) http.Handler {
		return authHandler.AuthMiddleware(http.HandlerFunc(handler))
	}

	verifiedAuthChain := func(handler http.HandlerFunc) http.Handler {
		return authHandler.AuthMiddleware(authHandler.RequireVerifiedEmailMiddleware(http.HandlerFunc(handler)))
	}

	adminChain := func(handler http.HandlerFunc) http.Handler {
		return authHandler.AuthMiddleware(adminService.RequirePlatformAdminMiddleware(http.HandlerFunc(handler)))
	}

	apiKeyChain := func(handler http.HandlerFunc) http.Handler {
		return apiKeyService.APIKeyAuthMiddleware(http.HandlerFunc(handler))
	}

	mux.Handle("GET /v1/auth/me", authChain(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(auth.UserContextKey).(*auth.User)
		httputil.RespondJSON(w, http.StatusOK, user)
	}))

	mux.Handle("POST /v1/links", verifiedAuthChain(linkHandler.CreateLink))
	mux.Handle("POST /v1/bio-pages", authChain(bioHandler.CreatePage))
	mux.Handle("POST /v1/bio-pages/{id}/links", authChain(bioHandler.AddLink))
	mux.HandleFunc("GET /v1/bio-pages/public/{slug}", bioHandler.PublicPage)
	mux.Handle("GET /v1/links/analytics", authChain(linkHandler.GetAnalytics))
	mux.Handle("GET /v1/links/qr", authChain(linkHandler.GenerateQRCode))
	mux.Handle("GET /v1/analytics/export", authChain(linkHandler.ExportCSVAnalytics))

	mux.Handle("POST /v1/workspaces", workspaceLimiter.Middleware(authChain(workspaceHandler.CreateWorkspace)))
	mux.Handle("GET /v1/workspaces", authChain(workspaceHandler.ListWorkspaces))
	mux.Handle("POST /v1/workspaces/members", authChain(workspaceHandler.AddMember))

	mux.Handle("GET /v1/admin/users", adminChain(adminHandler.ListUsers))
	mux.Handle("POST /v1/admin/blacklist-domains", adminChain(adminHandler.AddBlacklistDomain))
	mux.Handle("DELETE /v1/admin/blacklist-domains/", adminChain(adminHandler.RemoveBlacklistDomain))
	mux.Handle("POST /v1/admin/clicks/unflag", adminChain(adminHandler.UnflagClick))

	mux.Handle("POST /v1/api-keys", createAPIKeyLimiter.Middleware(authChain(apiKeyHandler.CreateAPIKey)))
	mux.Handle("GET /v1/api-keys", authChain(apiKeyHandler.ListAPIKeys))
	mux.Handle("DELETE /v1/api-keys/", authChain(apiKeyHandler.RevokeAPIKey))
	mux.Handle("GET /v1/api-usage", authChain(apiKeyHandler.GetUsageHistory))

	mux.Handle("POST /v1/api/links", apiKeyChain(linkHandler.CreateLink))

	securedHandler := httputil.SecurityHeaders(httputil.LimitRequestBody(mux))
	loggedHandler := httputil.RequestLoggerMiddleware(securedHandler)

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           loggedHandler,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		slog.Info("Trimly Platform API server running", slog.String("port", cfg.Port))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server failed unexpectedly", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	sig := <-stopChan
	slog.Info("Received shutdown signal", slog.String("signal", sig.String()))

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", slog.String("error", err.Error()))
	} else {
		slog.Info("HTTP server gracefully stopped")
	}

	authService.Shutdown()
	dbPool.Close()
	slog.Info("Database pool connection closed cleanly")
}
