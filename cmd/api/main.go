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
)

func main() {
	// Initialize Structured Logger (log/slog JSON Handler)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := config.LoadConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	// Adapters
	mailAdapter := mail.NewMailHogAdapter(cfg.SMTPHost, cfg.SMTPPort)

	// Auth Module
	authRepo := auth.NewRepository(dbPool)
	authService := auth.NewService(authRepo, mailAdapter)
	authHandler := auth.NewHandler(authService)

	// Workspace Module
	workspaceRepo := workspace.NewRepository(dbPool)
	workspaceService := workspace.NewService(workspaceRepo)
	workspaceHandler := workspace.NewHandler(workspaceService)

	// Admin Module
	adminRepo := admin.NewRepository(dbPool)
	adminService := admin.NewService(adminRepo)
	adminHandler := admin.NewHandler(adminService)

	// API Key Module (Rilis 2 B2B)
	apiKeyRepo := apikey.NewRepository(dbPool)
	apiKeyService := apikey.NewService(apiKeyRepo)
	apiKeyHandler := apikey.NewHandler(apiKeyService)

	// Link Module (Injected with AdminService as DomainBlacklistChecker)
	linkRepo := link.NewRepository(dbPool)
	linkService := link.NewService(linkRepo, adminService)
	linkService.SetURLScanner(security.NewMockURLScanner(cfg.ThreatDomains...))
	linkHandler := link.NewHandler(linkService)

	// Link-in-Bio Module
	bioRepo := bio.NewRepository(dbPool)
	bioService := bio.NewService(bioRepo)
	bioHandler := bio.NewHandler(bioService)

	// Router
	mux := http.NewServeMux()

	// TASK-701: Health Check (Liveness Probe)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httputil.RespondJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "trimly-platform",
		})
	})

	// Legacy /health compatibility
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		httputil.RespondJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "trimly-platform",
		})
	})

	// TASK-701: Readiness Probe (Checks Database Connection Ping)
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		pingCtx, pingCancel := context.WithTimeout(r.Context(), 2*time.Second)
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

	// Public Redirect Route (Fast Path)
	mux.HandleFunc("GET /r/", linkHandler.PublicRedirect)

	// Auth Endpoints
	mux.HandleFunc("POST /v1/auth/register", authHandler.Register)
	mux.HandleFunc("POST /v1/auth/verify-email", authHandler.VerifyEmail)
	mux.HandleFunc("POST /v1/auth/login", authHandler.Login)
	mux.HandleFunc("POST /v1/auth/logout", authHandler.Logout)

	// Middleware Chains
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

	// User Profile
	mux.Handle("GET /v1/auth/me", authChain(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(auth.UserContextKey).(*auth.User)
		httputil.RespondJSON(w, http.StatusOK, user)
	}))

	// Link Protected Endpoints (Web Session)
	mux.Handle("POST /v1/links", verifiedAuthChain(linkHandler.CreateLink))
	mux.Handle("POST /v1/bio-pages", authChain(bioHandler.CreatePage))
	mux.Handle("POST /v1/bio-pages/{id}/links", authChain(bioHandler.AddLink))
	mux.HandleFunc("GET /v1/bio-pages/public/{slug}", bioHandler.PublicPage)
	mux.Handle("GET /v1/links/analytics", authChain(linkHandler.GetAnalytics))
	mux.Handle("GET /v1/links/qr", authChain(linkHandler.GenerateQRCode))
	mux.Handle("GET /v1/analytics/export", authChain(linkHandler.ExportCSVAnalytics))

	// Workspace Protected Endpoints
	mux.Handle("POST /v1/workspaces", authChain(workspaceHandler.CreateWorkspace))
	mux.Handle("GET /v1/workspaces", authChain(workspaceHandler.ListWorkspaces))
	mux.Handle("POST /v1/workspaces/members", authChain(workspaceHandler.AddMember))

	// Minimal Platform Admin Endpoints
	mux.Handle("GET /v1/admin/users", adminChain(adminHandler.ListUsers))
	mux.Handle("POST /v1/admin/blacklist-domains", adminChain(adminHandler.AddBlacklistDomain))
	mux.Handle("DELETE /v1/admin/blacklist-domains/", adminChain(adminHandler.RemoveBlacklistDomain))
	mux.Handle("POST /v1/admin/clicks/unflag", adminChain(adminHandler.UnflagClick))

	// Rilis 2: B2B API Key Management & B2B Link Creation
	mux.Handle("POST /v1/api-keys", authChain(apiKeyHandler.CreateAPIKey))
	mux.Handle("GET /v1/api-keys", authChain(apiKeyHandler.ListAPIKeys))
	mux.Handle("DELETE /v1/api-keys/", authChain(apiKeyHandler.RevokeAPIKey))
	mux.Handle("GET /v1/api-usage", authChain(apiKeyHandler.GetUsageHistory))

	// B2B Integrator Link Creation Endpoint (Authenticated via API Key & Rate Limited 60/min + 5000/day)
	mux.Handle("POST /v1/api/links", apiKeyChain(linkHandler.CreateLink))

	// Wrap entire Mux with TASK-702 Request Logger Middleware
	loggedHandler := httputil.RequestLoggerMiddleware(mux)

	// HTTP Server Configuration
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      loggedHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// TASK-703: Graceful Shutdown Setup
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		slog.Info("Trimly Platform API server running", slog.String("port", cfg.Port))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server failed unexpectedly", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	// Wait for termination signal
	sig := <-stopChan
	slog.Info("Received shutdown signal", slog.String("signal", sig.String()))

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", slog.String("error", err.Error()))
	} else {
		slog.Info("HTTP server gracefully stopped")
	}

	// Close Database Pool cleanly
	dbPool.Close()
	slog.Info("Database pool connection closed cleanly")
}
