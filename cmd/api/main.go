package main

import (
	"context"
	"log"
	"net/http"

	"trimly-platform/internal/admin"
	"trimly-platform/internal/auth"
	"trimly-platform/internal/config"
	"trimly-platform/internal/link"
	"trimly-platform/internal/pkg/httputil"
	"trimly-platform/internal/pkg/mail"
	"trimly-platform/internal/workspace"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	cfg := config.LoadConfig()

	ctx := context.Background()
	dbPool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer dbPool.Close()

	if err := dbPool.Ping(ctx); err != nil {
		log.Printf("Warning: Database ping failed: %v", err)
	} else {
		log.Println("Successfully connected to PostgreSQL database")
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

	// Link Module (Injected with AdminService as DomainBlacklistChecker)
	linkRepo := link.NewRepository(dbPool)
	linkService := link.NewService(linkRepo, adminService)
	linkHandler := link.NewHandler(linkService)

	// Router
	mux := http.NewServeMux()

	// Health Check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		httputil.RespondJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "trimly-platform",
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

	// User Profile
	mux.Handle("GET /v1/auth/me", authChain(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(auth.UserContextKey).(*auth.User)
		httputil.RespondJSON(w, http.StatusOK, user)
	}))

	// Link Protected Endpoints
	mux.Handle("POST /v1/links", verifiedAuthChain(linkHandler.CreateLink))
	mux.Handle("GET /v1/links/analytics", authChain(linkHandler.GetAnalytics))

	// Workspace Protected Endpoints
	mux.Handle("POST /v1/workspaces", authChain(workspaceHandler.CreateWorkspace))
	mux.Handle("GET /v1/workspaces", authChain(workspaceHandler.ListWorkspaces))
	mux.Handle("POST /v1/workspaces/members", authChain(workspaceHandler.AddMember))

	// Minimal Platform Admin Endpoints
	mux.Handle("GET /v1/admin/users", adminChain(adminHandler.ListUsers))
	mux.Handle("POST /v1/admin/blacklist-domains", adminChain(adminHandler.AddBlacklistDomain))
	mux.Handle("DELETE /v1/admin/blacklist-domains/", adminChain(adminHandler.RemoveBlacklistDomain))
	mux.Handle("POST /v1/admin/clicks/unflag", adminChain(adminHandler.UnflagClick))

	log.Printf("Trimly Platform API server running on port :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
