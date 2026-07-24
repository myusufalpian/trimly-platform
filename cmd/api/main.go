package main

import (
	"context"
	"log"
	"net/http"

	"trimly-platform/internal/auth"
	"trimly-platform/internal/config"
	"trimly-platform/internal/pkg/httputil"
	"trimly-platform/internal/pkg/mail"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	cfg := config.LoadConfig()

	// Connect to PostgreSQL database pool
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

	// Initialize Email Adapter
	mailAdapter := mail.NewMailHogAdapter(cfg.SMTPHost, cfg.SMTPPort)

	// Initialize Auth Module (Repository, Service, Handler)
	authRepo := auth.NewRepository(dbPool)
	authService := auth.NewService(authRepo, mailAdapter)
	authHandler := auth.NewHandler(authService)

	// HTTP Routes
	mux := http.NewServeMux()

	// Health Check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		httputil.RespondJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "trimly-platform",
		})
	})

	// Auth Endpoints
	mux.HandleFunc("POST /v1/auth/register", authHandler.Register)
	mux.HandleFunc("POST /v1/auth/verify-email", authHandler.VerifyEmail)
	mux.HandleFunc("POST /v1/auth/login", authHandler.Login)
	mux.HandleFunc("POST /v1/auth/logout", authHandler.Logout)

	// Protected Verification Test Endpoint
	mux.Handle("GET /v1/auth/me", authHandler.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(auth.UserContextKey).(*auth.User)
		httputil.RespondJSON(w, http.StatusOK, user)
	})))

	mux.Handle("GET /v1/test-verified-action", authHandler.AuthMiddleware(authHandler.RequireVerifiedEmailMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.RespondJSON(w, http.StatusOK, map[string]string{"message": "Action permitted for verified user"})
	}))))

	log.Printf("Trimly Platform API server running on port :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
