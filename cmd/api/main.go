package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"kitchen-api/internal/auth"
	"kitchen-api/internal/database"
	"kitchen-api/internal/user"
)

func main() {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	db, err := database.NewPostgres(ctx, databaseURL)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}

	defer db.Close()

	userRepository := user.NewRepository(db)
	sessionRepository := auth.NewRepository(db)

	authService := auth.NewService(
		userRepository,
		sessionRepository,
	)

	authHandler := auth.NewHandler(authService)

	mux := http.NewServeMux()

	mux.HandleFunc(
		"GET /health",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			w.WriteHeader(http.StatusOK)

			_, _ = w.Write([]byte(`{
				"status": "ok",
				"database": "ok"
			}`))
		},
	)

	mux.HandleFunc(
		"POST /auth/register",
		authHandler.Register,
	)

	mux.HandleFunc(
		"POST /auth/login",
		authHandler.Login,
	)

	mux.HandleFunc(
		"POST /auth/refresh",
		authHandler.Refresh,
	)

	mux.HandleFunc(
		"POST /auth/logout",
		authHandler.Logout,
	)

	mux.HandleFunc(
		"GET /auth/me",
		authHandler.Me,
	)

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("API listening on :8080")

	if err := server.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}
