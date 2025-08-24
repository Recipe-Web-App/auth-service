// Package main provides the entry point for the OAuth2 authentication service.
// It initializes all dependencies, sets up HTTP routes with middleware,
// and starts the server with graceful shutdown support.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/auth"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/handlers"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/middleware"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/redis"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/token"
	"github.com/jsamuelsen/recipe-web-app/auth-service/pkg/logger"
)

func main() {
	// Load .env file only in development (when GO_ENV is not set or set to "development")
	goEnv := os.Getenv("GO_ENV")
	if goEnv == "" || goEnv == "development" {
		if err := godotenv.Load(); err != nil {
			// Only log if the error is not "file not found"
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: Error loading .env file: %v\n", err)
			}
		}
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output)
	log.Info("Starting OAuth2 Authentication Service")
	log.WithFields(logrus.Fields{
		"version": "1.0.0",
		"port":    cfg.Server.Port,
		"host":    cfg.Server.Host,
		"tls":     cfg.IsTLSEnabled(),
	}).Info("Service configuration loaded")

	// Initialize dependencies
	store, authService := initializeServices(cfg, log)
	defer closeStore(store, log)

	// Create sample client for testing
	createSampleClient(authService, log)

	// Set up HTTP server
	server := setupServer(cfg, store, authService, log)

	// Start and run server with graceful shutdown
	runServer(server, cfg, log)
}

func initializeServices(cfg *config.Config, log *logrus.Logger) (redis.Store, auth.Service) {
	// Try to initialize Redis store first
	redisStore, err := redis.NewClient(&cfg.Redis, log)
	if err != nil {
		log.WithError(err).Warn("Failed to connect to Redis, falling back to in-memory store")
		log.Warn("Note: In-memory store will not persist data between restarts")

		// Fall back to in-memory store
		memoryStore := redis.NewMemoryStore(log)

		// Initialize token services
		jwtService := token.NewJWTService(&cfg.JWT)
		pkceService := token.NewPKCEService()

		// Initialize OAuth2 service with memory store
		authService := auth.NewOAuth2Service(cfg, memoryStore, jwtService, pkceService, log)

		return memoryStore, authService
	}

	log.Info("Successfully connected to Redis store")

	// Initialize token services
	jwtService := token.NewJWTService(&cfg.JWT)
	pkceService := token.NewPKCEService()

	// Initialize OAuth2 service with Redis store
	authService := auth.NewOAuth2Service(cfg, redisStore, jwtService, pkceService, log)

	return redisStore, authService
}

func closeStore(store redis.Store, log *logrus.Logger) {
	if storeErr := store.Close(); storeErr != nil {
		log.WithError(storeErr).Error("Failed to close store connection")
	}
}

func createSampleClient(authService auth.Service, log *logrus.Logger) {
	ctx := context.Background()
	sampleClient, err := authService.RegisterClient(
		ctx,
		"Sample Client",
		[]string{"http://localhost:3000/callback", "http://localhost:8080/callback"},
		[]string{"openid", "profile", "email", "read", "write"},
		[]string{"authorization_code", "client_credentials", "refresh_token"},
	)
	if err != nil {
		log.WithError(err).Warn("Failed to create sample client")
	} else {
		log.WithFields(logrus.Fields{
			"client_id":     sampleClient.ID,
			"client_secret": sampleClient.Secret,
		}).Info("Sample client created for testing")
	}
}

func setupServer(cfg *config.Config, store redis.Store, authService auth.Service, log *logrus.Logger) *http.Server {
	// Initialize handlers
	oauth2Handler := handlers.NewOAuth2Handler(authService, cfg, log)
	healthHandler := handlers.NewHealthHandler(cfg, store, log)

	// Initialize middleware
	middlewareStack := middleware.NewStack(cfg, store, log)

	// Set up routes
	router := mux.NewRouter()

	// Health check routes (no middleware for basic functionality)
	healthMux := http.NewServeMux()
	healthHandler.RegisterRoutes(healthMux)
	router.PathPrefix("/health").Handler(healthMux)
	router.PathPrefix("/metrics").Handler(healthMux)

	// OAuth2 routes with full middleware stack
	oauth2Router := router.PathPrefix("/").Subrouter()
	oauth2Handler.RegisterRoutes(oauth2Router)

	// Apply middleware to OAuth2 routes
	finalHandler := middlewareStack.Chain(
		oauth2Router,
		middlewareStack.Recovery,
		middlewareStack.RequestLogger,
		middlewareStack.SecurityHeaders,
		middlewareStack.CORS,
		middlewareStack.RateLimit,
		middlewareStack.ContentType,
	)

	// Create HTTP server
	return &http.Server{
		Addr:         cfg.ServerAddr(),
		Handler:      finalHandler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}
}

func runServer(server *http.Server, cfg *config.Config, log *logrus.Logger) {
	// Start server in a goroutine
	go startServer(server, cfg, log)

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Create context with timeout for graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Attempt graceful shutdown
	if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
		log.WithError(shutdownErr).Error("Server forced to shutdown")
	} else {
		log.Info("Server exited gracefully")
	}
}

func startServer(server *http.Server, cfg *config.Config, log *logrus.Logger) {
	log.WithFields(logrus.Fields{
		"addr": server.Addr,
		"tls":  cfg.IsTLSEnabled(),
	}).Info("Starting HTTP server")

	var startErr error
	if cfg.IsTLSEnabled() {
		startErr = server.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
	} else {
		startErr = server.ListenAndServe()
	}

	if startErr != nil && startErr != http.ErrServerClosed {
		log.WithError(startErr).Fatal("Failed to start server")
	}
}
