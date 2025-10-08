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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/auth"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/database"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/handlers"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/middleware"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/redis"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/startup"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/token"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/pkg/logger"
)

func main() {
	// Load .env.local file only in development (when GO_ENV is not set or set to "development")
	goEnv := os.Getenv("GO_ENV")
	if goEnv == "" || goEnv == "development" {
		if err := godotenv.Load(".env.local"); err != nil {
			// Only log if the error is not "file not found"
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: Error loading .env.local file: %v\n", err)
			}
		}
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger with enhanced dual-output support
	log := logger.NewWithConfig(&cfg.Logging)
	log.Info("Starting OAuth2 Authentication Service")
	log.WithFields(logrus.Fields{
		"version": "1.0.0",
		"port":    cfg.Server.Port,
		"host":    cfg.Server.Host,
		"tls":     cfg.IsTLSEnabled(),
	}).Info("Service configuration loaded")

	// Initialize dependencies
	store, dbMgr, authService, userService := initializeServices(cfg, log)
	defer closeStore(store, log)
	defer closeDatabase(dbMgr, log)

	// Initialize client registration service and register clients
	clientRegSvc := startup.NewClientRegistrationService(cfg, authService, log)
	if regErr := clientRegSvc.RegisterClients(context.Background()); regErr != nil {
		log.WithError(regErr).Error("Failed to register clients during startup")
		// Don't exit, continue with service startup
	}

	// Set up HTTP server
	server := setupServer(cfg, store, dbMgr, authService, userService, log)

	// Start and run server with graceful shutdown
	runServer(server, cfg, log)
}

func initializeServices(
	cfg *config.Config,
	log *logrus.Logger,
) (redis.Store, *database.Manager, auth.Service, auth.UserService) {
	// Initialize database manager (optional)
	dbMgr, dbErr := database.NewManager(cfg, log)
	if dbErr != nil {
		log.WithError(dbErr).Error("Failed to initialize database manager")
		dbMgr = nil
	}

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

		// Initialize user service with memory store and database manager
		userService := auth.NewUserService(cfg, memoryStore, jwtService, log, dbMgr)

		return memoryStore, dbMgr, authService, userService
	}

	log.Info("Successfully connected to Redis store")

	// Initialize token services
	jwtService := token.NewJWTService(&cfg.JWT)
	pkceService := token.NewPKCEService()

	// Initialize OAuth2 service with Redis store
	authService := auth.NewOAuth2Service(cfg, redisStore, jwtService, pkceService, log)

	// Initialize user service with Redis store and database manager
	userService := auth.NewUserService(cfg, redisStore, jwtService, log, dbMgr)

	return redisStore, dbMgr, authService, userService
}

func closeStore(store redis.Store, log *logrus.Logger) {
	if storeErr := store.Close(); storeErr != nil {
		log.WithError(storeErr).Error("Failed to close store connection")
	}
}

func closeDatabase(dbMgr *database.Manager, log *logrus.Logger) {
	if dbMgr != nil {
		dbMgr.Close()
		log.Info("Database connections closed")
	}
}

func setupServer(
	cfg *config.Config,
	store redis.Store,
	dbMgr *database.Manager,
	authService auth.Service,
	userService auth.UserService,
	log *logrus.Logger,
) *http.Server {
	// Initialize handlers
	oauth2Handler := handlers.NewOAuth2Handler(authService, cfg, log)
	healthHandler := handlers.NewHealthHandler(cfg, store, dbMgr, log)

	// Initialize token service for user auth handler
	jwtService := token.NewJWTService(&cfg.JWT)
	userAuthHandler := handlers.NewUserAuthHandler(userService, jwtService, cfg, log)

	// Initialize middleware
	middlewareStack := middleware.NewStack(cfg, store, log)

	// Set up routes
	router := mux.NewRouter()

	// API v1 router with /api/v1/auth prefix
	apiV1Router := router.PathPrefix("/api/v1/auth").Subrouter()

	// Register health routes directly on the subrouter
	apiV1Router.HandleFunc("/health", healthHandler.Health).Methods("GET")
	apiV1Router.HandleFunc("/health/live", healthHandler.Liveness).Methods("GET")
	apiV1Router.HandleFunc("/health/ready", healthHandler.Readiness).Methods("GET")
	apiV1Router.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// OAuth2 routes with full middleware stack
	oauth2Handler.RegisterRoutes(apiV1Router)

	// User authentication routes
	apiV1Router.HandleFunc("/user-management/auth/register", userAuthHandler.Register).Methods("POST")
	apiV1Router.HandleFunc("/user-management/auth/login", userAuthHandler.Login).Methods("POST")
	apiV1Router.HandleFunc("/user-management/auth/logout", userAuthHandler.Logout).Methods("POST")
	apiV1Router.HandleFunc("/user-management/auth/refresh", userAuthHandler.RefreshToken).Methods("POST")
	apiV1Router.HandleFunc("/user-management/auth/reset-password", userAuthHandler.RequestPasswordReset).Methods("POST")
	apiV1Router.HandleFunc("/user-management/auth/reset-password/confirm", userAuthHandler.ConfirmPasswordReset).
		Methods("POST")

	// Apply middleware to the entire router
	finalHandler := middlewareStack.Chain(
		router,
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
