package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
)

const (
	healthCheckTimeout = 5 * time.Second
)

// ErrDatabaseUnavailable is returned when database operations are attempted while database is unavailable.
var ErrDatabaseUnavailable = errors.New("database is not available")

// Manager manages the PostgreSQL database connection pool and health monitoring.
type Manager struct {
	pool      *pgxpool.Pool
	config    *config.DatabaseConfig
	logger    *logrus.Logger
	available bool
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewManager creates a new database manager with connection pool and health monitoring.
// If database credentials are not configured, it returns a manager without connection.
func NewManager(cfg *config.Config, logger *logrus.Logger) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	manager := &Manager{
		config:    &cfg.PostgresDatabase,
		logger:    logger,
		available: false,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Only attempt connection if database is configured
	if cfg.IsPostgresDatabaseConfigured() {
		if err := manager.connect(); err != nil {
			logger.WithError(err).Warn("Failed to connect to PostgreSQL database on startup, will retry periodically")
		}

		// Start background health monitoring
		go manager.healthMonitor()
	} else {
		logger.Info("PostgreSQL database not configured, running without PostgreSQL")
	}

	return manager, nil
}

// connect establishes the database connection pool.
func (m *Manager) connect() error {
	dsn := m.buildDSN()

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return err
	}

	// Configure pool settings
	poolConfig.MaxConns = m.config.MaxConn
	poolConfig.MinConns = m.config.MinConn
	poolConfig.MaxConnLifetime = m.config.MaxConnLifetime
	poolConfig.MaxConnIdleTime = m.config.MaxConnIdleTime
	poolConfig.ConnConfig.ConnectTimeout = m.config.ConnectTimeout

	ctx, cancel := context.WithTimeout(m.ctx, m.config.ConnectTimeout)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return err
	}

	// Test the connection
	if pingErr := pool.Ping(ctx); pingErr != nil {
		pool.Close()
		return pingErr
	}

	m.mu.Lock()
	// Close old pool if exists
	if m.pool != nil {
		m.pool.Close()
	}
	m.pool = pool
	m.available = true
	m.mu.Unlock()

	m.logger.Info("Successfully connected to PostgreSQL database")
	return nil
}

// buildDSN constructs the PostgreSQL connection string.
func (m *Manager) buildDSN() string {
	return fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=%s search_path=%s",
		m.config.Host,
		strconv.Itoa(m.config.Port),
		m.config.Database,
		m.config.User,
		m.config.Password,
		m.config.SSLMode,
		m.config.Schema,
	)
}

// healthMonitor runs in a goroutine to periodically check database connectivity.
func (m *Manager) healthMonitor() {
	ticker := time.NewTicker(m.config.HealthCheckPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkHealth()
		}
	}
}

// checkHealth performs a health check on the database connection.
func (m *Manager) checkHealth() {
	m.mu.RLock()
	pool := m.pool
	wasAvailable := m.available
	m.mu.RUnlock()

	if pool == nil {
		// Try to reconnect if we don't have a pool
		if err := m.connect(); err != nil {
			m.mu.Lock()
			m.available = false
			m.mu.Unlock()

			if wasAvailable {
				m.logger.WithError(err).Warn("PostgreSQL database connection lost, attempting reconnection")
			}
		}
		return
	}

	ctx, cancel := context.WithTimeout(m.ctx, healthCheckTimeout)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		m.mu.Lock()
		m.available = false
		m.mu.Unlock()

		if wasAvailable {
			m.logger.WithError(err).Warn("PostgreSQL database health check failed, connection lost")
		}

		// Try to reconnect
		if reconnectErr := m.connect(); reconnectErr != nil {
			m.logger.WithError(reconnectErr).Debug("PostgreSQL reconnection attempt failed")
		}
	} else {
		m.mu.Lock()
		isAvailable := m.available
		m.available = true
		m.mu.Unlock()

		if !isAvailable {
			m.logger.Info("PostgreSQL database connection restored")
		}
	}
}

// IsAvailable returns true if the database is currently available.
func (m *Manager) IsAvailable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.available
}

// Pool returns the database connection pool. Returns nil if database is not available.
func (m *Manager) Pool() *pgxpool.Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.available {
		return m.pool
	}
	return nil
}

// Close closes the database connection pool and stops health monitoring.
func (m *Manager) Close() {
	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pool != nil {
		m.pool.Close()
		m.pool = nil
	}
	m.available = false
}

// Ping performs a health check on the database connection.
func (m *Manager) Ping(ctx context.Context) error {
	pool := m.Pool()
	if pool == nil {
		return ErrDatabaseUnavailable
	}
	return pool.Ping(ctx)
}
