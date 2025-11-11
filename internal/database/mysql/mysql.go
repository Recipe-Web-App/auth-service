package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	// Import MySQL driver for database/sql.
	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
)

const (
	healthCheckTimeout = 5 * time.Second
)

// ErrDatabaseUnavailable is returned when database operations are attempted while database is unavailable.
var ErrDatabaseUnavailable = errors.New("database is not available")

// Manager manages the MySQL database connection pool and health monitoring.
type Manager struct {
	db        *sql.DB
	config    *config.MySQLConfig
	logger    *logrus.Logger
	available bool
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewManager creates a new MySQL database manager with connection pool and health monitoring.
// If database credentials are not configured, it returns a manager without connection.
func NewManager(cfg *config.Config, logger *logrus.Logger) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	manager := &Manager{
		config:    &cfg.MySQLDatabase,
		logger:    logger,
		available: false,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Only attempt connection if database is configured
	if cfg.IsMySQLDatabaseConfigured() {
		if err := manager.connect(); err != nil {
			logger.WithError(err).Warn("Failed to connect to MySQL database on startup, will retry periodically")
		}

		// Start background health monitoring
		go manager.healthMonitor()
	} else {
		logger.Info("MySQL database not configured, running without MySQL")
	}

	return manager, nil
}

// connect establishes the database connection pool.
func (m *Manager) connect() error {
	dsn := m.buildDSN()

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}

	// Configure connection pool settings
	db.SetMaxOpenConns(m.config.MaxConn)
	db.SetMaxIdleConns(m.config.MinConn)
	db.SetConnMaxLifetime(m.config.MaxConnLifetime)
	db.SetConnMaxIdleTime(m.config.MaxConnIdleTime)

	// Test the connection with timeout
	ctx, cancel := context.WithTimeout(m.ctx, m.config.ConnectTimeout)
	defer cancel()

	if pingErr := db.PingContext(ctx); pingErr != nil {
		_ = db.Close() // Explicitly ignore close error on failed connection
		return pingErr
	}

	m.mu.Lock()
	// Close old connection if exists
	if m.db != nil {
		_ = m.db.Close() // Explicitly ignore close error on reconnection
	}
	m.db = db
	m.available = true
	m.mu.Unlock()

	m.logger.Info("Successfully connected to MySQL database")
	return nil
}

// buildDSN constructs the MySQL connection string.
func (m *Manager) buildDSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&timeout=%s",
		m.config.User,
		m.config.Password,
		m.config.Host,
		m.config.Port,
		m.config.Database,
		m.config.ConnectTimeout.String(),
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
	db := m.db
	wasAvailable := m.available
	m.mu.RUnlock()

	if db == nil {
		// Try to reconnect if we don't have a connection
		if err := m.connect(); err != nil {
			m.mu.Lock()
			m.available = false
			m.mu.Unlock()

			if wasAvailable {
				m.logger.WithError(err).Warn("MySQL database connection lost, attempting reconnection")
			}
		}
		return
	}

	ctx, cancel := context.WithTimeout(m.ctx, healthCheckTimeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		m.mu.Lock()
		m.available = false
		m.mu.Unlock()

		if wasAvailable {
			m.logger.WithError(err).Warn("MySQL database health check failed, connection lost")
		}

		// Try to reconnect
		if reconnectErr := m.connect(); reconnectErr != nil {
			m.logger.WithError(reconnectErr).Debug("MySQL reconnection attempt failed")
		}
	} else {
		m.mu.Lock()
		isAvailable := m.available
		m.available = true
		m.mu.Unlock()

		if !isAvailable {
			m.logger.Info("MySQL database connection restored")
		}
	}
}

// IsAvailable returns true if the database is currently available.
func (m *Manager) IsAvailable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.available
}

// DB returns the database connection. Returns nil if database is not available.
func (m *Manager) DB() *sql.DB {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.available {
		return m.db
	}
	return nil
}

// Close closes the database connection and stops health monitoring.
func (m *Manager) Close() {
	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db != nil {
		_ = m.db.Close() // Explicitly ignore close error during shutdown
		m.db = nil
	}
	m.available = false
}

// Ping performs a health check on the database connection.
func (m *Manager) Ping(ctx context.Context) error {
	db := m.DB()
	if db == nil {
		return ErrDatabaseUnavailable
	}
	return db.PingContext(ctx)
}
