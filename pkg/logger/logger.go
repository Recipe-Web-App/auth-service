// Package logger provides structured logging configuration for the OAuth2 service
// with support for different log levels, formats, and output destinations.
package logger

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
	"github.com/sirupsen/logrus"
)

const timestampFormat = "2006-01-02T15:04:05.000Z07:00"

// contextKey is an unexported type for keys stored in context to avoid collisions.
type contextKey string

// correlationIDKey is the context key used to store correlation IDs.
const correlationIDKey contextKey = "correlation_id"

// New creates a new configured logrus logger instance with the specified
// log level, format, and output destination.
func New(level, format, output string) *logrus.Logger {
	logger := logrus.New()

	// Set log level
	logLevel, err := logrus.ParseLevel(strings.ToLower(level))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)

	// Set format
	switch strings.ToLower(format) {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: timestampFormat,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: timestampFormat,
		})
	default:
		// Default to JSON for structured logging
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: timestampFormat,
		})
	}

	// Set output
	switch strings.ToLower(output) {
	case "stdout":
		logger.SetOutput(os.Stdout)
	case "stderr":
		logger.SetOutput(os.Stderr)
	case "":
		logger.SetOutput(os.Stdout)
	default:
		// Validate and clean the file path to prevent directory traversal attacks
		cleanPath := filepath.Clean(output)
		if strings.Contains(cleanPath, "..") {
			logger.SetOutput(os.Stdout)
			logger.Warn("Invalid log file path containing '..' detected, using stdout")
			return logger
		}

		// #nosec G304 -- Path is validated and cleaned above to prevent traversal attacks
		file, fileErr := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if fileErr != nil {
			logger.SetOutput(os.Stdout)
			logger.WithError(fileErr).Warn("Failed to open log file, using stdout")
		} else {
			logger.SetOutput(io.MultiWriter(os.Stdout, file))
		}
	}

	return logger
}

// NewWithConfig creates a new configured logrus logger instance using the complete LoggingConfig.
// Supports dual output with different formats for console and file logging.
func NewWithConfig(cfg *config.LoggingConfig) *logrus.Logger {
	if !cfg.EnableDualOutput {
		// Use the legacy single-output configuration
		return New(cfg.Level, cfg.Format, cfg.Output)
	}

	logger := logrus.New()

	// Set log level
	logLevel, err := logrus.ParseLevel(strings.ToLower(cfg.Level))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)

	// Set console output and formatter
	logger.SetOutput(os.Stdout)
	logger.SetFormatter(createFormatter(cfg.ConsoleFormat))

	// Add file output hook if file path is specified
	if cfg.FilePath == "" {
		return logger
	}

	cleanPath := filepath.Clean(cfg.FilePath)
	if strings.Contains(cleanPath, "..") {
		logger.Warn("Invalid log file path containing '..' detected, skipping file output")
		return logger
	}

	// #nosec G304 -- Path is validated and cleaned above to prevent traversal attacks
	file, fileErr := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if fileErr != nil {
		logger.WithError(fileErr).Warn("Failed to open log file, skipping file output")
		return logger
	}

	// Add hook for file output with different formatter
	fileHook := &FileHook{
		Writer:    file,
		Formatter: createFormatter(cfg.FileFormat),
	}
	logger.AddHook(fileHook)

	return logger
}

// createFormatter creates the appropriate logrus formatter based on the format string.
func createFormatter(format string) logrus.Formatter {
	switch strings.ToLower(format) {
	case "json":
		return &logrus.JSONFormatter{
			TimestampFormat: timestampFormat,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		}
	case "text":
		return &logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: timestampFormat,
			ForceColors:     true,
		}
	default:
		return &logrus.JSONFormatter{
			TimestampFormat: timestampFormat,
		}
	}
}

// FileHook implements logrus.Hook for file output with a different formatter.
type FileHook struct {
	Writer    io.Writer
	Formatter logrus.Formatter
}

// Levels returns the levels this hook should fire for.
func (hook *FileHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire is called when a log event is fired.
func (hook *FileHook) Fire(entry *logrus.Entry) error {
	if hook.Writer == nil || hook.Formatter == nil {
		return nil
	}

	// Format the entry using the file formatter
	formatted, err := hook.Formatter.Format(entry)
	if err != nil {
		return err
	}

	// Write to the file
	_, err = hook.Writer.Write(formatted)
	return err
}

// WithCorrelationID adds a correlation ID to log entries from context.
func WithCorrelationID(ctx context.Context, logger *logrus.Logger) *logrus.Entry {
	if correlationID := GetCorrelationID(ctx); correlationID != "" {
		return logger.WithField("correlation_id", correlationID)
	}
	return logrus.NewEntry(logger)
}

// GetCorrelationID extracts the correlation ID from context.
func GetCorrelationID(ctx context.Context) string {
	if correlationID, ok := ctx.Value(correlationIDKey).(string); ok {
		return correlationID
	}
	return ""
}

// SetCorrelationID stores a correlation ID in the context.
func SetCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, correlationIDKey, correlationID)
}
