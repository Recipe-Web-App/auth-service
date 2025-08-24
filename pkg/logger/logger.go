// Package logger provides structured logging configuration for the OAuth2 service
// with support for different log levels, formats, and output destinations.
package logger

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

const timestampFormat = "2006-01-02T15:04:05.000Z07:00"

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
