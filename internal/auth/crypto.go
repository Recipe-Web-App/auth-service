// Package auth provides cryptographic utilities for OAuth2 client authentication.
// This file contains functions for secure client secret hashing and verification using bcrypt.
package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	// BcryptCost defines the cost factor for bcrypt hashing.
	// Cost of 12 provides a good balance between security and performance.
	// Each increment doubles the time required to hash, making brute-force attacks harder.
	BcryptCost = 12
)

// HashClientSecret generates a bcrypt hash of the provided client secret.
// The hash can be safely stored in the database and used for future verification.
//
// Parameters:
//   - secret: The plaintext client secret to hash
//
// Returns:
//   - string: The bcrypt hash of the secret
//   - error: Any error encountered during hashing
//
// Example:
//
//	hash, err := HashClientSecret("my-secret-key")
//	if err != nil {
//	    return err
//	}
//	// Store hash in database
func HashClientSecret(secret string) (string, error) {
	if secret == "" {
		return "", errors.New("client secret cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash client secret: %w", err)
	}

	return string(hash), nil
}

// VerifyClientSecret compares a plaintext secret against a bcrypt hash.
// This is used during client authentication to validate credentials.
//
// Parameters:
//   - hash: The bcrypt hash stored in the database
//   - secret: The plaintext secret to verify
//
// Returns:
//   - error: nil if the secret matches the hash, otherwise an error
//
// Example:
//
//	err := VerifyClientSecret(storedHash, providedSecret)
//	if err != nil {
//	    return fmt.Errorf("invalid client credentials")
//	}
func VerifyClientSecret(hash, secret string) error {
	if hash == "" {
		return errors.New("hash cannot be empty")
	}
	if secret == "" {
		return errors.New("secret cannot be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	if err != nil {
		// bcrypt.ErrMismatchedHashAndPassword is returned when password doesn't match
		return fmt.Errorf("client secret verification failed: %w", err)
	}

	return nil
}
