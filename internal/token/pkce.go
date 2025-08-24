// Package token provides utilities for OAuth2 PKCE (Proof Key for Code Exchange)
// handling. It includes helpers to generate and validate PKCE code verifiers and
// code challenges using the plain and S256 methods defined in RFC 7636.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// PKCE-related constants. Lengths follow RFC 7636 recommendations.
const (
	// CodeChallengeMethodPlain represents the plain (no transformation)
	// challenge method.
	CodeChallengeMethodPlain = "plain"

	// CodeChallengeMethodS256 represents the SHA-256 based challenge method.
	CodeChallengeMethodS256 = "S256"

	// CodeVerifierMinLength is the minimum allowed length for a code verifier.
	CodeVerifierMinLength = 43

	// CodeVerifierMaxLength is the maximum allowed length for a code verifier.
	CodeVerifierMaxLength = 128

	// CodeChallengeMinLength is the minimum allowed length for a code challenge.
	CodeChallengeMinLength = 43

	// CodeChallengeMaxLength is the maximum allowed length for a code challenge.
	CodeChallengeMaxLength = 128

	// CodeEntropyBytes is the number of random bytes used to generate
	// a code verifier; kept separate from length constraints to avoid magic
	// numbers in the code.
	CodeEntropyBytes = 32
)

// PKCEService defines operations for generating and validating PKCE
// code verifiers and code challenges according to RFC 7636.
type PKCEService interface {
	// GenerateCodeVerifier returns a new, URL-safe, base64-encoded code
	// verifier suitable for use in an OAuth2 PKCE flow.
	GenerateCodeVerifier() (string, error)

	// GenerateCodeChallenge computes the code challenge for the provided
	// codeVerifier using the given method ("plain" or "S256").
	GenerateCodeChallenge(codeVerifier, method string) (string, error)

	// ValidateCodeChallenge returns true when the provided codeChallenge
	// matches the expected challenge for the given verifier and method.
	ValidateCodeChallenge(codeVerifier, codeChallenge, method string) bool

	// ValidateCodeVerifier verifies the verifier's length and allowed
	// character set.
	ValidateCodeVerifier(codeVerifier string) error

	// ValidateCodeChallengeMethod checks that the provided method is
	// supported ("plain" or "S256").
	ValidateCodeChallengeMethod(method string) error
}

type pkceService struct{}

// NewPKCEService constructs a PKCEService implementation.
func NewPKCEService() PKCEService {
	return &pkceService{}
}

// GenerateCodeVerifier generates a random, URL-safe, base64-encoded string
// suitable for use as a PKCE code verifier. The generated verifier is validated
// for minimum length; an error is returned if generation fails or the verifier
// does not meet requirements.
func (p *pkceService) GenerateCodeVerifier() (string, error) {
	bytes := make([]byte, CodeEntropyBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for code verifier: %w", err)
	}

	codeVerifier := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)

	if len(codeVerifier) < CodeVerifierMinLength {
		return "", errors.New("generated code verifier is too short")
	}

	return codeVerifier, nil
}

// GenerateCodeChallenge computes the code challenge for the provided
// codeVerifier using the requested method. The verifier and method are
// validated before computing the challenge.
func (p *pkceService) GenerateCodeChallenge(codeVerifier, method string) (string, error) {
	if err := p.ValidateCodeVerifier(codeVerifier); err != nil {
		return "", fmt.Errorf("invalid code verifier: %w", err)
	}

	if err := p.ValidateCodeChallengeMethod(method); err != nil {
		return "", fmt.Errorf("invalid code challenge method: %w", err)
	}

	switch method {
	case CodeChallengeMethodPlain:
		return codeVerifier, nil

	case CodeChallengeMethodS256:
		hash := sha256.Sum256([]byte(codeVerifier))
		codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
		return codeChallenge, nil

	default:
		return "", fmt.Errorf("unsupported code challenge method: %s", method)
	}
}

// ValidateCodeChallenge verifies that the provided codeChallenge is the
// expected challenge for the given verifier and method.
func (p *pkceService) ValidateCodeChallenge(codeVerifier, codeChallenge, method string) bool {
	if err := p.ValidateCodeVerifier(codeVerifier); err != nil {
		return false
	}

	if err := p.ValidateCodeChallengeMethod(method); err != nil {
		return false
	}

	expectedChallenge, err := p.GenerateCodeChallenge(codeVerifier, method)
	if err != nil {
		return false
	}

	return expectedChallenge == codeChallenge
}

// ValidateCodeVerifier checks that the code verifier is non-empty, meets
// configured length limits, and only contains unreserved characters as
// defined by RFC 7636 (ALPHA / DIGIT / "-" / "." / "_" / "~").
func (p *pkceService) ValidateCodeVerifier(codeVerifier string) error {
	if codeVerifier == "" {
		return errors.New("code verifier is empty")
	}

	if len(codeVerifier) < CodeVerifierMinLength {
		return fmt.Errorf("code verifier is too short (minimum %d characters)", CodeVerifierMinLength)
	}

	if len(codeVerifier) > CodeVerifierMaxLength {
		return fmt.Errorf("code verifier is too long (maximum %d characters)", CodeVerifierMaxLength)
	}

	for _, char := range codeVerifier {
		if !isUnreservedChar(char) {
			return fmt.Errorf("code verifier contains invalid character: %c", char)
		}
	}

	return nil
}

// ValidateCodeChallengeMethod ensures the provided method is supported.
func (p *pkceService) ValidateCodeChallengeMethod(method string) error {
	switch method {
	case CodeChallengeMethodPlain, CodeChallengeMethodS256:
		return nil
	case "":
		return errors.New("code challenge method is required")
	default:
		return fmt.Errorf("unsupported code challenge method: %s", method)
	}
}

// isUnreservedChar reports whether the rune is an unreserved character per
// RFC 7636 (allowed in code verifiers).
func isUnreservedChar(char rune) bool {
	return (char >= 'A' && char <= 'Z') ||
		(char >= 'a' && char <= 'z') ||
		(char >= '0' && char <= '9') ||
		char == '-' || char == '.' || char == '_' || char == '~'
}

// ParseCodeChallengeMethod trims whitespace and returns the default method
// (plain) when the input is empty. It does not perform strict validation of
// the returned method beyond defaulting.
func ParseCodeChallengeMethod(method string) string {
	method = strings.TrimSpace(method)
	if method == "" {
		return CodeChallengeMethodPlain
	}
	return method
}
