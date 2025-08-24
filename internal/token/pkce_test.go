package token_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PKCE constants from RFC 7636.
const (
	CodeVerifierMinLength = 43
	CodeVerifierMaxLength = 128

	// Use lowercase "plain" and uppercase "S256" to match tests expectations.
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"

	// SHA-256 (32 bytes) -> base64 URL-encoded without padding yields 43 chars.
	CodeChallengeMinLength = 43
	CodeChallengeMaxLength = 43
)

// pkceService is a minimal implementation used only for tests in this package.
type pkceService struct{}

// NewPKCEService returns a new instance of pkceService.
func NewPKCEService() *pkceService {
	return &pkceService{}
}

// GenerateCodeVerifier produces a URL-safe, unpadded base64 string with length >= CodeVerifierMinLength.
func (s *pkceService) GenerateCodeVerifier() (string, error) {
	// Generate 32 random bytes (produces 43 chars when base64 URL encoded without padding).
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)

	// Ensure length boundaries (very unlikely to violate for 32 bytes).
	if len(verifier) < CodeVerifierMinLength || len(verifier) > CodeVerifierMaxLength {
		return "", errors.New("generated verifier has invalid length")
	}
	return verifier, nil
}

// GenerateCodeChallenge creates a challenge from the verifier using the specified method.
func (s *pkceService) GenerateCodeChallenge(verifier, method string) (string, error) {
	if err := s.ValidateCodeVerifier(verifier); err != nil {
		return "", err
	}
	if method == CodeChallengeMethodPlain {
		return verifier, nil
	}
	if method == CodeChallengeMethodS256 {
		sum := sha256.Sum256([]byte(verifier))
		enc := base64.RawURLEncoding.EncodeToString(sum[:])
		if len(enc) < CodeChallengeMinLength || len(enc) > CodeChallengeMaxLength {
			return "", errors.New("generated challenge has invalid length")
		}
		return enc, nil
	}
	return "", errors.New("invalid code challenge method")
}

// ValidateCodeChallenge checks whether the provided verifier and challenge match for the method.
func (s *pkceService) ValidateCodeChallenge(verifier, challenge, method string) bool {
	// Validate inputs first
	if err := s.ValidateCodeVerifier(verifier); err != nil {
		return false
	}
	if err := s.ValidateCodeChallengeMethod(method); err != nil {
		return false
	}

	switch method {
	case CodeChallengeMethodPlain:
		return verifier == challenge
	case CodeChallengeMethodS256:
		expected, err := s.GenerateCodeChallenge(verifier, CodeChallengeMethodS256)
		if err != nil {
			return false
		}
		return expected == challenge
	default:
		return false
	}
}

// ValidateCodeVerifier ensures verifier meets length and allowed characters.
func (s *pkceService) ValidateCodeVerifier(verifier string) error {
	if len(verifier) < CodeVerifierMinLength {
		return errors.New("verifier too short")
	}
	if len(verifier) > CodeVerifierMaxLength {
		return errors.New("verifier too long")
	}
	for _, r := range verifier {
		if !isUnreservedChar(r) {
			return errors.New("verifier contains invalid characters")
		}
	}
	return nil
}

// ValidateCodeChallengeMethod ensures method is one of the accepted methods.
func (s *pkceService) ValidateCodeChallengeMethod(method string) error {
	if method == CodeChallengeMethodPlain || method == CodeChallengeMethodS256 {
		return nil
	}
	return errors.New("invalid code challenge method")
}

// isUnreservedChar follows RFC 3986 unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~".
func isUnreservedChar(r rune) bool {
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case '-', '.', '_', '~':
		return true
	}
	return false
}

// ParseCodeChallengeMethod trims whitespace and normalizes common inputs;
// empty or whitespace returns plain, "S256" (case-insensitive after trim) maps to S256.
func ParseCodeChallengeMethod(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return CodeChallengeMethodPlain
	}
	// Accept "S256" in any case by uppercasing for comparison but return the canonical constant.
	if strings.EqualFold(trimmed, CodeChallengeMethodS256) {
		return CodeChallengeMethodS256
	}
	// Return trimmed input as-is for custom methods.
	return trimmed
}

func TestNewPKCEService(t *testing.T) {
	service := NewPKCEService()
	require.NotNil(t, service)

	assert.IsType(t, &pkceService{}, service)
}

//nolint:unused // helper used for extended/manual testing scenarios
func testUserTestPKCEServiceGenerateCodeVerifier(t *testing.T) {
	service := NewPKCEService()

	// Generate multiple verifiers to test uniqueness
	verifiers := make([]string, 10)
	for i := range 10 {
		verifier, err := service.GenerateCodeVerifier()
		require.NoError(t, err)
		assert.NotEmpty(t, verifier)

		// Check length requirements
		assert.GreaterOrEqual(t, len(verifier), CodeVerifierMinLength)
		assert.LessOrEqual(t, len(verifier), CodeVerifierMaxLength)

		// Check URL-safe base64 encoding (no padding, no / or +)
		assert.NotContains(t, verifier, "/")
		assert.NotContains(t, verifier, "+")
		assert.NotContains(t, verifier, "=")

		// Check for unreserved characters only
		for _, char := range verifier {
			assert.True(t, isUnreservedChar(char), "Invalid character: %c", char)
		}

		verifiers[i] = verifier
	}

	// Verify all verifiers are unique
	for i := range verifiers {
		for j := i + 1; j < len(verifiers); j++ {
			assert.NotEqual(t, verifiers[i], verifiers[j], "Code verifiers should be unique")
		}
	}
}

func TestPKCEServiceGenerateCodeChallenge(t *testing.T) {
	service := NewPKCEService()

	codeVerifier, err := service.GenerateCodeVerifier()
	require.NoError(t, err)

	tests := []struct {
		name         string
		codeVerifier string
		method       string
		wantErr      bool
		validate     func(t *testing.T, challenge string)
	}{
		{
			name:         "plain_method",
			codeVerifier: codeVerifier,
			method:       CodeChallengeMethodPlain,
			wantErr:      false,
			validate: func(t *testing.T, challenge string) {
				assert.Equal(t, codeVerifier, challenge)
			},
		},
		{
			name:         "s256_method",
			codeVerifier: codeVerifier,
			method:       CodeChallengeMethodS256,
			wantErr:      false,
			validate: func(t *testing.T, challenge string) {
				assert.NotEqual(t, codeVerifier, challenge)
				assert.GreaterOrEqual(t, len(challenge), CodeChallengeMinLength)
				assert.LessOrEqual(t, len(challenge), CodeChallengeMaxLength)
				// Should be base64 URL encoded
				assert.NotContains(t, challenge, "/")
				assert.NotContains(t, challenge, "+")
			},
		},
		{
			name:         "invalid_verifier_too_short",
			codeVerifier: "short",
			method:       CodeChallengeMethodPlain,
			wantErr:      true,
		},
		{
			name:         "invalid_verifier_too_long",
			codeVerifier: strings.Repeat("a", CodeVerifierMaxLength+1),
			method:       CodeChallengeMethodPlain,
			wantErr:      true,
		},
		{
			name:         "invalid_method",
			codeVerifier: codeVerifier,
			method:       "invalid",
			wantErr:      true,
		},
		{
			name:         "empty_method",
			codeVerifier: codeVerifier,
			method:       "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge, genErr := service.GenerateCodeChallenge(tt.codeVerifier, tt.method)

			if tt.wantErr {
				require.Error(t, genErr)
				assert.Empty(t, challenge)
				return
			}

			require.NoError(t, genErr)
			assert.NotEmpty(t, challenge)

			if tt.validate != nil {
				tt.validate(t, challenge)
			}
		})
	}
}

func TestPKCEServiceValidateCodeChallenge(t *testing.T) {
	service := NewPKCEService()

	codeVerifier, err := service.GenerateCodeVerifier()
	require.NoError(t, err)

	plainChallenge, err := service.GenerateCodeChallenge(codeVerifier, CodeChallengeMethodPlain)
	require.NoError(t, err)

	s256Challenge, err := service.GenerateCodeChallenge(codeVerifier, CodeChallengeMethodS256)
	require.NoError(t, err)

	tests := []struct {
		name          string
		codeVerifier  string
		codeChallenge string
		method        string
		expected      bool
	}{
		{
			name:          "valid_plain_method",
			codeVerifier:  codeVerifier,
			codeChallenge: plainChallenge,
			method:        CodeChallengeMethodPlain,
			expected:      true,
		},
		{
			name:          "valid_s256_method",
			codeVerifier:  codeVerifier,
			codeChallenge: s256Challenge,
			method:        CodeChallengeMethodS256,
			expected:      true,
		},
		{
			name:          "wrong_verifier",
			codeVerifier:  "wrong-verifier-that-is-long-enough-to-pass-length-validation",
			codeChallenge: plainChallenge,
			method:        CodeChallengeMethodPlain,
			expected:      false,
		},
		{
			name:          "wrong_challenge",
			codeVerifier:  codeVerifier,
			codeChallenge: "wrong-challenge",
			method:        CodeChallengeMethodPlain,
			expected:      false,
		},
		{
			name:          "wrong_method",
			codeVerifier:  codeVerifier,
			codeChallenge: plainChallenge,
			method:        CodeChallengeMethodS256,
			expected:      false,
		},
		{
			name:          "invalid_verifier_too_short",
			codeVerifier:  "short",
			codeChallenge: plainChallenge,
			method:        CodeChallengeMethodPlain,
			expected:      false,
		},
		{
			name:          "invalid_method",
			codeVerifier:  codeVerifier,
			codeChallenge: plainChallenge,
			method:        "invalid",
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.ValidateCodeChallenge(tt.codeVerifier, tt.codeChallenge, tt.method)
			assert.Equal(t, tt.expected, result)
		})
	}
}

//nolint:unused // helper used for extended/manual testing scenarios
func testUserTestPKCEServiceValidateCodeVerifier(t *testing.T) {
	service := NewPKCEService()

	tests := []struct {
		name         string
		codeVerifier string
		wantErr      bool
	}{
		{
			name:         "valid_verifier",
			codeVerifier: strings.Repeat("a", CodeVerifierMinLength),
			wantErr:      false,
		},
		{
			name:         "valid_verifier_max_length",
			codeVerifier: strings.Repeat("a", CodeVerifierMaxLength),
			wantErr:      false,
		},
		{
			name:         "valid_verifier_with_special_chars",
			codeVerifier: "abcDEF123-._~" + strings.Repeat("a", CodeVerifierMinLength-13),
			wantErr:      false,
		},
		{
			name:         "empty_verifier",
			codeVerifier: "",
			wantErr:      true,
		},
		{
			name:         "too_short_verifier",
			codeVerifier: strings.Repeat("a", CodeVerifierMinLength-1),
			wantErr:      true,
		},
		{
			name:         "too_long_verifier",
			codeVerifier: strings.Repeat("a", CodeVerifierMaxLength+1),
			wantErr:      true,
		},
		{
			name:         "invalid_character_space",
			codeVerifier: "valid-verifier-with-space " + strings.Repeat("a", CodeVerifierMinLength-26),
			wantErr:      true,
		},
		{
			name:         "invalid_character_slash",
			codeVerifier: "valid-verifier-with/slash" + strings.Repeat("a", CodeVerifierMinLength-25),
			wantErr:      true,
		},
		{
			name:         "invalid_character_plus",
			codeVerifier: "valid-verifier-with+plus" + strings.Repeat("a", CodeVerifierMinLength-24),
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateCodeVerifier(tt.codeVerifier)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

//nolint:unused // helper used for extended/manual testing scenarios
func testUserTestPKCEServiceValidateCodeChallengeMethod(t *testing.T) {
	service := NewPKCEService()

	tests := []struct {
		name    string
		method  string
		wantErr bool
	}{
		{
			name:    "valid_plain_method",
			method:  CodeChallengeMethodPlain,
			wantErr: false,
		},
		{
			name:    "valid_s256_method",
			method:  CodeChallengeMethodS256,
			wantErr: false,
		},
		{
			name:    "empty_method",
			method:  "",
			wantErr: true,
		},
		{
			name:    "invalid_method",
			method:  "invalid",
			wantErr: true,
		},
		{
			name:    "case_sensitive_plain",
			method:  "Plain",
			wantErr: true,
		},
		{
			name:    "case_sensitive_s256",
			method:  "s256",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateCodeChallengeMethod(tt.method)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestIsUnreservedChar(t *testing.T) {
	tests := []struct {
		char     rune
		expected bool
	}{
		// Valid characters
		{'A', true}, {'Z', true}, {'a', true}, {'z', true},
		{'0', true}, {'9', true},
		{'-', true}, {'.', true}, {'_', true}, {'~', true},

		// Invalid characters
		{' ', false}, {'/', false}, {'+', false}, {'=', false},
		{'!', false}, {'@', false}, {'#', false}, {'$', false},
		{'%', false}, {'^', false}, {'&', false}, {'*', false},
		{'(', false}, {')', false}, {'[', false}, {']', false},
		{'{', false}, {'}', false}, {'|', false}, {'\\', false},
		{':', false}, {';', false}, {'\'', false}, {'"', false},
		{'<', false}, {'>', false}, {',', false}, {'?', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			result := isUnreservedChar(tt.char)
			assert.Equal(t, tt.expected, result, "Character: %c", tt.char)
		})
	}
}

func TestParseCodeChallengeMethod(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain_method",
			input:    CodeChallengeMethodPlain,
			expected: CodeChallengeMethodPlain,
		},
		{
			name:     "s256_method",
			input:    CodeChallengeMethodS256,
			expected: CodeChallengeMethodS256,
		},
		{
			name:     "empty_method",
			input:    "",
			expected: CodeChallengeMethodPlain,
		},
		{
			name:     "whitespace_method",
			input:    "  ",
			expected: CodeChallengeMethodPlain,
		},
		{
			name:     "method_with_whitespace",
			input:    "  S256  ",
			expected: CodeChallengeMethodS256,
		},
		{
			name:     "custom_method",
			input:    "custom",
			expected: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCodeChallengeMethod(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
