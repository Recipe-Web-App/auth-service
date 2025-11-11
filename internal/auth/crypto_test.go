package auth_test

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/auth"
)

func TestHashClientSecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		secret    string
		wantError bool
	}{
		{
			name:      "valid secret",
			secret:    "my-super-secure-client-secret-12345",
			wantError: false,
		},
		{
			name:      "empty secret",
			secret:    "",
			wantError: true,
		},
		{
			name:      "short secret",
			secret:    "short",
			wantError: false, // Hashing works, but validation should fail elsewhere
		},
		{
			name:      "long secret (exceeds bcrypt 72 byte limit)",
			secret:    strings.Repeat("a", 200),
			wantError: true, // bcrypt has a 72 byte password limit
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hash, err := auth.HashClientSecret(tt.secret)

			if tt.wantError {
				if err == nil {
					t.Errorf("HashClientSecret() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("HashClientSecret() unexpected error: %v", err)
				return
			}

			// Verify hash is not empty
			if hash == "" {
				t.Error("HashClientSecret() returned empty hash")
			}

			// Verify hash is bcrypt format (starts with $2a$ or $2b$)
			if !strings.HasPrefix(hash, "$2") {
				t.Errorf("HashClientSecret() returned invalid bcrypt hash format: %s", hash)
			}

			// Verify hash can be used to verify the secret
			if verifyErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(tt.secret)); verifyErr != nil {
				t.Errorf("Generated hash doesn't verify against original secret: %v", verifyErr)
			}
		})
	}
}

func TestVerifyClientSecret(t *testing.T) {
	t.Parallel()
	validSecret := "my-super-secure-client-secret-12345" // pragma: allowlist secret
	validHash, err := bcrypt.GenerateFromPassword([]byte(validSecret), auth.BcryptCost)
	if err != nil {
		t.Fatalf("Failed to generate test hash: %v", err)
	}

	tests := []struct {
		name      string
		hash      string
		secret    string
		wantError bool
	}{
		{
			name:      "valid secret and hash",
			hash:      string(validHash),
			secret:    validSecret,
			wantError: false,
		},
		{
			name:      "invalid secret",
			hash:      string(validHash),
			secret:    "wrong-secret",
			wantError: true,
		},
		{
			name:      "empty hash",
			hash:      "",
			secret:    validSecret,
			wantError: true,
		},
		{
			name:      "empty secret",
			hash:      string(validHash),
			secret:    "",
			wantError: true,
		},
		{
			name:      "invalid hash format",
			hash:      "not-a-bcrypt-hash",
			secret:    validSecret,
			wantError: true,
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			verifyErr := auth.VerifyClientSecret(tt.hash, tt.secret)

			if tt.wantError {
				if verifyErr == nil {
					t.Error("VerifyClientSecret() expected error but got none")
				}
				return
			}

			if verifyErr != nil {
				t.Errorf("VerifyClientSecret() unexpected error: %v", verifyErr)
			}
		})
	}
}

func TestHashClientSecretConsistency(t *testing.T) {
	t.Parallel()
	secret := "test-secret-for-consistency" // pragma: allowlist secret

	// Hash the same secret twice
	hash1, err1 := auth.HashClientSecret(secret)
	hash2, err2 := auth.HashClientSecret(secret)

	if err1 != nil || err2 != nil {
		t.Fatalf("Unexpected errors: err1=%v, err2=%v", err1, err2)
	}

	// Hashes should be different (bcrypt includes salt)
	if hash1 == hash2 {
		t.Error("HashClientSecret() generated identical hashes (salt not working)")
	}

	// But both should verify the secret
	if verifyErr := auth.VerifyClientSecret(hash1, secret); verifyErr != nil {
		t.Errorf("Hash1 failed to verify: %v", verifyErr)
	}

	if verifyErr := auth.VerifyClientSecret(hash2, secret); verifyErr != nil {
		t.Errorf("Hash2 failed to verify: %v", verifyErr)
	}
}

func TestBcryptCost(t *testing.T) {
	t.Parallel()
	// Verify that the bcrypt cost is set to expected value
	expectedCost := 12
	if auth.BcryptCost != expectedCost {
		t.Errorf("BcryptCost = %d, want %d", auth.BcryptCost, expectedCost)
	}

	// Verify that generated hashes use the correct cost
	secret := "test-secret" // pragma: allowlist secret
	hash, err := auth.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("Failed to hash secret: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("Failed to get cost from hash: %v", err)
	}

	if cost != expectedCost {
		t.Errorf("Generated hash has cost %d, want %d", cost, expectedCost)
	}
}
