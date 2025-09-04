package models

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	minPasswordLength = 8
	maxPasswordLength = 128
	maxEmailLength    = 255
	maxFullNameLength = 255
	minUsernameLength = 3
	maxUsernameLength = 50
)

type User struct {
	UserID    uuid.UUID `json:"user_id"             redis:"user_id"`
	Username  string    `json:"username"            redis:"username"`
	Email     *string   `json:"email,omitempty"     redis:"email"`
	FullName  *string   `json:"full_name,omitempty" redis:"full_name"`
	Bio       *string   `json:"bio,omitempty"       redis:"bio"`
	IsActive  bool      `json:"is_active"           redis:"is_active"`
	CreatedAt time.Time `json:"created_at"          redis:"created_at"`
	UpdatedAt time.Time `json:"updated_at"          redis:"updated_at"`
}

type UserWithPassword struct {
	User

	PasswordHash string `json:"-" redis:"password_hash"`
}

type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken *string   `json:"refresh_token,omitempty"`
	TokenType    TokenType `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
}

type UserLoginRequest struct {
	Username *string `json:"username,omitempty"`
	Email    *string `json:"email,omitempty"`
	Password string  `json:"password"`
}

type UserRegistrationRequest struct {
	Username string  `json:"username"`
	Email    string  `json:"email"`
	Password string  `json:"password"`
	FullName *string `json:"full_name,omitempty"`
	Bio      *string `json:"bio,omitempty"`
}

type UserRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type UserPasswordResetRequest struct {
	Email string `json:"email"`
}

type UserPasswordResetConfirmRequest struct {
	ResetToken  string `json:"reset_token"`
	NewPassword string `json:"new_password"`
}

type UserLoginResponse struct {
	User  User  `json:"user"`
	Token Token `json:"token"`
}

type UserRegistrationResponse struct {
	User  User   `json:"user"`
	Token *Token `json:"token,omitempty"`
}

type UserLogoutResponse struct {
	Message            string `json:"message"`
	SessionInvalidated bool   `json:"session_invalidated"`
}

type UserRefreshResponse struct {
	Message string `json:"message"`
	Token   Token  `json:"token"`
}

type UserPasswordResetResponse struct {
	Message   string `json:"message"`
	EmailSent bool   `json:"email_sent"`
}

type UserPasswordResetConfirmResponse struct {
	Message         string `json:"message"`
	PasswordUpdated bool   `json:"password_updated"`
}

type PasswordResetToken struct {
	Token     string    `json:"token"      redis:"token"`
	UserID    uuid.UUID `json:"user_id"    redis:"user_id"`
	Email     string    `json:"email"      redis:"email"`
	ExpiresAt time.Time `json:"expires_at" redis:"expires_at"`
	CreatedAt time.Time `json:"created_at" redis:"created_at"`
	Used      bool      `json:"used"       redis:"used"`
}

func (req *UserLoginRequest) Validate() error {
	if req.Username == nil && req.Email == nil {
		return errors.New("either username or email must be provided")
	}
	if req.Username != nil && req.Email != nil {
		return errors.New("provide either username or email, not both")
	}
	if req.Password == "" {
		return errors.New("password cannot be empty")
	}

	if req.Username != nil {
		username := strings.TrimSpace(*req.Username)
		if username == "" {
			return errors.New("username cannot be empty")
		}
		*req.Username = strings.ToLower(username)
	}

	if req.Email != nil {
		email := strings.TrimSpace(*req.Email)
		if email == "" {
			return errors.New("email cannot be empty")
		}
		*req.Email = strings.ToLower(email)
	}

	return nil
}

func (req *UserRegistrationRequest) Validate() error {
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		return errors.New("username is required")
	}
	if len(req.Username) < minUsernameLength || len(req.Username) > maxUsernameLength {
		return errors.New("username must be between 3 and 50 characters long")
	}

	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !usernameRegex.MatchString(req.Username) {
		return errors.New("username must contain only letters, numbers, underscores, and hyphens")
	}
	req.Username = strings.ToLower(req.Username)

	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		return errors.New("email is required")
	}
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.Email) {
		return errors.New("invalid email format")
	}
	req.Email = strings.ToLower(req.Email)

	if err := ValidatePassword(req.Password); err != nil {
		return err
	}

	if req.FullName != nil {
		fullName := strings.TrimSpace(*req.FullName)
		if len(fullName) > maxFullNameLength {
			return errors.New("full name must be less than 255 characters")
		}
		if fullName == "" {
			req.FullName = nil
		} else {
			*req.FullName = fullName
		}
	}

	return nil
}

func (req *UserRefreshRequest) Validate() error {
	if req.RefreshToken == "" {
		return errors.New("refresh_token is required")
	}
	return nil
}

func (req *UserPasswordResetRequest) Validate() error {
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		return errors.New("email is required")
	}
	if len(req.Email) > maxEmailLength {
		return errors.New("email must be less than 255 characters")
	}
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.Email) {
		return errors.New("invalid email format")
	}
	req.Email = strings.ToLower(req.Email)
	return nil
}

func (req *UserPasswordResetConfirmRequest) Validate() error {
	if req.ResetToken == "" {
		return errors.New("reset_token is required")
	}
	if err := ValidatePassword(req.NewPassword); err != nil {
		return err
	}
	return nil
}

func ValidatePassword(password string) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", minPasswordLength)
	}
	if len(password) > maxPasswordLength {
		return fmt.Errorf("password must be less than %d characters long", maxPasswordLength)
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}

	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}

	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}

	return nil
}

func NewUser(username, email, fullName, bio string) *UserWithPassword {
	now := time.Now()
	user := &UserWithPassword{
		User: User{
			UserID:    uuid.New(),
			Username:  strings.ToLower(strings.TrimSpace(username)),
			IsActive:  true,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	if email != "" {
		emailLower := strings.ToLower(strings.TrimSpace(email))
		user.Email = &emailLower
	}

	if fullName != "" {
		fullNameTrimmed := strings.TrimSpace(fullName)
		user.FullName = &fullNameTrimmed
	}

	if bio != "" {
		bioTrimmed := strings.TrimSpace(bio)
		user.Bio = &bioTrimmed
	}

	return user
}

func NewPasswordResetToken(userID uuid.UUID, email string, expiry time.Duration) *PasswordResetToken {
	now := time.Now()
	return &PasswordResetToken{
		Token:     uuid.New().String(),
		UserID:    userID,
		Email:     strings.ToLower(strings.TrimSpace(email)),
		ExpiresAt: now.Add(expiry),
		CreatedAt: now,
		Used:      false,
	}
}

func (prt *PasswordResetToken) IsExpired() bool {
	return time.Now().After(prt.ExpiresAt)
}
