package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"kitchen-api/internal/user"
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 30 * 24 * time.Hour

	MinPasswordLength = 8
	MaxPasswordLength = 72
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("expired token")
	ErrInvalidInput       = errors.New("invalid input")
)

type Service struct {
	users    *user.Repository
	sessions *Repository
}

func NewService(
	users *user.Repository,
	sessions *Repository,
) *Service {
	return &Service{
		users:    users,
		sessions: sessions,
	}
}

type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresIn  int64
	RefreshExpiresIn int64
}

type RegisterResult struct {
	User   *user.User
	Tokens TokenPair
}

func (s *Service) Register(
	ctx context.Context,
	email string,
	password string,
) (*RegisterResult, error) {
	email = normalizeEmail(email)

	if err := validateEmail(email); err != nil {
		return nil, err
	}

	if err := validatePassword(password); err != nil {
		return nil, err
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	newUser, err := s.users.Create(
		ctx,
		email,
		string(passwordHash),
	)
	if err != nil {
		return nil, err
	}

	tokens, err := s.createSession(ctx, newUser.ID)
	if err != nil {
		return nil, err
	}

	return &RegisterResult{
		User:   newUser,
		Tokens: tokens,
	}, nil
}

func (s *Service) Login(
	ctx context.Context,
	email string,
	password string,
) (*RegisterResult, error) {
	email = normalizeEmail(email)

	currentUser, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}

		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(currentUser.PasswordHash),
		[]byte(password),
	); err != nil {
		return nil, ErrInvalidCredentials
	}

	tokens, err := s.createSession(ctx, currentUser.ID)
	if err != nil {
		return nil, err
	}

	return &RegisterResult{
		User:   currentUser,
		Tokens: tokens,
	}, nil
}

func (s *Service) Refresh(
	ctx context.Context,
	refreshToken string,
) (*TokenPair, error) {
	if refreshToken == "" {
		return nil, ErrInvalidToken
	}

	refreshHash := hashToken(refreshToken)

	session, err := s.sessions.FindByRefreshTokenHash(
		ctx,
		refreshHash,
	)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if session.RevokedAt != nil {
		return nil, ErrInvalidToken
	}

	if !time.Now().UTC().Before(session.RefreshExpiresAt) {
		return nil, ErrExpiredToken
	}

	newTokens, newSession, err := generateSession(session.UserID)
	if err != nil {
		return nil, err
	}

	if err := s.sessions.Rotate(
		ctx,
		session.ID,
		newSession,
	); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil, ErrInvalidToken
		}

		return nil, err
	}

	return &newTokens, nil
}

func (s *Service) Logout(
	ctx context.Context,
	accessToken string,
) error {
	if accessToken == "" {
		return nil
	}

	accessHash := hashToken(accessToken)

	session, err := s.sessions.FindByAccessTokenHash(
		ctx,
		accessHash,
	)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil
		}

		return err
	}

	if session.RevokedAt != nil {
		return nil
	}

	return s.sessions.Revoke(ctx, session.ID)
}

func (s *Service) Authenticate(
	ctx context.Context,
	accessToken string,
) (*user.User, error) {
	if accessToken == "" {
		return nil, ErrInvalidToken
	}

	accessHash := hashToken(accessToken)

	session, err := s.sessions.FindByAccessTokenHash(
		ctx,
		accessHash,
	)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if session.RevokedAt != nil {
		return nil, ErrInvalidToken
	}

	if !time.Now().UTC().Before(session.AccessExpiresAt) {
		return nil, ErrExpiredToken
	}

	currentUser, err := s.users.FindByID(
		ctx,
		session.UserID,
	)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return currentUser, nil
}

func (s *Service) createSession(
	ctx context.Context,
	userID int64,
) (TokenPair, error) {
	tokens, session, err := generateSession(userID)
	if err != nil {
		return TokenPair{}, err
	}

	if err := s.sessions.CreateSession(ctx, session); err != nil {
		return TokenPair{}, err
	}

	return tokens, nil
}

func generateSession(
	userID int64,
) (TokenPair, Session, error) {
	accessToken, err := generateToken()
	if err != nil {
		return TokenPair{}, Session{}, err
	}

	refreshToken, err := generateToken()
	if err != nil {
		return TokenPair{}, Session{}, err
	}

	now := time.Now().UTC()

	accessExpiresAt := now.Add(AccessTokenTTL)
	refreshExpiresAt := now.Add(RefreshTokenTTL)

	session := Session{
		ID:               uuid.New(),
		UserID:           userID,
		AccessTokenHash:  hashToken(accessToken),
		RefreshTokenHash: hashToken(refreshToken),
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}

	tokens := TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		AccessExpiresIn:  int64(AccessTokenTTL.Seconds()),
		RefreshExpiresIn: int64(RefreshTokenTTL.Seconds()),
	}

	return tokens, session, nil
}

func generateToken() (string, error) {
	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))

	return hex.EncodeToString(hash[:])
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: email is required", ErrInvalidInput)
	}

	if !strings.Contains(email, "@") {
		return fmt.Errorf("%w: invalid email", ErrInvalidInput)
	}

	if len(email) > 320 {
		return fmt.Errorf("%w: email is too long", ErrInvalidInput)
	}

	return nil
}

func validatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf(
			"%w: password must contain at least %d characters",
			ErrInvalidInput,
			MinPasswordLength,
		)
	}

	if len(password) > MaxPasswordLength {
		return fmt.Errorf(
			"%w: password must contain no more than %d characters",
			ErrInvalidInput,
			MaxPasswordLength,
		)
	}

	return nil
}
