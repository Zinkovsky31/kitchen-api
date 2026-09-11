package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrSessionNotFound = errors.New("session not found")

type Session struct {
	ID               uuid.UUID
	UserID           int64
	AccessTokenHash  string
	RefreshTokenHash string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	RevokedAt        *time.Time
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

func (r *Repository) CreateSession(
	ctx context.Context,
	session Session,
) error {
	_, err := r.db.Exec(
		ctx,
		`
		INSERT INTO auth_sessions (
			id,
			user_id,
			access_token_hash,
			refresh_token_hash,
			access_expires_at,
			refresh_expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6)
		`,
		session.ID,
		session.UserID,
		session.AccessTokenHash,
		session.RefreshTokenHash,
		session.AccessExpiresAt,
		session.RefreshExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	return nil
}

func (r *Repository) FindByAccessTokenHash(
	ctx context.Context,
	tokenHash string,
) (*Session, error) {
	return r.findSession(
		ctx,
		`
		SELECT
			id,
			user_id,
			access_token_hash,
			refresh_token_hash,
			access_expires_at,
			refresh_expires_at,
			created_at,
			updated_at,
			revoked_at
		FROM auth_sessions
		WHERE access_token_hash = $1
		`,
		tokenHash,
	)
}

func (r *Repository) FindByRefreshTokenHash(
	ctx context.Context,
	tokenHash string,
) (*Session, error) {
	return r.findSession(
		ctx,
		`
		SELECT
			id,
			user_id,
			access_token_hash,
			refresh_token_hash,
			access_expires_at,
			refresh_expires_at,
			created_at,
			updated_at,
			revoked_at
		FROM auth_sessions
		WHERE refresh_token_hash = $1
		`,
		tokenHash,
	)
}

func (r *Repository) Revoke(
	ctx context.Context,
	sessionID uuid.UUID,
) error {
	now := time.Now().UTC()

	_, err := r.db.Exec(
		ctx,
		`
		UPDATE auth_sessions
		SET
			revoked_at = $1,
			updated_at = $1
		WHERE id = $2
		  AND revoked_at IS NULL
		`,
		now,
		sessionID,
	)

	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

func (r *Repository) Rotate(
	ctx context.Context,
	oldSessionID uuid.UUID,
	newSession Session,
) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin rotation transaction: %w", err)
	}

	defer tx.Rollback(ctx)

	now := time.Now().UTC()

	result, err := tx.Exec(
		ctx,
		`
		UPDATE auth_sessions
		SET
			revoked_at = $1,
			updated_at = $1
		WHERE id = $2
		  AND revoked_at IS NULL
		`,
		now,
		oldSessionID,
	)

	if err != nil {
		return fmt.Errorf("revoke old session: %w", err)
	}

	if result.RowsAffected() != 1 {
		return ErrSessionNotFound
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO auth_sessions (
			id,
			user_id,
			access_token_hash,
			refresh_token_hash,
			access_expires_at,
			refresh_expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6)
		`,
		newSession.ID,
		newSession.UserID,
		newSession.AccessTokenHash,
		newSession.RefreshTokenHash,
		newSession.AccessExpiresAt,
		newSession.RefreshExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("create rotated session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit rotation transaction: %w", err)
	}

	return nil
}

func (r *Repository) findSession(
	ctx context.Context,
	query string,
	arg string,
) (*Session, error) {
	var session Session

	err := r.db.QueryRow(
		ctx,
		query,
		arg,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenHash,
		&session.RefreshTokenHash,
		&session.AccessExpiresAt,
		&session.RefreshExpiresAt,
		&session.CreatedAt,
		&session.UpdatedAt,
		&session.RevokedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find session: %w", err)
	}

	return &session, nil
}
