CREATE TABLE auth_sessions (
                               id UUID PRIMARY KEY,

                               user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

                               access_token_hash TEXT NOT NULL UNIQUE,
                               refresh_token_hash TEXT NOT NULL UNIQUE,

                               access_expires_at TIMESTAMPTZ NOT NULL,
                               refresh_expires_at TIMESTAMPTZ NOT NULL,

                               created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                               updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

                               revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX idx_auth_sessions_user_id
    ON auth_sessions(user_id);

CREATE INDEX idx_auth_sessions_refresh_expires_at
    ON auth_sessions(refresh_expires_at);