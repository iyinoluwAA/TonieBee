CREATE TABLE IF NOT EXISTS oauth_providers (
    id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- 'google', 'github', 'twitter'
    provider_user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS oauth_providers_user_id_idx ON oauth_providers(user_id);
CREATE INDEX IF NOT EXISTS oauth_providers_provider_idx ON oauth_providers(provider);
CREATE INDEX IF NOT EXISTS oauth_providers_email_idx ON oauth_providers(email);

