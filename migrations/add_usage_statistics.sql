-- Migration to add usage statistics table with mode and model
CREATE TABLE IF NOT EXISTS api_key_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_key TEXT NOT NULL,
    key_type TEXT NOT NULL, -- 'api_key' or 'oauth'
    usage_date TEXT NOT NULL, -- YYYY-MM-DD
    mode TEXT NOT NULL DEFAULT 'unknown', -- 'openai', 'claude', 'google'
    model TEXT NOT NULL DEFAULT 'unknown',
    request_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    error_429_count INTEGER DEFAULT 0,
    user_access_token TEXT NOT NULL,
    UNIQUE(raw_key, usage_date, user_access_token, mode, model)
);

CREATE INDEX IF NOT EXISTS idx_usage_date ON api_key_usage(usage_date);
CREATE INDEX IF NOT EXISTS idx_user_token ON api_key_usage(user_access_token);
CREATE INDEX IF NOT EXISTS idx_mode_model ON api_key_usage(mode, model);
