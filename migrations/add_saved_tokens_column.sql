-- Migration to add saved_tokens column to api_key_usage table
ALTER TABLE api_key_usage ADD COLUMN saved_tokens INTEGER DEFAULT 0;
