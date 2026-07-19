-- Migration to add token tracking columns to api_key_usage table
ALTER TABLE api_key_usage ADD COLUMN prompt_tokens INTEGER DEFAULT 0;
ALTER TABLE api_key_usage ADD COLUMN completion_tokens INTEGER DEFAULT 0;
ALTER TABLE api_key_usage ADD COLUMN cached_tokens INTEGER DEFAULT 0;
