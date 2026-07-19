-- Add enable_logging column to api_credentials table
ALTER TABLE api_credentials ADD COLUMN enable_logging INTEGER DEFAULT 0;
