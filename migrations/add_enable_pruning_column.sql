-- Migration: Add enable_pruning column to api_credentials
ALTER TABLE api_credentials ADD COLUMN enable_pruning INTEGER DEFAULT 1;
