ALTER TABLE api_credentials ADD COLUMN oauth_credentials TEXT DEFAULT '';
ALTER TABLE api_credentials ADD COLUMN current_oauth_index INTEGER DEFAULT 0;
ALTER TABLE api_credentials ADD COLUMN oauth_key_states TEXT DEFAULT '[]';
