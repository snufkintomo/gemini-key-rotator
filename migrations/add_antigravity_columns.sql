ALTER TABLE api_credentials ADD COLUMN antigravity_credentials TEXT DEFAULT '';
ALTER TABLE api_credentials ADD COLUMN current_antigravity_index INTEGER DEFAULT 0;
ALTER TABLE api_credentials ADD COLUMN antigravity_key_states TEXT DEFAULT '[]';
