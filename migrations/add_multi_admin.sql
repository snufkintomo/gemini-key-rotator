-- Create admins table for multi-admin support
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT DEFAULT (datetime('now'))
);

-- Insert the initial super admin
INSERT OR IGNORE INTO admins (email, role) VALUES ('remus.to@gmail.com', 'super_admin');

-- Add owner_admin_id column to api_credentials
ALTER TABLE api_credentials ADD COLUMN owner_admin_id INTEGER REFERENCES admins(id);

-- Assign existing credentials to the super admin
UPDATE api_credentials SET owner_admin_id = (SELECT id FROM admins WHERE email = 'remus.to@gmail.com') WHERE owner_admin_id IS NULL;