-- SecureChat Pro Database Schema
-- Complete database schema with AI chat summarization support

-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_blocked INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Admins table
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Groups table
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    created_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES admins (id)
);

-- Group members table
CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT CHECK(role IN ('read_write', 'read_only')) DEFAULT 'read_write',
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE(group_id, user_id)
);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NULL,
    group_id INTEGER NULL,
    message_text TEXT,
    media_filename TEXT NULL,
    media_type TEXT NULL,
    message_type TEXT CHECK(message_type IN ('private', 'group')) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (recipient_id) REFERENCES users (id),
    FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
);

-- Chat summaries table (AI-powered summarization)
CREATE TABLE IF NOT EXISTS chat_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_type TEXT NOT NULL CHECK (chat_type IN ('private', 'group')),
    chat_id INTEGER NOT NULL,  -- user_id for private chats, group_id for group chats
    summary_text TEXT NOT NULL,
    message_count INTEGER NOT NULL,
    date_range_start TIMESTAMP NOT NULL,
    date_range_end TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER NOT NULL,  -- admin_id or user_id who generated the summary
    created_by_type TEXT NOT NULL CHECK (created_by_type IN ('admin', 'user'))
);

-- Indexes for better performance

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_blocked ON users(is_blocked);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- Admins table indexes
CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username);
CREATE INDEX IF NOT EXISTS idx_admins_created_at ON admins(created_at);

-- Groups table indexes
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name);
CREATE INDEX IF NOT EXISTS idx_groups_created_by ON groups(created_by);
CREATE INDEX IF NOT EXISTS idx_groups_created_at ON groups(created_at);

-- Group members table indexes
CREATE INDEX IF NOT EXISTS idx_group_members_group_id ON group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user_id ON group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_group_members_role ON group_members(role);
CREATE INDEX IF NOT EXISTS idx_group_members_added_at ON group_members(added_at);

-- Messages table indexes
CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_recipient_id ON messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_messages_group_id ON messages(group_id);
CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_messages_private_chat ON messages(sender_id, recipient_id, message_type);
CREATE INDEX IF NOT EXISTS idx_messages_group_chat ON messages(group_id, message_type);

-- Chat summaries table indexes
CREATE INDEX IF NOT EXISTS idx_chat_summaries_chat ON chat_summaries(chat_type, chat_id);
CREATE INDEX IF NOT EXISTS idx_chat_summaries_created_at ON chat_summaries(created_at);
CREATE INDEX IF NOT EXISTS idx_chat_summaries_created_by ON chat_summaries(created_by, created_by_type);
CREATE INDEX IF NOT EXISTS idx_chat_summaries_date_range ON chat_summaries(date_range_start, date_range_end);

-- Insert default admin account
-- Default password is 'admin123' - CHANGE THIS IMMEDIATELY IN PRODUCTION!
INSERT OR IGNORE INTO admins (username, password_hash) VALUES 
('admin', 'scrypt:32768:8:1$lxKnBWS3jk1QVGBV$46c2917e849c02f6a82d3a4a66e9c6b5cb0f30e52de23fb97b0d4b6b3e8b7d4e1a8f5c2d9e3b4a7c8f1d6e9b2c5a8f3e6d9c2b5a8e1f4d7c0b3a6e9');

-- Insert sample users for testing (optional - remove in production)
INSERT OR IGNORE INTO users (username, email, password_hash) VALUES 
('john_doe', 'john@example.com', 'scrypt:32768:8:1$lxKnBWS3jk1QVGBV$46c2917e849c02f6a82d3a4a66e9c6b5cb0f30e52de23fb97b0d4b6b3e8b7d4e1a8f5c2d9e3b4a7c8f1d6e9b2c5a8f3e6d9c2b5a8e1f4d7c0b3a6e9'),
('jane_smith', 'jane@example.com', 'scrypt:32768:8:1$lxKnBWS3jk1QVGBV$46c2917e849c02f6a82d3a4a66e9c6b5cb0f30e52de23fb97b0d4b6b3e8b7d4e1a8f5c2d9e3b4a7c8f1d6e9b2c5a8f3e6d9c2b5a8e1f4d7c0b3a6e9'),
('bob_wilson', 'bob@example.com', 'scrypt:32768:8:1$lxKnBWS3jk1QVGBV$46c2917e849c02f6a82d3a4a66e9c6b5cb0f30e52de23fb97b0d4b6b3e8b7d4e1a8f5c2d9e3b4a7c8f1d6e9b2c5a8f3e6d9c2b5a8e1f4d7c0b3a6e9'),
('alice_brown', 'alice@example.com', 'scrypt:32768:8:1$lxKnBWS3jk1QVGBV$46c2917e849c02f6a82d3a4a66e9c6b5cb0f30e52de23fb97b0d4b6b3e8b7d4e1a8f5c2d9e3b4a7c8f1d6e9b2c5a8f3e6d9c2b5a8e1f4d7c0b3a6e9');

-- Insert sample groups for testing (optional - remove in production)
INSERT OR IGNORE INTO groups (name, description, created_by) VALUES 
('General Discussion', 'Main chat room for general conversations', 1),
('Development Team', 'Chat room for development discussions', 1),
('Marketing Team', 'Marketing strategy and campaign discussions', 1),
('Support Team', 'Customer support coordination', 1);

-- Insert sample group memberships (optional - remove in production)
INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES 
(1, 1, 'read_write'),  -- john_doe in General Discussion
(1, 2, 'read_write'),  -- jane_smith in General Discussion
(1, 3, 'read_write'),  -- bob_wilson in General Discussion
(1, 4, 'read_write'),  -- alice_brown in General Discussion
(2, 1, 'read_write'),  -- john_doe in Development Team
(2, 3, 'read_write'),  -- bob_wilson in Development Team
(3, 2, 'read_write'),  -- jane_smith in Marketing Team
(3, 4, 'read_write'),  -- alice_brown in Marketing Team
(4, 2, 'read_write'),  -- jane_smith in Support Team
(4, 4, 'read_only');   -- alice_brown in Support Team (read-only)

-- Insert sample messages for testing (optional - remove in production)
INSERT OR IGNORE INTO messages (sender_id, recipient_id, message_text, message_type) VALUES 
(1, 2, 'Hey Jane, how are you doing today?', 'private'),
(2, 1, 'Hi John! I''m doing great, thanks for asking. How about you?', 'private'),
(1, 2, 'I''m good too! Working on the new chat features.', 'private');

INSERT OR IGNORE INTO messages (sender_id, group_id, message_text, message_type) VALUES 
(1, 1, 'Welcome everyone to our new chat system!', 'group'),
(2, 1, 'Thanks John! This looks amazing.', 'group'),
(3, 1, 'Excited to try out all the new features.', 'group'),
(4, 1, 'The AI summarization feature sounds really cool!', 'group'),
(1, 2, 'Development team meeting tomorrow at 10 AM.', 'group'),
(3, 2, 'I''ll be there. Should I prepare anything specific?', 'group'),
(1, 2, 'Just bring your current progress reports.', 'group');

-- Views for easier data access

-- View for user statistics
CREATE VIEW IF NOT EXISTS user_stats AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.is_blocked,
    u.created_at,
    COUNT(DISTINCT gm.group_id) as group_count,
    COUNT(DISTINCT m.id) as message_count,
    MAX(m.created_at) as last_message_at
FROM users u
LEFT JOIN group_members gm ON u.id = gm.user_id
LEFT JOIN messages m ON u.id = m.sender_id
GROUP BY u.id, u.username, u.email, u.is_blocked, u.created_at;

-- View for group statistics
CREATE VIEW IF NOT EXISTS group_stats AS
SELECT 
    g.id,
    g.name,
    g.description,
    g.created_at,
    COUNT(DISTINCT gm.user_id) as member_count,
    COUNT(DISTINCT m.id) as message_count,
    MAX(m.created_at) as last_message_at
FROM groups g
LEFT JOIN group_members gm ON g.id = gm.group_id
LEFT JOIN messages m ON g.id = m.group_id
GROUP BY g.id, g.name, g.description, g.created_at;

-- View for chat summary statistics
CREATE VIEW IF NOT EXISTS summary_stats AS
SELECT 
    chat_type,
    COUNT(*) as total_summaries,
    AVG(message_count) as avg_messages_per_summary,
    MIN(created_at) as first_summary_date,
    MAX(created_at) as latest_summary_date,
    COUNT(DISTINCT created_by) as unique_creators
FROM chat_summaries
GROUP BY chat_type;

-- Database version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

INSERT OR IGNORE INTO schema_version (version, description) VALUES 
(1, 'Initial schema with users, admins, groups, messages'),
(2, 'Added chat_summaries table for AI summarization'),
(3, 'Added comprehensive indexes for performance'),
(4, 'Added views for statistics and reporting');

-- Triggers for data integrity and automatic updates

-- Trigger to update group member count
CREATE TRIGGER IF NOT EXISTS update_group_member_count
AFTER INSERT ON group_members
BEGIN
    UPDATE groups 
    SET description = COALESCE(description, '') || ' [' || 
        (SELECT COUNT(*) FROM group_members WHERE group_id = NEW.group_id) || ' members]'
    WHERE id = NEW.group_id AND description NOT LIKE '%members]';
END;

-- Trigger to prevent self-messaging in private chats
CREATE TRIGGER IF NOT EXISTS prevent_self_message
BEFORE INSERT ON messages
WHEN NEW.message_type = 'private' AND NEW.sender_id = NEW.recipient_id
BEGIN
    SELECT RAISE(ABORT, 'Cannot send private message to yourself');
END;

-- Trigger to ensure either recipient_id or group_id is set
CREATE TRIGGER IF NOT EXISTS validate_message_target
BEFORE INSERT ON messages
BEGIN
    SELECT CASE
        WHEN NEW.message_type = 'private' AND NEW.recipient_id IS NULL THEN
            RAISE(ABORT, 'Private messages must have a recipient_id')
        WHEN NEW.message_type = 'group' AND NEW.group_id IS NULL THEN
            RAISE(ABORT, 'Group messages must have a group_id')
        WHEN NEW.message_type = 'private' AND NEW.group_id IS NOT NULL THEN
            RAISE(ABORT, 'Private messages cannot have a group_id')
        WHEN NEW.message_type = 'group' AND NEW.recipient_id IS NOT NULL THEN
            RAISE(ABORT, 'Group messages cannot have a recipient_id')
    END;
END;

-- Performance optimization: Analyze tables for query optimization
ANALYZE;

-- Final verification queries (commented out - uncomment for debugging)
/*
-- Verify all tables exist
.tables

-- Check table structures
.schema users
.schema admins
.schema groups
.schema group_members
.schema messages
.schema chat_summaries

-- Check sample data
SELECT 'Users:' as info, COUNT(*) as count FROM users
UNION ALL
SELECT 'Admins:', COUNT(*) FROM admins
UNION ALL
SELECT 'Groups:', COUNT(*) FROM groups
UNION ALL
SELECT 'Group Members:', COUNT(*) FROM group_members
UNION ALL
SELECT 'Messages:', COUNT(*) FROM messages
UNION ALL
SELECT 'Chat Summaries:', COUNT(*) FROM chat_summaries;
*/