-- XSS Lab schema
-- All queries against these tables use parameterized SQL (this is an XSS lab, not a SQLi lab).

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS progress;
DROP TABLE IF EXISTS profiles;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,      -- plaintext on purpose: this is a lab fixture, not a real credential
    role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE profiles (
    user_id INTEGER PRIMARY KEY,
    display_name TEXT NOT NULL,
    bio TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL,
    post_id INTEGER,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(post_id) REFERENCES posts(id)
);

CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    body TEXT NOT NULL,
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE progress (
    session_id TEXT NOT NULL,
    level TEXT NOT NULL,
    completed_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id, level)
);

-- Seed data
INSERT INTO users (username, password, role) VALUES ('alice', 'lab-password-1', 'user');
INSERT INTO users (username, password, role) VALUES ('admin', 'lab-password-admin', 'admin');

INSERT INTO profiles (user_id, display_name, bio) VALUES (1, 'Alice', 'I like hiking and Python.');
INSERT INTO profiles (user_id, display_name, bio) VALUES (2, 'Site Admin', 'Keeper of the dashboard.');

INSERT INTO posts (level, title, body) VALUES
    ('level2', 'Welcome to the Lab Blog', 'This is the first post. Feel free to leave a comment below.'),
    ('level8', 'Community Announcements', 'Reminder: be excellent to each other. The admin reviews new comments daily.');
