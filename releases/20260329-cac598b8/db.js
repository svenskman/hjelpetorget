// VERSION: 0.2.0
'use strict';
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = process.env.DATA_DIR || './data';
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'hjelpetorget.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    email        TEXT UNIQUE NOT NULL,
    password     TEXT NOT NULL,
    name         TEXT NOT NULL,
    bio          TEXT DEFAULT '',
    avatar       TEXT DEFAULT NULL,
    location     TEXT DEFAULT '',
    phone        TEXT DEFAULT '',
    verified     INTEGER DEFAULT 0,
    verify_token TEXT DEFAULT NULL,
    reset_token  TEXT DEFAULT NULL,
    reset_expiry INTEGER DEFAULT NULL,
    role         TEXT DEFAULT 'user',
    created_at   INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS categories (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    slug  TEXT UNIQUE NOT NULL,
    name  TEXT NOT NULL,
    icon  TEXT NOT NULL,
    color TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS posts (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category_id INTEGER REFERENCES categories(id),
    type        TEXT NOT NULL CHECK(type IN ('offer','request')),
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    location    TEXT DEFAULT '',
    status      TEXT DEFAULT 'open' CHECK(status IN ('open','closed','done')),
    fylke       TEXT DEFAULT NULL,
    kommune     TEXT DEFAULT NULL,
    flagged     INTEGER DEFAULT 0,
    flag_reasons TEXT DEFAULT NULL,
    flag_reviewed INTEGER DEFAULT 0,
    email_token TEXT DEFAULT NULL,
    created_at  INTEGER DEFAULT (unixepoch()),
    updated_at  INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS post_images (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    ord     INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT PRIMARY KEY,
    post_id    TEXT REFERENCES posts(id) ON DELETE SET NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_read_at    INTEGER DEFAULT 0,
    PRIMARY KEY (conversation_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id              TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body            TEXT NOT NULL,
    created_at      INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS reviews (
    id          TEXT PRIMARY KEY,
    reviewer_id TEXT NOT NULL REFERENCES users(id),
    reviewee_id TEXT NOT NULL REFERENCES users(id),
    post_id     TEXT REFERENCES posts(id) ON DELETE SET NULL,
    rating      INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    comment     TEXT DEFAULT '',
    created_at  INTEGER DEFAULT (unixepoch()),
    UNIQUE(reviewer_id, reviewee_id, post_id)
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    payload    TEXT DEFAULT '{}',
    read       INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid     TEXT PRIMARY KEY,
    data    TEXT NOT NULL,
    expires INTEGER
  );

  CREATE TABLE IF NOT EXISTS skill_levels (
    user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    level        TEXT DEFAULT 'beginner' CHECK(level IN ('beginner','experienced','professional')),
    completed    INTEGER DEFAULT 0,
    avg_rating   REAL DEFAULT 0,
    promoted_at  INTEGER DEFAULT NULL,
    promoted_by  TEXT DEFAULT NULL
  );

  CREATE TABLE IF NOT EXISTS admin_requests (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason       TEXT DEFAULT '',
    status       TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','expired')),
    approved_by  TEXT DEFAULT NULL,
    approved_at  INTEGER DEFAULT NULL,
    expires_at   INTEGER DEFAULT NULL,
    created_at   INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS admin_log (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    user_name  TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT DEFAULT NULL,
    detail     TEXT DEFAULT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_admin_req_user   ON admin_requests(user_id);
  CREATE INDEX IF NOT EXISTS idx_admin_req_status ON admin_requests(status);
  CREATE INDEX IF NOT EXISTS idx_admin_log_user   ON admin_log(user_id);

  CREATE INDEX IF NOT EXISTS idx_posts_user    ON posts(user_id);
  CREATE INDEX IF NOT EXISTS idx_posts_status  ON posts(status);
  CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id);
  CREATE INDEX IF NOT EXISTS idx_notif_user    ON notifications(user_id, read);
`);

// Migrations for existing databases
const migrations = [
  "ALTER TABLE posts ADD COLUMN flagged INTEGER DEFAULT 0",
  "ALTER TABLE posts ADD COLUMN flag_reasons TEXT DEFAULT NULL",
  "ALTER TABLE posts ADD COLUMN flag_reviewed INTEGER DEFAULT 0",
  "ALTER TABLE posts ADD COLUMN email_token TEXT DEFAULT NULL",
  "ALTER TABLE posts ADD COLUMN fylke TEXT DEFAULT NULL",
  "ALTER TABLE posts ADD COLUMN skill_level TEXT DEFAULT 'any' CHECK(skill_level IN ('any','experienced','professional'))",
  "CREATE TABLE IF NOT EXISTS skill_levels (user_id TEXT PRIMARY KEY, level TEXT DEFAULT 'beginner', completed INTEGER DEFAULT 0, avg_rating REAL DEFAULT 0, promoted_at INTEGER DEFAULT NULL, promoted_by TEXT DEFAULT NULL)",
  "ALTER TABLE posts ADD COLUMN kommune TEXT DEFAULT NULL",
  "ALTER TABLE users ADD COLUMN admin_until INTEGER DEFAULT NULL",
  "CREATE INDEX IF NOT EXISTS idx_posts_flagged ON posts(flagged)",
  "CREATE TABLE IF NOT EXISTS admin_requests (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, reason TEXT DEFAULT '', status TEXT DEFAULT 'pending', approved_by TEXT DEFAULT NULL, approved_at INTEGER DEFAULT NULL, expires_at INTEGER DEFAULT NULL, created_at INTEGER DEFAULT (unixepoch()))",
  "CREATE TABLE IF NOT EXISTS admin_log (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, user_name TEXT NOT NULL, action TEXT NOT NULL, target TEXT DEFAULT NULL, detail TEXT DEFAULT NULL, created_at INTEGER DEFAULT (unixepoch()))",
];
for (const sql of migrations) {
  try { db.exec(sql); } catch {}
}

// Seed categories
const cats = [
  { slug:'hjem',      name:'Hjemmet',    icon:'🏠', color:'#E8936A' },
  { slug:'hage',      name:'Hagen',      icon:'🌱', color:'#6AAF7C' },
  { slug:'lekser',    name:'Lekser',     icon:'📚', color:'#7C9FE8' },
  { slug:'bil',       name:'Bil',        icon:'🚗', color:'#B07CE8' },
  { slug:'handyman',  name:'Handyman',   icon:'🔧', color:'#E8C06A' },
  { slug:'barn',      name:'Barnepass',  icon:'🧸', color:'#E87CA0' },
  { slug:'dyr',       name:'Dyr',        icon:'🐾', color:'#7CCFE8' },
  { slug:'mat',       name:'Mat',        icon:'🍳', color:'#E8A06A' },
  { slug:'transport', name:'Transport',  icon:'🚲', color:'#9CE87C' },
  { slug:'annet',     name:'Annet',      icon:'✨', color:'#AAAAAA' },
];
const ins = db.prepare('INSERT OR IGNORE INTO categories (slug,name,icon,color) VALUES (?,?,?,?)');
for (const c of cats) ins.run(c.slug, c.name, c.icon, c.color);

module.exports = db;
