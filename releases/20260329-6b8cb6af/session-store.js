// VERSION: 0.2.0
'use strict';
const session = require('express-session');
const db = require('./db');

db.prepare('DELETE FROM sessions WHERE expires < ?').run(Math.floor(Date.now() / 1000));

class SqliteStore extends session.Store {
  get(sid, cb) {
    try {
      const row = db.prepare('SELECT data, expires FROM sessions WHERE sid=?').get(sid);
      if (!row) return cb(null, null);
      if (row.expires && row.expires < Math.floor(Date.now() / 1000)) {
        db.prepare('DELETE FROM sessions WHERE sid=?').run(sid);
        return cb(null, null);
      }
      cb(null, JSON.parse(row.data));
    } catch (e) { cb(e); }
  }
  set(sid, session, cb) {
    try {
      const expires = session.cookie && session.cookie.expires
        ? Math.floor(new Date(session.cookie.expires).getTime() / 1000)
        : Math.floor(Date.now() / 1000) + 86400 * 30;
      db.prepare('INSERT OR REPLACE INTO sessions (sid,data,expires) VALUES (?,?,?)').run(sid, JSON.stringify(session), expires);
      cb(null);
    } catch (e) { cb(e); }
  }
  destroy(sid, cb) {
    try { db.prepare('DELETE FROM sessions WHERE sid=?').run(sid); cb(null); } catch (e) { cb(e); }
  }
  touch(sid, session, cb) { this.set(sid, session, cb); }
}

module.exports = SqliteStore;
