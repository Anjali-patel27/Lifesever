// db.js
const Database = require('better-sqlite3');
const db = new Database('lifesaver.db');

db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  public_json TEXT NOT NULL,
  private_cipher BLOB NOT NULL,
  private_iv BLOB NOT NULL,
  private_salt BLOB NOT NULL,
  private_tag BLOB NOT NULL,
  pwd_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`);

module.exports = db;
