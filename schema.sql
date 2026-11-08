CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  checked_in_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attendance_name ON attendance (name, checked_in_at);

CREATE TABLE IF NOT EXISTS users (
  name_key TEXT PRIMARY KEY,        -- lowercase name, so "Ana" and "ana" are the same person
  name TEXT NOT NULL,
  salt TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  failed INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT
);
