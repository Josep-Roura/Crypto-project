from __future__ import annotations
import sqlite3, json, time
from typing import Optional, Tuple, List, Dict, Any
from pydantic import BaseModel
from cipherlab.core.config import DB_PATH

class User(BaseModel):
    id: int
    username: str
    pw_hash: str

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def init_db() -> None:
    conn = get_conn()
    stmts = [
        'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL);',
        'CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, name TEXT NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL, deleted_at INTEGER, FOREIGN KEY(owner_id) REFERENCES users(id));',
        'CREATE TABLE IF NOT EXISTS file_blobs (id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL, version INTEGER NOT NULL, manifest_json TEXT NOT NULL, ciphertext_path TEXT NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY(file_id) REFERENCES files(id), UNIQUE(file_id, version));',
        'CREATE TABLE IF NOT EXISTS file_acl (file_id INTEGER NOT NULL, user_id INTEGER NOT NULL, can_read INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(file_id, user_id), FOREIGN KEY(file_id) REFERENCES files(id), FOREIGN KEY(user_id) REFERENCES users(id));',
        'CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, file_id INTEGER, details_json TEXT);'
    ]
    for s in stmts: conn.execute(s)
    conn.commit(); conn.close()

def create_user(username: str, pw_hash: str) -> Tuple[bool, Optional[str]]:
    try:
        conn = get_conn()
        conn.execute('INSERT INTO users(username, pw_hash) VALUES(?,?)', (username, pw_hash))
        conn.commit(); conn.close()
        return True, None
    except sqlite3.IntegrityError:
        return False, 'El usuario ya existe'
    except Exception as e:
        return False, str(e)

def get_user_by_username(username: str) -> Optional[User]:
    conn = get_conn()
    cur = conn.execute('SELECT id, username, pw_hash FROM users WHERE username = ?', (username,))
    row = cur.fetchone(); conn.close()
    if row: return User(id=row[0], username=row[1], pw_hash=row[2])
    return None

# ---- Drive ----
def create_file(owner_id: int, name: str, size: int) -> int:
    conn = get_conn()
    now = int(time.time())
    cur = conn.execute('INSERT INTO files(owner_id, name, size, created_at) VALUES(?,?,?,?)',
                       (owner_id, name, size, now))
    fid = cur.lastrowid
    conn.execute('INSERT OR IGNORE INTO file_acl(file_id, user_id, can_read) VALUES(?,?,1)', (fid, owner_id))
    conn.commit(); conn.close()
    return fid

def add_file_blob(file_id: int, version: int, manifest_json: str, ciphertext_path: str) -> None:
    conn = get_conn()
    now = int(time.time())
    conn.execute('INSERT INTO file_blobs(file_id, version, manifest_json, ciphertext_path, created_at) VALUES(?,?,?,?,?)',
                 (file_id, version, manifest_json, ciphertext_path, now))
    conn.commit(); conn.close()

def list_files_for_user(user_id: int) -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.execute(
        'SELECT f.id, f.name, f.size, f.created_at FROM files f '
        'JOIN file_acl a ON a.file_id = f.id AND a.user_id = ? AND a.can_read = 1 '
        'WHERE f.deleted_at IS NULL ORDER BY f.created_at DESC', (user_id,)
    )
    rows = cur.fetchall(); conn.close()
    return [ {'id': r[0], 'name': r[1], 'size': r[2], 'created_at': r[3]} for r in rows ]

def get_latest_blob(file_id: int):
    conn = get_conn()
    cur = conn.execute('SELECT version, manifest_json, ciphertext_path FROM file_blobs WHERE file_id = ? ORDER BY version DESC LIMIT 1', (file_id,))
    row = cur.fetchone(); conn.close()
    return row

def add_acl(file_id: int, user_id: int) -> None:
    conn = get_conn()
    conn.execute('INSERT OR REPLACE INTO file_acl(file_id, user_id, can_read) VALUES(?,?,1)', (file_id, user_id))
    conn.commit(); conn.close()

def remove_acl(file_id: int, user_id: int) -> None:
    conn = get_conn()
    conn.execute('UPDATE file_acl SET can_read = 0 WHERE file_id = ? AND user_id = ?', (file_id, user_id))
    conn.commit(); conn.close()

def audit(actor: str, action: str, file_id: int = None, details: dict = None) -> None:
    conn = get_conn()
    conn.execute('INSERT INTO audit(ts, actor, action, file_id, details_json) VALUES(?,?,?,?,?)',
                 (int(time.time()), actor, action, file_id, json.dumps(details or {})))
    conn.commit(); conn.close()
