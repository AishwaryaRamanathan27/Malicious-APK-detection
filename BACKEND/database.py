import sqlite3
import time
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'apk_scanner.db')


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scanned_apks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash TEXT UNIQUE NOT NULL,
            file_name TEXT NOT NULL,
            package_name TEXT,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            result_json TEXT NOT NULL,
            scanned_at REAL NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_file_hash ON scanned_apks(file_hash)
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_risk_level ON scanned_apks(risk_level)
    ''')

    conn.commit()
    conn.close()
    print("✅ Database initialised at:", DB_PATH)


def save_apk_result(file_hash, file_name, package_name, risk_score, risk_level, result_json):
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT OR REPLACE INTO scanned_apks
            (file_hash, file_name, package_name, risk_score, risk_level, result_json, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (file_hash, file_name, package_name, risk_score, risk_level, result_json, time.time()))
        conn.commit()
    finally:
        conn.close()


def get_apk_by_hash(file_hash):
    conn = get_db_connection()
    try:
        row = conn.execute(
            'SELECT * FROM scanned_apks WHERE file_hash = ?', (file_hash,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_all_scans():
    conn = get_db_connection()
    try:
        rows = conn.execute('''
            SELECT id, file_hash, file_name, package_name,
                   risk_score, risk_level, scanned_at
            FROM scanned_apks
            ORDER BY scanned_at DESC
        ''').fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d['scanned_at_formatted'] = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(d['scanned_at'])
            )
            result.append(d)
        return result
    finally:
        conn.close()


def delete_scan(file_hash):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM scanned_apks WHERE file_hash = ?', (file_hash,))
        conn.commit()
    finally:
        conn.close()
