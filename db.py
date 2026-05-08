import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source    TEXT NOT NULL,
            level     TEXT NOT NULL,
            message   TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_event(timestamp, source, level, message):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO events (timestamp, source, level, message)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, source, level, message))
    conn.commit()
    conn.close()

def get_events(limit=1000):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT timestamp, source, level, message
        FROM events
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT level, COUNT(*) as count
        FROM events
        GROUP BY level
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows
