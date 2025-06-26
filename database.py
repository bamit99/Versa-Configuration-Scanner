import sqlite3
import os
from flask import current_app as app

DATABASE_FILE = 'scans.db'

def init_db():
    """Initializes the SQLite database and creates the scans table if it doesn't exist."""
    db_path = os.path.join(app.root_path, DATABASE_FILE)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            platform TEXT NOT NULL,
            status TEXT NOT NULL,
            report_name TEXT,
            error TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    app.logger.info(f"Database initialized at {db_path}")

def get_db_connection():
    """Establishes a connection to the database."""
    db_path = os.path.join(app.root_path, DATABASE_FILE)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row # This allows accessing columns by name
    return conn

def add_scan_record(scan_data):
    """Adds a new scan record to the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (id, filename, platform, status, report_name, error)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (scan_data['id'], scan_data['filename'], scan_data['platform'],
          scan_data['status'], scan_data.get('report_name'), scan_data.get('error')))
    conn.commit()
    conn.close()
    app.logger.info(f"Scan record added to DB: {scan_data['id']}")

def update_scan_record(scan_id, status, report_name=None, error=None):
    """Updates an existing scan record in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE scans
        SET status = ?, report_name = ?, error = ?
        WHERE id = ?
    ''', (status, report_name, error, scan_id))
    conn.commit()
    conn.close()
    app.logger.info(f"Scan record updated in DB: {scan_id} to status {status}")

def get_all_scans():
    """Retrieves all scan records from the database, ordered by timestamp."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans ORDER BY timestamp DESC')
    scans = cursor.fetchall()
    conn.close()
    return [dict(row) for row in scans] # Convert rows to dictionaries

def get_scan_by_id(scan_id):
    """Retrieves a single scan record by its ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    scan = cursor.fetchone()
    conn.close()
    return dict(scan) if scan else None
