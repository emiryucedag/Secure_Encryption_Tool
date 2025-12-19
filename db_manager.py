import sqlite3
import logging

def init_db():
    conn = sqlite3.connect("secure_vault.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS secure_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_note(title, encrypted_data):
    conn = sqlite3.connect("secure_vault.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO secure_notes (title, encrypted_data) VALUES (?, ?)", (title, encrypted_data))
    conn.commit()
    conn.close()
    # LOG EKLENDİ
    logging.info(f"Not veritabanına kaydedildi: {title}")

def get_all_notes():
    conn = sqlite3.connect("secure_vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, title FROM secure_notes ORDER BY date DESC")
    notes = cursor.fetchall()
    conn.close()
    return notes

def get_note_content(note_id):
    conn = sqlite3.connect("secure_vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_data FROM secure_notes WHERE id = ?", (note_id,))
    res = cursor.fetchone()
    conn.close()
    return res[0] if res else None

def delete_note(note_id):
    try:
        conn = sqlite3.connect("secure_vault.db")
        cursor = conn.cursor()
        
        # 1. Silmeden önce notun başlığını sorgula
        cursor.execute("SELECT title FROM secure_notes WHERE id = ?", (note_id,))
        res = cursor.fetchone()
        note_title = res[0] if res else "Bilinmiyor"
        
        # 2. Silme işlemini gerçekleştir
        cursor.execute("DELETE FROM secure_notes WHERE id = ?", (note_id,))
        conn.commit()
        conn.close()
        
        # 3. Güncellenmiş detaylı log
        logging.info(f"Not veritabanından silindi - Başlık: {note_title} (ID: {note_id})")
        
    except Exception as e:
        logging.error(f"Veritabanı silme hatası (ID: {note_id}): {e}")