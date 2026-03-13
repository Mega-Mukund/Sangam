import sqlite3
import os

DATABASE = 'data/sangam.db'

def list_users():
    if not os.path.exists(DATABASE):
        print(f"Database {DATABASE} not found.")
        return
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    users = cursor.execute('SELECT id, username, display_name FROM users').fetchall()
    print("Users in database:")
    for user in users:
        print(f"ID: {user['id']}, Username: {user['username']}, Display Name: {user['display_name']}")
    
    conn.close()

if __name__ == "__main__":
    list_users()
