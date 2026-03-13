import sqlite3
import os

DATABASE = 'data/sangam.db'

def cleanup():
    if not os.path.exists(DATABASE):
        return
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Delete test accounts
    dummy_usernames = ['test', 'alice', 'modtest3']
    for username in dummy_usernames:
        # Get user id
        user = cursor.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            uid = user[0]
            # Delete related data (posts, comments, etc. to avoid orphans)
            cursor.execute('DELETE FROM posts WHERE user_id = ?', (uid,))
            cursor.execute('DELETE FROM post_comments WHERE user_id = ?', (uid,))
            cursor.execute('DELETE FROM friendships WHERE user_id1 = ? OR user_id2 = ?', (uid, uid))
            cursor.execute('DELETE FROM direct_messages WHERE sender_id = ? OR recipient_id = ?', (uid, uid))
            cursor.execute('DELETE FROM users WHERE id = ?', (uid,))
            print(f"Deleted user {username} (ID: {uid})")
            
    conn.commit()
    conn.close()

if __name__ == "__main__":
    cleanup()
