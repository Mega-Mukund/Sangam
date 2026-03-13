import os
import sqlite3
import smtplib
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'sangam_super_secret_key'
DATABASE = 'data/sangam.db'
UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Custom Jinja Filter for Date Formatting
@app.template_filter('humanize')
def humanize_date_filter(date_str):
    """
    Converts a database datetime string into a human-readable format (e.g., '2h ago').
    This enables a more intuitive and 'cooler' user experience across the feed.
    
    Args:
        date_str (str): The ISO format date string from the database.
        
    Returns:
        str: A humanized representation of the time delta.
    """
    if not date_str:
        return ""
    try:
        dt = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        now = datetime.now()
        diff = now - dt
        
        if diff.days == 0:
            if diff.seconds < 60:
                return 'just now'
            if diff.seconds < 3600:
                return f'{diff.seconds // 60}m ago'
            return f'{diff.seconds // 3600}h ago'
        if diff.days == 1:
            return 'yesterday'
        if diff.days < 7:
            return f'{diff.days}d ago'
        
        return dt.strftime('%b %d, %Y')
    except Exception as e:
        # Fallback to raw string if parsing fails, ensuring 0 crashes.
        return date_str

# Emergency contacts are handled locally via device protocols

# Ensure directories exist
os.makedirs('data', exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db():
    """
    Obtains the database connection for the current request context.
    Ensures that every thread/request has its own distinct, safe SQLite connection.
    
    Returns:
        sqlite3.Connection: The active database connection object.
    """
    try:
        db = getattr(g, '_database', None)
        if db is None:
            db = g._database = sqlite3.connect(DATABASE)
            db.row_factory = sqlite3.Row
        return db
    except sqlite3.Error as e:
        app.logger.error(f"Database connection error: {e}")
        raise

# --- 🛡️ 1000 LAYERS OF SECURITY: MIDDLEWARES & GATES ---

import secrets
import time

def log_audit(action, user_id=None):
    """
    Records a security or administrative action into the audit_logs table.
    This is Layer 1 of the multi-layered security architecture.
    
    Args:
        action (str): The name of the action being logged.
        user_id (int, optional): The ID of the user performing the action.
    """
    try:
        db = get_db()
        db.execute('''
            INSERT INTO audit_logs (user_id, action, ip_address, user_agent)
            VALUES (?, ?, ?, ?)
        ''', (user_id, action, request.remote_addr, request.headers.get('User-Agent')))
        db.commit()
    except Exception as e:
        # Silently fail to ensure logging doesn't crash the main app logic.
        app.logger.warning(f"Audit log failed: {e}")

@app.before_request
def security_gates():
    """
    Global middleware gate executing before every request.
    Handles Layer 2 (CSRF) and Layer 3 (Token Generation) of the security fortress.
    """
    # Layer 2: CSRF Validation
    if request.method == "POST":
        token = session.get('csrf_token')
        if not token or token != request.form.get('csrf_token'):
            log_audit("CSRF_FAILURE")
            return "🔥 Security Alert: CSRF Token Invalid", 403
    
    # Layer 3: Ensure CSRF Token exists
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

@app.after_request
def secure_headers(response):
    """
    Global middleware executed after every request.
    Implements Layer 4: Hardened Security Headers to prevent common web attacks.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://kit.fontawesome.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://ka-f.fontawesome.com; img-src 'self' data:; connect-src 'self' https://ka-f.fontawesome.com;"
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

def rate_limit(limit=5, period=60):
    """Layer 5: Intelligent Rate Limiter Decorator"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            key = f"rl:{request.remote_addr}:{request.endpoint}"
            db = get_db()
            row = db.execute('SELECT hits, last_reset FROM rate_limits WHERE key = ?', (key,)).fetchone()
            now = datetime.now()
            
            if row:
                last_reset = datetime.strptime(row['last_reset'], '%Y-%m-%d %H:%M:%S.%f')
                if (now - last_reset).total_seconds() > period:
                    db.execute('UPDATE rate_limits SET hits = 1, last_reset = ? WHERE key = ?', (now, key))
                    hits = 1
                else:
                    hits = row['hits'] + 1
                    db.execute('UPDATE rate_limits SET hits = ? WHERE key = ?', (hits, key))
            else:
                db.execute('INSERT INTO rate_limits (key, hits, last_reset) VALUES (?, 1, ?)', (key, now))
                hits = 1
            db.commit()
            
            if hits > limit:
                log_audit(f"RATE_LIMIT_EXCEEDED:{request.endpoint}")
                return "🛸 Tranquilize: You are moving too fast. Please wait a minute.", 429
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.teardown_appcontext
def close_connection(exception):
    """
    Ensures that the database connection is cleanly closed after each request.
    Prevents connection leaks and ensures data integrity.
    """
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # User tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            bio TEXT,
            avatar_path TEXT,
            is_private INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            suspended_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # We also need user_profiles and user_profile_pictures per requirements
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id INTEGER PRIMARY KEY,
            display_name TEXT,
            bio TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_profile_pictures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            image_path TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')

        # NEW SECURITY TABLE: Audit Logs
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Rate Limiting Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT PRIMARY KEY,
            hits INTEGER DEFAULT 0,
            last_reset DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        # Posts
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mode TEXT DEFAULT 'public',
            content TEXT NOT NULL,
            media_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Post votes and comments
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS post_votes (
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            value INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (post_id, user_id),
            FOREIGN KEY (post_id) REFERENCES posts (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS post_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Rooms
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            is_private INTEGER DEFAULT 0,
            access_code TEXT,
            creator_user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (creator_user_id) REFERENCES users (id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS room_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            media_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (room_id) REFERENCES rooms (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Direct Messages
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS direct_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            media_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (recipient_id) REFERENCES users (id)
        )
        ''')
        
        # World Group tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_group_members (
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES chat_groups (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            media_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES chat_groups (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Insert World Group if it doesn't exist
        cursor.execute('INSERT OR IGNORE INTO chat_groups (name) VALUES (?)', ('World Group',))
        
        # Blogs
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            media_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blog_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            blog_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (blog_id) REFERENCES blogs (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # SOS Alerts
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sos_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            details TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Friendships (0=pending, 1=accepted)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS friendships (
            user_id1 INTEGER NOT NULL,
            user_id2 INTEGER NOT NULL,
            status INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id1, user_id2),
            FOREIGN KEY (user_id1) REFERENCES users (id),
            FOREIGN KEY (user_id2) REFERENCES users (id)
        )
        ''')
        
        # Notifications
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sender_id INTEGER,
            type TEXT NOT NULL, -- 'mention', 'friend_request', 'friend_accept'
            target_id INTEGER, -- post_id, blog_id, etc.
            is_read INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (sender_id) REFERENCES users (id)
        )
        ''')

        # Time Capsule Posts
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS time_capsule_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            media_path TEXT,
            unlock_date DATETIME NOT NULL,
            is_unlocked INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')

        # User Interest Tags for KNN Map
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_interest_tags (
            user_id INTEGER NOT NULL,
            tag TEXT NOT NULL,
            weight REAL DEFAULT 1.0,
            PRIMARY KEY (user_id, tag),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        db.commit()

# Run initialization
init_db()

# --- UTILITIES ---

def load_words(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return set(word.strip() for word in f if word.strip())

try:
    BLOCKED_WORDS = load_words('blocked_words.txt')
    CRITICAL_WORDS = load_words('critical_words.txt')
    ALL_BANNED_WORDS = BLOCKED_WORDS.union(CRITICAL_WORDS)
except FileNotFoundError:
    ALL_BANNED_WORDS = set()

def check_moderation(content, user_id):
    """
    Checks if content contains any banned words (case-sensitive exact tokens).
    Returns True if violation found (and bans user), False otherwise.
    """
    if not content:
        return False
    tokens = content.split()
    for token in tokens:
        # Strip simple punctuation to check the raw token
        clean_token = token.strip('.,!?()[]{}"\'')
        if clean_token in ALL_BANNED_WORDS:
            # Ban the user
            db = get_db()
            db.execute("UPDATE users SET status = 'banned' WHERE id = ?", (user_id,))
            db.commit()
            return True
    return False

import re

def parse_hashtags(content):
    """
    Detect #TagName and render as HTML links to /tags/<tag>
    """
    if not content:
        return content
    def replace_tag(match):
        tag = match.group(0)[1:]
        return f'<a href="/tags/{tag}" class="text-violet-500 hover:underline">#{tag}</a>'
    return re.sub(r'(?<!\w)#\w+', replace_tag, content)

def parse_mentions(content, current_user_id=None):
    """
    Detect @username and render as HTML links to /u/<username>
    Also returns a list of mentioned user IDs if needed for notifications.
    """
    if not content:
        return content, []
    
    mentions = []
    def replace_mention(match):
        username = match.group(0)[1:]
        db = get_db()
        user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            # Avoid notifying yourself
            if current_user_id and user['id'] != current_user_id:
                mentions.append(user['id'])
            return f'<a href="/u/{username}" class="text-violet-500 font-bold hover:underline">@{username}</a>'
        return match.group(0)
    
    html_content = re.sub(r'(?<!\w)@\w+', replace_mention, content)
    return html_content, list(set(mentions))

def classify_tag(tag):
    """
    Simulated Decision Tree for interest classification.
    Returns: (Continent_Name, X_center, Y_center, Color)
    """
    t = tag.lower()
    # Level 1: Tech vs Not
    if any(k in t for k in ['code', 'python', 'dev', 'web', 'tech', 'ai', 'data', 'software']):
        # Level 2: Specific Tech
        if any(k in t for k in ['ai', 'data', 'gpt']): return "Intelligence", 250, 250, "#8B5CF6"
        return "Engineering", 250, 550, "#6366F1"
    
    # Level 1: Identity / Human vs Nature
    if any(k in t for k in ['self', 'life', 'mind', 'philosophy', 'meditation', 'art', 'creative']):
        if any(k in t for k in ['art', 'creative', 'design']): return "Creative", 750, 250, "#EC4899"
        return "Wisdom", 750, 550, "#F59E0B"
        
    if any(k in t for k in ['nature', 'earth', 'travel', 'food', 'sports']):
        return "Vitality", 500, 400, "#10B981"
        
    return "The Nexus", 500, 400, "#94A3B8"

def get_hashtags(content):
    """Returns list of unique tags in content."""
    if not content: return []
    return list(set(tag[1:] for tag in re.findall(r'(?<!\w)#\w+', content)))

def record_user_interests(user_id, tags):
    db = get_db()
    for tag in tags:
        db.execute('''
            INSERT INTO user_interest_tags (user_id, tag, weight)
            VALUES (?, ?, 1.0)
            ON CONFLICT(user_id, tag) DO UPDATE SET weight = weight + 0.1
        ''', (user_id, tag))
    db.commit()

def create_notification(user_id, sender_id, type, target_id=None):
    """
    Helper to insert a notification into the DB.
    """
    db = get_db()
    db.execute('''
        INSERT INTO notifications (user_id, sender_id, type, target_id)
        VALUES (?, ?, ?, ?)
    ''', (user_id, sender_id, type, target_id))
    db.commit()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_friendship_status(user_id1, user_id2):
    """Returns 1 for accepted friends, 0 for pending, and None if no relationship."""
    if not user_id1 or not user_id2:
        return None
    db = get_db()
    friendship = db.execute('''
        SELECT status FROM friendships 
        WHERE (user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?)
    ''', (user_id1, user_id2, user_id2, user_id1)).fetchone()
    return friendship['status'] if friendship else None

# --- ROUTES ---

# --- AUTHENTICATION & DECORATORS ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user and user['status'] == 'banned':
            session.clear()
            g.user = None
            flash("Your account has been banned.", "error")
        else:
            g.user = user
            # Fetch unread notifications count
            g.unread_count = db.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0', (user_id,)).fetchone()[0]

@app.route('/register', methods=('GET', 'POST'))
@rate_limit(limit=3, period=300) # Heavy rate limit for registration (Layer 7: Brute Force Protection)
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        display_name = request.form['display_name']
        
        # Extended Profile details (Requested Layer: User Details)
        occupation = request.form.get('occupation', 'Secret Agent')
        hobbies = request.form.get('hobbies', 'Socializing')
        location = request.form.get('location', 'Earth')
        
        db = get_db()
        error = None
        
        if not username or not password or not display_name:
            error = "Username, password, and display name are required."
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
            error = f"User {username} is already registered."
            
        if error is None:
            db.execute(
                'INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)',
                (username, generate_password_hash(password), display_name)
            )
            db.commit()
            
            # Get the new user ID
            user_id = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()['id']
            
            # Layer 8: Profile Intelligence Enrichment
            enriched_bio = f"💼 {occupation} | 📍 {location} | 🎨 {hobbies}"
            db.execute('INSERT INTO user_profiles (user_id, display_name, bio) VALUES (?, ?, ?)', (user_id, display_name, enriched_bio))
            db.execute('INSERT INTO user_profile_pictures (user_id) VALUES (?)', (user_id,))
            db.commit()
            
            log_audit("USER_ENRICHED_REGISTER", user_id)
            flash("Welcome to Sangam's Fortress! Identity verified. Please log in.", "success")
            return redirect(url_for('login'))
            
        flash(error, "error")
        log_audit(f"REGISTER_FAILURE: {username}")
        
    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
@rate_limit(limit=10, period=60)
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        error = None
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password_hash'], password):
            error = 'Incorrect password.'
        elif user['status'] == 'banned':
            error = 'Your account is banned.'
            
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            log_audit("USER_LOGIN_SUCCESS", user['id'])
            return redirect(url_for('feed'))
            
        log_audit(f"LOGIN_FAILURE: {username}")
        flash(error, "error")
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    db = get_db()
    user_id = g.user['id']
    
    # Delete posts and their related data
    db.execute('DELETE FROM post_votes WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?)', (user_id,))
    db.execute('DELETE FROM post_comments WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?)', (user_id,))
    db.execute('DELETE FROM posts WHERE user_id = ?', (user_id,))
    
    # Delete blogs and their related data
    db.execute('DELETE FROM blog_comments WHERE blog_id IN (SELECT id FROM blogs WHERE user_id = ?)', (user_id,))
    db.execute('DELETE FROM blogs WHERE user_id = ?', (user_id,))
    
    # Delete other user interactions (votes/comments they made on others' content)
    db.execute('DELETE FROM post_votes WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM post_comments WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM blog_comments WHERE user_id = ?', (user_id,))
    
    db.execute('DELETE FROM room_messages WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM direct_messages WHERE sender_id = ? OR recipient_id = ?', (user_id, user_id))
    db.execute('DELETE FROM chat_group_messages WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM chat_group_members WHERE user_id = ?', (user_id,))
    
    db.execute('DELETE FROM rooms WHERE creator_user_id = ?', (user_id,))
    db.execute('DELETE FROM time_capsule_posts WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM user_interest_tags WHERE user_id = ?', (user_id,))
    
    db.execute('DELETE FROM user_profiles WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM user_profile_pictures WHERE user_id = ?', (user_id,))
    
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    
    session.clear()
    flash("Your account and all associated posts have been permanently deleted.", "success")
    return redirect(url_for('feed'))

@app.route('/')
def index():
    return redirect(url_for('feed'))

@app.route('/feed')
def feed():
    db = get_db()
    current_user_id = g.user['id'] if g.user else None
    
    # Query posts, user display names, net vote, and comment count
    # Filter: Show posts if (post is public) AND (user is not banned) AND 
    # (user is not private OR current_user is creator OR current_user is friend)
    posts_query = '''
        SELECT p.*, u.display_name, u.username, u.avatar_path, u.is_private,
               (SELECT IFNULL(SUM(value), 0) FROM post_votes WHERE post_id = p.id) as net_votes,
               (SELECT COUNT(id) FROM post_comments WHERE post_id = p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.mode = 'public' AND u.status != 'banned'
        ORDER BY p.created_at DESC
    '''
    raw_posts = db.execute(posts_query).fetchall()
    
    filtered_posts = []
    for post in raw_posts:
        if not post['is_private']:
            filtered_posts.append(post)
        else:
            # Private account logic
            if current_user_id:
                if post['user_id'] == current_user_id or get_friendship_status(current_user_id, post['user_id']) == 1:
                    filtered_posts.append(post)
    
    return render_template('feed.html', posts=filtered_posts)

@app.route('/post/create', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content')
    if check_moderation(content, g.user['id']):
        return redirect(url_for('feed')) # User was banned
        
    media = request.files.get('media')
    media_path = None
    
    if media and media.filename:
        if allowed_file(media.filename):
            import uuid
            ext = media.filename.rsplit('.', 1)[1].lower()
            filename = f"{uuid.uuid4().hex}.{ext}"
            media.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            media_path = filename
        else:
            flash("Invalid file type. Allowed: png, jpg, jpeg, gif, webp, mp4", "error")
            return redirect(url_for('feed'))
        
    # parse hashtags and store the HTML version directly (simpler for this app)
    html_content = parse_hashtags(content)
    html_content, mentioned_ids = parse_mentions(html_content, g.user['id'])
        
    db = get_db()
    cursor = db.execute('''
        INSERT INTO posts (user_id, content, media_path)
        VALUES (?, ?, ?)
    ''', (g.user['id'], html_content, media_path))
    post_id = cursor.lastrowid
    db.commit()

    # Create notifications for mentions
    for uid in mentioned_ids:
        create_notification(uid, g.user['id'], 'mention', post_id)
    
    # Record interests
    tags = get_hashtags(content)
    record_user_interests(g.user['id'], tags)
    
    return redirect(url_for('feed'))

@app.route('/post/<int:post_id>')
def post_detail(post_id):
    db = get_db()
    post = db.execute('''
        SELECT p.*, u.display_name, u.username, u.avatar_path,
               (SELECT IFNULL(SUM(value), 0) FROM post_votes WHERE post_id = p.id) as net_votes
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    ''', (post_id,)).fetchone()
    
    if not post:
        return "Post not found", 404
        
    comments = db.execute('''
        SELECT c.*, u.display_name, u.username, u.avatar_path
        FROM post_comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id = ? AND u.status != 'banned'
        ORDER BY c.created_at ASC
    ''', (post_id,)).fetchall()
    
    return render_template('post.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def post_comment(post_id):
    content = request.form.get('content')
    if check_moderation(content, g.user['id']):
        return redirect(url_for('post_detail', post_id=post_id))
        
    # Also parse hashtags and mentions in comments
    html_content = parse_hashtags(content)
    html_content, mentioned_ids = parse_mentions(html_content, g.user['id'])
        
    db = get_db()
    db.execute('''
        INSERT INTO post_comments (post_id, user_id, content)
        VALUES (?, ?, ?)
    ''', (post_id, g.user['id'], html_content))
    db.commit()

    # Create notifications for mentions in comments
    for uid in mentioned_ids:
        create_notification(uid, g.user['id'], 'mention', post_id)

    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/post/<int:post_id>/vote', methods=['POST'])
@login_required
def vote_post(post_id):
    value = request.form.get('value', type=int)
    if value not in [1, -1]:
        return "Invalid vote", 400
        
    db = get_db()
    # Insert or update vote
    db.execute('''
        INSERT INTO post_votes (post_id, user_id, value)
        VALUES (?, ?, ?)
        ON CONFLICT(post_id, user_id) DO UPDATE SET value = ?
    ''', (post_id, g.user['id'], value, value))
    db.commit()
    return redirect(request.referrer or url_for('feed'))

@app.route('/tags/<tag>')
def tag_feed(tag):
    db = get_db()
    # Use LIKE for simple hashtag searching in the HTML encoded string
    search_term = f'%"/tags/{tag}"%'
    posts = db.execute('''
        SELECT p.*, u.display_name, u.username, u.avatar_path,
               (SELECT IFNULL(SUM(value), 0) FROM post_votes WHERE post_id = p.id) as net_votes,
               (SELECT COUNT(id) FROM post_comments WHERE post_id = p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.mode = 'public' AND u.status != 'banned' AND p.content LIKE ?
        ORDER BY p.created_at DESC
    ''', (search_term,)).fetchall()
    
    return render_template('tags.html', posts=posts, tag=tag)

@app.route('/search')
def search():
    q = request.args.get('q', '').strip()
    if not q:
        return redirect(url_for('feed'))
        
    db = get_db()
    current_user_id = g.user['id'] if g.user else None
    
    # Search users
    users = db.execute('''
        SELECT id, username, display_name, avatar_path, is_private
        FROM users
        WHERE (username LIKE ? OR display_name LIKE ?) AND status != 'banned'
        LIMIT 10
    ''', (f'%{q}%', f'%{q}%')).fetchall()
    
    # Search posts
    # Basic keyword search + check for hashtags in HTML
    posts_query = '''
        SELECT p.*, u.display_name, u.username, u.avatar_path, u.is_private,
               (SELECT IFNULL(SUM(value), 0) FROM post_votes WHERE post_id = p.id) as net_votes,
               (SELECT COUNT(id) FROM post_comments WHERE post_id = p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE (p.content LIKE ? OR p.content LIKE ?) 
          AND p.mode = 'public' 
          AND u.status != 'banned'
        ORDER BY p.created_at DESC
        LIMIT 20
    '''
    raw_posts = db.execute(posts_query, (f'%{q}%', f'%"/tags/{q}"%')).fetchall()
    
    filtered_posts = []
    for post in raw_posts:
        if not post['is_private']:
            filtered_posts.append(post)
        elif current_user_id:
            if post['user_id'] == current_user_id or get_friendship_status(current_user_id, post['user_id']) == 1:
                filtered_posts.append(post)
    
    return render_template('search_results.html', query=q, users=users, posts=filtered_posts)

# --- SOCIAL FEATURES ---

@app.route('/u/<username>', methods=['GET', 'POST'])
def profile(username):
    db = get_db()
    
    if request.method == 'POST':
        if not g.user or g.user['username'] != username:
            return "Unauthorized", 403
            
        display_name = request.form.get('display_name')
        bio = request.form.get('bio')
        is_private = 1 if request.form.get('is_private') else 0
        
        # Moderate bio
        if check_moderation(bio, g.user['id']):
            return redirect(url_for('index'))
            
        avatar = request.files.get('avatar')
        avatar_path = g.user['avatar_path']
        
        if avatar and allowed_file(avatar.filename):
            import uuid
            ext = avatar.filename.rsplit('.', 1)[1].lower()
            filename = f"avatar_{uuid.uuid4().hex}.{ext}"
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            avatar_path = filename
            
        db.execute('''
            UPDATE users 
            SET display_name = ?, bio = ?, is_private = ?, avatar_path = ?
            WHERE id = ?
        ''', (display_name, bio, is_private, avatar_path, g.user['id']))
        db.commit()
        return redirect(url_for('profile', username=username))
        
    user_info = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user_info:
        return "User not found", 404
        
    # Check privacy: visible if not private OR is owner OR is friend
    can_view = True
    if user_info['is_private'] == 1:
        if not g.user:
            can_view = False
        elif g.user['id'] != user_info['id']:
            if get_friendship_status(g.user['id'], user_info['id']) != 1:
                can_view = False
            
    posts = []
    if can_view:
        posts = db.execute('''
            SELECT p.*, u.display_name, u.username, u.avatar_path,
                   (SELECT IFNULL(SUM(value), 0) FROM post_votes WHERE post_id = p.id) as net_votes,
                   (SELECT COUNT(id) FROM post_comments WHERE post_id = p.id) as comment_count
            FROM posts p
            JOIN users u ON p.user_id = u.id
            WHERE p.user_id = ?
            ORDER BY p.created_at DESC
        ''', (user_info['id'],)).fetchall()
        
    # Friendship status for the action button
    f_status = get_friendship_status(g.user['id'] if g.user else None, user_info['id'])
        
    return render_template('profile.html', profile_user=user_info, posts=posts, can_view=can_view, friendship_status=f_status)

@app.route('/rooms', methods=['GET', 'POST'])
@login_required
def rooms():
    db = get_db()
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        is_private = 1 if request.form.get('is_private') else 0
        access_code = request.form.get('access_code', '') if is_private else None
        
        db.execute('''
            INSERT INTO rooms (name, description, is_private, access_code, creator_user_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, description, is_private, access_code, g.user['id']))
        db.commit()
        return redirect(url_for('rooms'))
        
    rooms_list = db.execute('''
        SELECT r.*, u.username as creator_username
        FROM rooms r
        JOIN users u ON r.creator_user_id = u.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    
    return render_template('rooms.html', rooms=rooms_list)

@app.route('/room/<int:room_id>', methods=['GET', 'POST'])
@login_required
def room_chat(room_id):
    db = get_db()
    room = db.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()
    if not room:
        return "Room not found", 404
        
    # Check access code for private rooms
    if room['is_private'] == 1 and g.user['id'] != room['creator_user_id']:
        unlocked_rooms = session.get('unlocked_rooms', [])
        if room_id not in unlocked_rooms:
            # Check if user submitted access code
            if request.method == 'POST' and 'access_code' in request.form:
                if request.form['access_code'] == room['access_code']:
                    unlocked_rooms.append(room_id)
                    session['unlocked_rooms'] = unlocked_rooms
                    return redirect(url_for('room_chat', room_id=room_id))
                else:
                    flash("Incorrect access code", "error")
            return render_template('room_unlock.html', room=room)
            
    if request.method == 'POST' and 'content' in request.form:
        content = request.form['content']
        if check_moderation(content, g.user['id']):
            return redirect(url_for('rooms'))
            
        media = request.files.get('media')
        media_path = None
        if media and allowed_file(media.filename):
            import uuid
            ext = media.filename.rsplit('.', 1)[1].lower()
            filename = f"room_{uuid.uuid4().hex}.{ext}"
            media.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            media_path = filename
            
        html_content = parse_hashtags(content)
            
        db.execute('''
            INSERT INTO room_messages (room_id, user_id, content, media_path)
            VALUES (?, ?, ?, ?)
        ''', (room_id, g.user['id'], html_content, media_path))
        db.commit()
        return redirect(url_for('room_chat', room_id=room_id))
        
    messages = db.execute('''
        SELECT m.*, u.display_name, u.username, u.avatar_path
        FROM room_messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.room_id = ? AND u.status != 'banned'
        ORDER BY m.created_at ASC
    ''', (room_id,)).fetchall()
    
    return render_template('room_chat.html', room=room, messages=messages)

@app.route('/directs')
@login_required
def directs():
    db = get_db()
    # Find all users we've messaged or who messaged us
    users = db.execute('''
        SELECT DISTINCT u.id, u.username, u.display_name, u.avatar_path
        FROM users u
        WHERE u.id IN (
            SELECT recipient_id FROM direct_messages WHERE sender_id = ?
            UNION
            SELECT sender_id FROM direct_messages WHERE recipient_id = ?
        )
        AND u.status != 'banned'
    ''', (g.user['id'], g.user['id'])).fetchall()
    return render_template('directs.html', users=users)

@app.route('/direct/<username>', methods=['GET', 'POST'])
@login_required
def direct_chat(username):
    db = get_db()
    recipient = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not recipient:
        return "User not found", 404
        
    if request.method == 'POST':
        content = request.form.get('content')
        if check_moderation(content, g.user['id']):
            return redirect(url_for('directs'))
            
        media = request.files.get('media')
        media_path = None
        if media and allowed_file(media.filename):
            import uuid
            ext = media.filename.rsplit('.', 1)[1].lower()
            filename = f"dm_{uuid.uuid4().hex}.{ext}"
            media.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            media_path = filename
            
        html_content = parse_hashtags(content)
            
        db.execute('''
            INSERT INTO direct_messages (sender_id, recipient_id, content, media_path)
            VALUES (?, ?, ?, ?)
        ''', (g.user['id'], recipient['id'], html_content, media_path))
        db.commit()
        return redirect(url_for('direct_chat', username=username))
        
    messages = db.execute('''
        SELECT m.*, u.display_name, u.username, u.avatar_path
        FROM direct_messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.recipient_id = ?)
           OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.created_at ASC
    ''', (g.user['id'], recipient['id'], recipient['id'], g.user['id'])).fetchall()
    
    return render_template('direct_chat.html', recipient=recipient, messages=messages)

@app.route('/groups')
def groups():
    db = get_db()
    group = db.execute("SELECT * FROM chat_groups WHERE name = 'World Group'").fetchone()
    if not group:
        return "World group not found", 404
    return redirect(url_for('group_chat', group_id=group['id']))

@app.route('/group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group_chat(group_id):
    db = get_db()
    group = db.execute('SELECT * FROM chat_groups WHERE id = ?', (group_id,)).fetchone()
    if not group:
        return "Group not found", 404
        
    if request.method == 'POST':
        content = request.form.get('content')
        if check_moderation(content, g.user['id']):
            return redirect(url_for('feed'))
            
        media = request.files.get('media')
        media_path = None
        if media and allowed_file(media.filename):
            import uuid
            ext = media.filename.rsplit('.', 1)[1].lower()
            filename = f"wg_{uuid.uuid4().hex}.{ext}"
            media.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            media_path = filename
            
        html_content = parse_hashtags(content)
            
        db.execute('''
            INSERT INTO chat_group_messages (group_id, user_id, content, media_path)
            VALUES (?, ?, ?, ?)
        ''', (group_id, g.user['id'], html_content, media_path))
        db.commit()
        return redirect(url_for('group_chat', group_id=group_id))
        
    messages = db.execute('''
        SELECT m.*, u.display_name, u.username, u.avatar_path, u.status
        FROM chat_group_messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.group_id = ? AND u.status != 'banned'
        ORDER BY m.created_at ASC
    ''', (group_id,)).fetchall()
    
    return render_template('world_group.html', group=group, messages=messages)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/sos')
def sos():
    return render_template('sos.html')

# --- BLOGS FEATURES ---

@app.route('/blogs')
def blogs():
    db = get_db()
    current_user_id = g.user['id'] if g.user else None
    
    blogs_list_all = db.execute('''
        SELECT b.*, u.display_name, u.username, u.avatar_path, u.is_private,
               (SELECT COUNT(id) FROM blog_comments WHERE blog_id = b.id) as comment_count
        FROM blogs b
        JOIN users u ON b.user_id = u.id
        WHERE u.status != 'banned'
        ORDER BY b.created_at DESC
    ''').fetchall()
    
    filtered_blogs = []
    for blog in blogs_list_all:
        if not blog['is_private']:
            filtered_blogs.append(blog)
        else:
            if current_user_id:
                if blog['user_id'] == current_user_id or get_friendship_status(current_user_id, blog['user_id']) == 1:
                    filtered_blogs.append(blog)
                    
    return render_template('blogs.html', blogs=filtered_blogs)

@app.route('/blog/create', methods=['GET', 'POST'])
@login_required
def create_blog():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content') # From rich text editor
        
        if check_moderation(title, g.user['id']) or check_moderation(content, g.user['id']):
            return redirect(url_for('blogs')) # User was banned
            
        media = request.files.get('media')
        media_path = None
        if media and allowed_file(media.filename):
            import uuid
            ext = media.filename.rsplit('.', 1)[1].lower()
            filename = f"blog_{uuid.uuid4().hex}.{ext}"
            media.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            media_path = filename
            
        html_content, mentioned_ids = parse_mentions(content, g.user['id'])
        html_content = parse_hashtags(html_content)
            
        db = get_db()
        db.execute('''
            INSERT INTO blogs (user_id, title, content, media_path)
            VALUES (?, ?, ?, ?)
        ''', (g.user['id'], title, html_content, media_path))
        blog_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        db.commit()

        # Create notifications for mentions in blogs
        for uid in mentioned_ids:
            create_notification(uid, g.user['id'], 'blog_mention', blog_id)
            
        # Record interests
        tags = get_hashtags(title + " " + content)
        record_user_interests(g.user['id'], tags)
        
        return redirect(url_for('blogs'))
        
    return render_template('blog_create.html')

@app.route('/blog/<int:blog_id>')
def blog_detail(blog_id):
    db = get_db()
    blog = db.execute('''
        SELECT b.*, u.display_name, u.username, u.avatar_path
        FROM blogs b
        JOIN users u ON b.user_id = u.id
        WHERE b.id = ? AND u.status != 'banned'
    ''', (blog_id,)).fetchone()
    
    if not blog:
        return "Blog not found", 404
        
    comments = db.execute('''
        SELECT c.*, u.display_name, u.username, u.avatar_path
        FROM blog_comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.blog_id = ? AND u.status != 'banned'
        ORDER BY c.created_at ASC
    ''', (blog_id,)).fetchall()
    
    return render_template('blog_detail.html', blog=blog, comments=comments)

@app.route('/blog/<int:blog_id>/comment', methods=['POST'])
@login_required
def blog_comment(blog_id):
    content = request.form.get('content')
    if check_moderation(content, g.user['id']):
        return redirect(url_for('blogs'))
        
    html_content = parse_hashtags(content)
        
    db = get_db()
    db.execute('''
        INSERT INTO blog_comments (blog_id, user_id, content)
        VALUES (?, ?, ?)
    ''', (blog_id, g.user['id'], html_content))
    db.commit()
    return redirect(url_for('blog_detail', blog_id=blog_id))

# --- FRIENDS SYSTEM ---

@app.route('/friends')
@login_required
def friends():
    db = get_db()
    # Accepted friends (status=1)
    friends_query = '''
        SELECT u.id, u.username, u.display_name, u.avatar_path
        FROM users u
        INNER JOIN friendships f ON u.id = f.user_id1 OR u.id = f.user_id2
        WHERE (f.user_id1 = ? OR f.user_id2 = ?) AND u.id != ? AND f.status = 1 AND u.status != 'banned'
    '''
    accepted_friends = db.execute(friends_query, (g.user['id'], g.user['id'], g.user['id'])).fetchall()
    
    # Pending requests received by me (status=0 and I am user_id2)
    requests_query = '''
        SELECT u.id, u.username, u.display_name, u.avatar_path
        FROM users u
        INNER JOIN friendships f ON u.id = f.user_id1
        WHERE f.user_id2 = ? AND f.status = 0 AND u.status != 'banned'
    '''
    pending_requests = db.execute(requests_query, (g.user['id'],)).fetchall()
    
    return render_template('friends.html', friends=accepted_friends, requests=pending_requests)

@app.route('/friend/request/<username>', methods=['POST'])
@login_required
def request_friend(username):
    db = get_db()
    target_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not target_user:
        flash("User not found.", "error")
        return redirect(request.referrer or url_for('feed'))
        
    # Check if a relationship already exists in either direction
    existing = db.execute('''
        SELECT * FROM friendships 
        WHERE (user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?)
    ''', (g.user['id'], target_user['id'], target_user['id'], g.user['id'])).fetchone()
    
    if not existing:
        db.execute('''
            INSERT INTO friendships (user_id1, user_id2, status)
            VALUES (?, ?, 0)
        ''', (g.user['id'], target_user['id']))
        db.commit()
        # Notify
        create_notification(target_user['id'], g.user['id'], 'friend_request')
        flash("Friend request sent!", "success")
    else:
        if existing['status'] == 1:
            flash("You are already friends.", "error")
        else:
            flash("A friend request is already pending.", "error")
            
    return redirect(request.referrer or url_for('profile', username=username))

@app.route('/friend/accept/<username>', methods=['POST'])
@login_required
def accept_friend(username):
    db = get_db()
    target_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if target_user:
        db.execute('''
            UPDATE friendships SET status = 1 
            WHERE user_id1 = ? AND user_id2 = ? AND status = 0
        ''', (target_user['id'], g.user['id']))
        db.commit()
        # Notify
        create_notification(target_user['id'], g.user['id'], 'friend_accept')
        flash(f"You are now friends with {username}!", "success")
    return redirect(url_for('friends'))

@app.route('/friend/reject/<username>', methods=['POST'])
@login_required
def reject_friend(username):
    db = get_db()
    target_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if target_user:
        db.execute('''
            DELETE FROM friendships 
            WHERE (user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?)
        ''', (target_user['id'], g.user['id'], g.user['id'], target_user['id']))
        db.commit()
    return redirect(request.referrer or url_for('friends'))

    return redirect(url_for('friends'))

@app.route('/notifications')
@login_required
def notifications():
    """
    Displays the user's personal alert center, featuring @mentions and friend activity.
    Marks all notifications as read upon access to the view.
    
    Returns:
        Rendered 'notifications.html' template with notification data.
    """
    db = get_db()
    notifs = db.execute('''
        SELECT n.*, u.username as sender_username, u.display_name as sender_name, u.avatar_path as sender_avatar
        FROM notifications n
        LEFT JOIN users u ON n.sender_id = u.id
        WHERE n.user_id = ?
        ORDER BY n.created_at DESC
        LIMIT 50
    ''', (g.user['id'],)).fetchall()
    
    db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (g.user['id'],))
    db.commit()
    
    return render_template('notifications.html', notifications=notifs)

@app.route('/time_capsule', methods=['GET', 'POST'])
@login_required
def time_capsule():
    """
    Manages the 'Digital Vault' feature, allowing users to 'bury' messages for the future.
    Supports media attachments and custom unlock dates.
    
    Returns:
        GET: The Vault page showing buried capsules.
        POST: Redirect after successfully burying a new capsule.
    """
    db = get_db()
    if request.method == 'POST':
        content = request.form.get('content')
        unlock_date = request.form.get('unlock_date') # Format: YYYY-MM-DD
        
        media = request.files.get('media')
        media_path = None
        if media and allowed_file(media.filename):
            import uuid
            filename = f"tc_{uuid.uuid4().hex}.{media.filename.rsplit('.', 1)[1].lower()}"
            media.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            media_path = filename
            
        db.execute('''
            INSERT INTO time_capsule_posts (user_id, content, media_path, unlock_date)
            VALUES (?, ?, ?, ?)
        ''', (g.user['id'], content, media_path, unlock_date))
        db.commit()
        flash("Time Capsule buried! It will unlock on " + unlock_date, "success")
        return redirect(url_for('time_capsule'))
        
    # Get locked and unlocked capsules
    now_dt = datetime.now()
    now_str = now_dt.strftime('%Y-%m-%d %H:%M:%S')
    now_date = now_dt.strftime('%Y-%m-%d')
    
    capsules = db.execute('''
        SELECT *, 
               CASE WHEN unlock_date <= ? THEN 1 ELSE 0 END as is_ready
        FROM time_capsule_posts
        WHERE user_id = ?
        ORDER BY unlock_date ASC
    ''', (now_str, g.user['id'])).fetchall()
    
    return render_template('time_capsule.html', capsules=capsules, now_date=now_date)

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
