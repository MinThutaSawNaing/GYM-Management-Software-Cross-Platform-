from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
import sqlite3
import random
import string
import qrcode
import io
import base64
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from PIL import Image

app = Flask(__name__)

app.secret_key = 'gym_app_secret_key_12345'

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads/blog_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
BLOG_IMAGE_SIZE = (1200, 627)

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def resize_and_save_image(file, filename):
    # Open the image file
    img = Image.open(file)
    
    # Convert to RGB if necessary (for PNG with transparency)
    if img.mode in ('RGBA', 'P'):
        img = img.convert('RGB')
    
    # Resize the image to the required dimensions
    img = img.resize(BLOG_IMAGE_SIZE, Image.LANCZOS)
    
    # Save the resized image
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    img.save(filepath, 'JPEG', quality=85)
    
    return filepath

# Helper function to robustly parse datetime strings
def parse_datetime(date_string):
    if not date_string:
        return None
    try:
        # Try parsing with microseconds first
        return datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        # If that fails, try parsing without microseconds
        return datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')

# Database initialization
def init_db():
    conn = sqlite3.connect('database/gym.db')
    cursor = conn.cursor()
    
    # Users table
    # The 'approved' column is now repurposed for 'banned' status.
    # 0 = Active (not banned), 1 = Banned
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL,
        approved INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Updated to support monthly and trainer session subscriptions
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        subscription_type TEXT NOT NULL, -- 'monthly' or 'trainer_sessions'
        status TEXT DEFAULT 'active', -- 'active' or 'expired'
        months INTEGER DEFAULT 0, -- Number of months for monthly subscription
        trainer_id INTEGER, -- Trainer ID for trainer sessions
        trainer_sessions INTEGER DEFAULT 0, -- Number of trainer sessions
        price REAL, -- Price paid for this subscription
        activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (trainer_id) REFERENCES users (id)
    )
    ''')

    # Trainer pricing table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS trainer_pricing (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trainer_id INTEGER,
        price_per_session REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (trainer_id) REFERENCES users (id)
    )
    ''')

    # System settings table for monthly subscription price
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT UNIQUE NOT NULL,
        setting_value TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Check-in/out logs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS check_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        check_type TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Messages table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        subject TEXT,
        message TEXT,
        reply TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        replied_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Blog/Announcements table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        image_path TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        author_id INTEGER,
        FOREIGN KEY (author_id) REFERENCES users (id)
    )
    ''')
    
    # Check if we need to migrate old subscription data
    # This is a simple migration for existing subscriptions
    cursor.execute("PRAGMA table_info(subscriptions)")
    columns = [column[1] for column in cursor.fetchall()]
        
    # If the old columns exist but new ones don't, we need to migrate
    if 'plan' in columns and 'subscription_type' not in columns:
        # Add new columns
        cursor.execute("ALTER TABLE subscriptions ADD COLUMN subscription_type TEXT")
        cursor.execute("ALTER TABLE subscriptions ADD COLUMN months INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE subscriptions ADD COLUMN trainer_id INTEGER")
        cursor.execute("ALTER TABLE subscriptions ADD COLUMN trainer_sessions INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE subscriptions ADD COLUMN price REAL")
        
        # Migrate existing data
        old_subscriptions = cursor.execute("SELECT * FROM subscriptions").fetchall()
        for sub in old_subscriptions:
            # Convert old plan to new subscription_type
            cursor.execute(
                "UPDATE subscriptions SET subscription_type = ?, months = 1 WHERE id = ?",
                ('monthly', sub['id'])
            )
    
    # OTP table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS otp_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code TEXT NOT NULL,
        expires_at TIMESTAMP,
        used INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # QR codes table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS qr_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code_type TEXT NOT NULL,
        code_value TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Check if admin exists, if not create one.
    # Admin is created as 'active' by setting approved=0.
    cursor.execute("SELECT * FROM users WHERE role='admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, email, role, approved) VALUES (?, ?, ?, ?, ?)",
                      ('admin', 'admin123', 'admin@gym.com', 'admin', 0)) # Set approved to 0 (active)
    # Check if monthly subscription price is set, if not create default
    cursor.execute("SELECT * FROM system_settings WHERE setting_key='monthly_price'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)",
                    ('monthly_price', '50000')) # Default 50,000 MMK

    # Initialize trainer pricing for all trainers
    trainers = cursor.execute("SELECT id FROM users WHERE role='trainer'").fetchall()
    for trainer in trainers:
        cursor.execute("SELECT * FROM trainer_pricing WHERE trainer_id=?", (trainer['id'],))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO trainer_pricing (trainer_id, price_per_session) VALUES (?, ?)",
                        (trainer['id'], 20000)) # Default 20,000 MMK per session
    
    # Check if QR codes exist, if not create them
    cursor.execute("SELECT * FROM qr_codes WHERE code_type='user'")
    if not cursor.fetchone():
        user_qr = f"USER-{random.randint(100000, 999999)}"
        cursor.execute("INSERT INTO qr_codes (code_type, code_value) VALUES (?, ?)", ('user', user_qr))
    
    cursor.execute("SELECT * FROM qr_codes WHERE code_type='trainer'")
    if not cursor.fetchone():
        trainer_qr = f"TRAINER-{random.randint(100000, 999999)}"
        cursor.execute("INSERT INTO qr_codes (code_type, code_value) VALUES (?, ?)", ('trainer', trainer_qr))
    
    conn.commit()
    conn.close()

# Initialize database on app start
if not os.path.exists('database'):
    os.makedirs('database')
if not os.path.exists('static/images'):
    os.makedirs('static/images')
if not os.path.exists('static/js'):
    os.makedirs('static/js')
init_db()

# Helper functions
def get_db_connection():
    conn = sqlite3.connect('database/gym.db')
    conn.row_factory = sqlite3.Row
    return conn

def is_logged_in():
    return 'user_id' in session

def get_user_role():
    if is_logged_in():
        conn = get_db_connection()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        return user['role'] if user else None
    return None

def generate_captcha():
    return ''.join(random.choices(string.digits, k=4))

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_to_mailbox(email, otp):
    # In a real application, this would send an email
    # For this demo, we'll just store it in a "mailbox" table
    conn = get_db_connection()
    expires_at = datetime.now() + timedelta(minutes=10)
    conn.execute('INSERT INTO otp_codes (email, code, expires_at, created_at) VALUES (?, ?, ?, ?)',
                (email, otp, expires_at, datetime.now()))
    conn.commit()
    conn.close()

def is_otp_valid(email, code):
    conn = get_db_connection()
    otp_record = conn.execute(
        'SELECT * FROM otp_codes WHERE email = ? AND code = ? AND used = 0 AND expires_at > ?',
        (email, code, datetime.now())
    ).fetchone()
    
    if otp_record:
        conn.execute('UPDATE otp_codes SET used = 1 WHERE id = ?', (otp_record['id'],))
        conn.commit()
        conn.close()
        return True
    
    conn.close()
    return False

# Routes
@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('main'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        captcha = generate_captcha()
        session['captcha'] = captcha
        return render_template('login.html', captcha=captcha, page='login')
    
    username = request.form.get('username')
    password = request.form.get('password')
    captcha_input = request.form.get('captcha')
    
    if captcha_input != session.get('captcha'):
        flash('Invalid CAPTCHA', 'error')
        captcha = generate_captcha()
        session['captcha'] = captcha
        return render_template('login.html', captcha=captcha, page='login')
    
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ? AND password = ?',
        (username, password)
    ).fetchone()
    
    if user:
        # Check if user is banned (approved == 1)
        if user['approved'] == 1:
            flash('Your account has been banned. Please contact the administrator.', 'error')
            captcha = generate_captcha()
            session['captcha'] = captcha
            return render_template('login.html', captcha=captcha, page='login')

        # Check if user has an active and non-expired monthly subscription
        monthly_subscription = conn.execute(
            'SELECT * FROM subscriptions WHERE user_id = ? AND subscription_type = "monthly" AND status = "active" ORDER BY created_at DESC LIMIT 1',
            (user['id'],)
        ).fetchone()

        # Use the robust parser for expiry check
        if monthly_subscription and monthly_subscription['expires_at'] and parse_datetime(monthly_subscription['expires_at']) < datetime.now():
            flash('Your monthly subscription has expired. Please contact admin to renew.', 'error')
            captcha = generate_captcha()
            session['captcha'] = captcha
            return render_template('login.html', captcha=captcha, page='login')
        conn.close()
        
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        return redirect(url_for('main'))
    else:
        conn.close()
        flash('Invalid username or password', 'error')
        captcha = generate_captcha()
        session['captcha'] = captcha
        return render_template('login.html', captcha=captcha, page='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        captcha = generate_captcha()
        session['captcha'] = captcha
        return render_template('login.html', captcha=captcha, page='register')
    
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    role = request.form.get('role', 'user')
    captcha_input = request.form.get('captcha')
    
    if captcha_input != session.get('captcha'):
        flash('Invalid CAPTCHA', 'error')
        captcha = generate_captcha()
        session['captcha'] = captcha
        return render_template('login.html', captcha=captcha, page='register')
    
    conn = get_db_connection()
    
    # Check if username or email already exists
    existing_user = conn.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        (username, email)
    ).fetchone()
    
    if existing_user:
        conn.close()
        flash('Username or email already exists', 'error')
        captcha = generate_captcha()
        session['captcha'] = captcha
        return render_template('login.html', captcha=captcha, page='register')
    
    # Generate and send OTP
    otp = generate_otp()
    send_otp_to_mailbox(email, otp)
    
    # Store user data temporarily in session
    session['temp_user'] = {
        'username': username,
        'password': password,
        'email': email,
        'role': role
    }
    session['otp_email'] = email
    
    conn.close()
    return redirect(url_for('verify_otp'))

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp_email' not in session:
        return redirect(url_for('register'))
    
    if request.method == 'GET':
        return render_template('login.html', page='otp')
    
    otp_input = request.form.get('otp')
    email = session['otp_email']
    
    if is_otp_valid(email, otp_input):
        # OTP is valid, create user
        temp_user = session['temp_user']
        conn = get_db_connection()
        # New users are now 'active' by default (approved=0)
        conn.execute(
            'INSERT INTO users (username, password, email, role, approved) VALUES (?, ?, ?, ?, ?)',
            (temp_user['username'], temp_user['password'], temp_user['email'], temp_user['role'], 0)
        )
        conn.commit()
        conn.close()
        
        # Clear temporary session data
        session.pop('temp_user', None)
        session.pop('otp_email', None)
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('Invalid OTP', 'error')
        return render_template('login.html', page='otp')

@app.route('/mailbox')
def mailbox():
    # This endpoint simulates a mailbox for OTP codes
    conn = get_db_connection()
    otps = conn.execute(
        'SELECT * FROM otp_codes ORDER BY created_at DESC LIMIT 10'
    ).fetchall()
    conn.close()
    
    return render_template('login.html', page='mailbox', otps=otps)

@app.route('/main')
def main():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    role = get_user_role()
    user_id = session['user_id']
    
    # If admin, redirect to admin route
    if role == 'admin':
        return redirect(url_for('admin'))
    
    conn = get_db_connection()
    
    # Get user data
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    # Get blogs/announcements
    blogs = conn.execute('SELECT * FROM blogs ORDER BY created_at DESC').fetchall()
    
    # Get user messages
    messages = conn.execute(
        'SELECT * FROM messages WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    
    # Get user's active subscriptions
    monthly_subscription = conn.execute(
        'SELECT * FROM subscriptions WHERE user_id = ? AND subscription_type = "monthly" AND status = "active" ORDER BY created_at DESC LIMIT 1',
        (user_id,)
    ).fetchone()

    trainer_subscriptions = conn.execute(
        'SELECT s.*, t.username as trainer_name FROM subscriptions s JOIN users t ON s.trainer_id = t.id WHERE s.user_id = ? AND s.subscription_type = "trainer_sessions" AND s.status = "active"',
        (user_id,)
    ).fetchall()

    # Check if monthly subscription is expired
    is_monthly_expired = False
    if monthly_subscription and monthly_subscription['expires_at']:
        is_monthly_expired = parse_datetime(monthly_subscription['expires_at']) < datetime.now()
    
    # Get check-in/out logs
    check_logs = conn.execute(
        'SELECT * FROM check_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5',
        (user_id,)
    ).fetchall()
    
    # Get QR codes
    user_qr = conn.execute('SELECT code_value FROM qr_codes WHERE code_type = "user"').fetchone()
    trainer_qr = conn.execute('SELECT code_value FROM qr_codes WHERE code_type = "trainer"').fetchone()
    
    conn.close()
    
    return render_template(
        'main.html',
        user=user,
        role=role,
        blogs=blogs,
        messages=messages,
        monthly_subscription=monthly_subscription,
        is_monthly_expired=is_monthly_expired,
        trainer_subscriptions=trainer_subscriptions,
        check_logs=check_logs,
        user_qr=user_qr['code_value'] if user_qr else None,
        trainer_qr=trainer_qr['code_value'] if trainer_qr else None
    )

@app.route('/admin')
def admin():
    if not is_logged_in() or get_user_role() != 'admin':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    
    # Get current user data
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    # Get all users
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    
    # Get all subscriptions
    all_subscriptions = conn.execute('''
        SELECT s.*, u.username, u.email, t.username as trainer_name 
        FROM subscriptions s 
        JOIN users u ON s.user_id = u.id 
        LEFT JOIN users t ON s.trainer_id = t.id 
        ORDER BY s.created_at DESC
    ''').fetchall()

    # Get active subscriptions
    active_subscriptions = [s for s in all_subscriptions if s['status'] == 'active']

    # Get expired subscriptions
    expired_subscriptions = [
        s for s in all_subscriptions 
        if s['status'] == 'expired' or (s['expires_at'] and parse_datetime(s['expires_at']) < datetime.now())
    ]

    # Get monthly subscription price
    monthly_price_setting = conn.execute(
        'SELECT setting_value FROM system_settings WHERE setting_key = ?', 
        ('monthly_price',)
    ).fetchone()
    monthly_price = monthly_price_setting['setting_value'] if monthly_price_setting else '50000'

    # Get trainer pricing
    trainer_pricing = conn.execute('''
        SELECT tp.*, u.username 
        FROM trainer_pricing tp 
        JOIN users u ON tp.trainer_id = u.id
    ''').fetchall()

    # Get all trainers for dropdown
    trainers = conn.execute('SELECT id, username FROM users WHERE role = "trainer"').fetchall()
        
    # Get all messages
    all_messages = conn.execute(
        'SELECT m.*, u.username FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.created_at DESC'
    ).fetchall()
    
    # Get all blogs
    all_blogs = conn.execute(
        'SELECT b.*, u.username FROM blogs b JOIN users u ON b.author_id = u.id ORDER BY b.created_at DESC'
    ).fetchall()
    
    # Get QR codes
    user_qr = conn.execute('SELECT code_value FROM qr_codes WHERE code_type = "user"').fetchone()
    trainer_qr = conn.execute('SELECT code_value FROM qr_codes WHERE code_type = "trainer"').fetchone()
    
    conn.close()
    
    return render_template(
        'main.html',
        user=user,
        role='admin',
        page='admin',
        users=users,
        all_subscriptions=all_subscriptions,
        active_subscriptions=active_subscriptions,
        expired_subscriptions=expired_subscriptions,
        all_messages=all_messages,
        all_blogs=all_blogs,
        user_qr=user_qr['code_value'] if user_qr else None,
        trainer_qr=trainer_qr['code_value'] if trainer_qr else None,
        monthly_price=monthly_price,
        trainer_pricing=trainer_pricing,
        trainers=trainers
    )

@app.route('/create-user', methods=['POST'])
def create_user():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    role = request.form.get('role')
    # The 'approved' field from the form now represents 'active' status.
    # 0 means active, 1 means banned. Default to active (0).
    active = 0 if request.form.get('approved') == 'on' else 1

    conn = get_db_connection()
    
    # Check if username or email already exists
    existing_user = conn.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        (username, email)
    ).fetchone()
    
    if existing_user:
        conn.close()
        return jsonify({'success': False, 'message': 'Username or email already exists'})
    
    conn.execute(
        'INSERT INTO users (username, password, email, role, approved) VALUES (?, ?, ?, ?, ?)',
        (username, password, email, role, active)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'User created successfully'})

@app.route('/edit-user', methods=['POST'])
def edit_user():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    role = request.form.get('role')
    # The 'approved' field from the form now represents 'active' status.
    active = 0 if request.form.get('approved') == 'on' else 1
    
    conn = get_db_connection()
    
    # Check if username or email already exists (excluding current user)
    existing_user = conn.execute(
        'SELECT * FROM users WHERE (username = ? OR email = ?) AND id != ?',
        (username, email, user_id)
    ).fetchone()
    
    if existing_user:
        conn.close()
        return jsonify({'success': False, 'message': 'Username or email already exists'})
    
    if password:
        conn.execute(
            'UPDATE users SET username = ?, password = ?, email = ?, role = ?, approved = ? WHERE id = ?',
            (username, password, email, role, active, user_id)
        )
    else:
        conn.execute(
            'UPDATE users SET username = ?, email = ?, role = ?, approved = ? WHERE id = ?',
            (username, email, role, active, user_id)
        )
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'User updated successfully'})

@app.route('/toggle-ban-user', methods=['POST'])
def toggle_ban_user():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})

    user_id_to_toggle = request.form.get('user_id')
    if not user_id_to_toggle:
        return jsonify({'success': False, 'message': 'User ID is required'})

    # Prevent an admin from banning themselves
    if int(user_id_to_toggle) == session['user_id']:
        return jsonify({'success': False, 'message': 'You cannot change your own ban status.'})

    conn = get_db_connection()
    user = conn.execute('SELECT approved FROM users WHERE id = ?', (user_id_to_toggle,)).fetchone()

    if not user:
        conn.close()
        return jsonify({'success': False, 'message': 'User not found'})

    # Toggle ban status: 0 (active) becomes 1 (banned), and vice-versa.
    new_status = 1 if user['approved'] == 0 else 0

    conn.execute('UPDATE users SET approved = ? WHERE id = ?', (new_status, user_id_to_toggle))
    conn.commit()
    conn.close()

    status_text = 'banned' if new_status == 1 else 'unbanned'
    return jsonify({'success': True, 'message': f'User {status_text} successfully.'})


@app.route('/delete-user', methods=['POST'])
def delete_user():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = request.form.get('user_id')
    
    # Prevent an admin from deleting themselves
    if int(user_id) == session['user_id']:
        return jsonify({'success': False, 'message': 'You cannot delete your own account.'})

    conn = get_db_connection()
    
    # Delete related records
    conn.execute('DELETE FROM subscriptions WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM check_logs WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM messages WHERE user_id = ?', (user_id,))
    
    # Delete user
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'User deleted successfully'})
@app.route('/create-user-subscription', methods=['POST'])
def create_user_subscription():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = request.form.get('user_id')
    subscription_type = request.form.get('subscription_type')
    
    conn = get_db_connection()
    
    # Calculate expiration date
    now = datetime.now()
    expires_at = None
    
    if subscription_type == 'monthly':
        months = int(request.form.get('months', 1))
        expires_at = now + timedelta(days=30 * months)
        
        # Get monthly price
        price_setting = conn.execute(
            'SELECT setting_value FROM system_settings WHERE setting_key = ?', 
            ('monthly_price',)
        ).fetchone()
        price = float(price_setting['setting_value']) if price_setting else 50000.0
        
        # Create monthly subscription
        conn.execute(
            'INSERT INTO subscriptions (user_id, subscription_type, status, months, price, activated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (user_id, subscription_type, 'active', months, price, now, expires_at)
        )
        
    elif subscription_type == 'trainer_sessions':
        trainer_id = request.form.get('trainer_id')
        sessions = int(request.form.get('sessions', 1))
        
        # Get trainer session price
        trainer_price = conn.execute(
            'SELECT price_per_session FROM trainer_pricing WHERE trainer_id = ?', 
            (trainer_id,)
        ).fetchone()
        price = float(trainer_price['price_per_session']) * sessions if trainer_price else 20000.0 * sessions
        
        # Create trainer session subscription
        conn.execute(
            'INSERT INTO subscriptions (user_id, subscription_type, status, trainer_id, trainer_sessions, price, activated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (user_id, subscription_type, 'active', trainer_id, sessions, price, now)
        )
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Subscription added successfully.'})

@app.route('/update-monthly-price', methods=['POST'])
def update_monthly_price():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    price = request.form.get('price')
    
    if not price or not price.replace('.', '', 1).isdigit():
        return jsonify({'success': False, 'message': 'Invalid price format'})
    
    conn = get_db_connection()
    conn.execute(
        'UPDATE system_settings SET setting_value = ?, updated_at = ? WHERE setting_key = ?',
        (price, datetime.now(), 'monthly_price')
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Monthly subscription price updated successfully.'})

@app.route('/update-trainer-price', methods=['POST'])
def update_trainer_price():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    trainer_id = request.form.get('trainer_id')
    price = request.form.get('price')
    
    if not price or not price.replace('.', '', 1).isdigit():
        return jsonify({'success': False, 'message': 'Invalid price format'})
    
    conn = get_db_connection()
    
    # Check if price entry exists
    existing = conn.execute(
        'SELECT id FROM trainer_pricing WHERE trainer_id = ?', 
        (trainer_id,)
    ).fetchone()
    
    if existing:
        conn.execute(
            'UPDATE trainer_pricing SET price_per_session = ?, updated_at = ? WHERE trainer_id = ?',
            (price, datetime.now(), trainer_id)
        )
    else:
        conn.execute(
            'INSERT INTO trainer_pricing (trainer_id, price_per_session, updated_at) VALUES (?, ?, ?)',
            (trainer_id, price, datetime.now())
        )
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Trainer session price updated successfully.'})

@app.route('/use-trainer-session', methods=['POST'])
def use_trainer_session():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = session['user_id']
    trainer_id = request.form.get('trainer_id')
    
    conn = get_db_connection()
    
    # Find active trainer session subscription for this trainer
    subscription = conn.execute(
        'SELECT * FROM subscriptions WHERE user_id = ? AND trainer_id = ? AND subscription_type = "trainer_sessions" AND status = "active" AND trainer_sessions > 0',
        (user_id, trainer_id)
    ).fetchone()
    
    if not subscription:
        conn.close()
        return jsonify({'success': False, 'message': 'No active trainer sessions found for this trainer.'})
    
    # Decrement session count
    new_sessions = subscription['trainer_sessions'] - 1
    if new_sessions <= 0:
        # Mark as expired if no sessions left
        conn.execute(
            'UPDATE subscriptions SET trainer_sessions = ?, status = "expired" WHERE id = ?',
            (new_sessions, subscription['id'])
        )
    else:
        conn.execute(
            'UPDATE subscriptions SET trainer_sessions = ? WHERE id = ?',
            (new_sessions, subscription['id'])
        )
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Trainer session used successfully.', 'remaining_sessions': new_sessions})
@app.route('/send-message', methods=['POST'])
def send_message():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = session['user_id']
    subject = request.form.get('subject')
    message = request.form.get('message')
    
    # Debug print
    print(f"Received message: subject={subject}, message={message}, user_id={user_id}")
    
    # Check if values are empty
    if not subject or not message:
        return jsonify({'success': False, 'message': 'Subject and message cannot be empty'})
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO messages (user_id, subject, message) VALUES (?, ?, ?)',
        (user_id, subject, message)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Message sent successfully'})

@app.route('/reply-message', methods=['POST'])
def reply_message():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    message_id = request.form.get('message_id')
    reply = request.form.get('reply')
    
    print(f"Replying to message with ID: {message_id}")  # Debug print
    
    if not message_id:
        return jsonify({'success': False, 'message': 'Message ID is required'})
    
    if not reply:
        return jsonify({'success': False, 'message': 'Reply text is required'})
    
    conn = get_db_connection()
    
    # Check if message exists
    message = conn.execute('SELECT * FROM messages WHERE id = ?', (message_id,)).fetchone()
    if not message:
        conn.close()
        return jsonify({'success': False, 'message': 'Message not found'})
    
    try:
        conn.execute(
            'UPDATE messages SET reply = ?, replied_at = ? WHERE id = ?',
            (reply, datetime.now(), message_id)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Reply sent successfully'})
    except Exception as e:
        print(f"Error replying to message: {e}")  # Debug print
        conn.close()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'})

@app.route('/create-blog', methods=['POST'])
def create_blog():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    title = request.form.get('title')
    content = request.form.get('content')
    image_path = None
    
    # Handle image upload
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid filename conflicts
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{timestamp}_{filename}"
            
            try:
                image_path = resize_and_save_image(file, filename)
                # Convert to relative path for database storage
                image_path = image_path.replace('\\', '/')  # Ensure forward slashes
            except Exception as e:
                return jsonify({'success': False, 'message': f'Error processing image: {str(e)}'})
    
    # Check if title is empty
    if not title:
        return jsonify({'success': False, 'message': 'Title cannot be empty'})
    
    # Check if content is empty
    if not content:
        return jsonify({'success': False, 'message': 'Content cannot be empty'})
    
    author_id = session['user_id']
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO blogs (title, content, image_path, author_id) VALUES (?, ?, ?, ?)',
        (title, content, image_path, author_id)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Blog created successfully'})

@app.route('/edit-blog', methods=['POST'])
def edit_blog():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    blog_id = request.form.get('blog_id')
    title = request.form.get('title')
    content = request.form.get('content')
    
    conn = get_db_connection()
    
    # Get current blog to check if we need to delete old image
    current_blog = conn.execute('SELECT * FROM blogs WHERE id = ?', (blog_id,)).fetchone()
    old_image_path = current_blog['image_path'] if current_blog else None
    
    image_path = old_image_path  # Default to existing image
    
    # Handle image upload
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid filename conflicts
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{timestamp}_{filename}"
            
            try:
                # Delete old image if it exists
                if old_image_path and os.path.exists(old_image_path):
                    os.remove(old_image_path)
                
                # Process and save new image
                image_path = resize_and_save_image(file, filename)
                # Convert to relative path for database storage
                image_path = image_path.replace('\\', '/')  # Ensure forward slashes
            except Exception as e:
                conn.close()
                return jsonify({'success': False, 'message': f'Error processing image: {str(e)}'})
    
    conn.execute(
        'UPDATE blogs SET title = ?, content = ?, image_path = ? WHERE id = ?',
        (title, content, image_path, blog_id)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Blog updated successfully'})

@app.route('/delete-blog', methods=['POST'])
def delete_blog():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    blog_id = request.form.get('blog_id')
    
    conn = get_db_connection()
    
    # Get blog info to delete associated image
    blog = conn.execute('SELECT * FROM blogs WHERE id = ?', (blog_id,)).fetchone()
    
    # Delete the blog
    conn.execute('DELETE FROM blogs WHERE id = ?', (blog_id,))
    conn.commit()
    conn.close()
    
    # Delete the image file if it exists
    if blog and blog['image_path'] and os.path.exists(blog['image_path']):
        try:
            os.remove(blog['image_path'])
        except Exception as e:
            print(f"Error deleting image: {e}")
    
    return jsonify({'success': True, 'message': 'Blog deleted successfully'})
@app.route('/check-in-out', methods=['POST'])
def check_in_out():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = session['user_id']
    qr_value = request.form.get('qr_value')
    
    print(f"QR value received: {qr_value}")  # Debug print
    
    conn = get_db_connection()
    
    # Get user role
    user = conn.execute('SELECT role FROM users WHERE id = ?', (user_id,)).fetchone()
    print(f"User role: {user['role'] if user else 'None'}")  # Debug print
    
    # Get QR code
    qr_code = conn.execute('SELECT * FROM qr_codes WHERE code_value = ?', (qr_value,)).fetchone()
    print(f"QR code found: {qr_code is not None}")  # Debug print
    
    if not qr_code:
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid QR code'})
    
    # Check if QR code matches user role
    if (user['role'] == 'user' and qr_code['code_type'] != 'user') or \
       (user['role'] == 'trainer' and qr_code['code_type'] != 'trainer'):
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid QR code for your role'})
    
    # Check last check-in/out
    last_check = conn.execute(
        'SELECT * FROM check_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1',
        (user_id,)
    ).fetchone()
    
    check_type = 'in'
    if last_check and last_check['check_type'] == 'in':
        check_type = 'out'
    
    # Record check-in/out
    conn.execute(
        'INSERT INTO check_logs (user_id, check_type) VALUES (?, ?)',
        (user_id, check_type)
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': f'Check-{check_type} successful',
        'check_type': check_type
    })

@app.route('/generate-qr-codes')
def generate_qr_codes():
    if not is_logged_in() or get_user_role() != 'admin':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    
    # Get current user data
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    # Generate new QR codes
    user_qr = f"USER-{random.randint(100000, 999999)}"
    trainer_qr = f"TRAINER-{random.randint(100000, 999999)}"
    
    # Update QR codes in database
    conn.execute('UPDATE qr_codes SET code_value = ? WHERE code_type = "user"', (user_qr,))
    conn.execute('UPDATE qr_codes SET code_value = ? WHERE code_type = "trainer"', (trainer_qr,))
    
    conn.commit()
    
    # Get updated QR codes
    user_qr_record = conn.execute('SELECT code_value FROM qr_codes WHERE code_type = "user"').fetchone()
    trainer_qr_record = conn.execute('SELECT code_value FROM qr_codes WHERE code_type = "trainer"').fetchone()
    
    conn.close()
    
    # Generate QR code images
    user_qr_img = qrcode.make(user_qr_record['code_value'])
    trainer_qr_img = qrcode.make(trainer_qr_record['code_value'])
    
    # Convert to base64 for display
    user_qr_buffer = io.BytesIO()
    user_qr_img.save(user_qr_buffer, format='PNG')
    user_qr_buffer.seek(0)
    user_qr_base64 = base64.b64encode(user_qr_buffer.getvalue()).decode()
    
    trainer_qr_buffer = io.BytesIO()
    trainer_qr_img.save(trainer_qr_buffer, format='PNG')
    trainer_qr_buffer.seek(0)
    trainer_qr_base64 = base64.b64encode(trainer_qr_buffer.getvalue()).decode()
    
    return render_template(
        'main.html',
        user=user,
        role='admin',
        page='qr_codes',
        user_qr_base64=user_qr_base64,
        trainer_qr_base64=trainer_qr_base64,
        user_qr_value=user_qr_record['code_value'],
        trainer_qr_value=trainer_qr_record['code_value']
    )
    
@app.route('/get-checked-in-users')
def get_checked_in_users():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    conn = get_db_connection()
    
    # Get all users whose last check was "in"
    checked_in_users = conn.execute('''
        SELECT u.id, u.username, u.role, cl.timestamp as check_in_time
        FROM users u
        INNER JOIN check_logs cl ON u.id = cl.user_id
        INNER JOIN (
            SELECT user_id, MAX(timestamp) as last_timestamp
            FROM check_logs
            GROUP BY user_id
        ) latest ON cl.user_id = latest.user_id AND cl.timestamp = latest.last_timestamp
        WHERE cl.check_type = 'in'
        ORDER BY cl.timestamp DESC
    ''').fetchall()
    
    conn.close()
    
    return jsonify({
        'success': True,
        'users': [dict(user) for user in checked_in_users]
    })
    
@app.route('/get-attendance-records', methods=['POST'])
def get_attendance_records():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    username = request.form.get('username', '')
    start_date = request.form.get('start_date', '')
    end_date = request.form.get('end_date', '')
    
    conn = get_db_connection()
    
    # Build the query with optional filters
    query = '''
        SELECT u.id, u.username, u.role, cl.check_type, cl.timestamp
        FROM users u
        INNER JOIN check_logs cl ON u.id = cl.user_id
        WHERE 1=1
    '''
    params = []
    
    if username:
        query += ' AND u.username LIKE ?'
        params.append(f'%{username}%')
    
    if start_date:
        query += ' AND DATE(cl.timestamp) >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND DATE(cl.timestamp) <= ?'
        params.append(end_date)
    
    query += ' ORDER BY cl.timestamp DESC'
    
    attendance_records = conn.execute(query, params).fetchall()
    
    # Calculate total check-in days for each user
    user_days = {}
    for record in attendance_records:
        user_id = record['id']
        check_date = record['timestamp'].split(' ')[0]  # Extract date part
        
        if user_id not in user_days:
            user_days[user_id] = set()
        
        # Only count days where the user checked in
        if record['check_type'] == 'in':
            user_days[user_id].add(check_date)
    
    # Convert to dict with count
    user_checkin_days = {user_id: len(days) for user_id, days in user_days.items()}
    
    conn.close()
    
    # Add check-in days count to each record
    records_with_days = []
    for record in attendance_records:
        record_dict = dict(record)
        record_dict['checkin_days'] = user_checkin_days.get(record['id'], 0)
        records_with_days.append(record_dict)
    
    return jsonify({
        'success': True,
        'records': records_with_days
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)