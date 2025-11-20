from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
import sqlite3
import random
import string
import qrcode
import io
import base64
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = 'gym_app_secret_key_12345'

# Database initialization
def init_db():
    conn = sqlite3.connect('database/gym.db')
    cursor = conn.cursor()
    
    # Users table
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
    
    # Subscriptions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        plan TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        payment_verified INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        author_id INTEGER,
        FOREIGN KEY (author_id) REFERENCES users (id)
    )
    ''')
    
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
    
    # Check if admin exists, if not create one
    cursor.execute("SELECT * FROM users WHERE role='admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, email, role, approved) VALUES (?, ?, ?, ?, ?)",
                      ('admin', 'admin123', 'admin@gym.com', 'admin', 1))
    
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
    conn.close()
    
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        return redirect(url_for('main'))
    else:
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
        # OTP is valid, create the user
        temp_user = session['temp_user']
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
            (temp_user['username'], temp_user['password'], temp_user['email'], temp_user['role'])
        )
        conn.commit()
        conn.close()
        
        # Clear temporary session data
        session.pop('temp_user', None)
        session.pop('otp_email', None)
        
        flash('Registration successful! Please wait for admin approval.', 'success')
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
    
    # Get subscription info
    subscription = conn.execute(
        'SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
        (user_id,)
    ).fetchone()
    
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
        subscription=subscription,
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
    # Get all subscriptions (not just pending)
    all_subscriptions = conn.execute(
        'SELECT s.*, u.username, u.email FROM subscriptions s JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC'
    ).fetchall()
    
    # Get pending subscriptions
    pending_subscriptions = [s for s in all_subscriptions if s['status'] == 'pending']
    
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
        user=user,  # Add this line
        role='admin',  # Add this line
        page='admin',
        users=users,
        all_subscriptions=all_subscriptions,
        pending_subscriptions=pending_subscriptions,
        all_messages=all_messages,
        all_blogs=all_blogs,
        user_qr=user_qr['code_value'] if user_qr else None,
        trainer_qr=trainer_qr['code_value'] if trainer_qr else None
    )

@app.route('/create-user', methods=['POST'])
def create_user():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    role = request.form.get('role')
    approved = 1 if request.form.get('approved') == 'on' else 0
    
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
        (username, password, email, role, approved)
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
    approved = 1 if request.form.get('approved') == 'on' else 0
    
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
            (username, password, email, role, approved, user_id)
        )
    else:
        conn.execute(
            'UPDATE users SET username = ?, email = ?, role = ?, approved = ? WHERE id = ?',
            (username, email, role, approved, user_id)
        )
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'User updated successfully'})

@app.route('/delete-user', methods=['POST'])
def delete_user():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = request.form.get('user_id')
    
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

@app.route('/create-subscription', methods=['POST'])
def create_subscription():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = session['user_id']
    plan = request.form.get('plan')
    
    conn = get_db_connection()
    
    # Check if user already has an active subscription
    existing_subscription = conn.execute(
        'SELECT * FROM subscriptions WHERE user_id = ? AND status = "active"',
        (user_id,)
    ).fetchone()
    
    if existing_subscription:
        conn.close()
        return jsonify({'success': False, 'message': 'You already have an active subscription'})
    
    conn.execute(
        'INSERT INTO subscriptions (user_id, plan, status) VALUES (?, ?, ?)',
        (user_id, plan, 'pending')
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Subscription created successfully'})

@app.route('/approve-subscription', methods=['POST'])
def approve_subscription():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    subscription_id = request.form.get('subscription_id')
    
    conn = get_db_connection()
    conn.execute(
        'UPDATE subscriptions SET status = "active", payment_verified = 1 WHERE id = ?',
        (subscription_id,)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Subscription approved successfully'})

@app.route('/reject-subscription', methods=['POST'])
def reject_subscription():
    if not is_logged_in() or get_user_role() != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    subscription_id = request.form.get('subscription_id')
    
    conn = get_db_connection()
    conn.execute(
        'UPDATE subscriptions SET status = "rejected" WHERE id = ?',
        (subscription_id,)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Subscription rejected successfully'})

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
    
    # Check if title is empty
    if not title:
        return jsonify({'success': False, 'message': 'Title cannot be empty'})
    
    # Check if content is empty
    if not content:
        return jsonify({'success': False, 'message': 'Content cannot be empty'})
    
    author_id = session['user_id']
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO blogs (title, content, author_id) VALUES (?, ?, ?)',
        (title, content, author_id)
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
    conn.execute(
        'UPDATE blogs SET title = ?, content = ? WHERE id = ?',
        (title, content, blog_id)
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
    conn.execute('DELETE FROM blogs WHERE id = ?', (blog_id,))
    conn.commit()
    conn.close()
    
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
        user=user,  # Add this line
        role='admin',  # Add this line
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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)