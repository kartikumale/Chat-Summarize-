import os
import sqlite3
import secrets
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    print("Warning: PIL (Pillow) not available. Image resizing disabled.")
    PIL_AVAILABLE = False
    Image = None
from dotenv import load_dotenv
from groq_service import GroqChatSummarizer
import json
import re



app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

load_dotenv()

groq_summarizer = GroqChatSummarizer()

# Add the nl2br filter
@app.template_filter('nl2br')
def nl2br_filter(text):
    """Convert newlines to HTML break tags"""
    if text:
        # Replace \n with <br> tags
        return text.replace('\n', '<br>')
    return text

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'pdf', 'doc', 'docx', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect('chat.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Admin access required.')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def login_or_admin_required(f):
    """Allow access if user is logged in OR admin is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session and 'admin_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_user_blocked():
    """Check if current user is blocked"""
    if 'user_id' in session:
        conn = get_db_connection()
        user = conn.execute('SELECT is_blocked FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        if user and user['is_blocked']:
            session.clear()
            flash('Your account has been blocked.')
            return redirect(url_for('login'))
    return None

def check_user_blocked_if_user():
    """Check if current user is blocked (only applies to regular users, not admins)"""
    if 'user_id' in session:
        conn = get_db_connection()
        user = conn.execute('SELECT is_blocked FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        if user and user['is_blocked']:
            session.clear()
            flash('Your account has been blocked.')
            return redirect(url_for('login'))
    return None

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    elif 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required!')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match!')
            return render_template('register.html')
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long!')
            return render_template('register.html')
        
        conn = get_db_connection()
        
        # Check if user exists
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('Username or email already exists!')
            conn.close()
            return render_template('register.html')
        
        # Create user
        password_hash = generate_password_hash(password)
        try:
            conn.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Registration failed. Please try again.')
            return render_template('register.html')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if not username or not password:
            flash('Username and password are required!')
            return render_template('login.html')
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and not user['is_blocked'] and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Welcome back, {user["username"]}!')
            return redirect(url_for('dashboard'))
        else:
            if user and user['is_blocked']:
                flash('Your account has been blocked. Please contact an administrator.')
            else:
                flash('Invalid username or password!')
    
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        conn = get_db_connection()
        admin = conn.execute(
            'SELECT * FROM admins WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if admin and check_password_hash(admin['password_hash'], password):
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            flash(f'Admin logged in successfully!')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials!')
    
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    username = session.get('username') or session.get('admin_username')
    session.clear()
    if username:
        flash(f'Goodbye, {username}!')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Check if user is blocked
    blocked_check = check_user_blocked()
    if blocked_check:
        return blocked_check
    
    conn = get_db_connection()
    
    # Get all users for private chat (excluding blocked users and self)
    users = conn.execute(
        'SELECT id, username FROM users WHERE id != ? AND is_blocked = 0 ORDER BY username',
        (session['user_id'],)
    ).fetchall()
    
    # Get user's groups
    groups = conn.execute('''
        SELECT g.id, g.name, g.description, gm.role
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.user_id = ?
        ORDER BY g.name
    ''', (session['user_id'],)).fetchall()
    
    # Get recent private chats with last message info
    recent_private = conn.execute('''
        SELECT DISTINCT u.id, u.username,
               (SELECT message_text FROM messages 
                WHERE (sender_id = ? AND recipient_id = u.id) 
                   OR (sender_id = u.id AND recipient_id = ?)
                ORDER BY created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM messages 
                WHERE (sender_id = ? AND recipient_id = u.id) 
                   OR (sender_id = u.id AND recipient_id = ?)
                ORDER BY created_at DESC LIMIT 1) as last_message_time
        FROM users u
        WHERE EXISTS (
            SELECT 1 FROM messages m 
            WHERE (m.sender_id = ? AND m.recipient_id = u.id) 
               OR (m.sender_id = u.id AND m.recipient_id = ?)
        ) AND u.is_blocked = 0
        ORDER BY last_message_time DESC
        LIMIT 10
    ''', (session['user_id'], session['user_id'], session['user_id'], 
          session['user_id'], session['user_id'], session['user_id'])).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', users=users, groups=groups, recent_private=recent_private)

@app.route('/chat/<chat_type>/<int:chat_id>')
@login_or_admin_required
def chat(chat_type, chat_id):
    # Check if user is blocked (only for regular users, not admins)
    if 'user_id' in session:
        blocked_check = check_user_blocked_if_user()
        if blocked_check:
            return blocked_check
    
    conn = get_db_connection()
    
    # Determine if current session is admin
    is_admin = 'admin_id' in session
    current_user_id = session.get('user_id') if not is_admin else None
    
    if chat_type == 'private':
        if is_admin:
            # Admin can view any private chat - get all messages for this user
            messages = conn.execute('''
                SELECT m.*, u.username as sender_username
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE message_type = 'private' 
                AND (recipient_id = ? OR sender_id = ?)
                ORDER BY created_at ASC
            ''', (chat_id, chat_id)).fetchall()
            
            # Get the user info for chat header
            other_user = conn.execute(
                'SELECT id, username FROM users WHERE id = ?', (chat_id,)
            ).fetchone()
            
            if not other_user:
                flash('User not found!')
                conn.close()
                return redirect(url_for('admin_dashboard'))
            
            chat_info = {
                'type': 'private',
                'id': chat_id,
                'name': f"All Private Messages - {other_user['username']} (Admin View)",
                'can_write': False,  # Admin viewing mode, cannot send messages
                'is_admin_view': True
            }
        else:
            # Regular user private chat logic (existing code)
            other_user = conn.execute(
                'SELECT id, username FROM users WHERE id = ? AND is_blocked = 0',
                (chat_id,)
            ).fetchone()
            
            if not other_user:
                flash('User not found or blocked!')
                conn.close()
                return redirect(url_for('dashboard'))
            
            messages = conn.execute('''
                SELECT m.*, u.username as sender_username
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE message_type = 'private' 
                AND ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))
                ORDER BY created_at ASC
            ''', (current_user_id, chat_id, chat_id, current_user_id)).fetchall()
            
            chat_info = {
                'type': 'private',
                'id': chat_id,
                'name': other_user['username'],
                'can_write': True,
                'is_admin_view': False
            }
    
    else:  # group chat
        if is_admin:
            # Admin can view any group chat
            group = conn.execute('SELECT * FROM groups WHERE id = ?', (chat_id,)).fetchone()
            
            if not group:
                flash('Group not found!')
                conn.close()
                return redirect(url_for('admin_groups'))
            
            # Get all group messages
            messages = conn.execute('''
                SELECT m.*, u.username as sender_username
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE message_type = 'group' AND group_id = ?
                ORDER BY created_at ASC
            ''', (chat_id,)).fetchall()
            
            chat_info = {
                'type': 'group',
                'id': chat_id,
                'name': f"{group['name']} (Admin View)",
                'can_write': False,  # Admin viewing mode, cannot send messages
                'is_admin_view': True
            }
        else:
            # Regular user group chat logic (existing code)
            membership = conn.execute('''
                SELECT gm.role, g.name, g.description
                FROM group_members gm
                JOIN groups g ON gm.group_id = g.id
                WHERE gm.group_id = ? AND gm.user_id = ?
            ''', (chat_id, current_user_id)).fetchone()
            
            if not membership:
                flash('You are not a member of this group!')
                conn.close()
                return redirect(url_for('dashboard'))
            
            messages = conn.execute('''
                SELECT m.*, u.username as sender_username
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE message_type = 'group' AND group_id = ?
                ORDER BY created_at ASC
            ''', (chat_id,)).fetchall()
            
            chat_info = {
                'type': 'group',
                'id': chat_id,
                'name': membership['name'],
                'can_write': membership['role'] == 'read_write',
                'is_admin_view': False
            }
    
    conn.close()
    
    return render_template('chat.html', messages=messages, chat_info=chat_info)

@app.route('/send_message', methods=['POST'])
@login_required  # Only regular users can send messages
def send_message():
    # Check if user is blocked
    blocked_check = check_user_blocked_if_user()
    if blocked_check:
        return blocked_check
    
    chat_type = request.form['chat_type']
    chat_id = int(request.form['chat_id'])
    message_text = request.form.get('message_text', '').strip()
    
    conn = get_db_connection()
    
    # Handle file upload
    media_filename = None
    media_type = None
    
    if 'media_file' in request.files:
        file = request.files['media_file']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to prevent conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                media_filename = filename
                media_type = filename.rsplit('.', 1)[1].lower()
                
                # Resize images if they're too large
                if media_type in ['jpg', 'jpeg', 'png'] and PIL_AVAILABLE:
                    try:
                        with Image.open(file_path) as img:
                            if img.width > 1920 or img.height > 1080:
                                img.thumbnail((1920, 1080), Image.Resampling.LANCZOS)
                                img.save(file_path, optimize=True, quality=85)
                    except Exception as e:
                        print(f"Error resizing image: {e}")
                elif media_type in ['jpg', 'jpeg', 'png'] and not PIL_AVAILABLE:
                    print("Warning: Image resizing disabled - PIL not available")
                        
            except Exception as e:
                flash('Error uploading file. Please try again.')
                conn.close()
                return redirect(url_for('chat', chat_type=chat_type, chat_id=chat_id))
    
    # Validate message
    if not message_text and not media_filename:
        flash('Message cannot be empty!')
        conn.close()
        return redirect(url_for('chat', chat_type=chat_type, chat_id=chat_id))
    
    # Check permissions and insert message
    try:
        if chat_type == 'private':
            # Check if other user is not blocked
            other_user = conn.execute(
                'SELECT is_blocked FROM users WHERE id = ?', (chat_id,)
            ).fetchone()
            
            if not other_user or other_user['is_blocked']:
                flash('Cannot send message to this user!')
                conn.close()
                return redirect(url_for('dashboard'))
            
            # Insert message
            conn.execute('''
                INSERT INTO messages (sender_id, recipient_id, message_text, media_filename, media_type, message_type)
                VALUES (?, ?, ?, ?, ?, 'private')
            ''', (session['user_id'], chat_id, message_text, media_filename, media_type))
        
        else:  # group
            # Check if user can write to group
            membership = conn.execute(
                'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
                (chat_id, session['user_id'])
            ).fetchone()
            
            if not membership or membership['role'] != 'read_write':
                flash('You do not have permission to send messages to this group!')
                conn.close()
                return redirect(url_for('chat', chat_type=chat_type, chat_id=chat_id))
            
            # Insert message
            conn.execute('''
                INSERT INTO messages (sender_id, group_id, message_text, media_filename, media_type, message_type)
                VALUES (?, ?, ?, ?, ?, 'group')
            ''', (session['user_id'], chat_id, message_text, media_filename, media_type))
        
        conn.commit()
        flash('Message sent successfully!')
        
    except Exception as e:
        flash('Error sending message. Please try again.')
        print(f"Error sending message: {e}")
    finally:
        conn.close()
    
    return redirect(url_for('chat', chat_type=chat_type, chat_id=chat_id))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# AJAX endpoint for fetching new messages
@app.route('/api/messages/<chat_type>/<int:chat_id>')
@login_or_admin_required
def api_messages(chat_type, chat_id):
    # Check if user is blocked (only for regular users)
    if 'user_id' in session:
        blocked_check = check_user_blocked_if_user()
        if blocked_check:
            return jsonify({'error': 'User blocked'}), 403
    
    last_message_id = request.args.get('last_id', 0, type=int)
    is_admin = 'admin_id' in session
    current_user_id = session.get('user_id') if not is_admin else None
    
    conn = get_db_connection()
    
    try:
        if chat_type == 'private':
            if is_admin:
                # Admin can see all private messages for the user
                messages = conn.execute('''
                    SELECT m.*, u.username as sender_username
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE message_type = 'private' 
                    AND (recipient_id = ? OR sender_id = ?)
                    AND m.id > ?
                    ORDER BY created_at ASC
                ''', (chat_id, chat_id, last_message_id)).fetchall()
            else:
                # Regular user private messages
                messages = conn.execute('''
                    SELECT m.*, u.username as sender_username
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE message_type = 'private' 
                    AND ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))
                    AND m.id > ?
                    ORDER BY created_at ASC
                ''', (current_user_id, chat_id, chat_id, current_user_id, last_message_id)).fetchall()
        
        else:  # group
            if is_admin:
                # Admin can see all group messages
                messages = conn.execute('''
                    SELECT m.*, u.username as sender_username
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE message_type = 'group' AND group_id = ? AND m.id > ?
                    ORDER BY created_at ASC
                ''', (chat_id, last_message_id)).fetchall()
            else:
                # Check if user is member
                membership = conn.execute(
                    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
                    (chat_id, current_user_id)
                ).fetchone()
                
                if not membership:
                    return jsonify({'error': 'Not a group member'}), 403
                
                messages = conn.execute('''
                    SELECT m.*, u.username as sender_username
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE message_type = 'group' AND group_id = ? AND m.id > ?
                    ORDER BY created_at ASC
                ''', (chat_id, last_message_id)).fetchall()
        
        return jsonify([dict(msg) for msg in messages])
        
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

# Admin Routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    
    # Get statistics
    stats = {
        'total_users': conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count'],
        'total_groups': conn.execute('SELECT COUNT(*) as count FROM groups').fetchone()['count'],
        'total_messages': conn.execute('SELECT COUNT(*) as count FROM messages').fetchone()['count'],
        'blocked_users': conn.execute('SELECT COUNT(*) as count FROM users WHERE is_blocked = 1').fetchone()['count']
    }
    
    # Recent activity
    recent_messages = conn.execute('''
        SELECT m.*, u.username as sender_username,
               CASE 
                   WHEN m.message_type = 'private' THEN ru.username
                   WHEN m.message_type = 'group' THEN g.name
               END as target_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        LEFT JOIN users ru ON m.recipient_id = ru.id
        LEFT JOIN groups g ON m.group_id = g.id
        ORDER BY m.created_at DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', stats=stats, recent_messages=recent_messages)

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/toggle_user_block/<int:user_id>')
@admin_required
def toggle_user_block(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT is_blocked, username FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user:
        new_status = 1 - user['is_blocked']  # Toggle between 0 and 1
        conn.execute('UPDATE users SET is_blocked = ? WHERE id = ?', (new_status, user_id))
        conn.commit()
        
        action = "blocked" if new_status else "unblocked"
        flash(f'User "{user["username"]}" has been {action}!')
    else:
        flash('User not found!')
    
    conn.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/groups')
@admin_required
def admin_groups():
    conn = get_db_connection()
    groups = conn.execute('''
        SELECT g.*, COUNT(gm.user_id) as member_count
        FROM groups g
        LEFT JOIN group_members gm ON g.id = gm.group_id
        GROUP BY g.id
        ORDER BY g.created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('admin_groups.html', groups=groups)

@app.route('/admin/create_group', methods=['GET', 'POST'])
@admin_required
def create_group():
    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form.get('description', '').strip()
        member_ids = request.form.getlist('members')
        member_roles = request.form.getlist('roles')
        
        if not name:
            flash('Group name is required!')
            return redirect(url_for('create_group'))
        
        if not member_ids:
            flash('At least one member is required!')
            return redirect(url_for('create_group'))
        
        conn = get_db_connection()
        
        try:
            # Create group
            cursor = conn.execute(
                'INSERT INTO groups (name, description, created_by) VALUES (?, ?, ?)',
                (name, description, session['admin_id'])
            )
            group_id = cursor.lastrowid
            
            # Add members
            for i, member_id in enumerate(member_ids):
                role = member_roles[i] if i < len(member_roles) else 'read_write'
                conn.execute(
                    'INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
                    (group_id, member_id, role)
                )
            
            conn.commit()
            flash(f'Group "{name}" created successfully!')
            return redirect(url_for('admin_groups'))
            
        except Exception as e:
            flash('Error creating group. Please try again.')
            print(f"Error creating group: {e}")
        finally:
            conn.close()
    
    # GET request - show form
    conn = get_db_connection()
    users = conn.execute('SELECT id, username FROM users WHERE is_blocked = 0 ORDER BY username').fetchall()
    conn.close()
    
    return render_template('create_group.html', users=users)

@app.route('/admin/messages')
@admin_required
def admin_messages():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    # Get filter parameters
    search = request.args.get('search', '').strip()
    message_type = request.args.get('type', '').strip()
    date_from = request.args.get('date_from', '').strip()
    
    conn = get_db_connection()
    
    # Build query with filters
    query = '''
        SELECT m.*, u.username as sender_username,
               CASE 
                   WHEN m.message_type = 'private' THEN ru.username
                   WHEN m.message_type = 'group' THEN g.name
               END as target_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        LEFT JOIN users ru ON m.recipient_id = ru.id
        LEFT JOIN groups g ON m.group_id = g.id
        WHERE 1=1
    '''
    
    params = []
    
    if search:
        query += ' AND (m.message_text LIKE ? OR u.username LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    
    if message_type:
        query += ' AND m.message_type = ?'
        params.append(message_type)
    
    if date_from:
        query += ' AND DATE(m.created_at) >= ?'
        params.append(date_from)
    
    # Get total count for pagination
    count_query = query.replace('SELECT m.*, u.username as sender_username,', 'SELECT COUNT(*) as count,').replace('CASE WHEN m.message_type = \'private\' THEN ru.username WHEN m.message_type = \'group\' THEN g.name END as target_name', '1')
    total_messages = conn.execute(count_query, params).fetchone()['count']
    
    # Add ordering and pagination
    query += ' ORDER BY m.created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    messages = conn.execute(query, params).fetchall()
    
    conn.close()
    
    return render_template('admin_messages.html', 
                         messages=messages, 
                         page=page, 
                         per_page=per_page,
                         total_messages=total_messages)

@app.route('/admin/delete_message/<int:message_id>')
@admin_required
def delete_message(message_id):
    conn = get_db_connection()
    
    try:
        # Get message info to delete media file if exists
        message = conn.execute('SELECT media_filename FROM messages WHERE id = ?', (message_id,)).fetchone()
        
        if message and message['media_filename']:
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], message['media_filename'])
            if os.path.exists(media_path):
                try:
                    os.remove(media_path)
                except Exception as e:
                    print(f"Error deleting media file: {e}")
        
        # Delete message
        conn.execute('DELETE FROM messages WHERE id = ?', (message_id,))
        conn.commit()
        flash('Message deleted successfully!')
        
    except Exception as e:
        flash('Error deleting message.')
        print(f"Error deleting message: {e}")
    finally:
        conn.close()
    
    return redirect(url_for('admin_messages'))

@app.route('/admin/bulk_delete_by_user', methods=['POST'])
@admin_required
def bulk_delete_by_user():
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    conn = get_db_connection()
    
    try:
        # Get user ID
        user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get all media files from this user's messages
        media_files = conn.execute(
            'SELECT media_filename FROM messages WHERE sender_id = ? AND media_filename IS NOT NULL',
            (user['id'],)
        ).fetchall()
        
        # Delete media files
        for media in media_files:
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], media['media_filename'])
            if os.path.exists(media_path):
                try:
                    os.remove(media_path)
                except Exception as e:
                    print(f"Error deleting media file: {e}")
        
        # Delete all messages from user
        deleted_count = conn.execute('DELETE FROM messages WHERE sender_id = ?', (user['id'],)).rowcount
        conn.commit()
        
        return jsonify({'success': True, 'deleted_count': deleted_count})
        
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/admin/bulk_delete_by_date', methods=['POST'])
@admin_required
def bulk_delete_by_date():
    data = request.get_json()
    date_from = data.get('date_from')
    date_to = data.get('date_to')
    
    if not date_from or not date_to:
        return jsonify({'error': 'Both dates required'}), 400
    
    conn = get_db_connection()
    
    try:
        # Get all media files in date range
        media_files = conn.execute(
            'SELECT media_filename FROM messages WHERE DATE(created_at) BETWEEN ? AND ? AND media_filename IS NOT NULL',
            (date_from, date_to)
        ).fetchall()
        
        # Delete media files
        for media in media_files:
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], media['media_filename'])
            if os.path.exists(media_path):
                try:
                    os.remove(media_path)
                except Exception as e:
                    print(f"Error deleting media file: {e}")
        
        # Delete messages in date range
        deleted_count = conn.execute(
            'DELETE FROM messages WHERE DATE(created_at) BETWEEN ? AND ?',
            (date_from, date_to)
        ).rowcount
        conn.commit()
        
        return jsonify({'success': True, 'deleted_count': deleted_count})
        
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()


# Add these new routes to your app.py file (after the existing admin routes)

@app.route('/admin/group_messages/<int:group_id>')
@admin_required
def admin_group_messages(group_id):
    """View and manage all messages in a specific group"""
    conn = get_db_connection()
    
    # Get group info
    group = conn.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    if not group:
        flash('Group not found!')
        conn.close()
        return redirect(url_for('admin_groups'))
    
    # Get group members
    members = conn.execute('''
        SELECT u.username, gm.role, gm.added_at
        FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = ?
        ORDER BY u.username
    ''', (group_id,)).fetchall()
    
    # Get all messages in this group with pagination
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    # Get filter parameters
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '').strip()
    
    query = '''
        SELECT m.*, u.username as sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.message_type = 'group' AND m.group_id = ?
    '''
    params = [group_id]
    
    if search:
        query += ' AND (m.message_text LIKE ? OR u.username LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    
    if date_from:
        query += ' AND DATE(m.created_at) >= ?'
        params.append(date_from)
    
    # Get total count for pagination
    count_query = query.replace('SELECT m.*, u.username as sender_username', 'SELECT COUNT(*) as count')
    total_messages = conn.execute(count_query, params).fetchone()['count']
    
    # Add ordering and pagination
    query += ' ORDER BY m.created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    messages = conn.execute(query, params).fetchall()
    
    conn.close()
    
    return render_template('admin_group_messages.html', 
                         group=group, 
                         members=members,
                         messages=messages, 
                         page=page, 
                         per_page=per_page,
                         total_messages=total_messages)

@app.route('/admin/delete_group_message/<int:message_id>')
@admin_required
def delete_group_message(message_id):
    """Delete a specific group message"""
    conn = get_db_connection()
    
    try:
        # Get message info to delete media file if exists and get group_id for redirect
        message = conn.execute(
            'SELECT media_filename, group_id FROM messages WHERE id = ? AND message_type = "group"', 
            (message_id,)
        ).fetchone()
        
        if not message:
            flash('Message not found!')
            conn.close()
            return redirect(url_for('admin_groups'))
        
        group_id = message['group_id']
        
        # Delete media file if exists
        if message['media_filename']:
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], message['media_filename'])
            if os.path.exists(media_path):
                try:
                    os.remove(media_path)
                except Exception as e:
                    print(f"Error deleting media file: {e}")
        
        # Delete message
        conn.execute('DELETE FROM messages WHERE id = ?', (message_id,))
        conn.commit()
        flash('Group message deleted successfully!')
        
        conn.close()
        return redirect(url_for('admin_group_messages', group_id=group_id))
        
    except Exception as e:
        flash('Error deleting message.')
        print(f"Error deleting group message: {e}")
        conn.close()
        return redirect(url_for('admin_groups'))

@app.route('/admin/bulk_delete_group_messages/<int:group_id>', methods=['POST'])
@admin_required
def bulk_delete_group_messages(group_id):
    """Bulk delete all messages in a group"""
    conn = get_db_connection()
    
    try:
        # Get all media files from this group's messages
        media_files = conn.execute(
            'SELECT media_filename FROM messages WHERE group_id = ? AND media_filename IS NOT NULL',
            (group_id,)
        ).fetchall()
        
        # Delete media files
        for media in media_files:
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], media['media_filename'])
            if os.path.exists(media_path):
                try:
                    os.remove(media_path)
                except Exception as e:
                    print(f"Error deleting media file: {e}")
        
        # Delete all messages from group
        deleted_count = conn.execute(
            'DELETE FROM messages WHERE group_id = ?', 
            (group_id,)
        ).rowcount
        conn.commit()
        
        flash(f'Successfully deleted {deleted_count} messages from the group!')
        
    except Exception as e:
        flash('Error deleting group messages.')
        print(f"Error bulk deleting group messages: {e}")
    finally:
        conn.close()
    
    return redirect(url_for('admin_group_messages', group_id=group_id))

@app.route('/admin/delete_group/<int:group_id>')
@admin_required
def delete_group(group_id):
    """Delete an entire group and all its messages"""
    conn = get_db_connection()
    
    try:
        # Get group name for confirmation
        group = conn.execute('SELECT name FROM groups WHERE id = ?', (group_id,)).fetchone()
        if not group:
            flash('Group not found!')
            conn.close()
            return redirect(url_for('admin_groups'))
        
        # Get all media files from this group's messages
        media_files = conn.execute(
            'SELECT media_filename FROM messages WHERE group_id = ? AND media_filename IS NOT NULL',
            (group_id,)
        ).fetchall()
        
        # Delete media files
        for media in media_files:
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], media['media_filename'])
            if os.path.exists(media_path):
                try:
                    os.remove(media_path)
                except Exception as e:
                    print(f"Error deleting media file: {e}")
        
        # Delete all messages from group (this will cascade delete due to foreign key)
        conn.execute('DELETE FROM messages WHERE group_id = ?', (group_id,))
        
        # Delete group members (this will cascade delete due to foreign key)
        conn.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
        
        # Delete the group itself
        conn.execute('DELETE FROM groups WHERE id = ?', (group_id,))
        
        conn.commit()
        flash(f'Group "{group["name"]}" and all its messages have been deleted successfully!')
        
    except Exception as e:
        flash('Error deleting group.')
        print(f"Error deleting group: {e}")
    finally:
        conn.close()
    
    return redirect(url_for('admin_groups'))


@app.route('/summarize_chat/<chat_type>/<int:chat_id>')
@login_or_admin_required
def summarize_chat_page(chat_type, chat_id):
    """Show the chat summarization page"""
    # Check if user is blocked (only for regular users)
    if 'user_id' in session:
        blocked_check = check_user_blocked_if_user()
        if blocked_check:
            return blocked_check
    
    conn = get_db_connection()
    is_admin = 'admin_id' in session
    current_user_id = session.get('user_id') if not is_admin else None
    
    # Get chat info and verify permissions
    if chat_type == 'private':
        if is_admin:
            other_user = conn.execute(
                'SELECT id, username FROM users WHERE id = ?', (chat_id,)
            ).fetchone()
            if not other_user:
                flash('User not found!')
                conn.close()
                return redirect(url_for('admin_dashboard'))
            chat_name = f"Private Chat with {other_user['username']}"
        else:
            other_user = conn.execute(
                'SELECT id, username FROM users WHERE id = ? AND is_blocked = 0',
                (chat_id,)
            ).fetchone()
            if not other_user:
                flash('User not found or blocked!')
                conn.close()
                return redirect(url_for('dashboard'))
            chat_name = f"Private Chat with {other_user['username']}"
    
    else:  # group chat
        if is_admin:
            group = conn.execute('SELECT * FROM groups WHERE id = ?', (chat_id,)).fetchone()
            if not group:
                flash('Group not found!')
                conn.close()
                return redirect(url_for('admin_groups'))
            chat_name = group['name']
        else:
            membership = conn.execute('''
                SELECT gm.role, g.name, g.description
                FROM group_members gm
                JOIN groups g ON gm.group_id = g.id
                WHERE gm.group_id = ? AND gm.user_id = ?
            ''', (chat_id, current_user_id)).fetchone()
            
            if not membership:
                flash('You are not a member of this group!')
                conn.close()
                return redirect(url_for('dashboard'))
            chat_name = membership['name']
    
    # Get existing summaries for this chat
    existing_summaries = conn.execute('''
        SELECT * FROM chat_summaries 
        WHERE chat_type = ? AND chat_id = ?
        ORDER BY created_at DESC
        LIMIT 10
    ''', (chat_type, chat_id)).fetchall()
    
    # Get message count and date range
    if chat_type == 'private':
        if is_admin:
            stats = conn.execute('''
                SELECT COUNT(*) as count, MIN(created_at) as first_msg, MAX(created_at) as last_msg
                FROM messages 
                WHERE message_type = 'private' AND (recipient_id = ? OR sender_id = ?)
            ''', (chat_id, chat_id)).fetchone()
        else:
            stats = conn.execute('''
                SELECT COUNT(*) as count, MIN(created_at) as first_msg, MAX(created_at) as last_msg
                FROM messages 
                WHERE message_type = 'private' 
                AND ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))
            ''', (current_user_id, chat_id, chat_id, current_user_id)).fetchone()
    else:
        stats = conn.execute('''
            SELECT COUNT(*) as count, MIN(created_at) as first_msg, MAX(created_at) as last_msg
            FROM messages 
            WHERE message_type = 'group' AND group_id = ?
        ''', (chat_id,)).fetchone()
    
    conn.close()
    
    chat_info = {
        'type': chat_type,
        'id': chat_id,
        'name': chat_name,
        'is_admin': is_admin
    }
    
    return render_template('summarize_chat.html', 
                         chat_info=chat_info, 
                         existing_summaries=existing_summaries,
                         stats=stats)

@app.route('/generate_summary', methods=['POST'])
@login_or_admin_required
def generate_summary():
    """Generate a new chat summary"""
    # Check if user is blocked (only for regular users)
    if 'user_id' in session:
        blocked_check = check_user_blocked_if_user()
        if blocked_check:
            return blocked_check
    
    data = request.get_json()
    chat_type = data.get('chat_type')
    chat_id = data.get('chat_id')
    summary_length = data.get('summary_length', 'medium')
    date_from = data.get('date_from')
    date_to = data.get('date_to')
    focus_areas = data.get('focus_areas', [])
    
    if not chat_type or not chat_id:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    conn = get_db_connection()
    is_admin = 'admin_id' in session
    current_user_id = session.get('user_id') if not is_admin else None
    
    try:
        # Verify permissions and get messages
        if chat_type == 'private':
            if is_admin:
                # Admin can access any private chat
                query = '''
                    SELECT m.*, u.username as sender_username
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE message_type = 'private' 
                    AND (recipient_id = ? OR sender_id = ?)
                '''
                params = [chat_id, chat_id]
                
                # Get chat name
                other_user = conn.execute(
                    'SELECT username FROM users WHERE id = ?', (chat_id,)
                ).fetchone()
                chat_name = f"Private Chat with {other_user['username']}" if other_user else f"User {chat_id}"
            else:
                # Regular user private chat
                other_user = conn.execute(
                    'SELECT username FROM users WHERE id = ? AND is_blocked = 0',
                    (chat_id,)
                ).fetchone()
                
                if not other_user:
                    return jsonify({'error': 'User not found or blocked'}), 403
                
                query = '''
                    SELECT m.*, u.username as sender_username
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE message_type = 'private' 
                    AND ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))
                '''
                params = [current_user_id, chat_id, chat_id, current_user_id]
                chat_name = f"Private Chat with {other_user['username']}"
        
        else:  # group chat
            if is_admin:
                # Admin can access any group
                group = conn.execute('SELECT name FROM groups WHERE id = ?', (chat_id,)).fetchone()
                if not group:
                    return jsonify({'error': 'Group not found'}), 404
                
                query = '''
                    SELECT m.*, u.username as sender_username
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE message_type = 'group' AND group_id = ?
                '''
                params = [chat_id]
                chat_name = group['name']
            else:
                # Check group membership
                membership = conn.execute('''
                    SELECT g.name FROM group_members gm
                    JOIN groups g ON gm.group_id = g.id
                    WHERE gm.group_id = ? AND gm.user_id = ?
                ''', (chat_id, current_user_id)).fetchone()
                
                if not membership:
                    return jsonify({'error': 'Not a group member'}), 403
                
                query = '''
                    SELECT m.*, u.username as sender_username
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE message_type = 'group' AND group_id = ?
                '''
                params = [chat_id]
                chat_name = membership['name']
        
        # Add date filters if provided
        if date_from:
            query += ' AND DATE(m.created_at) >= ?'
            params.append(date_from)
        
        if date_to:
            query += ' AND DATE(m.created_at) <= ?'
            params.append(date_to)
        
        query += ' ORDER BY m.created_at ASC'
        
        # Get messages
        messages = conn.execute(query, params).fetchall()
        
        if not messages:
            return jsonify({'error': 'No messages found for the specified criteria'}), 404
        
        # Convert to list of dictionaries
        message_list = [dict(msg) for msg in messages]
        
        # Generate summary using Groq
        if focus_areas:
            summary_text = groq_summarizer.generate_summary_with_focus(
                message_list, chat_type, chat_name, focus_areas
            )
        else:
            summary_text = groq_summarizer.generate_summary(
                message_list, chat_type, chat_name, summary_length
            )
        
        if not summary_text:
            return jsonify({'error': 'Failed to generate summary'}), 500
        
        # Save summary to database
        creator_id = session.get('admin_id') if is_admin else session.get('user_id')
        creator_type = 'admin' if is_admin else 'user'
        
        cursor = conn.execute('''
            INSERT INTO chat_summaries 
            (chat_type, chat_id, summary_text, message_count, date_range_start, date_range_end, created_by, created_by_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            chat_type, chat_id, summary_text, len(message_list),
            messages[0]['created_at'], messages[-1]['created_at'],
            creator_id, creator_type
        ))
        
        summary_id = cursor.lastrowid
        conn.commit()
        
        return jsonify({
            'success': True,
            'summary_id': summary_id,
            'summary_text': summary_text,
            'message_count': len(message_list),
            'date_range': f"{messages[0]['created_at']} to {messages[-1]['created_at']}"
        })
        
    except Exception as e:
        print(f"Error generating summary: {e}")
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        conn.close()

@app.route('/delete_summary/<int:summary_id>')
@login_or_admin_required
def delete_summary(summary_id):
    """Delete a chat summary"""
    # Check if user is blocked (only for regular users)
    if 'user_id' in session:
        blocked_check = check_user_blocked_if_user()
        if blocked_check:
            return blocked_check
    
    conn = get_db_connection()
    is_admin = 'admin_id' in session
    current_user_id = session.get('user_id') if not is_admin else session.get('admin_id')
    
    try:
        # Get summary info
        summary = conn.execute(
            'SELECT * FROM chat_summaries WHERE id = ?', (summary_id,)
        ).fetchone()
        
        if not summary:
            flash('Summary not found!')
            conn.close()
            return redirect(url_for('dashboard'))
        
        # Check permissions - users can only delete their own summaries, admins can delete any
        if not is_admin and (summary['created_by'] != current_user_id or summary['created_by_type'] != 'user'):
            flash('You can only delete your own summaries!')
            conn.close()
            return redirect(url_for('dashboard'))
        
        # Delete summary
        conn.execute('DELETE FROM chat_summaries WHERE id = ?', (summary_id,))
        conn.commit()
        flash('Summary deleted successfully!')
        
        # Redirect back to appropriate page
        redirect_url = url_for('summarize_chat_page', 
                             chat_type=summary['chat_type'], 
                             chat_id=summary['chat_id'])
        
    except Exception as e:
        flash('Error deleting summary.')
        print(f"Error deleting summary: {e}")
        redirect_url = url_for('dashboard')
    finally:
        conn.close()
    
    return redirect(redirect_url)

@app.route('/admin/all_summaries')
@admin_required
def admin_all_summaries():
    """Admin view of all chat summaries"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    # Get filter parameters
    chat_type_filter = request.args.get('chat_type', '').strip()
    date_from = request.args.get('date_from', '').strip()
    
    conn = get_db_connection()
    
    # Build query with filters
    query = '''
        SELECT cs.*, 
               CASE 
                   WHEN cs.chat_type = 'private' THEN u.username
                   WHEN cs.chat_type = 'group' THEN g.name
               END as chat_name,
               CASE 
                   WHEN cs.created_by_type = 'admin' THEN a.username
                   WHEN cs.created_by_type = 'user' THEN cu.username
               END as creator_name
        FROM chat_summaries cs
        LEFT JOIN users u ON cs.chat_type = 'private' AND cs.chat_id = u.id
        LEFT JOIN groups g ON cs.chat_type = 'group' AND cs.chat_id = g.id
        LEFT JOIN admins a ON cs.created_by_type = 'admin' AND cs.created_by = a.id
        LEFT JOIN users cu ON cs.created_by_type = 'user' AND cs.created_by = cu.id
        WHERE 1=1
    '''
    
    params = []
    
    if chat_type_filter:
        query += ' AND cs.chat_type = ?'
        params.append(chat_type_filter)
    
    if date_from:
        query += ' AND DATE(cs.created_at) >= ?'
        params.append(date_from)
    
    # Get total count for pagination
    count_query = query.replace('SELECT cs.*,', 'SELECT COUNT(*) as count,').replace('CASE WHEN cs.chat_type = \'private\' THEN u.username WHEN cs.chat_type = \'group\' THEN g.name END as chat_name, CASE WHEN cs.created_by_type = \'admin\' THEN a.username WHEN cs.created_by_type = \'user\' THEN cu.username END as creator_name', '1')
    total_summaries = conn.execute(count_query, params).fetchone()['count']
    
    # Add ordering and pagination
    query += ' ORDER BY cs.created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    summaries = conn.execute(query, params).fetchall()
    
    conn.close()
    
    return render_template('admin_all_summaries.html', 
                         summaries=summaries, 
                         page=page, 
                         per_page=per_page,
                         total_summaries=total_summaries)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    flash('Page not found!')
    return redirect(url_for('index'))

@app.errorhandler(413)
def file_too_large(error):
    flash('File is too large! Maximum size is 16MB.')
    return redirect(request.url)

@app.errorhandler(500)
def internal_error(error):
    flash('An internal error occurred. Please try again.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Create uploads directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize database if it doesn't exist
    if not os.path.exists('chat.db'):
        print("Database not found. Please run: sqlite3 chat.db < schema.sql")
    
    print("Starting Secure Chat Application...")
    print("Default admin credentials:")
    print("Username: admin")
    print("Password: admin123")
    print("Please change these credentials immediately!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)