from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Database configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database schema"""
    if not os.path.exists(DB_PATH):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                full_name TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE time_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                in_time TEXT NOT NULL,
                out_time TEXT NOT NULL,
                total_hours REAL NOT NULL,
                deviation_minutes INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, date),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()
        
        # Create admin user
        admin_password = generate_password_hash('Admin007')
        cursor.execute('''
            INSERT INTO users (username, email, password, full_name, is_admin)
            VALUES (?, ?, ?, ?, ?)
        ''', ('Admin', 'admin@worklog.local', admin_password, 'Administrator', 1))
        conn.commit()
        conn.close()

def user_exists(username, email):
    """Check if user with given username or email already exists"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def register_user(username, email, password, full_name):
    """Register a new user with hashed password"""
    hashed_password = generate_password_hash(password)
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, email, password, full_name)
            VALUES (?, ?, ?, ?)
        ''', (username, email, hashed_password, full_name))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

def authenticate_user(username, password):
    """Authenticate user and return user data if credentials are correct"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password):
        return dict(user)
    return None

def get_all_users():
    """Get all users from database (for admin panel)"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, full_name, is_admin, created_at FROM users ORDER BY created_at DESC')
    users = cursor.fetchall()
    conn.close()
    return users

def get_user_by_id(user_id):
    """Get user by ID (for admin panel)"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, full_name, is_admin, created_at FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def update_user(user_id, username, email, full_name):
    """Update user details (admin only)"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET username = ?, email = ?, full_name = ?
            WHERE id = ?
        ''', (username, email, full_name, user_id))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

def log_login(user_id, username, ip_address=None):
    """Log user login to database"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO login_history (user_id, username, ip_address)
            VALUES (?, ?, ?)
        ''', (user_id, username, ip_address))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def get_user_login_history(user_id):
    """Get all login attempts for a user"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM login_history WHERE user_id = ? ORDER BY login_time DESC', (user_id,))
    history = cursor.fetchall()
    conn.close()
    return history

def delete_user(user_id):
    """Delete user and their entries (admin only)"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        # Delete user's time entries first
        cursor.execute('DELETE FROM time_entries WHERE user_id = ?', (user_id,))
        # Delete user's login history
        cursor.execute('DELETE FROM login_history WHERE user_id = ?', (user_id,))
        # Delete user
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

# ==================== Time Tracking Helper Functions ====================

def time_to_minutes(time_str):
    """Convert HH:MM format to total minutes"""
    try:
        parts = time_str.split(':')
        hours = int(parts[0])
        minutes = int(parts[1])
        return hours * 60 + minutes
    except:
        return None

def calculate_hours_and_deviation(in_time, out_time):
    """Calculate total hours and deviation from 8:42 target"""
    in_mins = time_to_minutes(in_time)
    out_mins = time_to_minutes(out_time)
    
    if in_mins is None or out_mins is None:
        return None, None
    
    # Handle case where out_time is next day
    if out_mins <= in_mins:
        out_mins += 24 * 60
    
    total_minutes = out_mins - in_mins
    total_hours = total_minutes / 60
    
    # Target is 8:42 = 522 minutes
    target_minutes = 8 * 60 + 42  # 522 minutes
    deviation = total_minutes - target_minutes
    
    return round(total_hours, 2), int(deviation)

def get_week_start(date_obj):
    """Get Monday of the week for given date"""
    return date_obj - timedelta(days=date_obj.weekday())

def get_entries_for_week(user_id, date_obj=None):
    """Get all entries for the current week"""
    if date_obj is None:
        date_obj = datetime.now().date()
    
    week_start = get_week_start(date_obj)
    week_end = week_start + timedelta(days=6)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM time_entries 
        WHERE user_id = ? AND date BETWEEN ? AND ? 
        ORDER BY date ASC
    ''', (user_id, week_start.isoformat(), week_end.isoformat()))
    
    entries = cursor.fetchall()
    conn.close()
    
    return entries, week_start, week_end

def get_entries_for_month(user_id, year=None, month=None):
    """Get all entries for the current month"""
    today = datetime.now().date()
    if year is None:
        year = today.year
    if month is None:
        month = today.month
    
    month_start = datetime(year, month, 1).date()
    if month == 12:
        month_end = datetime(year + 1, 1, 1).date() - timedelta(days=1)
    else:
        month_end = datetime(year, month + 1, 1).date() - timedelta(days=1)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM time_entries 
        WHERE user_id = ? AND date BETWEEN ? AND ? 
        ORDER BY date ASC
    ''', (user_id, month_start.isoformat(), month_end.isoformat()))
    
    entries = cursor.fetchall()
    conn.close()
    
    return entries, month_start, month_end

def add_months(source_date, months):
    """Add months to a date (months can be negative)"""
    month = source_date.month - 1 + months
    year = source_date.year + month // 12
    month = month % 12 + 1
    day = min(source_date.day, (datetime(year, month % 12 + 1, 1) - timedelta(days=1)).day)
    return datetime(year, month, day).date()

def entry_exists(user_id, date_str):
    """Check if entry already exists for date"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM time_entries WHERE user_id = ? AND date = ?', (user_id, date_str))
    result = cursor.fetchone()
    conn.close()
    return result is not None

@app.route('/')
def index():
    """Home page - redirect to login if not logged in, else to tracker"""
    if 'user_id' in session:
        return redirect(url_for('tracker'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User signup page"""
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        
        # Validation
        if not all([username, email, password, confirm_password, full_name]):
            error = 'All fields are required'
        elif len(username) < 3:
            error = 'Username must be at least 3 characters'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters'
        elif password != confirm_password:
            error = 'Passwords do not match'
        elif user_exists(username, email):
            error = 'Username or email already exists'
        else:
            if register_user(username, email, password, full_name):
                return redirect(url_for('login', success='Account created successfully. Please log in.'))
            else:
                error = 'Failed to create account. Please try again.'
    
    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    error = None
    success = request.args.get('success')
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validation
        if not username or not password:
            error = 'Username and password are required'
        else:
            user = authenticate_user(username, password)
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['full_name'] = user['full_name']
                session['is_admin'] = user['is_admin']
                
                # Log login attempt
                ip_address = request.remote_addr
                log_login(user['id'], user['username'], ip_address)
                
                # Redirect admin to admin dashboard
                if user['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('tracker'))
            else:
                error = 'Invalid username or password'
    
    return render_template('login.html', error=error, success=success)

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    return redirect(url_for('login', success='Logged out successfully.'))

@app.route('/tracker')
def tracker():
    """Display time tracker with current week and month data"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    today = datetime.now().date()
    
    # read offsets from query params (can be negative for previous)
    try:
        week_offset = int(request.args.get('week_offset', '0'))
    except ValueError:
        week_offset = 0
    try:
        month_offset = int(request.args.get('month_offset', '0'))
    except ValueError:
        month_offset = 0

    # Compute target dates based on offsets
    target_week_date = today + timedelta(weeks=week_offset)
    week_entries, week_start, week_end = get_entries_for_week(session['user_id'], target_week_date)

    target_month_date = add_months(today, month_offset)
    month_entries, month_start, month_end = get_entries_for_month(session['user_id'], target_month_date.year, target_month_date.month)
    
    # Calculate weekly totals
    weekly_total_hours = 0
    weekly_total_deviation = 0
    for entry in week_entries:
        weekly_total_hours += entry['total_hours']
        weekly_total_deviation += entry['deviation_minutes']
    
    # Calculate monthly totals
    monthly_total_hours = 0
    monthly_total_deviation = 0
    for entry in month_entries:
        monthly_total_hours += entry['total_hours']
        monthly_total_deviation += entry['deviation_minutes']
    
    # Convert week entries to list of dicts for template
    week_data = []
    for entry in week_entries:
        week_data.append({
            'date': entry['date'],
            'day': datetime.fromisoformat(entry['date']).strftime('%A'),
            'in_time': entry['in_time'],
            'out_time': entry['out_time'],
            'total_hours': entry['total_hours'],
            'deviation_minutes': entry['deviation_minutes']
        })
    
    context = {
        'today': today.isoformat(),
        'week_start': week_start.isoformat(),
        'week_end': week_end.isoformat(),
        'week_number': target_week_date.isocalendar()[1],
        'week_year': target_week_date.isocalendar()[0],
        'week_offset': week_offset,
        'month_offset': month_offset,
        'week_entries': week_data,
        'weekly_total_hours': weekly_total_hours,
        'weekly_total_deviation': weekly_total_deviation,
        'monthly_total_hours': round(monthly_total_hours, 2),
        'monthly_total_deviation': monthly_total_deviation,
        'month_str': target_month_date.strftime('%B %Y'),
        'month_number': target_month_date.month,
        'month_year': target_month_date.year,
        'month_full': target_month_date.strftime('%B'),
        'total_days_in_month': (datetime(target_month_date.year, target_month_date.month % 12 + 1, 1) - timedelta(days=1)).day,
        'current_day_of_month': target_month_date.day,
        'month_range': f"{month_start.day} {month_start.strftime('%B')} to {month_end.day} {month_end.strftime('%B')}",
        'username': session.get('username'),
        'full_name': session.get('full_name')
    }
    
    return render_template('tracker.html', **context)

@app.route('/add_entry', methods=['POST'])
def add_entry():
    """Add a new time entry"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    
    date_str = data.get('date')
    in_time = data.get('in_time')
    out_time = data.get('out_time')
    
    # Validation
    if not date_str or not in_time or not out_time:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    if entry_exists(session['user_id'], date_str):
        return jsonify({'success': False, 'error': 'Entry already exists for this date'}), 400
    
    # Validate time format
    if len(in_time.split(':')) != 2 or len(out_time.split(':')) != 2:
        return jsonify({'success': False, 'error': 'Invalid time format. Use HH:MM'}), 400
    
    # Calculate hours and deviation
    total_hours, deviation_minutes = calculate_hours_and_deviation(in_time, out_time)
    
    if total_hours is None:
        return jsonify({'success': False, 'error': 'Invalid time values'}), 400
    
    if total_hours <= 0:
        return jsonify({'success': False, 'error': 'Out time must be after in time'}), 400
    
    # Store in database
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO time_entries (user_id, date, in_time, out_time, total_hours, deviation_minutes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], date_str, in_time, out_time, total_hours, deviation_minutes))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Entry added successfully',
            'total_hours': total_hours,
            'deviation_minutes': deviation_minutes
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/update_entry/<date_str>', methods=['POST'])
def update_entry(date_str):
    """Update an existing time entry"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    
    in_time = data.get('in_time')
    out_time = data.get('out_time')
    
    # Validation
    if not in_time or not out_time:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    # Validate time format
    if len(in_time.split(':')) != 2 or len(out_time.split(':')) != 2:
        return jsonify({'success': False, 'error': 'Invalid time format. Use HH:MM'}), 400
    
    # Calculate hours and deviation
    total_hours, deviation_minutes = calculate_hours_and_deviation(in_time, out_time)
    
    if total_hours is None:
        return jsonify({'success': False, 'error': 'Invalid time values'}), 400
    
    if total_hours <= 0:
        return jsonify({'success': False, 'error': 'Out time must be after in time'}), 400
    
    # Update in database (verify user owns this entry)
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE time_entries 
            SET in_time = ?, out_time = ?, total_hours = ?, deviation_minutes = ?
            WHERE user_id = ? AND date = ?
        ''', (in_time, out_time, total_hours, deviation_minutes, session['user_id'], date_str))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Entry updated successfully',
            'total_hours': total_hours,
            'deviation_minutes': deviation_minutes
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete_entry/<date_str>', methods=['POST'])
def delete_entry(date_str):
    """Delete a time entry"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM time_entries WHERE user_id = ? AND date = ?', (session['user_id'], date_str))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Entry deleted successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== Graph Data Routes ====================

@app.route('/api/graph/daily')
def graph_daily():
    """Get daily average login hours for current week"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        today = datetime.now().date()
        
        # Calculate the week start for current week
        week_start = get_week_start(today)
        week_end = week_start + timedelta(days=6)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT date, total_hours FROM time_entries 
            WHERE user_id = ? AND date BETWEEN ? AND ? 
            ORDER BY date ASC
        ''', (session['user_id'], week_start.isoformat(), week_end.isoformat()))
        
        entries = cursor.fetchall()
        conn.close()
        
        # Build daily data for all days in the week
        daily_hours = {}
        daily_counts = {}
        days_to_show = []
        
        for i in range(7):
            date = week_start + timedelta(days=i)
            date_str = date.isoformat()
            daily_hours[date_str] = 0
            daily_counts[date_str] = 0
            days_to_show.append(date)
        
        for entry in entries:
            if entry['date'] in daily_hours:
                daily_hours[entry['date']] += entry['total_hours']
                daily_counts[entry['date']] += 1
        
        # Calculate averages - show 0 for empty days
        daily_averages = {}
        labels = []
        for date in days_to_show:
            date_str = date.isoformat()
            if daily_counts[date_str] > 0:
                daily_averages[date_str] = daily_hours[date_str] / daily_counts[date_str]
            else:
                daily_averages[date_str] = 0
            labels.append(date.strftime('%a').upper())
        
        values = list(daily_averages.values())
        
        return jsonify({
            'success': True,
            'labels': labels,
            'values': values,
            'dates': list(daily_averages.keys())
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/graph/weekly')
def graph_weekly():
    """Get weekly average summary for current month"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        today = datetime.now().date()
        month_start = datetime(today.year, today.month, 1).date()
        if today.month == 12:
            month_end = datetime(today.year + 1, 1, 1).date() - timedelta(days=1)
        else:
            month_end = datetime(today.year, today.month + 1, 1).date() - timedelta(days=1)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT date, total_hours FROM time_entries 
            WHERE user_id = ? AND date BETWEEN ? AND ? 
            ORDER BY date ASC
        ''', (session['user_id'], month_start.isoformat(), month_end.isoformat()))
        
        entries = cursor.fetchall()
        conn.close()
        
        # Find all unique weeks in the month
        week_starts = set()
        current_date = month_start
        while current_date <= month_end:
            week_start = get_week_start(current_date)
            if week_start + timedelta(days=6) >= month_start:
                week_starts.add(week_start)
            current_date += timedelta(days=1)
        
        # Sort week starts and create data structure
        sorted_week_starts = sorted(week_starts)
        weekly_hours = {}
        weekly_counts = {}
        
        for idx, week_start in enumerate(sorted_week_starts, 1):
            weekly_hours[f'W{idx}'] = 0
            weekly_counts[f'W{idx}'] = 0
        
        # Add entry data
        for entry in entries:
            entry_date = datetime.fromisoformat(entry['date']).date()
            week_start = get_week_start(entry_date)
            
            # Find which week number this is
            for idx, ws in enumerate(sorted_week_starts, 1):
                if ws == week_start:
                    key = f'W{idx}'
                    weekly_hours[key] += entry['total_hours']
                    weekly_counts[key] += 1
                    break
        
        # Calculate averages - show 0 for empty weeks
        weekly_averages = {}
        for key in sorted(weekly_hours.keys(), key=lambda x: int(x[1:])):
            if weekly_counts[key] > 0:
                weekly_averages[key] = weekly_hours[key] / weekly_counts[key]
            else:
                weekly_averages[key] = 0
        
        labels = list(weekly_averages.keys())
        values = list(weekly_averages.values())
        
        return jsonify({
            'success': True,
            'labels': labels,
            'values': values
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/graph/monthly')
def graph_monthly():
    """Get monthly average summary for current year"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        today = datetime.now().date()
        year = today.year
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT date, total_hours FROM time_entries 
            WHERE user_id = ? AND strftime('%Y', date) = ? 
            ORDER BY date ASC
        ''', (session['user_id'], str(year)))
        
        entries = cursor.fetchall()
        conn.close()
        
        # Group by month - show all 12 months for the selected year
        monthly_hours = {}
        monthly_counts = {}
        for m in range(1, 13):
            month_key = datetime(year, m, 1).strftime('%b').upper()
            monthly_hours[month_key] = 0
            monthly_counts[month_key] = 0
        
        for entry in entries:
            entry_date = datetime.fromisoformat(entry['date']).date()
            month_key = entry_date.strftime('%b').upper()
            if month_key in monthly_hours:
                monthly_hours[month_key] += entry['total_hours']
                monthly_counts[month_key] += 1
        
        # Calculate averages - show 0 for empty months
        monthly_averages = {}
        for month_key in monthly_hours:
            if monthly_counts[month_key] > 0:
                monthly_averages[month_key] = monthly_hours[month_key] / monthly_counts[month_key]
            else:
                monthly_averages[month_key] = 0
        
        labels = list(monthly_averages.keys())
        values = list(monthly_averages.values())
        
        return jsonify({
            'success': True,
            'labels': labels,
            'values': values
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== Admin Routes ====================

@app.route('/admin_dashboard')
def admin_dashboard():
    """Admin dashboard to view and manage users"""
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    users = get_all_users()
    
    # Get login history for each user
    users_with_login = []
    for user in users:
        user_dict = dict(user)
        login_history = get_user_login_history(user_dict['id'])
        user_dict['last_login'] = None
        user_dict['total_logins'] = len(login_history)
        
        if login_history:
            user_dict['last_login'] = login_history[0]['login_time']
        
        users_with_login.append(user_dict)
    
    return render_template('admin_dashboard.html', users=users_with_login)

@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    """Edit user details (admin only)"""
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    # Prevent admin from editing themselves
    if user_id == session['user_id']:
        return redirect(url_for('admin_dashboard'))
    
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for('admin_dashboard'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        
        if not all([username, email, full_name]):
            error = 'All fields are required'
        else:
            if update_user(user_id, username, email, full_name):
                return redirect(url_for('admin_dashboard'))
            else:
                error = 'Username or email already exists'
    
    return render_template('admin_edit_user.html', user=user, error=error)

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    """Delete user (admin only)"""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Not authorized'}), 403
    
    # Prevent admin from deleting themselves
    if user_id == session['user_id']:
        return jsonify({'success': False, 'error': 'Cannot delete yourself'}), 400
    
    if delete_user(user_id):
        return jsonify({'success': True, 'message': 'User deleted successfully'}), 200
    else:
        return jsonify({'success': False, 'error': 'Failed to delete user'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)
