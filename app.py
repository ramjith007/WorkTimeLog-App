from flask import Flask, render_template, request, jsonify
from datetime import datetime, timedelta
import sqlite3
import os
import json

app = Flask(__name__)

# Database configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'time_tracker.db')

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
            CREATE TABLE time_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT UNIQUE NOT NULL,
                in_time TEXT NOT NULL,
                out_time TEXT NOT NULL,
                total_hours REAL NOT NULL,
                deviation_minutes INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

def time_to_minutes(time_str):
    """Convert HH:MM format to total minutes"""
    try:
        parts = time_str.split(':')
        hours = int(parts[0])
        minutes = int(parts[1])
        return hours * 60 + minutes
    except:
        return None

def minutes_to_hours_format(minutes):
    """Convert minutes to HH:MM format"""
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours:02d}:{mins:02d}"

def calculate_hours_and_deviation(in_time, out_time):
    """Calculate total hours and deviation from 8:40 target"""
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

def get_entries_for_week(date_obj=None):
    """Get all entries for the current week"""
    if date_obj is None:
        date_obj = datetime.now().date()
    
    week_start = get_week_start(date_obj)
    week_end = week_start + timedelta(days=6)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM time_entries 
        WHERE date BETWEEN ? AND ? 
        ORDER BY date ASC
    ''', (week_start.isoformat(), week_end.isoformat()))
    
    entries = cursor.fetchall()
    conn.close()
    
    return entries, week_start, week_end

def get_entries_for_month(year=None, month=None):
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
        WHERE date BETWEEN ? AND ? 
        ORDER BY date ASC
    ''', (month_start.isoformat(), month_end.isoformat()))
    
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

def entry_exists(date_str):
    """Check if entry already exists for date"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM time_entries WHERE date = ?', (date_str,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

@app.route('/')
def index():
    """Display main page with current week and month data"""
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
    week_entries, week_start, week_end = get_entries_for_week(target_week_date)

    target_month_date = add_months(today, month_offset)
    month_entries, month_start, month_end = get_entries_for_month(target_month_date.year, target_month_date.month)
    
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
        'month_range': f"{month_start.day} {month_start.strftime('%B')} to {month_end.day} {month_end.strftime('%B')}"
    }
    
    return render_template('index.html', **context)

@app.route('/add_entry', methods=['POST'])
def add_entry():
    """Add a new time entry"""
    data = request.get_json()
    
    date_str = data.get('date')
    in_time = data.get('in_time')
    out_time = data.get('out_time')
    
    # Validation
    if not date_str or not in_time or not out_time:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    if entry_exists(date_str):
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
            INSERT INTO time_entries (date, in_time, out_time, total_hours, deviation_minutes)
            VALUES (?, ?, ?, ?, ?)
        ''', (date_str, in_time, out_time, total_hours, deviation_minutes))
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
    
    # Update in database
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE time_entries 
            SET in_time = ?, out_time = ?, total_hours = ?, deviation_minutes = ?
            WHERE date = ?
        ''', (in_time, out_time, total_hours, deviation_minutes, date_str))
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
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM time_entries WHERE date = ?', (date_str,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Entry deleted successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
