# User Authentication System with Flask

A simple, functional web application built with Flask that provides user signup and login functionality. All user data is stored persistently in SQLite with secure password hashing.

## Features

- **User Registration (Signup)**
  - Create account with username, email, password, and full name
  - Validation for duplicate usernames/emails
  - Password confirmation
  - Secure password hashing using Werkzeug

- **User Login**
  - Login with username and password
  - Secure credential verification
  - Session-based authentication

- **User Dashboard**
  - Welcome page after successful login
  - User profile page with account information
  - Logout functionality

- **Notes Management**
  - Create, edit, and delete personal notes
  - Organize notes with categories
  - Tabbed interface for easy category browsing
  - Each note has title, content, category, and timestamps
  - Notes are private to each user

- **Security**
  - Password hashing (not stored in plain text)
  - Session-based authentication
  - SQL injection protection (parameterized queries)
  - Input validation
  - User data isolation (users see only their own notes)

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Frontend**: HTML (no CSS frameworks, no JavaScript libraries)
- **Security**: Werkzeug for password hashing

## Project Structure

```
Auth-System/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── users.db              # SQLite database (created on first run)
└── templates/
    ├── base.html         # Base template with styling
    ├── login.html        # Login page
    ├── signup.html       # Registration page
    ├── welcome.html      # Welcome page after login
    ├── profile.html      # User profile page
    ├── notes.html        # Notes listing with tabs
    └── edit_note.html    # Note editing page
```

## Installation & Setup

### 1. Clone or Download the Project

```bash
cd "c:\Users\RRADHAKR\OneDrive - Volvo Cars\Beam Shape\RamjithR\My Projects\Auth-System"
```

### 2. Create a Virtual Environment (Optional but Recommended)

```bash
python -m venv venv
venv\Scripts\activate  # On Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

The application will start on `http://localhost:5001`

## Usage

### First Time Setup
- No users exist initially
- Navigate to the **Sign Up** page to create the first user
- Fill in all required fields:
  - Full Name
  - Username (3+ characters)
  - Email
  - Password (6+ characters)
  - Confirm Password

### User Registration
1. Click "Sign Up" on the login page
2. Enter all required information
3. Ensure passwords match
4. System validates for duplicate usernames/emails
5. Account is created and you're redirected to login

### User Login
1. Enter your username and password
2. Click "Login"
3. Successful login redirects to welcome page
4. Session is created and maintained

### User Dashboard
- **Welcome Page**: Shows personalized greeting and account details
- **Profile Page**: Displays full account information including registration date
- **Logout**: Clears session and returns to login page

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,           -- Hashed password
    full_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### Notes Table
```sql
CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,              -- Note title
    content TEXT NOT NULL,            -- Note content
    category TEXT NOT NULL,           -- Category for organization (becomes a tab)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)  -- Link to user
)
```

## Security Features

1. **Password Hashing**
   - Uses Werkzeug's `generate_password_hash()` for secure password storage
   - Passwords are never stored in plain text
   - Uses `check_password_hash()` for authentication

2. **SQL Injection Protection**
   - All database queries use parameterized statements
   - Input is never directly concatenated into SQL queries

3. **Session Management**
   - Session key stored server-side
   - Secret key should be changed in production
   - Session data includes: user_id, username, full_name

4. **Input Validation**
   - Required field validation
   - Username minimum 3 characters
   - Password minimum 6 characters
   - Email format validation
   - Password confirmation matching

## Error Handling

The application provides clear error messages for:
- Missing form fields: "All fields are required"
- Duplicate username/email: "Username or email already exists"
- Invalid credentials: "Invalid username or password"
- Password mismatch: "Passwords do not match"
- Short username/password: "Username must be at least 3 characters"
- Database errors: Informative error messages

## Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Home (redirects to login or welcome) |
| `/signup` | GET, POST | User registration page |
| `/login` | GET, POST | User login page |
| `/welcome` | GET | Welcome page (protected) |
| `/profile` | GET | User profile page (protected) |
| `/logout` | GET | Logout and clear session |
| `/notes` | GET | Notes listing with category tabs (protected) |
| `/add_note` | POST | Create a new note (protected) |
| `/edit_note/<note_id>` | GET, POST | Edit a note (protected) |
| `/delete_note/<note_id>` | POST | Delete a note (protected) |

## Protected Routes

The following routes require authentication:
- `/welcome` - Redirects to login if not authenticated
- `/profile` - Redirects to login if not authenticated
- `/notes` - Redirects to login if not authenticated
- `/add_note` - Redirects to login if not authenticated
- `/edit_note/<note_id>` - Redirects to login if not authenticated
- `/delete_note/<note_id>` - Redirects to login if not authenticated

## Data Persistence

- All user data is stored in `users.db` (SQLite database)
- Database is created automatically on first run
- Data persists across server restarts
- Each user record includes creation timestamp

## Configuration

To modify app settings, edit `app.py`:

```python
# Change secret key (IMPORTANT for production)
app.secret_key = 'your-secret-key-change-this-in-production'

# Change port
app.run(debug=True, port=5001)
```

## Testing the Application

### Test Flow 1: Register and Login
1. Start the app
2. Go to `/signup`
3. Register a new user with details
4. Login with the same credentials
5. View welcome page and profile

### Test Flow 2: Multiple Users
1. Register user1 (username: john, password: password123)
2. Register user2 (username: jane, password: password456)
3. Test login with user1 credentials
4. Logout
5. Test login with user2 credentials
6. Verify each user sees their own data

### Test Flow 3: Validation
1. Try to register with same username (should fail)
2. Try to register with same email (should fail)
3. Try to login with wrong password (should fail)
4. Try passwordless login (should fail)

### Test Flow 4: Notes Management
1. Login as a user
2. Click "My Notes" on the welcome page
3. Create a new note with title "Shopping List" in category "Todo"
4. Create another note with title "Project Ideas" in category "Ideas"
5. Create a note in category "Personal"
6. Verify tabs show all three categories (Todo, Ideas, Personal)
7. Click tabs to switch between them
8. Edit a note - click "Edit", modify content, save
9. Delete a note - click "Delete", confirm popup
10. Verify note count decreases in tab header

### Test Flow 5: User Isolation
1. Login as user1, create 3 notes
2. Logout
3. Login as user2
4. Verify "My Notes" shows only user2's notes (should be empty)
5. Create notes as user2
6. Logout, login as user1
7. Verify user1 sees their original 3 notes, not user2's notes

## Notes

- The database file (`users.db`) is created in the same directory as `app.py`
- For production deployment, change the `secret_key` to a random, secure value
- Consider enabling HTTPS for production deployments
- Implement additional security measures like rate limiting for production use

## Troubleshooting

**Port already in use**: Change the port in `app.py`
```python
app.run(debug=True, port=5002)  # Use a different port
```

**Database errors**: Delete `users.db` and restart the app to reinitialize

**Import errors**: Make sure dependencies are installed:
```bash
pip install -r requirements.txt
```

## Future Enhancements

- Email verification
- Password reset functionality
- Profile update/edit capability
- User role management
- Account deletion option
- Login history/activity tracking
- Two-factor authentication
- User profile pictures
- Account settings page

---

**Created**: February 2026
**Technology**: Flask + SQLite + HTML
**License**: Open Source
