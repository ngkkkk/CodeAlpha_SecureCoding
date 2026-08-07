from flask import Flask, request, render_template_string, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import sqlite3
import os
import subprocess
import re

app = Flask(__name__)

# FIX 1: Secrets should be loaded from environment variables, never hardcoded.
# Example: export SECRET_KEY="your-production-secret-key"
app.secret_key = os.environ.get("SECRET_KEY", "default-dev-key")

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''DROP TABLE IF EXISTS users''') # Drop to ensure fresh schema with hashed passwords
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    # FIX 5: Hash passwords using PBKDF2 (Werkzeug default)
    hashed_pw = generate_password_hash('admin123')
    cursor.execute('''INSERT INTO users (id, username, password) VALUES (1, 'admin', ?)''', (hashed_pw,))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return "Welcome to the secure app!"

# FIX 2 & FIX 5: Prevent SQL Injection using parameterized queries & verify hashed password
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Secure SQL query using parameterized query (?) - fetch by username
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        
        # Verify the hash securely using check_password_hash
        if user and check_password_hash(user[2], password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('admin'))
        else:
            return "Invalid credentials."
            
    return '''
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

# FIX 3: Prevent XSS using templating engine variables (Jinja2 auto-escaping)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # Secure against XSS: Using Jinja2 context variables ensures auto-escaping
    template = "<h1>Hello, {{ name }}!</h1>"
    return render_template_string(template, name=name)

# FIX 4: Prevent Command Injection by using subprocess with argument lists and input validation
@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')
    
    # Input validation: Ensure the input looks like an IP address
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return "Invalid IP address format.", 400

    try:
        # Secure: Using subprocess.run with a list of arguments avoids shell=True risks
        result = subprocess.run(['ping', '-c', '1', ip], capture_output=True, text=True, timeout=5)
        return f"<pre>{escape(result.stdout)}</pre>"
    except Exception as e:
        return "An error occurred during ping."

# FIX 6: Prevent Missing Authentication by requiring a valid session
@app.route('/admin')
def admin():
    if not session.get('logged_in'):
        return "Unauthorized. Please login first.", 401
    
    return f"<h1>Admin Dashboard</h1><p>Welcome to the secure admin area, {escape(session.get('username'))}.</p>"

if __name__ == '__main__':
    init_db()
    # Debug mode should be False in production!
    app.run(debug=False)
