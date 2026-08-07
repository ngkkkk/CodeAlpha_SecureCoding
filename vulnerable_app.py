# pyrefly: ignore [missing-import]
from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Hardcoded Secret (Vulnerability 1: Sensitive Data Exposure)
SECRET_API_KEY = "12345-abcde-super-secret-key"

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    cursor.execute('''INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return "Welcome to the vulnerable app!"

# SQL Injection (Vulnerability 2)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # Vulnerable SQL query using string formatting
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return f"Welcome, {username}!"
        else:
            return "Invalid credentials."
            
    return '''
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

# Cross-Site Scripting - XSS (Vulnerability 3)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # Vulnerable to Reflected XSS
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

# Command Injection (Vulnerability 4)
@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')
    # Vulnerable to Command Injection
    response = os.popen(f"ping -c 1 {ip}").read()
    return f"<pre>{response}</pre>"

# Missing Authentication (Vulnerability 5)
@app.route('/admin')
def admin():
    # Anyone can access this page without logging in!
    return "<h1>Admin Dashboard</h1><p>Welcome to the secret admin area. You have full control.</p>"

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
