from flask import Flask, render_template, request, redirect, url_for, session, send_file, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, random
import qrcode
from io import BytesIO
from flask_session import Session

app = Flask(__name__)
app.secret_key = "supersecretkey"  # To manage sessions (required by Flask)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
DATABASE = 'members.db'

# Simple user store for staff and members (no security library)
USERS = {

    "staff": {"password": "staffpass", "role": "staff", "mfa_secret": None, "mfa_verified": False},
    "member": {"password": "memberpass", "role": "member", "mfa_secret": None, "mfa_verified": False},
    "pakkarim": {"password": "karim", "role": "staff", "mfa_secret": None, "mfa_verified": False},
    "hashed_password": {generate_password_hash("password")}
}

print("User added successfully with hashed password!")

# Helper function to connect to the SQLite database
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                membership_status TEXT NOT NULL
                )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                id INTEGER PRIMARY KEY,
                class_name TEXT NOT NULL,
                class_time TEXT NOT NULL
                )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                member_id INTEGER,
                class_id INTEGER,
                FOREIGN KEY (member_id) REFERENCES members (id),
                FOREIGN KEY (class_id) REFERENCES classes (id)
                )''')
    db.commit()

@app.after_request
def apply_hsts(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ---- Generate and Display QR Code ----
@app.route('/generate_qr')
def generate_qr():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Generate a random 6-digit OTP
    otp = str(random.randint(100000, 999999))
    session['otp'] = otp  # Store OTP in session

    # Create QR code with OTP embedded as text
    qr = qrcode.make(f"Scan this QR Code with your camera: {otp}")
    img_io = BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png')

# ---- OTP Verification Route ----
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        if entered_otp == session.get('otp'):
            session['mfa_verified'] = True
            return redirect(url_for('dashboard'))

        return "Invalid OTP. Try again."

    return render_template('verify_otp.html')

# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in USERS and USERS[username]['password'] == password:
            session['user'] = username
            session['role'] = USERS[username]['role']
            return redirect(url_for('verify_otp'))
        else:
            return "Login Failed!"

    return render_template('login.html')

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    role = session['role']
    return render_template('dashboard.html', username=username)

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))

    return render_template('add_member.html')

# View specific member classes
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get member classes
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                       "JOIN member_classes mc ON c.id = mc.class_id "
                       "WHERE mc.member_id = ?", [member_id])
    return render_template('member_classes.html', member=member, classes=classes)

# Register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")  # Get all available classes

    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES(?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))

    return render_template('register_class.html', member_id=member_id, classes=classes)

# View members
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# Registering a Member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))

    return render_template('register_member.html')

# Function to create a new user
def register_user(username, password, role):
    db = sqlite3.connect("members.db")
    cursor = db.cursor()

    try:
        # Hash the password before storing it
        hashed_password = generate_password_hash(password)

        # Insert user into database
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                       (username, hashed_password, role))
        
        db.commit()
        return "User registered successfully!"
    
    except sqlite3.IntegrityError:
        return "Error: Username already exists."
    
    finally:
        db.close()

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))

    return render_template('add_class.html')

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    db = get_db()
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    db.commit()

    return redirect(url_for('view_members'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)