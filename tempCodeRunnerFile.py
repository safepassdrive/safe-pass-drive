from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import sqlite3
import os
from werkzeug.utils import secure_filename
from utils.qr_generator import generate_qr_code
from flask import send_from_directory
from utils.otp_generator import generate_otp, send_otp

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user store for admin login
USERS = {"admin@gmail.com": {"password": "adminpass"}}

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Database setup
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            contact TEXT NOT NULL,
            documents TEXT NOT NULL
        )''')
        db.commit()

# Utility to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    name = request.form['name']
    contact = request.form['contact']
    file = request.files['document']

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
    else:
        flash('Invalid file type')
        return redirect(url_for('index'))

    # Save to the database
    db = get_db()
    db.execute('INSERT INTO users (name, contact, documents) VALUES (?, ?, ?)', (name, contact, file_path))
    db.commit()

    # Generate QR code with user ID embedded in the URL to opt_pg
    user_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    qr_data = url_for('opt_pg', user_id=user_id, _external=True)
    img_str = generate_qr_code(qr_data)

    return render_template('qr_code.html', qr_code_url=f"data:image/png;base64,{img_str}")

@app.route('/opt_pg/<int:user_id>')
def opt_pg(user_id):
    return render_template('opt_pg.html', user_id=user_id)


@app.route('/info/<int:user_id>/authorize')
def authorize(user_id):

    return redirect(url_for('login.html', user_id=user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    user_id = request.args.get('user_id')  # Retrieve the user_id from the query string
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email in USERS and USERS[email]['password'] == password:
            user = User(email)
            login_user(user)
            return redirect(url_for('user_info', user_id=user_id))  # Redirect to the user_info with the user_id
        else:
            flash('Invalid credentials')
    return render_template('login.html', user_id=user_id)








@app.route('/info/<int:user_id>/emergency')
def emergency(user_id):
    db = get_db()
    user = db.execute('SELECT name, contact FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        return render_template('emrinfo.html', name=user['name'], contact=user['contact'])
    else:
        return "User not found", 404







@app.route('/info/<int:user_id>')
@login_required
def user_info(user_id):
    db = get_db()
    user = db.execute('SELECT name, contact, documents FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        document_filename = os.path.basename(user['documents'])
        return render_template('user_info.html', 
                               name=user['name'], 
                               contact=user['contact'], 
                               document_filename=document_filename)
    else:
        return "User not found", 404

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()
    app.run(debug=True)
