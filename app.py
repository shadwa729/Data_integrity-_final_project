from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, send_file
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_session import Session
from werkzeug.utils import secure_filename
import os
import io
import pyotp
import qrcode

from crypto_utils import encrypt_file, decrypt_file, hash_file, generate_aes_key

app = Flask(__name__)
app.secret_key = 'securedocs-secret-key'

# Session config
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# MySQL config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'securedocs_db'

mysql = MySQL(app)
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def log_action(username, action_type, message):
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO logs (username, action_type, message)
        VALUES (%s, %s, %s)
    """, (username, action_type, message))
    mysql.connection.commit()
    cur.close()

@app.route('/')
def home():
    if 'username' in session:
        role = session.get('role')
        return f"""
            Welcome {role.capitalize()} {session['username']}!<br>
            <a href='/upload'>Upload Document</a><br>
            <a href='/documents'>My Documents</a><br>
            {'<a href="/admin">Go to Admin Panel</a><br>' if role == 'admin' else ''}
            {'<a href="/logs">View System Logs</a><br>' if role == 'admin' else ''}
            <a href='/logout'>Logout</a>
        """
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        totp_secret = pyotp.random_base32()

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO users (username, email, password, 2fa_secret)
            VALUES (%s, %s, %s, %s)
        """, (username, email, hashed_pw, totp_secret))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('qr_page', username=username))

    return render_template('register.html')

@app.route('/qr/<username>')
def qr_page(username):
    return f'''
        <h2>2FA Setup</h2>
        <p>Scan this QR code with Google Authenticator or Authy:</p>
        <img src="/qrcode/{username}" alt="QR Code"><br><br>
        <a href="/login">Continue to Login</a>
    '''

@app.route('/qrcode/<username>')
def show_qr(username):
    cur = mysql.connection.cursor()
    cur.execute("SELECT 2fa_secret FROM users WHERE username = %s", (username,))
    secret = cur.fetchone()[0]
    cur.close()

    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(name=username, issuer_name="SecureDocs")
    img = qrcode.make(otp_uri)

    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)

    return send_file(buf, mimetype='image/png')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.check_password_hash(user[3], password):
            session['pre_2fa_user'] = user[1]
            return redirect(url_for('two_factor'))
        return "Login Failed"
    return render_template('login.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form['token']
        username = session['pre_2fa_user']

        cur = mysql.connection.cursor()
        cur.execute("SELECT 2fa_secret, role FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        cur.close()

        secret, role = result
        totp = pyotp.TOTP(secret)

        if totp.verify(token):
            session.pop('pre_2fa_user')
            session['username'] = username
            session['role'] = role
            return redirect(url_for('home'))
        else:
            return "Invalid 2FA code"

    return '''
        <h2>Enter 2FA Code</h2>
        <form method="POST">
            <input type="text" name="token" placeholder="Enter 6-digit code" required><br>
            <button type="submit">Verify</button>
        </form>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
def admin_panel():
    if 'username' in session and session.get('role') == 'admin':
        return "Welcome to the Admin Panel"
    return "Access denied. Admins only."

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_bytes = file.read()

            key = b'ThisIsATestKeyForDemoPurposes123!'[:32]  # Simulated static key
            encrypted_data = encrypt_file(file_bytes, key)
            file_hash = hash_file(file_bytes)

            encrypted_filename = f"{session['username']}_{filename}.enc"
            filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)

            with open(filepath, 'wb') as f:
                f.write(encrypted_data)

            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO documents (user_id, filename, original_filename, file_hash)
                VALUES ((SELECT id FROM users WHERE username = %s), %s, %s, %s)
            """, (session['username'], encrypted_filename, filename, file_hash))
            mysql.connection.commit()
            cur.close()

            return f"File uploaded and encrypted as: {encrypted_filename}"
    return '''
        <h2>Upload Document</h2>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file" required><br><br>
            <button type="submit">Upload</button>
        </form>
        <br><a href="/">Home</a>
    '''

@app.route('/documents')
def documents():
    if 'username' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id, original_filename, filename, file_hash, upload_time
        FROM documents
        WHERE user_id = (SELECT id FROM users WHERE username = %s)
    """, (session['username'],))
    docs = cur.fetchall()
    cur.close()

    doc_html = "<h2>Your Documents</h2><table border='1'>"
    doc_html += "<tr><th>Original Name</th><th>Download</th><th>Verify</th><th>Uploaded</th></tr>"

    for doc in docs:
        doc_id, original, enc_file, file_hash, upload_time = doc
        verify_url = url_for('verify_document', file=enc_file, expected_hash=file_hash)
        download_url = url_for('download_file', filename=enc_file)
        doc_html += f"<tr><td>{original}</td><td><a href='{download_url}'>Download</a></td><td><a href='{verify_url}'>Check Integrity</a></td><td>{upload_time}</td></tr>"

    doc_html += "</table><br><a href='/'>Home</a>"
    return doc_html

@app.route('/verify')
def verify_document():
    from flask import request

    file = request.args.get('file')
    expected_hash = request.args.get('expected_hash')

    file_path = os.path.join('uploads', file)

    if not os.path.exists(file_path):
        return "File not found."

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    try:
        key = b'ThisIsATestKeyForDemoPurposes123!'[:32]
        decrypted_data = decrypt_file(encrypted_data, key)
        actual_hash = hash_file(decrypted_data)

        if actual_hash == expected_hash:
            result = "<span style='color: green;'>✅ File integrity verified.</span>"
        else:
            result = "<span style='color: red;'>❌ File has been tampered with!</span>"
            log_action(session['username'], "integrity_failure", f"File mismatch: {file}")

        return f"""
            Expected Hash: {expected_hash}<br>
            Actual Hash: {actual_hash}<br>
            {result}<br>
            <a href='/documents'>Back to documents</a>
        """
    except Exception as e:
        return f"Decryption failed: {str(e)}<br><a href='/documents'>Back</a>"

@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/logs')
def view_logs():
    if 'username' not in session or session.get('role') != 'admin':
        return "Access denied. Admins only."

    cur = mysql.connection.cursor()
    cur.execute("SELECT username, action_type, message, timestamp FROM logs ORDER BY timestamp DESC")
    logs = cur.fetchall()
    cur.close()

    html = "<h2>System Logs</h2><table border='1'>"
    html += "<tr><th>User</th><th>Action</th><th>Details</th><th>Time</th></tr>"

    for log in logs:
        username, action, msg, ts = log
        html += f"<tr><td>{username}</td><td>{action}</td><td>{msg}</td><td>{ts}</td></tr>"

    html += "</table><br><a href='/'>Back to Home</a>"
    return html

@app.route('/testdb')
def testdb():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT DATABASE();")
        db = cur.fetchone()
        return f"Connected to database: {db}"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
