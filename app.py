from flask import Flask, render_template, request, redirect, session, send_file
import mysql.connector
import os

app = Flask(__name__)
app.secret_key = 'secretkey'

UPLOAD_FOLDER = 'files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="access_control"
    )

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s",
                       (request.form['username'], request.form['password']))
        user = cursor.fetchone()
        if user:
            session['user'] = user
            return redirect('/dashboard')
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    user = session['user']
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    if user['role'] == 'admin':
        cursor.execute("SELECT * FROM resources")
    else:
        cursor.execute("""
            SELECT r.* FROM resources r
            JOIN acl a ON a.resource_id = r.id
            WHERE a.user_id = %s
        """, (user['id'],))
    resources = cursor.fetchall()
    return render_template('dashboard.html', user=user, resources=resources)

@app.route('/view/<int:resource_id>')
def view_file(resource_id):
    return handle_file_access(resource_id, operation='read')

@app.route('/edit/<int:resource_id>', methods=['GET', 'POST'])
def edit_file(resource_id):
    return handle_file_access(resource_id, operation='edit')

@app.route('/delete/<int:resource_id>', methods=['POST'])
def delete_file(resource_id):
    return handle_file_access(resource_id, operation='delete')

def handle_file_access(resource_id, operation):
    if 'user' not in session:
        return redirect('/login')
    user = session['user']
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # Get resource info
    cursor.execute("SELECT * FROM resources WHERE id=%s", (resource_id,))
    resource = cursor.fetchone()
    if not resource:
        return render_template('access_denied.html', mac=False, dac=False, rbac=False)

    # MAC: clearance level vs classification level
    mac = user['clearance_level'] >= resource['classification_level']

    # DAC: check ACL
    cursor.execute("SELECT * FROM acl WHERE user_id=%s AND resource_id=%s", (user['id'], resource_id))
    acl_entry = cursor.fetchone()
    dac = acl_entry is not None

    # RBAC: based on ACL role
    rbac_roles = {
        'read': ['reader', 'editor', 'owner'],
        'edit': ['editor', 'owner'],
        'delete': ['owner']
    }

    rbac = acl_entry and acl_entry['role'] in rbac_roles.get(operation, [])

    if user['role'] == 'admin' or (mac and dac and rbac):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], resource['file_name'])

        if operation == 'read':
            return send_file(file_path)

        elif operation == 'edit':
            if request.method == 'POST':
                with open(file_path, 'w') as f:
                    f.write(request.form['content'])
                return redirect('/dashboard')
            with open(file_path, 'r') as f:
                content = f.read()
            return render_template('edit_file.html', content=content, resource=resource)

        elif operation == 'delete':
            os.remove(file_path)
            cursor.execute("DELETE FROM resources WHERE id=%s", (resource_id,))
            cursor.execute("DELETE FROM acl WHERE resource_id=%s", (resource_id,))
            conn.commit()
            return redirect('/dashboard')

    # Access denied
    return render_template('access_denied.html', mac=mac, dac=dac, rbac=rbac)

@app.route('/manage', methods=['GET', 'POST'])
def manage():
    if 'user' not in session or session['user']['role'] != 'admin':
        return render_template('access_denied.html', mac=False, dac=False, rbac=False)

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        user_id = request.form['user_id']
        resource_id = request.form['resource_id']
        role = request.form['role']
        cursor.execute("INSERT INTO acl (user_id, resource_id, role) VALUES (%s, %s, %s)",
                       (user_id, resource_id, role))
        conn.commit()

    cursor.execute("SELECT * FROM users WHERE role != 'admin'")
    users = cursor.fetchall()
    cursor.execute("SELECT * FROM resources")
    resources = cursor.fetchall()

    cursor.execute("""
        SELECT a.user_id, a.resource_id, a.role, u.username, r.name as resource_name
        FROM acl a
        JOIN users u ON a.user_id = u.id
        JOIN resources r ON a.resource_id = r.id
    """)
    acl_entries = cursor.fetchall()

    return render_template('manage.html', users=users, resources=resources, acl_entries=acl_entries)

@app.route('/revoke_access', methods=['POST'])
def revoke_access():
    if 'user' not in session or session['user']['role'] != 'admin':
        return render_template('access_denied.html', mac=False, dac=False, rbac=False)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM acl WHERE user_id=%s AND resource_id=%s",
                   (request.form['user_id'], request.form['resource_id']))
    conn.commit()
    return redirect('/manage')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/access_denied')
def access_denied():
    return render_template('access_denied.html', mac=False, dac=False, rbac=False)

if __name__ == '__main__':
    app.run(debug=True)
