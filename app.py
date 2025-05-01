from flask import Flask, render_template, request, redirect, session, send_from_directory
import mysql.connector
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="access_control"
    )

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
        user = cur.fetchone()
        if user:
            session['user'] = user
            return redirect('/dashboard')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    user = session['user']
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM resources")
    resources = cur.fetchall()
    return render_template('dashboard.html', user=user, resources=resources)

@app.route('/access/<int:res_id>')
def access_file(res_id):
    if 'user' not in session:
        return redirect('/')
    user = session['user']
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    # RBAC: Check if user has access via ACL
    cur.execute("SELECT * FROM acl WHERE user_id=%s AND resource_id=%s", (user['id'], res_id))
    access = cur.fetchone()
    # MAC: Check if user's clearance >= resource's classification
    cur.execute("SELECT * FROM resources WHERE id=%s", (res_id,))
    resource = cur.fetchone()
    if not resource:
        return "Resource not found", 404
    if access or user['role'] == 'admin':
        # DAC: Owner has access
        if resource['owner_id'] == user['id']:
            filename = resource['file_name']
            return send_from_directory('project_files', filename)
        # MAC: Check clearance
        if user['clearance_level'] >= resource['classification_level']:
            filename = resource['file_name']
            return send_from_directory('project_files', filename)
    return "Access Denied", 403

@app.route('/manage', methods=['GET', 'POST'])
def manage():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect('/dashboard')
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    if request.method == 'POST':
        user_id = request.form['user_id']
        resource_id = request.form['resource_id']
        cur.execute("INSERT INTO acl (user_id, resource_id) VALUES (%s, %s)", (user_id, resource_id))
        conn.commit()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    cur.execute("SELECT * FROM resources")
    resources = cur.fetchall()
    return render_template('manage.html', users=users, resources=resources)

if __name__ == '__main__':
    app.run(debug=True)
