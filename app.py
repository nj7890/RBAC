from flask import Flask, render_template, request, redirect, session
import mysql.connector

app = Flask(__name__)
app.secret_key = 'secret_key'

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",   # Replace with your password
        database="acl_rbac"
    )

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s AND password=%s", 
                    (request.form['username'], request.form['password']))
        user = cur.fetchone()
        conn.close()
        if user:
            session['user'] = user
            return redirect('/dashboard')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM resources")
    resources = cur.fetchall()
    conn.close()
    return render_template('dashboard.html', user=session['user'], resources=resources)

@app.route('/access/<int:res_id>')
def access_resource(res_id):
    if 'user' not in session:
        return redirect('/')
    user = session['user']
    mode = request.args.get('mode', 'rbac')
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    allowed = False
    if mode == 'rbac':
        cur.execute("SELECT * FROM rbac WHERE role=%s AND resource_id=%s", 
                    (user['role'], res_id))
        row = cur.fetchone()
        allowed = row and row['can_access']
    else:
        cur.execute("SELECT * FROM acl WHERE user_id=%s AND resource_id=%s", 
                    (user['id'], res_id))
        row = cur.fetchone()
        allowed = row and row['can_access']
    conn.close()
    return f"Access granted to Resource {res_id}" if allowed else render_template("access_denied.html")

@app.route('/manage', methods=['GET', 'POST'])
def manage():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect('/')
    if request.method == 'POST':
        mode = request.form['mode']
        res_id = int(request.form['res_id'])
        can_access = int(request.form['can_access'])
        conn = get_db()
        cur = conn.cursor()
        if mode == 'rbac':
            role = request.form['role']
            cur.execute("INSERT INTO rbac (role, resource_id, can_access) VALUES (%s, %s, %s)", 
                        (role, res_id, can_access))
        else:
            user_id = int(request.form['user_id'])
            cur.execute("INSERT INTO acl (user_id, resource_id, can_access) VALUES (%s, %s, %s)", 
                        (user_id, res_id, can_access))
        conn.commit()
        conn.close()
    return render_template('manage.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
if __name__ == "__main__":
    app.run(debug=True)
