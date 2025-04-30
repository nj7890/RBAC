import mysql.connector

def init_db():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",   # Change to your MySQL password
    )
    cursor = conn.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS acl_rbac")
    cursor.execute("USE acl_rbac")

    # Drop existing tables
    cursor.execute("DROP TABLE IF EXISTS acl")
    cursor.execute("DROP TABLE IF EXISTS rbac")
    cursor.execute("DROP TABLE IF EXISTS resources")
    cursor.execute("DROP TABLE IF EXISTS users")

    # Create tables
    cursor.execute("""
    CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE,
        password VARCHAR(100),
        role VARCHAR(50)
    )
    """)

    cursor.execute("""
    CREATE TABLE resources (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100)
    )
    """)

    cursor.execute("""
    CREATE TABLE acl (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        resource_id INT,
        can_access BOOLEAN
    )
    """)

    cursor.execute("""
    CREATE TABLE rbac (
        id INT AUTO_INCREMENT PRIMARY KEY,
        role VARCHAR(50),
        resource_id INT,
        can_access BOOLEAN
    )
    """)

    # Dummy users
    cursor.executemany("""
        INSERT INTO users (username, password, role) VALUES (%s, %s, %s)
    """, [
        ('admin', 'admin123', 'admin'),
        ('teacher1', 'teach123', 'teacher'),
        ('student1', 'stud123', 'student')
    ])

    # Dummy resources
    cursor.executemany("""
        INSERT INTO resources (name) VALUES (%s)
    """, [
        ('Resource A',),
        ('Resource B',),
        ('Resource C',)
    ])

    # RBAC
    cursor.executemany("""
        INSERT INTO rbac (role, resource_id, can_access) VALUES (%s, %s, %s)
    """, [
        ('teacher', 1, True),
        ('student', 2, True),
        ('student', 3, False)
    ])

    # ACL
    cursor.executemany("""
        INSERT INTO acl (user_id, resource_id, can_access) VALUES (%s, %s, %s)
    """, [
        (2, 3, True),
        (3, 1, False)
    ])

    conn.commit()
    conn.close()
    print("MySQL DB initialized.")

if __name__ == "__main__":
    init_db()
