import os
import sqlite3
import requests
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.secret_key = "supersecret"

DATABASE = "database.db"

# ---------------- DATABASE INIT ----------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS servers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        ip TEXT,
        user_id INTEGER,
        status TEXT DEFAULT 'UNKNOWN',
        response_time REAL DEFAULT 0,
        total_checks INTEGER DEFAULT 0,
        failed_checks INTEGER DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER,
        start_time TEXT,
        status TEXT
    )
    """)

    cursor.execute("SELECT * FROM users WHERE role='admin'")
    if not cursor.fetchone():
        cursor.execute("""
        INSERT INTO users(name,email,password,role)
        VALUES(?,?,?,?)
        """, ("Admin", "admin@cyberhealth.com",
              generate_password_hash("admin123"),
              "admin"))

    conn.commit()
    conn.close()

init_db()

# ---------------- MONITORING THREAD ----------------
def monitor_servers():
    while True:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM servers")
        servers = cursor.fetchall()

        for server in servers:
            try:
                start = time.time()
                requests.get(server[2], timeout=5)
                response_time = round(time.time() - start, 2)
                status = "UP"
                failed = server[7]
            except:
                response_time = 0
                status = "DOWN"
                failed = server[7] + 1

                cursor.execute("""
                INSERT INTO incidents(server_id,start_time,status)
                VALUES(?,?,?)
                """, (server[0], datetime.now().strftime("%Y-%m-%d %H:%M"),
                      "OPEN"))

            total = server[6] + 1

            cursor.execute("""
            UPDATE servers
            SET status=?, response_time=?, total_checks=?, failed_checks=?
            WHERE id=?
            """, (status, response_time, total, failed, server[0]))

        conn.commit()
        conn.close()
        time.sleep(30)

threading.Thread(target=monitor_servers, daemon=True).start()

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO users(name,email,password,role)
        VALUES(?,?,?,?)
        """,(request.form["name"],
             request.form["email"],
             generate_password_hash(request.form["password"]),
             "user"))

        conn.commit()
        conn.close()
        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?",
                       (request.form["email"],))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], request.form["password"]):
            session["user_id"] = user[0]
            session["role"] = user[4]
            return redirect("/dashboard")
        else:
            return "Invalid Login"

    return render_template("login.html")

@app.route("/dashboard", methods=["GET","POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    if request.method == "POST":
        cursor.execute("""
        INSERT INTO servers(name,ip,user_id)
        VALUES(?,?,?)
        """,(request.form["name"],
             request.form["ip"],
             session["user_id"]))
        conn.commit()

    if session["role"] == "admin":
        cursor.execute("SELECT * FROM servers")
    else:
        cursor.execute("SELECT * FROM servers WHERE user_id=?",
                       (session["user_id"],))

    servers = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", servers=servers)

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect("/dashboard")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.execute("SELECT * FROM incidents")
    incidents = cursor.fetchall()
    conn.close()

    return render_template("admin.html",
                           users=users,
                           incidents=incidents)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
