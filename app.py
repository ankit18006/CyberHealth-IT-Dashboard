import sqlite3
import threading
import time
import requests
import concurrent.futures
from datetime import datetime
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "enterprise_secret"
DB = "database.db"

CHECK_INTERVAL = 30
FAIL_THRESHOLD = 2

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS servers(
        id INTEGER PRIMARY KEY,
        name TEXT,
        ip TEXT,
        user_id INTEGER,
        status TEXT DEFAULT 'UNKNOWN',
        response_time REAL DEFAULT 0,
        total_checks INTEGER DEFAULT 0,
        failed_checks INTEGER DEFAULT 0,
        consecutive_fail INTEGER DEFAULT 0
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS checks(
        id INTEGER PRIMARY KEY,
        server_id INTEGER,
        status TEXT,
        response_time REAL,
        timestamp TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY,
        server_id INTEGER,
        start_time TEXT,
        end_time TEXT,
        status TEXT
    )""")

    c.execute("SELECT * FROM users WHERE role='admin'")
    if not c.fetchone():
        c.execute("""
        INSERT INTO users(name,email,password,role)
        VALUES(?,?,?,?)
        """,("Admin","admin@cyber.com",
             generate_password_hash("admin123"),
             "admin"))

    conn.commit()
    conn.close()

init_db()

# ---------------- SLA ENGINE ----------------
def calculate_sla(server_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM checks WHERE server_id=?", (server_id,))
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM checks WHERE server_id=? AND status='DOWN'", (server_id,))
    down = c.fetchone()[0]
    conn.close()
    if total == 0:
        return 0
    return round(((total - down) / total) * 100, 2)

# ---------------- MONITORING ENGINE ----------------
def check_server(server):
    server_id, name, ip, user_id, status, rt, total, failed, cons = server
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        start = time.time()
        requests.get(ip, timeout=5)
        response = round((time.time() - start)*1000,2)
        return server_id,"UP",response,0,now
    except:
        return server_id,"DOWN",0,1,now

def monitoring_loop():
    while True:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT * FROM servers")
        servers = c.fetchall()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_server, servers)

        for server_id,status,response,fail_inc,now in results:
            c.execute("""
            INSERT INTO checks(server_id,status,response_time,timestamp)
            VALUES(?,?,?,?)
            """,(server_id,status,response,now))

            c.execute("SELECT consecutive_fail FROM servers WHERE id=?", (server_id,))
            cons = c.fetchone()[0]

            if status == "DOWN":
                cons += 1
            else:
                cons = 0

            c.execute("""
            UPDATE servers
            SET status=?, response_time=?, total_checks=total_checks+1,
                consecutive_fail=?, failed_checks=failed_checks+?
            WHERE id=?
            """,(status,response,cons,fail_inc,server_id))

            # INCIDENT LOGIC
            if cons >= FAIL_THRESHOLD and status=="DOWN":
                c.execute("""
                INSERT INTO incidents(server_id,start_time,status)
                VALUES(?,?,?)
                """,(server_id,now,"OPEN"))

            if status=="UP":
                c.execute("""
                UPDATE incidents
                SET end_time=?, status='RESOLVED'
                WHERE server_id=? AND status='OPEN'
                """,(now,server_id))

        conn.commit()
        conn.close()
        time.sleep(CHECK_INTERVAL)

threading.Thread(target=monitoring_loop, daemon=True).start()

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        conn=sqlite3.connect(DB)
        c=conn.cursor()
        c.execute("""
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
    if request.method=="POST":
        conn=sqlite3.connect(DB)
        c=conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?",(request.form["email"],))
        user=c.fetchone()
        conn.close()
        if user and check_password_hash(user[3],request.form["password"]):
            session["user_id"]=user[0]
            session["role"]=user[4]
            return redirect("/dashboard")
    return render_template("login.html")

@app.route("/dashboard", methods=["GET","POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    conn=sqlite3.connect(DB)
    c=conn.cursor()

    if request.method=="POST":
        c.execute("""
        INSERT INTO servers(name,ip,user_id)
        VALUES(?,?,?)
        """,(request.form["name"],
             request.form["ip"],
             session["user_id"]))
        conn.commit()

    if session["role"]=="admin":
        c.execute("SELECT * FROM servers")
    else:
        c.execute("SELECT * FROM servers WHERE user_id=?",(session["user_id"],))

    servers=c.fetchall()

    sla_data=[]
    for s in servers:
        sla_data.append(calculate_sla(s[0]))

    conn.close()
    return render_template("dashboard.html",servers=servers,sla_data=sla_data)

@app.route("/admin")
def admin():
    if session.get("role")!="admin":
        return redirect("/dashboard")
    conn=sqlite3.connect(DB)
    c=conn.cursor()
    c.execute("SELECT * FROM users")
    users=c.fetchall()
    c.execute("SELECT * FROM incidents")
    incidents=c.fetchall()
    conn.close()
    return render_template("admin.html",users=users,incidents=incidents)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)
