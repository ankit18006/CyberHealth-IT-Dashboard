import sqlite3
import threading
import time
import requests
import concurrent.futures
import io
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
app.secret_key = "enterprise_secret"
DB = "database.db"

CHECK_INTERVAL = 30
FAIL_THRESHOLD = 2
monitor_started = False

# ---------------- DATABASE INIT ----------------
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

    c.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts(
        id INTEGER PRIMARY KEY,
        email TEXT,
        timestamp TEXT,
        success INTEGER
    )""")

    # Default Admin
    c.execute("SELECT * FROM users WHERE role='admin'")
    if not c.fetchone():
        c.execute("""
        INSERT INTO users(name,email,password,role)
        VALUES(?,?,?,?)
        """,(
            "Super Admin",
            "admin@cyberhealth.com",
            generate_password_hash("admin123"),
            "admin"
        ))

    conn.commit()
    conn.close()

init_db()

# ---------------- SLA CALC ----------------
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

# ---------------- MONTHLY SLA ----------------
def get_monthly_sla():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
    SELECT strftime('%m', timestamp),
           COUNT(*),
           SUM(CASE WHEN status='DOWN' THEN 1 ELSE 0 END)
    FROM checks
    GROUP BY strftime('%m', timestamp)
    ORDER BY strftime('%m', timestamp)
    """)

    rows = c.fetchall()
    conn.close()

    labels, data = [], []

    for row in rows:
        month, total, down = row
        down = down if down else 0

        sla = 0 if total == 0 else round(((total - down) / total) * 100, 2)
        labels.append(month)
        data.append(sla)

    return labels, data

# ---------------- MONITOR ENGINE ----------------
def check_server(server):
    server_id, name, ip, user_id, status, rt, total, failed, cons = server
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        start = time.time()
        requests.get(ip, timeout=5)
        response = round((time.time() - start) * 1000, 2)
        return server_id, "UP", response, 0, now
    except:
        return server_id, "DOWN", 0, 1, now

def monitoring_loop():
    while True:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT * FROM servers")
        servers = c.fetchall()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_server, servers)

        for server_id, status, response, fail_inc, now in results:

            c.execute("""
            INSERT INTO checks(server_id,status,response_time,timestamp)
            VALUES(?,?,?,?)
            """,(server_id,status,response,now))

            c.execute("SELECT consecutive_fail FROM servers WHERE id=?", (server_id,))
            cons = c.fetchone()[0]
            cons = cons + 1 if status == "DOWN" else 0

            c.execute("""
            UPDATE servers
            SET status=?, response_time=?, total_checks=total_checks+1,
                consecutive_fail=?, failed_checks=failed_checks+?
            WHERE id=?
            """,(status,response,cons,fail_inc,server_id))

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

def start_monitor():
    global monitor_started
    if not monitor_started:
        monitor_started = True
        threading.Thread(target=monitoring_loop, daemon=True).start()

# Start monitoring immediately (Flask 3 safe)
start_monitor()

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return render_template("landing.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        conn = sqlite3.connect(DB)
        c = conn.cursor()
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
    if request.method == "POST":
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (request.form["email"],))
        user = c.fetchone()

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if user and check_password_hash(user[3], request.form["password"]):
            c.execute("INSERT INTO login_attempts(email,timestamp,success) VALUES(?,?,1)",
                      (request.form["email"], now))
            conn.commit()
            conn.close()

            session["user_id"] = user[0]
            session["role"] = user[4]

            return redirect("/admin" if user[4]=="admin" else "/dashboard")
        else:
            c.execute("INSERT INTO login_attempts(email,timestamp,success) VALUES(?,?,0)",
                      (request.form["email"], now))
            conn.commit()
            conn.close()

    return render_template("login.html")

@app.route("/dashboard", methods=["GET","POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    if session["role"] == "admin":
        return redirect("/admin")

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    if request.method == "POST":
        c.execute("""
        INSERT INTO servers(name,ip,user_id)
        VALUES(?,?,?)
        """,(request.form["name"],
             request.form["ip"],
             session["user_id"]))
        conn.commit()

    c.execute("SELECT * FROM servers WHERE user_id=?", (session["user_id"],))
    servers = c.fetchall()

    sla_data = [calculate_sla(s[0]) for s in servers]

    conn.close()
    return render_template("dashboard.html",
                           servers=servers,
                           sla_data=sla_data)

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect("/dashboard")

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT * FROM users")
    users = c.fetchall()

    c.execute("SELECT * FROM servers")
    servers = c.fetchall()

    c.execute("SELECT * FROM incidents")
    incidents = c.fetchall()

    c.execute("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 20")
    login_attempts = c.fetchall()

    labels, monthly_sla = get_monthly_sla()

    total_checks = sum([s[6] for s in servers])
    total_failed = sum([s[7] for s in servers])
    combined_sla = 0 if total_checks==0 else round(((total_checks-total_failed)/total_checks)*100,2)

    risk_score = 0
    if combined_sla < 98:
        risk_score += 50
    if len(incidents) > 5:
        risk_score += 50

    risk_level = "LOW"
    if risk_score >= 80:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"

    conn.close()

    return render_template("admin.html",
                           users=users,
                           servers=servers,
                           incidents=incidents,
                           login_attempts=login_attempts,
                           combined_sla=combined_sla,
                           monthly_labels=labels,
                           monthly_sla=monthly_sla,
                           risk_score=risk_score,
                           risk_level=risk_level)

@app.route("/export_incidents_pdf")
def export_incidents_pdf():
    if session.get("role") != "admin":
        return redirect("/dashboard")

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM incidents")
    incidents = c.fetchall()
    conn.close()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    elements = []
    style = getSampleStyleSheet()

    elements.append(Paragraph("CyberHealth Incident Report", style['Title']))
    elements.append(Spacer(1, 12))

    data = [["Server ID","Start","End","Status"]]
    for inc in incidents:
        data.append([inc[1], inc[2], inc[3], inc[4]])

    elements.append(Table(data))
    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer,
                     as_attachment=True,
                     download_name="incident_report.pdf",
                     mimetype='application/pdf')

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
