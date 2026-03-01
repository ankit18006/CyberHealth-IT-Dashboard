from flask import Flask, render_template, request, redirect, session, send_file
import sqlite3
import requests
import datetime
import psutil
import threading
import time
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "cyberhealth_enterprise"

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect("database.db")
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
        user_id INTEGER,
        name TEXT,
        url TEXT,
        status TEXT,
        response_time REAL,
        date TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        message TEXT,
        severity TEXT,
        date TEXT
    )
    """)

    # Create default admin
    cursor.execute("SELECT * FROM users WHERE role='admin'")
    if not cursor.fetchone():
        cursor.execute("""
        INSERT INTO users(name,email,password,role)
        VALUES ('Admin','admin@cyber.com',?, 'admin')
        """, (generate_password_hash("admin123"),))

    conn.commit()
    conn.close()

init_db()

# ---------------- SERVER CHECK ----------------
def check_server(url):
    try:
        start = time.time()
        r = requests.get(url, timeout=5)
        response_time = round(time.time() - start,2)
        return ("UP" if r.status_code==200 else "DOWN", response_time)
    except:
        return ("DOWN", 0)

# ---------------- BACKGROUND MONITOR ----------------
def background_monitor():
    while True:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("SELECT id,name,url,user_id FROM servers")
        servers = cursor.fetchall()

        for s in servers:
            status, response = check_server(s[2])
            cursor.execute("""
            UPDATE servers SET status=?,response_time=?,date=?
            WHERE id=?
            """,(status,response,
                 datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),s[0]))

            if status=="DOWN":
                cursor.execute("""
                INSERT INTO incidents(user_id,message,severity,date)
                VALUES (?,?,?,?)
                """,(s[3],f"{s[1]} is DOWN","High",
                     datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))

        conn.commit()
        conn.close()

        time.sleep(30)

threading.Thread(target=background_monitor, daemon=True).start()

# ---------------- LOGIN ----------------
@app.route("/", methods=["GET","POST"])
def login():
    if request.method=="POST":
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (request.form["email"],))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], request.form["password"]):
            session["user_id"]=user[0]
            session["role"]=user[4]
            return redirect("/dashboard")

    return render_template("login.html")

# ---------------- DASHBOARD ----------------
@app.route("/dashboard", methods=["GET","POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    if request.method=="POST":
        status,response = check_server(request.form["url"])
        cursor.execute("""
        INSERT INTO servers(user_id,name,url,status,response_time,date)
        VALUES (?,?,?,?,?,?)
        """,(session["user_id"],
             request.form["name"],
             request.form["url"],
             status,response,
             datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))
        conn.commit()

    cursor.execute("SELECT * FROM servers WHERE user_id=?",(session["user_id"],))
    servers=cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE user_id=?",(session["user_id"],))
    incidents_count=cursor.fetchone()[0]

    total=len(servers)
    up=len([s for s in servers if s[4]=="UP"])
    sla=round((up/total)*100,2) if total>0 else 0

    cpu=psutil.cpu_percent()
    ram=psutil.virtual_memory().percent
    disk=psutil.disk_usage('/').percent

    conn.close()

    return render_template("dashboard.html",
                           servers=servers,
                           total=total,
                           up=up,
                           sla=sla,
                           cpu=cpu,
                           ram=ram,
                           disk=disk,
                           incidents_count=incidents_count)

# ---------------- ADMIN PANEL ----------------
@app.route("/admin")
def admin():
    if session.get("role")!="admin":
        return redirect("/dashboard")

    conn=sqlite3.connect("database.db")
    cursor=conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM servers")
    total_servers=cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents")
    total_incidents=cursor.fetchone()[0]

    cursor.execute("SELECT date,status FROM servers")
    data=cursor.fetchall()

    dates=[d[0] for d in data]
    status_values=[1 if d[1]=="UP" else 0 for d in data]

    conn.close()

    return render_template("admin.html",
                           total_servers=total_servers,
                           total_incidents=total_incidents,
                           dates=dates,
                           status_values=status_values)

# ---------------- PDF EXPORT ----------------
@app.route("/export_pdf")
def export_pdf():
    file_path="/tmp/incident_report.pdf"
    doc=SimpleDocTemplate(file_path,pagesize=A4)
    styles=getSampleStyleSheet()
    elements=[Paragraph("CyberHealth Incident Report",styles["Heading1"]),
              Spacer(1,12)]
    doc.build(elements)
    return send_file(file_path,as_attachment=True)

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)