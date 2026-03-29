"""
FinTrack — Personal Finance Tracker
Flask backend with JWT auth, SQLite, REST API
"""
import os, sqlite3, hashlib, hmac, json, re, base64
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, g

app = Flask(__name__,
    template_folder="frontend/templates",
    static_folder="frontend/static")

SECRET_KEY = os.environ.get("SECRET_KEY", "fintrack-dev-secret-2024-changeme")
DATABASE   = os.environ.get("DATABASE", "fintrack.db")

# ── DB ──────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            currency TEXT DEFAULT 'USD',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('income','expense')),
            category TEXT NOT NULL,
            amount REAL NOT NULL CHECK(amount > 0),
            note TEXT DEFAULT '',
            date TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            limit_amount REAL NOT NULL,
            month TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            UNIQUE(user_id, category, month)
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    db.commit(); db.close()
    print("Database ready")

# ── Security ────────────────────────────────────────
def hash_pw(pw):
    return hmac.new(SECRET_KEY.encode(), pw.encode(), hashlib.sha256).hexdigest()

def check_pw(pw, h):
    return hmac.compare_digest(hash_pw(pw), h)

def make_token(uid, username):
    payload = json.dumps({"uid": uid, "u": username,
        "exp": (datetime.utcnow()+timedelta(days=7)).isoformat()})
    b64 = base64.b64encode(payload.encode()).decode()
    sig  = hmac.new(SECRET_KEY.encode(), b64.encode(), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"

def read_token(token):
    try:
        b64, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(
            hmac.new(SECRET_KEY.encode(), b64.encode(), hashlib.sha256).hexdigest(), sig):
            return None
        p = json.loads(base64.b64decode(b64).decode())
        if datetime.fromisoformat(p["exp"]) < datetime.utcnow(): return None
        return p
    except: return None

def auth(f):
    @wraps(f)
    def wrap(*a, **kw):
        tok = request.headers.get("Authorization","").replace("Bearer ","")
        p   = read_token(tok)
        if not p: return jsonify({"error":"Unauthorized"}), 401
        g.uid = p["uid"]; g.uname = p["u"]
        return f(*a, **kw)
    return wrap

def clean(v, n=200): return str(v).strip()[:n]

CATS = ["Food","Transport","Shopping","Health","Housing","Entertainment",
        "Education","Utilities","Savings","Salary","Freelance","Investment","Gift","Other"]

# ── Frontend ─────────────────────────────────────────
@app.route("/")
def index(): return render_template("index.html")

# ── Auth ─────────────────────────────────────────────
@app.route("/api/auth/signup", methods=["POST"])
def signup():
    d = request.get_json() or {}
    u, e, pw, cur = clean(d.get("username","")), clean(d.get("email","")), \
                    d.get("password",""), d.get("currency","USD")
    if not all([u,e,pw]): return jsonify({"error":"All fields required"}), 400
    if len(u)<3: return jsonify({"error":"Username min 3 chars"}), 400
    if not re.match(r"^[\w]+$",u): return jsonify({"error":"Username: letters/numbers/_"}), 400
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$",e): return jsonify({"error":"Invalid email"}), 400
    if len(pw)<6: return jsonify({"error":"Password min 6 chars"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users(username,email,password,currency) VALUES(?,?,?,?)",
                   (u,e,hash_pw(pw),cur)); db.commit()
        row = db.execute("SELECT id FROM users WHERE username=?",(u,)).fetchone()
        db.execute("INSERT INTO notifications(user_id,message) VALUES(?,?)",
                   (row["id"],"Welcome to FinTrack! Add your first transaction.")); db.commit()
        return jsonify({"token":make_token(row["id"],u),"username":u,"currency":cur}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error":"Username or email already taken"}), 409

@app.route("/api/auth/login", methods=["POST"])
def login():
    d = request.get_json() or {}
    u, pw = clean(d.get("username","")), d.get("password","")
    if not u or not pw: return jsonify({"error":"Username and password required"}), 400
    db  = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
    if not row or not check_pw(pw, row["password"]):
        return jsonify({"error":"Invalid credentials"}), 401
    return jsonify({"token":make_token(row["id"],row["username"]),
                    "username":row["username"],"currency":row["currency"]})

@app.route("/api/auth/me", methods=["GET"])
@auth
def me():
    row = get_db().execute(
        "SELECT id,username,email,currency,created_at FROM users WHERE id=?",(g.uid,)).fetchone()
    return jsonify(dict(row)) if row else (jsonify({"error":"Not found"}),404)

@app.route("/api/auth/profile", methods=["PUT"])
@auth
def update_profile():
    d = request.get_json() or {}
    cur = clean(d.get("currency","USD"),5)
    get_db().execute("UPDATE users SET currency=? WHERE id=?",(cur,g.uid))
    get_db().commit()
    return jsonify({"message":"Updated","currency":cur})

# ── Dashboard ────────────────────────────────────────
@app.route("/api/dashboard", methods=["GET"])
@auth
def dashboard():
    db, uid = get_db(), g.uid
    month = datetime.now().strftime("%Y-%m")
    totals = db.execute(
        "SELECT type, COALESCE(SUM(amount),0) t FROM transactions WHERE user_id=? GROUP BY type",
        (uid,)).fetchall()
    inc = next((r["t"] for r in totals if r["type"]=="income"), 0)
    exp = next((r["t"] for r in totals if r["type"]=="expense"), 0)
    monthly = db.execute("""
        SELECT strftime('%Y-%m',date) mo,
               SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) income,
               SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) expense
        FROM transactions WHERE user_id=?
        GROUP BY mo ORDER BY mo DESC LIMIT 6
    """, (uid,)).fetchall()
    cats = db.execute("""
        SELECT category, SUM(amount) total FROM transactions
        WHERE user_id=? AND type='expense' AND date LIKE ?
        GROUP BY category ORDER BY total DESC
    """, (uid, month+"%")).fetchall()
    recent = db.execute(
        "SELECT * FROM transactions WHERE user_id=? ORDER BY date DESC,created_at DESC LIMIT 5",
        (uid,)).fetchall()
    budgets = db.execute("""
        SELECT b.category, b.limit_amount, COALESCE(SUM(t.amount),0) spent
        FROM budgets b
        LEFT JOIN transactions t ON t.user_id=b.user_id AND t.category=b.category
            AND t.type='expense' AND t.date LIKE ?
        WHERE b.user_id=? AND b.month=? GROUP BY b.id
    """, (month+"%", uid, month)).fetchall()
    return jsonify({
        "balance":round(inc-exp,2),"income":round(inc,2),"expense":round(exp,2),
        "monthly":[dict(r) for r in reversed(list(monthly))],
        "categories":[dict(r) for r in cats],
        "recent":[dict(r) for r in recent],
        "budgets":[dict(r) for r in budgets],
    })

# ── Transactions ─────────────────────────────────────
@app.route("/api/transactions", methods=["GET"])
@auth
def list_tx():
    page=max(1,int(request.args.get("page",1)))
    pp=min(50,int(request.args.get("per_page",20)))
    srch=clean(request.args.get("search",""))
    typ=request.args.get("type",""); cat=request.args.get("category","")
    mon=request.args.get("month","")
    db=get_db(); sql="SELECT * FROM transactions WHERE user_id=?"; args=[g.uid]
    if srch: sql+=" AND (note LIKE ? OR category LIKE ?)"; args+=[f"%{srch}%",f"%{srch}%"]
    if typ in ("income","expense"): sql+=" AND type=?"; args.append(typ)
    if cat: sql+=" AND category=?"; args.append(cat)
    if mon: sql+=" AND date LIKE ?"; args.append(mon+"%")
    cnt=db.execute(sql.replace("SELECT *","SELECT COUNT(*)"),args).fetchone()[0]
    sql+=" ORDER BY date DESC,created_at DESC LIMIT ? OFFSET ?"; args+=[pp,(page-1)*pp]
    rows=db.execute(sql,args).fetchall()
    return jsonify({"transactions":[dict(r) for r in rows],"total":cnt,
                    "page":page,"pages":max(1,-(-cnt//pp))})

@app.route("/api/transactions", methods=["POST"])
@auth
def add_tx():
    d=request.get_json() or {}
    typ=d.get("type",""); cat=clean(d.get("category",""))
    note=clean(d.get("note","")); dt=clean(d.get("date",""))
    try: amt=float(d.get("amount",0))
    except: return jsonify({"error":"Invalid amount"}),400
    if typ not in ("income","expense"): return jsonify({"error":"Invalid type"}),400
    if cat not in CATS: return jsonify({"error":"Invalid category"}),400
    if amt<=0: return jsonify({"error":"Amount must be positive"}),400
    if not dt: return jsonify({"error":"Date required"}),400
    db=get_db()
    cur=db.execute("INSERT INTO transactions(user_id,type,category,amount,note,date) VALUES(?,?,?,?,?,?)",
        (g.uid,typ,cat,round(amt,2),note,dt)); db.commit()
    if typ=="expense":
        mon=dt[:7]
        bud=db.execute("SELECT limit_amount FROM budgets WHERE user_id=? AND category=? AND month=?",
            (g.uid,cat,mon)).fetchone()
        if bud:
            spent=db.execute("SELECT COALESCE(SUM(amount),0) s FROM transactions "
                "WHERE user_id=? AND type='expense' AND category=? AND date LIKE ?",
                (g.uid,cat,mon+"%")).fetchone()["s"]
            pct=spent/bud["limit_amount"]*100
            if pct>=90:
                db.execute("INSERT INTO notifications(user_id,message) VALUES(?,?)",
                    (g.uid,f"Budget alert: {cat} is at {pct:.0f}% of monthly limit!"))
                db.commit()
    row=db.execute("SELECT * FROM transactions WHERE id=?",(cur.lastrowid,)).fetchone()
    return jsonify(dict(row)),201

@app.route("/api/transactions/<int:tid>", methods=["PUT"])
@auth
def update_tx(tid):
    db=get_db()
    tx=db.execute("SELECT * FROM transactions WHERE id=? AND user_id=?",(tid,g.uid)).fetchone()
    if not tx: return jsonify({"error":"Not found"}),404
    d=request.get_json() or {}
    typ=d.get("type",tx["type"]); cat=clean(d.get("category",tx["category"]))
    note=clean(d.get("note",tx["note"])); dt=clean(d.get("date",tx["date"]))
    try: amt=float(d.get("amount",tx["amount"]))
    except: return jsonify({"error":"Invalid amount"}),400
    db.execute("UPDATE transactions SET type=?,category=?,amount=?,note=?,date=? WHERE id=? AND user_id=?",
               (typ,cat,round(amt,2),note,dt,tid,g.uid)); db.commit()
    return jsonify(dict(db.execute("SELECT * FROM transactions WHERE id=?",(tid,)).fetchone()))

@app.route("/api/transactions/<int:tid>", methods=["DELETE"])
@auth
def del_tx(tid):
    r=get_db().execute("DELETE FROM transactions WHERE id=? AND user_id=?",(tid,g.uid))
    get_db().commit()
    return jsonify({"message":"Deleted"}) if r.rowcount else (jsonify({"error":"Not found"}),404)

# ── Budgets ──────────────────────────────────────────
@app.route("/api/budgets", methods=["GET"])
@auth
def get_budgets():
    mon=request.args.get("month",datetime.now().strftime("%Y-%m"))
    db=get_db()
    rows=db.execute("""
        SELECT b.*, COALESCE(SUM(t.amount),0) spent
        FROM budgets b
        LEFT JOIN transactions t ON t.user_id=b.user_id AND t.category=b.category
            AND t.type='expense' AND t.date LIKE ?
        WHERE b.user_id=? AND b.month=? GROUP BY b.id
    """,(mon+"%",g.uid,mon)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/budgets", methods=["POST"])
@auth
def set_budget():
    d=request.get_json() or {}
    cat=clean(d.get("category",""))
    mon=clean(d.get("month",datetime.now().strftime("%Y-%m")))
    try: lim=float(d.get("limit_amount",0))
    except: return jsonify({"error":"Invalid amount"}),400
    if cat not in CATS: return jsonify({"error":"Invalid category"}),400
    if lim<=0: return jsonify({"error":"Limit must be positive"}),400
    db=get_db()
    db.execute("""INSERT INTO budgets(user_id,category,limit_amount,month) VALUES(?,?,?,?)
        ON CONFLICT(user_id,category,month) DO UPDATE SET limit_amount=excluded.limit_amount""",
        (g.uid,cat,round(lim,2),mon)); db.commit()
    return jsonify({"message":"Budget saved"})

@app.route("/api/budgets/<int:bid>", methods=["DELETE"])
@auth
def del_budget(bid):
    get_db().execute("DELETE FROM budgets WHERE id=? AND user_id=?",(bid,g.uid))
    get_db().commit()
    return jsonify({"message":"Deleted"})

# ── Notifications ────────────────────────────────────
@app.route("/api/notifications", methods=["GET"])
@auth
def get_notifs():
    db=get_db()
    rows=db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
        (g.uid,)).fetchall()
    unread=db.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",
        (g.uid,)).fetchone()[0]
    return jsonify({"notifications":[dict(r) for r in rows],"unread":unread})

@app.route("/api/notifications/read", methods=["PUT"])
@auth
def mark_read():
    get_db().execute("UPDATE notifications SET is_read=1 WHERE user_id=?",(g.uid,))
    get_db().commit()
    return jsonify({"message":"Marked read"})

# ── Analytics ────────────────────────────────────────
@app.route("/api/analytics", methods=["GET"])
@auth
def analytics():
    db,uid=get_db(),g.uid
    daily=db.execute("""
        SELECT date,
               SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) expense,
               SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) income
        FROM transactions WHERE user_id=? AND date >= date('now','-30 days')
        GROUP BY date ORDER BY date
    """,(uid,)).fetchall()
    top_cats=db.execute("""
        SELECT category, SUM(amount) total, COUNT(*) count
        FROM transactions WHERE user_id=? AND type='expense'
        GROUP BY category ORDER BY total DESC LIMIT 8
    """,(uid,)).fetchall()
    savings=db.execute("""
        SELECT strftime('%Y-%m',date) mo,
               SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) income,
               SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) expense
        FROM transactions WHERE user_id=?
        GROUP BY mo ORDER BY mo DESC LIMIT 6
    """,(uid,)).fetchall()
    return jsonify({
        "daily":[dict(r) for r in daily],
        "top_cats":[dict(r) for r in top_cats],
        "savings":[dict(r) for r in reversed(list(savings))]
    })

# ── Run ──────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port=int(os.environ.get("PORT",5000))
    debug=os.environ.get("FLASK_DEBUG","true").lower()=="true"
    print(f"\nFinTrack running at http://localhost:{port}\n")
    app.run(host="0.0.0.0",port=port,debug=debug)
