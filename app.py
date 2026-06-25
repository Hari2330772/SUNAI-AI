
SUNAI Pro v3 - Flask Backend with Supabase Database
Users never get deleted! Persistent storage!
"""
import os, json, hashlib, uuid, base64
from flask import Flask, request, jsonify, render_template, session, redirect
from flask_cors import CORS
from datetime import date, timedelta
from functools import wraps
from dotenv import load_dotenv
from groq import Groq
import urllib.request, urllib.error

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "sunai-secret-2024")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
CORS(app, supports_credentials=True)

groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY", ""))

FREE_LIMIT = 10
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

# â”€â”€ Supabase helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def sb_request(method, table, data=None, query=""):
    url = f"{SUPABASE_URL}/rest/v1/{table}{query}"
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"Supabase error: {err}")
        return None
    except Exception as e:
        print(f"Request error: {e}")
        return None

def get_user_by_id(uid):
    result = sb_request("GET", "users", query=f"?id=eq.{uid}")
    return result[0] if result else None

def get_user_by_email(email):
    result = sb_request("GET", "users", query=f"?email=eq.{email}")
    return result[0] if result else None

def save_user(user):
    # Upsert user
    existing = get_user_by_id(user["id"])
    if existing:
        sb_request("PATCH", "users", data=user, query=f"?id=eq.{user['id']}")
    else:
        sb_request("POST", "users", data=user)

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def get_history(uid):
    result = sb_request("GET", "chat_history",
                        query=f"?user_id=eq.{uid}&order=id.asc&limit=100")
    return result or []

def add_history(uid, role, content):
    sb_request("POST", "chat_history", data={
        "user_id": uid, "role": role,
        "content": content, "created_at": str(date.today())
    })

def clear_history_db(uid):
    sb_request("DELETE", "chat_history", query=f"?user_id=eq.{uid}")

# â”€â”€ Auth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "login_required"}), 401
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    return get_user_by_id(session.get("user_id", ""))

# â”€â”€ Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/")
def index():
    return render_template("index.html", free_limit=FREE_LIMIT)

@app.route("/register", methods=["POST"])
def register():
    data  = request.json or {}
    name  = data.get("name","").strip()
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
    if not name or not email or not pw:
        return jsonify({"error": "All fields required"}), 400
    if get_user_by_email(email):
        return jsonify({"error": "Email already registered"}), 400
    uid   = str(uuid.uuid4())
    today = str(date.today())
    user  = {"id": uid, "name": name, "email": email,
             "password": hash_pw(pw), "plan": "free",
             "joined": today, "usage": {today: 0}}
    save_user(user)
    session.permanent = True
    session["user_id"] = uid
    return jsonify({"success": True, "name": name, "plan": "free", "email": email})

@app.route("/login", methods=["POST"])
def login():
    data  = request.json or {}
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
    user  = get_user_by_email(email)
    if not user or user["password"] != hash_pw(pw):
        return jsonify({"error": "Invalid email or password"}), 401
    session.permanent = True
    session["user_id"] = user["id"]
    return jsonify({"success": True, "name": user["name"],
                    "plan": user["plan"], "email": user["email"]})

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/me")
@login_required
def me():
    user  = get_current_user()
    if not user: session.clear(); return jsonify({"error": "not_found"}), 404
    today = str(date.today())
    usage = user.get("usage") or {}
    if isinstance(usage, str): usage = json.loads(usage)
    used  = usage.get(today, 0)
    remaining = 999 if user["plan"] == "pro" else max(0, FREE_LIMIT - used)
    return jsonify({"name": user["name"], "plan": user["plan"],
                    "email": user.get("email",""),
                    "used_today": used, "remaining": remaining})

@app.route("/upgrade", methods=["POST"])
@login_required
def upgrade():
    uid  = session["user_id"]
    user = get_user_by_id(uid)
    if user:
        user["plan"] = "pro"
        save_user(user)
        return jsonify({"success": True})
    return jsonify({"error": "Not found"}), 404

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    uid  = session["user_id"]
    user = get_user_by_id(uid)
    if not user: return jsonify({"error": "not_found"}), 404
    today = str(date.today())
    usage = user.get("usage") or {}
    if isinstance(usage, str): usage = json.loads(usage)
    usage = {today: usage.get(today, 0)}
    used  = usage[today]
    if user["plan"] == "free" and used >= FREE_LIMIT:
        return jsonify({"error": "limit_reached",
                        "message": f"You've used all {FREE_LIMIT} free queries today. Upgrade to Pro!"}), 429
    messages = (request.json or {}).get("messages", [])
    if not messages: return jsonify({"error": "No message"}), 400
    try:
        resp  = groq_client.chat.completions.create(
            model="qwen/qwen3.6-27b",
            messages=[{"role": "system", "content":
                "You are SUNAI, a brilliant friendly AI assistant. Help with coding, science, career, math, and any topic. Be clear, concise and helpful."}
            ] + messages, max_tokens=1500)
        reply = resp.choices[0].message.content
        usage[today] = used + 1
        user["usage"] = usage
        save_user(user)
        add_history(uid, "user",      messages[-1]["content"])
        add_history(uid, "assistant", reply)
        remaining = 999 if user["plan"] == "pro" else max(0, FREE_LIMIT - usage[today])
        return jsonify({"reply": reply, "remaining": remaining, "plan": user["plan"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/analyze-image", methods=["POST"])
