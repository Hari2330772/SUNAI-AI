"""
SUNAI v4.0 — Flask Backend
──────────────────────────
v4.0 New features:
  • Streaming responses via Server-Sent Events (SSE)  — /chat/stream
  • Stop-generation token: client sends abort, server stops streaming
  • All previous security fixes retained (bcrypt, limiter, CSRF, atomic quota,
    Razorpay signature verification, MIME magic, supabase-py SDK)
"""
import os, json, uuid, hmac, hashlib, time, threading
import bcrypt
import razorpay
from flask import (Flask, request, jsonify, render_template,
                   session, redirect, Response, stream_with_context)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import date, timedelta, datetime
from functools import wraps
from dotenv import load_dotenv
from supabase import create_client, Client
from groq import Groq
import google.generativeai as genai

# python-magic is optional — gracefully degrade if libmagic not installed
try:
    import magic as _magic
    _MAGIC_AVAILABLE = True
except Exception:
    _MAGIC_AVAILABLE = False

load_dotenv()

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") != "development",
    SESSION_COOKIE_HTTPONLY=True,
    MAX_CONTENT_LENGTH=12 * 1024 * 1024,
)
CORS(app, supports_credentials=True,
     origins=os.environ.get("ALLOWED_ORIGINS", "*").split(","))

limiter = Limiter(key_func=get_remote_address, app=app,
                  default_limits=[], storage_uri="memory://")

# ── External clients ──────────────────────────────────────────────────────────
supabase: Client = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])
groq_client      = Groq(api_key=os.environ["GROQ_API_KEY"])
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", ""))
vision_model     = genai.GenerativeModel("gemini-2.5-flash")
rzp_client       = razorpay.Client(
    auth=(os.environ.get("RAZORPAY_KEY_ID", ""),
          os.environ.get("RAZORPAY_KEY_SECRET", ""))
)

FREE_LIMIT           = 10
HISTORY_LIMIT        = 100
FREE_HISTORY_TTL_DAYS = 30
GROQ_MODEL           = "llama-3.1-8b-instant"

# Active stream abort flags: { stream_id: threading.Event }
_abort_events: dict[str, threading.Event] = {}

# ── Password helpers ──────────────────────────────────────────────────────────
def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pw(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

# ── Supabase helpers ──────────────────────────────────────────────────────────
def get_user_by_id(uid: str) -> dict | None:
    try:
        r = supabase.table("users").select("*").eq("id", uid).maybe_single().execute()
        return getattr(r, "data", None)
    except Exception as e:
        app.logger.error("get_user_by_id: %s", e)
        return None

def get_user_by_email(email: str) -> dict | None:
    try:
        r = supabase.table("users").select("*").eq("email", email).maybe_single().execute()
        return getattr(r, "data", None)
    except Exception as e:
        app.logger.error("get_user_by_email: %s", e)
        return None

def save_user(user: dict):
    supabase.table("users").upsert(user).execute()

def get_today_usage(uid: str) -> int:
    try:
        r = (supabase.table("usage_counts").select("count")
             .eq("user_id", uid).eq("day", str(date.today()))
             .maybe_single().execute())
        d = getattr(r, "data", None)
        return d["count"] if d else 0
    except Exception:
        return 0

def increment_usage(uid: str) -> int:
    """Atomic increment via Postgres RPC. Returns new count, or -1 if limit hit.

    Supabase SQL (run once):
    ─────────────────────────────────────────────────────────────────────
    CREATE OR REPLACE FUNCTION increment_daily_usage(
        p_user_id uuid, p_day date, p_limit int)
    RETURNS int LANGUAGE plpgsql AS $$
    DECLARE new_count int;
    BEGIN
      INSERT INTO usage_counts (user_id, day, count) VALUES (p_user_id, p_day, 1)
      ON CONFLICT (user_id, day)
      DO UPDATE SET count = usage_counts.count + 1
      WHERE usage_counts.count < p_limit
      RETURNING count INTO new_count;
      RETURN COALESCE(new_count, -1);
    END; $$;
    ─────────────────────────────────────────────────────────────────────
    """
    r = supabase.rpc("increment_daily_usage", {
        "p_user_id": uid, "p_day": str(date.today()), "p_limit": FREE_LIMIT
    }).execute()
    return r.data

def get_history(uid: str) -> list:
    try:
        r = (supabase.table("chat_history").select("role,content,created_at")
             .eq("user_id", uid).order("id", desc=False).limit(HISTORY_LIMIT).execute())
        return getattr(r, "data", []) or []
    except Exception:
        return []

def add_history(uid: str, role: str, content: str):
    try:
        supabase.table("chat_history").insert({
            "user_id": uid, "role": role, "content": content,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
    except Exception as e:
        app.logger.error("add_history: %s", e)

def clear_history_db(uid: str):
    supabase.table("chat_history").delete().eq("user_id", uid).execute()

def prune_old_history(uid: str, plan: str):
    if plan != "free":
        return
    cutoff = (datetime.utcnow() - timedelta(days=FREE_HISTORY_TTL_DAYS)).isoformat()
    try:
        supabase.table("chat_history").delete().eq("user_id", uid).lt("created_at", cutoff).execute()
    except Exception:
        pass

def set_session_token(uid: str, token: str):
    supabase.table("users").update({"session_token": token}).eq("id", uid).execute()

def verify_session_token(uid: str, token: str) -> bool:
    try:
        r = (supabase.table("users").select("session_token")
             .eq("id", uid).maybe_single().execute())
        d = getattr(r, "data", None)
        return bool(d and d.get("session_token") == token)
    except Exception:
        return False

# ── Auth decorator ────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        uid   = session.get("user_id")
        token = session.get("session_token")
        if not uid or not token:
            return jsonify({"error": "login_required"}), 401
        if not verify_session_token(uid, token):
            session.clear()
            return jsonify({"error": "session_expired"}), 401
        return f(*args, **kwargs)
    return decorated

def get_current_user() -> dict | None:
    return get_user_by_id(session.get("user_id", ""))

# ── File validation ───────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".py", ".js", ".html", ".css", ".csv", ".md"}
ALLOWED_MIME_TYPES = {
    "application/pdf", "text/plain", "text/x-python",
    "application/javascript", "text/html", "text/css",
    "text/csv", "text/markdown", "application/octet-stream",
}

def validate_file(f) -> tuple[bool, str]:
    ext = os.path.splitext(f.filename.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Extension {ext} not allowed."
    if _MAGIC_AVAILABLE:
        header = f.read(2048); f.seek(0)
        mime = _magic.from_buffer(header, mime=True)
        if mime not in ALLOWED_MIME_TYPES:
            return False, f"File content ({mime}) not allowed."
    return True, ""

# ── Quota helper ──────────────────────────────────────────────────────────────
def _check_quota(user: dict) -> tuple[bool, tuple | None]:
    if user["plan"] == "pro":
        return True, None
    new_count = increment_usage(user["id"])
    if new_count == -1:
        return False, (jsonify({
            "error": "limit_reached",
            "message": f"You've used all {FREE_LIMIT} free queries today. Upgrade to Pro!"
        }), 429)
    return True, None

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = (
    "You are SUNAI, a brilliant and friendly AI assistant. "
    "Help with coding, science, career, mathematics, and any topic. "
    "Format code in fenced code blocks with the language name. "
    "Use markdown for structure. Be clear, concise, and genuinely helpful."
)

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template(
        "index.html",
        free_limit=FREE_LIMIT,
        razorpay_key_id=os.environ.get("RAZORPAY_KEY_ID", ""),
    )

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
@limiter.limit("5/minute; 20/hour")
def register():
    d     = request.get_json(silent=True) or {}
    name  = d.get("name",     "").strip()
    email = d.get("email",    "").strip().lower()
    pw    = d.get("password", "")

    if not name or not email or not pw:
        return jsonify({"error": "All fields required"}), 400
    if len(pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if get_user_by_email(email):
        time.sleep(0.3)
        return jsonify({"error": "Email already registered"}), 400

    uid   = str(uuid.uuid4())
    token = str(uuid.uuid4())
    save_user({"id": uid, "name": name, "email": email,
               "password": hash_pw(pw), "plan": "free",
               "joined": str(date.today()), "session_token": token})
    session.permanent = True
    session["user_id"]       = uid
    session["session_token"] = token
    return jsonify({"success": True, "name": name, "plan": "free"})


@app.route("/login", methods=["POST"])
@limiter.limit("10/minute; 30/hour")
def login():
    d     = request.get_json(silent=True) or {}
    email = d.get("email",    "").strip().lower()
    pw    = d.get("password", "")

    user  = get_user_by_email(email)
    dummy = "$2b$12$invalidhashfortimingpurposesonly000000000000000000000000"
    stored = user["password"] if user else dummy
    ok    = check_pw(pw, stored)

    if not user or not ok:
        time.sleep(0.3)
        return jsonify({"error": "Invalid email or password"}), 401

    token = str(uuid.uuid4())
    set_session_token(user["id"], token)
    session.permanent = True
    session["user_id"]       = user["id"]
    session["session_token"] = token
    return jsonify({"success": True, "name": user["name"], "plan": user["plan"]})


@app.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid:
        set_session_token(uid, "")
    session.clear()
    return redirect("/")


@app.route("/me")
@login_required
def me():
    user = get_current_user()
    if not user:
        session.clear()
        return jsonify({"error": "not_found"}), 404
    used      = get_today_usage(user["id"])
    remaining = 999 if user["plan"] == "pro" else max(0, FREE_LIMIT - used)
    prune_old_history(user["id"], user["plan"])
    return jsonify({"name": user["name"], "plan": user["plan"],
                    "email": user.get("email", ""),
                    "used_today": used, "remaining": remaining})

# ── Streaming chat (v4.0) ─────────────────────────────────────────────────────
@app.route("/chat/stream", methods=["POST"])
@login_required
@limiter.limit("60/minute")
def chat_stream():
    """
    Streaming SSE endpoint.
    Client receives:  data: <token>\n\n   for each chunk
                      data: [DONE]\n\n   when finished
                      data: [ERROR] <msg>\n\n  on failure
    Client can abort: POST /chat/abort  with { stream_id }
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "not_found"}), 404

    allowed, err = _check_quota(user)
    if not allowed:
        return err

    body     = request.get_json(silent=True) or {}
    messages = body.get("messages", [])
    if not messages:
        return jsonify({"error": "No messages provided"}), 400

    stream_id = str(uuid.uuid4())
    abort_evt = threading.Event()
    _abort_events[stream_id] = abort_evt

    clean = [
        {"role": m["role"] if m.get("role") in ("user", "assistant") else "user",
         "content": str(m.get("content", ""))[:8000]}
        for m in messages[-40:]
    ]

    def generate():
        full_reply = []
        try:
            # Send stream_id first so client can abort if needed
            yield f"data: [STREAM_ID:{stream_id}]\n\n"

            stream = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "system", "content": SYSTEM_PROMPT}] + clean,
                max_tokens=2048,
                stream=True,
            )

            for chunk in stream:
                if abort_evt.is_set():
                    yield "data: [ABORTED]\n\n"
                    return

                delta = chunk.choices[0].delta
                token = getattr(delta, "content", None) or ""
                if token:
                    full_reply.append(token)
                    # SSE-escape: newlines in token must be split across data: lines
                    escaped = token.replace("\n", "\ndata: ")
                    yield f"data: {escaped}\n\n"

            yield "data: [DONE]\n\n"

            # Persist to history after full reply
            reply_text = "".join(full_reply)
            add_history(user["id"], "user",      clean[-1]["content"])
            add_history(user["id"], "assistant", reply_text)

        except Exception as e:
            app.logger.exception("Stream error")
            yield f"data: [ERROR] Processing failed. Please try again.\n\n"
        finally:
            _abort_events.pop(stream_id, None)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":       "no-cache",
            "X-Accel-Buffering":   "no",   # disable nginx buffering
            "Connection":          "keep-alive",
        }
    )


@app.route("/chat/abort", methods=["POST"])
@login_required
def chat_abort():
    """Signal an active stream to stop."""
    sid = (request.get_json(silent=True) or {}).get("stream_id", "")
    evt = _abort_events.get(sid)
    if evt:
        evt.set()
        return jsonify({"success": True})
    return jsonify({"error": "Stream not found"}), 404


# ── Non-streaming fallback (kept for compatibility) ───────────────────────────
@app.route("/chat", methods=["POST"])
@login_required
@limiter.limit("60/minute")
def chat():
    user = get_current_user()
    if not user:
        return jsonify({"error": "not_found"}), 404

    allowed, err = _check_quota(user)
    if not allowed:
        return err

    messages = (request.get_json(silent=True) or {}).get("messages", [])
    if not messages:
        return jsonify({"error": "No message provided"}), 400

    clean = [
        {"role": m["role"] if m.get("role") in ("user", "assistant") else "user",
         "content": str(m.get("content", ""))[:8000]}
        for m in messages[-40:]
    ]

    try:
        resp  = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "system", "content": SYSTEM_PROMPT}] + clean,
            max_tokens=1500,
        )
        reply = resp.choices[0].message.content
        add_history(user["id"], "user",      clean[-1]["content"])
        add_history(user["id"], "assistant", reply)
        used      = get_today_usage(user["id"])
        remaining = 999 if user["plan"] == "pro" else max(0, FREE_LIMIT - used)
        return jsonify({"reply": reply, "remaining": remaining, "plan": user["plan"]})
    except Exception:
        app.logger.exception("Chat failed")
        return jsonify({"error": "Processing failed. Please try again."}), 500


# ── Image analysis ────────────────────────────────────────────────────────────
@app.route("/analyze-image", methods=["POST"])
@login_required
@limiter.limit("30/minute")
def analyze_image():
    user = get_current_user()
    if not user:
        return jsonify({"error": "not_found"}), 404

    allowed, err = _check_quota(user)
    if not allowed:
        return err

    if "image" not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    img_file = request.files["image"]
    if _MAGIC_AVAILABLE:
        header = img_file.read(2048); img_file.seek(0)
        if not _magic.from_buffer(header, mime=True).startswith("image/"):
            return jsonify({"error": "Not a valid image file"}), 400

    question = request.form.get("question", "Describe this image in detail.")[:1000]
    try:
        import PIL.Image, io
        img  = PIL.Image.open(io.BytesIO(img_file.read()))
        resp = vision_model.generate_content(
            [f"You are SUNAI, a helpful AI assistant. {question}", img])
        reply = resp.text
        add_history(user["id"], "user",      f"[Image] {question}")
        add_history(user["id"], "assistant", reply)
        return jsonify({"reply": reply})
    except Exception:
        app.logger.exception("Image analysis failed")
        return jsonify({"error": "Image processing failed. Please try again."}), 500


# ── File analysis ─────────────────────────────────────────────────────────────
@app.route("/analyze-file", methods=["POST"])
@login_required
@limiter.limit("20/minute")
def analyze_file():
    user = get_current_user()
    if not user:
        return jsonify({"error": "not_found"}), 404

    allowed, err = _check_quota(user)
    if not allowed:
        return err

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    ok, reason = validate_file(f)
    if not ok:
        return jsonify({"error": reason}), 400

    question = request.form.get("question", "Summarize this document.")[:1000]
    try:
        if f.filename.lower().endswith(".pdf"):
            import PyPDF2, io
            text = "\n".join(
                p.extract_text() or ""
                for p in PyPDF2.PdfReader(io.BytesIO(f.read())).pages
            )
        else:
            text = f.read().decode("utf-8", errors="ignore")
        text = text[:8000]
        resp = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are SUNAI, a helpful AI assistant."},
                {"role": "user",   "content": f"File:\n\n{text}\n\nQuestion: {question}"},
            ],
            max_tokens=1500,
        )
        reply = resp.choices[0].message.content
        add_history(user["id"], "user",      f"[File: {f.filename}] {question}")
        add_history(user["id"], "assistant", reply)
        return jsonify({"reply": reply})
    except Exception:
        app.logger.exception("File analysis failed")
        return jsonify({"error": "File processing failed. Please try again."}), 500


# ── Payment ───────────────────────────────────────────────────────────────────
@app.route("/create-order", methods=["POST"])
@login_required
@limiter.limit("5/minute")
def create_order():
    try:
        order = rzp_client.order.create({"amount": 19900, "currency": "INR", "payment_capture": 1})
        return jsonify({"order_id": order["id"], "amount": order["amount"]})
    except Exception:
        app.logger.exception("Razorpay order creation failed")
        return jsonify({"error": "Could not initiate payment. Try again."}), 500


@app.route("/verify-payment", methods=["POST"])
@login_required
@limiter.limit("5/minute")
def verify_payment():
    d          = request.get_json(silent=True) or {}
    order_id   = d.get("razorpay_order_id",  "")
    payment_id = d.get("razorpay_payment_id", "")
    signature  = d.get("razorpay_signature",  "")
    if not all([order_id, payment_id, signature]):
        return jsonify({"error": "Missing payment fields"}), 400

    key_secret = os.environ.get("RAZORPAY_KEY_SECRET", "").encode()
    expected   = hmac.new(key_secret, f"{order_id}|{payment_id}".encode(),
                          hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        app.logger.warning("Invalid Razorpay sig for user %s", session["user_id"])
        return jsonify({"error": "Payment verification failed"}), 400

    supabase.table("users").update({"plan": "pro"}).eq("id", session["user_id"]).execute()
    return jsonify({"success": True, "message": "Upgraded to Pro!"})


# ── History ───────────────────────────────────────────────────────────────────
@app.route("/history")
@login_required
def history():
    rows = get_history(session["user_id"])
    return jsonify({"history": [
        {"role": r["role"], "content": r["content"], "time": r.get("created_at", "")}
        for r in rows
    ]})


@app.route("/history/clear", methods=["POST"])
@login_required
@limiter.limit("10/minute")
def clear_history():
    clear_history_db(session["user_id"])
    return jsonify({"success": True})


# ── SEO ───────────────────────────────────────────────────────────────────────
@app.route("/sitemap.xml")
def sitemap():
    base = os.environ.get("SITE_URL", "https://sunai.example.com")
    return app.response_class(
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f'<url><loc>{base}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>'
        f'</urlset>',
        mimetype="application/xml"
    )

@app.route("/robots.txt")
def robots():
    base = os.environ.get("SITE_URL", "https://sunai.example.com")
    return app.response_class(
        f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml",
        mimetype="text/plain"
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=os.environ.get("FLASK_ENV") == "development",
            host="0.0.0.0", port=port)
