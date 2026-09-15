import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "mvp.db"
DB.parent.mkdir(exist_ok=True)
DATABASE_URL = (os.environ.get("DATABASE_URL") or os.environ.get("NEON_DATABASE_URL", "")).strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]
if DATABASE_URL and "sslmode=" not in DATABASE_URL.lower():
    DATABASE_URL += "&sslmode=require" if "?" in DATABASE_URL else "?sslmode=require"
SECRET = os.environ.get("APP_SECRET", "dev-only-secret-change-me").encode()
KEY = hashlib.sha256(SECRET + b"|paper-encryption").digest()  # demo key; production: KMS/HSM
PUZZLE_ROUNDS_PER_DAY = max(1, int(os.environ.get("PUZZLE_ROUNDS_PER_DAY", "1000")))
MAX_PUZZLE_ROUNDS = max(1000, int(os.environ.get("MAX_PUZZLE_ROUNDS", "2000000")))
app = FastAPI(title="EPSS - Exam Paper Secure System", version="0.2.0")


class AccessRow(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


class PostgresCursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.lastrowid = None

    def fetchone(self):
        row = self.cursor.fetchone()
        return AccessRow(row) if row else None

    def fetchall(self):
        return [AccessRow(row) for row in self.cursor.fetchall()]


class PostgresConnection:
    is_postgres = True

    def __init__(self):
        import psycopg
        from psycopg.rows import dict_row

        self.connection = psycopg.connect(DATABASE_URL, row_factory=dict_row)

    def execute(self, query, params=()):
        query = query.replace("?", "%s")
        return PostgresCursor(self.connection.execute(query, params))

    def executescript(self, script):
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def db():
    if DATABASE_URL:
        return PostgresConnection()
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c


def now_ts() -> int:
    return int(time.time())


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180_000)
    return "pbkdf2$180000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_b64, digest_b64 = stored.split("$", 3)
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(digest_b64))
    except Exception:
        return False


def legacy_or_password_hash(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2$"):
        return verify_password(password, stored)
    return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)


def init_db():
    c = db()
    schema = """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            author_scope TEXT DEFAULT 'all',
            centre_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS centres(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            code TEXT UNIQUE NOT NULL,
            location TEXT DEFAULT '',
            status TEXT DEFAULT 'ACTIVE',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS papers(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            author_id INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            nonce TEXT NOT NULL,
            release_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            puzzle_seed TEXT NOT NULL DEFAULT '',
            puzzle_rounds INTEGER NOT NULL DEFAULT 0,
            unlocked INTEGER DEFAULT 0,
            FOREIGN KEY(author_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS paper_centres(
            paper_id INTEGER NOT NULL,
            centre_id INTEGER NOT NULL,
            watermark TEXT UNIQUE NOT NULL,
            PRIMARY KEY(paper_id, centre_id),
            FOREIGN KEY(paper_id) REFERENCES papers(id) ON DELETE CASCADE,
            FOREIGN KEY(centre_id) REFERENCES centres(id)
        );
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            paper_id INTEGER,
            actor TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            ip TEXT NOT NULL,
            detail TEXT DEFAULT '',
            ts INTEGER NOT NULL,
            prev_hash TEXT,
            event_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            paper_id INTEGER,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            ts INTEGER NOT NULL,
            resolved INTEGER DEFAULT 0
        );
        """
    if DATABASE_URL:
        schema = schema.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    c.executescript(schema)

    # Gentle migration for the first MVP schema.
    if DATABASE_URL:
        cols = {r["column_name"] for r in c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users'").fetchall()}
    else:
        cols = {r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()}
    if "centre_id" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN centre_id INTEGER")
    if DATABASE_URL:
        paper_cols = {r["column_name"] for r in c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='papers'").fetchall()}
    else:
        paper_cols = {r[1] for r in c.execute("PRAGMA table_info(papers)").fetchall()}
    if "description" not in paper_cols:
        c.execute("ALTER TABLE papers ADD COLUMN description TEXT DEFAULT ''")
    if "puzzle_seed" not in paper_cols:
        c.execute("ALTER TABLE papers ADD COLUMN puzzle_seed TEXT NOT NULL DEFAULT ''")
    if "puzzle_rounds" not in paper_cols:
        c.execute("ALTER TABLE papers ADD COLUMN puzzle_rounds INTEGER NOT NULL DEFAULT 0")

    seed_centres = [
        ("CIT Coimbatore", "CIT001", "Coimbatore, Tamil Nadu"),
        ("SSN Chennai", "SSN001", "Chennai, Tamil Nadu"),
        ("REC Tiruchirappalli", "REC001", "Tiruchirappalli, Tamil Nadu"),
        ("NIT Trichy", "NITT001", "Tiruchirappalli, Tamil Nadu"),
        ("VIT Vellore", "VIT001", "Vellore, Tamil Nadu"),
        ("Anna University", "AU001", "Chennai, Tamil Nadu"),
        ("PSG Tech", "PSGT001", "Coimbatore, Tamil Nadu"),
    ]
    for name, code, location in seed_centres:
        c.execute(
            "INSERT INTO centres(name,code,location,status,created_at) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING" if DATABASE_URL else "INSERT OR IGNORE INTO centres(name,code,location,status,created_at) VALUES(?,?,?,?,?)",
            (name, code, location, "ACTIVE", now_ts()),
        )

    # Create demo accounts or repair the legacy account records.
    def upsert_user(username, password, role, centre_id=None, scope="all"):
        existing = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        ph = hash_password(password)
        if existing:
            c.execute(
                "UPDATE users SET password_hash=?, role=?, author_scope=?, centre_id=? WHERE id=?",
                (ph, role, scope, centre_id, existing["id"]),
            )
        else:
            c.execute(
                "INSERT INTO users(username,password_hash,role,author_scope,centre_id) VALUES(?,?,?,?,?)",
                (username, ph, role, scope, centre_id),
            )

    cit = c.execute("SELECT id FROM centres WHERE code='CIT001'").fetchone()[0]
    ssn = c.execute("SELECT id FROM centres WHERE code='SSN001'").fetchone()[0]
    rec = c.execute("SELECT id FROM centres WHERE code='REC001'").fetchone()[0]
    upsert_user("admin", "admin123", "admin", None, "all")
    upsert_user("setter1", "setter123", "setter", None, "all")
    upsert_user("setter2", "setter123", "setter", None, "all")
    upsert_user("CIT001", "centre123", "exam_centre", cit, "centre")
    upsert_user("SSN001", "centre123", "exam_centre", ssn, "centre")
    upsert_user("REC001", "centre123", "exam_centre", rec, "centre")

    # Migrate any papers created by the old MVP, preserving them as CIT001 assignments.
    # Old papers stored a single centre text; this keeps existing demo data usable.
    orphan = []
    if "centre" in paper_cols:
        orphan = c.execute(
            "SELECT p.id, p.centre FROM papers p LEFT JOIN paper_centres pc ON pc.paper_id=p.id WHERE pc.paper_id IS NULL"
        ).fetchall()
    for row in orphan:
        centre = c.execute("SELECT id FROM centres WHERE code=? OR name=?", (row["centre"], row["centre"])).fetchone()
        if not centre:
            centre = c.execute("SELECT id FROM centres WHERE code='CIT001'").fetchone()
        c.execute(
            "INSERT INTO paper_centres(paper_id,centre_id,watermark) VALUES(?,?,?) ON CONFLICT DO NOTHING" if DATABASE_URL else "INSERT OR IGNORE INTO paper_centres(paper_id,centre_id,watermark) VALUES(?,?,?)",
            (row["id"], centre[0], secrets.token_hex(12)),
        )

    # Upgrade legacy users to the renamed roles.
    c.execute("UPDATE users SET role='setter' WHERE role='author'")
    c.commit()
    c.close()


init_db()


def token_for(user):
    issued = now_ts()
    payload = f"{user['id']}:{user['username']}:{issued}:{secrets.token_hex(8)}".encode()
    sig = hmac.new(SECRET, payload, hashlib.sha256).hexdigest().encode()
    return base64.urlsafe_b64encode(payload + b"." + sig).decode()


def current_user(request: Request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(401, "Authentication required")
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        payload, sig = raw.rsplit(b".", 1)
        expected = hmac.new(SECRET, payload, hashlib.sha256).hexdigest().encode()
        if not hmac.compare_digest(expected, sig):
            raise ValueError
        parts = payload.decode().split(":")
        uid = int(parts[0])
        issued = int(parts[2])
        if now_ts() - issued > 8 * 60 * 60:
            raise ValueError
    except Exception:
        raise HTTPException(401, "Invalid or expired session")
    c = db()
    u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    c.close()
    if not u:
        raise HTTPException(401, "Unknown user")
    return u


def audit(paper_id, actor, role, action, request: Request, detail=""):
    c = db()
    last = c.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["event_hash"] if last else ""
    ts = now_ts()
    ip = request.client.host if request.client else "unknown"
    material = f"{paper_id}|{actor}|{role}|{action}|{ip}|{detail}|{ts}|{prev}"
    eh = hashlib.sha256(material.encode()).hexdigest()
    c.execute(
        "INSERT INTO audit(paper_id,actor,role,action,ip,detail,ts,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?,?,?)",
        (paper_id, actor, role, action, ip, detail, ts, prev, eh),
    )
    c.commit()
    c.close()


def alert(paper_id, severity, message):
    c = db()
    c.execute(
        "INSERT INTO alerts(paper_id,severity,message,ts) VALUES(?,?,?,?)",
        (paper_id, severity, message, now_ts()),
    )
    c.commit()
    c.close()


def puzzle_rounds_for(release_at: int) -> int:
    days = max(1, (release_at - now_ts() + 86399) // 86400)
    return min(MAX_PUZZLE_ROUNDS, days * PUZZLE_ROUNDS_PER_DAY)


def solve_time_puzzle(seed: str, rounds: int) -> str:
    value = seed.encode()
    for _ in range(rounds):
        value = hashlib.sha256(value).digest()
    return value.hex()


def require_setter(user):
    if user["role"] not in ("setter", "admin"):
        raise HTTPException(403, "Setter access required")


class Login(BaseModel):
    username: str
    password: str
    login_as: str


class CentreIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    code: str = Field(min_length=2, max_length=30, pattern=r"^[A-Za-z0-9_-]+$")
    location: str = Field(default="", max_length=160)


class PaperIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    content: str = Field(min_length=1, max_length=200000)
    release_at: int = Field(gt=0)
    centre_ids: List[int] = Field(min_length=1)


@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "server_time": now_ts()}


@app.post("/api/login")
def login(x: Login, request: Request):
    if x.login_as not in ("setter", "exam_centre"):
        raise HTTPException(400, "Invalid login type")
    c = db()
    u = c.execute("SELECT * FROM users WHERE username=?", (x.username,)).fetchone()
    c.close()
    if not u or not legacy_or_password_hash(x.password, u["password_hash"]):
        audit(None, x.username, x.login_as, "LOGIN_FAILED", request, f"login_as={x.login_as}")
        raise HTTPException(401, "Invalid credentials")
    if x.login_as == "setter" and u["role"] not in ("setter", "admin"):
        audit(None, u["username"], u["role"], "LOGIN_DENIED", request, "wrong login portal")
        raise HTTPException(403, "Use the Exam Centre login")
    if x.login_as == "exam_centre" and u["role"] != "exam_centre":
        audit(None, u["username"], u["role"], "LOGIN_DENIED", request, "wrong login portal")
        raise HTTPException(403, "Use the Question Setter login")
    audit(None, u["username"], u["role"], "LOGIN", request, f"portal={x.login_as}")
    centre = None
    if u["centre_id"]:
        c = db()
        centre = c.execute("SELECT id,name,code,location FROM centres WHERE id=?", (u["centre_id"],)).fetchone()
        c.close()
    return {
        "token": token_for(u),
        "user": {
            "username": u["username"],
            "role": u["role"],
            "scope": u["author_scope"],
            "centre": dict(centre) if centre else None,
        },
    }


@app.get("/api/me")
def me(request: Request):
    u = current_user(request)
    centre = None
    if u["centre_id"]:
        c = db()
        centre = c.execute("SELECT id,name,code,location FROM centres WHERE id=?", (u["centre_id"],)).fetchone()
        c.close()
    return {"username": u["username"], "role": u["role"], "centre": dict(centre) if centre else None}


@app.get("/api/centres")
def list_centres(request: Request):
    u = current_user(request)
    require_setter(u)
    c = db()
    rows = c.execute("SELECT id,name,code,location,status,created_at FROM centres WHERE status='ACTIVE' ORDER BY name").fetchall()
    c.close()
    return [dict(x) for x in rows]


@app.post("/api/centres")
def create_centre(x: CentreIn, request: Request):
    u = current_user(request)
    require_setter(u)
    c = db()
    try:
        cur = c.execute(
            ("INSERT INTO centres(name,code,location,status,created_at) VALUES(?,?,?,?,?) RETURNING id" if DATABASE_URL else "INSERT INTO centres(name,code,location,status,created_at) VALUES(?,?,?,?,?)"),
            (x.name.strip(), x.code.strip().upper(), x.location.strip(), "ACTIVE", now_ts()),
        )
        cid = cur.fetchone()["id"] if DATABASE_URL else cur.lastrowid
        c.commit()
    except Exception as e:
        is_integrity_error = isinstance(e, sqlite3.IntegrityError) or (
            DATABASE_URL and e.__class__.__module__.startswith("psycopg")
        )
        if not is_integrity_error:
            raise
        c.rollback()
        c.close()
        raise HTTPException(409, "Centre name or code already exists") from e
    c.close()
    audit(None, u["username"], u["role"], "CENTRE_CREATED", request, f"centre_id={cid};code={x.code.upper()}")
    return {"id": cid, "name": x.name.strip(), "code": x.code.strip().upper(), "location": x.location.strip()}


@app.post("/api/questions")
def create_paper(p: PaperIn, request: Request):
    u = current_user(request)
    require_setter(u)
    if p.release_at <= now_ts():
        raise HTTPException(400, "Release time must be in the future")
    c = db()
    centres = c.execute(
        f"SELECT id,code,name FROM centres WHERE id IN ({','.join('?' for _ in p.centre_ids)}) AND status='ACTIVE'",
        p.centre_ids,
    ).fetchall()
    if len(centres) != len(set(p.centre_ids)):
        c.close()
        raise HTTPException(400, "One or more centres are invalid")

    digest = hashlib.sha256(p.content.encode()).hexdigest()
    nonce = secrets.token_bytes(12)
    # Centre list is authenticated along with title/hash; assignment metadata is checked separately.
    centre_codes = ",".join(sorted(x["code"] for x in centres))
    aad = f"paper|{p.title}|{digest}|{centre_codes}".encode()
    ciphertext = AESGCM(KEY).encrypt(nonce, p.content.encode(), aad)
    puzzle_seed = secrets.token_hex(32)
    puzzle_rounds = puzzle_rounds_for(p.release_at)
    cur = c.execute(
        ("INSERT INTO papers(title,description,author_id,content_hash,ciphertext,nonce,release_at,created_at,puzzle_seed,puzzle_rounds) VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id" if DATABASE_URL else "INSERT INTO papers(title,description,author_id,content_hash,ciphertext,nonce,release_at,created_at,puzzle_seed,puzzle_rounds) VALUES(?,?,?,?,?,?,?,?,?,?)"),
        (p.title.strip(), p.description.strip(), u["id"], digest, base64.b64encode(ciphertext).decode(), base64.b64encode(nonce).decode(), p.release_at, now_ts(), puzzle_seed, puzzle_rounds),
    )
    pid = cur.fetchone()["id"] if DATABASE_URL else cur.lastrowid
    watermark_map = {}
    for centre in centres:
        watermark = "EPSS-" + secrets.token_hex(12).upper()
        c.execute(
            "INSERT INTO paper_centres(paper_id,centre_id,watermark) VALUES(?,?,?)",
            (pid, centre["id"], watermark),
        )
        watermark_map[centre["code"]] = watermark
    c.commit()
    c.close()
    audit(pid, u["username"], u["role"], "PAPER_CREATED", request, json.dumps({"fingerprint": digest, "centres": list(watermark_map)}))
    return {"id": pid, "fingerprint": digest, "release_at": p.release_at, "puzzle_rounds": puzzle_rounds, "watermarks": watermark_map}


@app.get("/api/questions")
def setter_papers(request: Request):
    u = current_user(request)
    require_setter(u)
    c = db()
    centre_codes_aggregate = "STRING_AGG(c.code, ', ')" if DATABASE_URL else "GROUP_CONCAT(c.code, ', ')"
    if u["role"] == "admin":
        rows = c.execute(
            f"""
            SELECT p.id,p.title,p.description,p.content_hash,p.release_at,p.created_at,p.unlocked,
                   u.username author,
                   COUNT(pc.centre_id) centre_count,
                   {centre_codes_aggregate} centre_codes
            FROM papers p
            JOIN users u ON u.id=p.author_id
            LEFT JOIN paper_centres pc ON pc.paper_id=p.id
            LEFT JOIN centres c ON c.id=pc.centre_id
            GROUP BY p.id, u.username ORDER BY p.id DESC
            """
        ).fetchall()
    else:
        rows = c.execute(
            f"""
            SELECT p.id,p.title,p.description,p.content_hash,p.release_at,p.created_at,p.unlocked,
                   u.username author,
                   COUNT(pc.centre_id) centre_count,
                   {centre_codes_aggregate} centre_codes
            FROM papers p
            JOIN users u ON u.id=p.author_id
            LEFT JOIN paper_centres pc ON pc.paper_id=p.id
            LEFT JOIN centres c ON c.id=pc.centre_id
            WHERE p.author_id=?
            GROUP BY p.id, u.username ORDER BY p.id DESC
            """,
            (u["id"],),
        ).fetchall()
    c.close()
    return [dict(x) for x in rows]


@app.get("/api/exam/papers")
def centre_papers(request: Request):
    u = current_user(request)
    if u["role"] != "exam_centre":
        raise HTTPException(403, "Exam Centre access required")
    c = db()
    rows = c.execute(
        """
        SELECT p.id,p.title,p.description,p.release_at,p.created_at,p.unlocked,p.puzzle_rounds,pc.watermark,c.name centre_name,c.code centre_code
        FROM papers p
        JOIN paper_centres pc ON pc.paper_id=p.id
        JOIN centres c ON c.id=pc.centre_id
        WHERE pc.centre_id=? ORDER BY p.release_at ASC, p.id DESC
        """,
        (u["centre_id"],),
    ).fetchall()
    c.close()
    return [dict(x) for x in rows]


@app.get("/api/exam/papers/{pid}")
def exam_view_paper(pid: int, request: Request):
    u = current_user(request)
    if u["role"] != "exam_centre":
        raise HTTPException(403, "Exam Centre access required")
    c = db()
    row = c.execute(
        """
        SELECT p.*,pc.centre_id,pc.watermark,c.name centre_name,c.code centre_code
        FROM papers p JOIN paper_centres pc ON pc.paper_id=p.id JOIN centres c ON c.id=pc.centre_id
        WHERE p.id=? AND pc.centre_id=?
        """,
        (pid, u["centre_id"]),
    ).fetchone()
    c.close()
    if not row:
        audit(pid, u["username"], u["role"], "PAPER_VIEW_DENIED", request, "not assigned to centre")
        raise HTTPException(404, "Paper not assigned to this centre")
    audit(pid, u["username"], u["role"], "PAPER_VIEW", request, f"centre={row['centre_code']}")
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "release_at": row["release_at"],
        "created_at": row["created_at"],
        "centre_name": row["centre_name"],
        "centre_code": row["centre_code"],
        "watermark": row["watermark"],
        "server_time": now_ts(),
        "locked": now_ts() < row["release_at"],
        "puzzle_rounds": row["puzzle_rounds"],
    }


@app.post("/api/exam/papers/{pid}/unlock")
def exam_unlock(pid: int, request: Request):
    u = current_user(request)
    if u["role"] != "exam_centre":
        raise HTTPException(403, "Exam Centre access required")
    c = db()
    p = c.execute(
        """
        SELECT p.*,pc.centre_id,pc.watermark,c.name centre_name,c.code centre_code
        FROM papers p JOIN paper_centres pc ON pc.paper_id=p.id JOIN centres c ON c.id=pc.centre_id
        WHERE p.id=? AND pc.centre_id=?
        """,
        (pid, u["centre_id"]),
    ).fetchone()
    c.close()
    if not p:
        audit(pid, u["username"], u["role"], "UNLOCK_ATTEMPT_DENIED", request, "not assigned to centre")
        alert(pid, "HIGH", f"Unauthorized unlock attempt by {u['username']}")
        raise HTTPException(404, "Paper not assigned to this centre")

    now = now_ts()
    audit(pid, u["username"], u["role"], "UNLOCK_ATTEMPT", request, f"server_time={now};release_at={p['release_at']};centre={p['centre_code']}")
    if now < p["release_at"]:
        alert(pid, "HIGH", f"Early unlock attempt by {u['username']} at {p['centre_code']}")
        raise HTTPException(403, f"Paper is locked until {datetime.fromtimestamp(p['release_at'], timezone.utc).isoformat()}")

    puzzle_result = solve_time_puzzle(p["puzzle_seed"], p["puzzle_rounds"])
    audit(pid, u["username"], u["role"], "TIME_PUZZLE_SOLVED", request, f"rounds={p['puzzle_rounds']};result={puzzle_result[:16]}")

    c = db()
    assigned_codes = [r[0] for r in c.execute("SELECT c.code FROM paper_centres pc JOIN centres c ON c.id=pc.centre_id WHERE pc.paper_id=? ORDER BY c.code", (pid,)).fetchall()]
    c.close()
    aad = f"paper|{p['title']}|{p['content_hash']}|{','.join(assigned_codes)}".encode()
    try:
        content = AESGCM(KEY).decrypt(base64.b64decode(p["nonce"]), base64.b64decode(p["ciphertext"]), aad).decode()
    except Exception:
        alert(pid, "CRITICAL", "Cryptographic integrity/authentication failure detected")
        raise HTTPException(500, "Integrity verification failed")
    if hashlib.sha256(content.encode()).hexdigest() != p["content_hash"]:
        alert(pid, "CRITICAL", "SHA-256 fingerprint mismatch detected")
        raise HTTPException(500, "Fingerprint mismatch")

    c = db()
    c.execute("UPDATE papers SET unlocked=1 WHERE id=?", (pid,))
    c.commit()
    c.close()
    audit(pid, u["username"], u["role"], "UNLOCK_SUCCESS", request, f"centre={p['centre_code']};integrity=verified")
    # The forensic print is intentionally placed in an HTML comment. It is not visually shown in the paper body,
    # but survives copy/export flows that preserve the source.
    marked_content = content + f"\n\n<!-- EPSS FORENSIC CENTRE MARK: {p['watermark']} -->"
    return {
        "id": pid,
        "title": p["title"],
        "centre_name": p["centre_name"],
        "centre_code": p["centre_code"],
        "watermark": p["watermark"],
        "fingerprint": p["content_hash"],
        "puzzle_rounds": p["puzzle_rounds"],
        "server_time": now,
        "content": marked_content,
    }


@app.get("/api/papers/{pid}/audit")
def paper_audit(pid: int, request: Request):
    u = current_user(request)
    require_setter(u)
    c = db()
    p = c.execute("SELECT author_id,title FROM papers WHERE id=?", (pid,)).fetchone()
    if not p:
        c.close()
        raise HTTPException(404, "Paper not found")
    if u["role"] != "admin" and p["author_id"] != u["id"]:
        c.close()
        raise HTTPException(403, "Forbidden")
    rows = c.execute(
        "SELECT id,actor,role,action,ip,detail,ts,event_hash FROM audit WHERE paper_id=? ORDER BY id",
        (pid,),
    ).fetchall()
    c.close()
    return [dict(x) for x in rows]


@app.get("/api/audit")
def global_audit(request: Request):
    u = current_user(request)
    require_setter(u)
    c = db()
    if u["role"] == "admin":
        rows = c.execute(
            """
            SELECT a.id,a.paper_id,a.actor,a.role,a.action,a.ip,a.detail,a.ts,a.event_hash,p.title
            FROM audit a LEFT JOIN papers p ON p.id=a.paper_id ORDER BY a.id DESC LIMIT 500
            """
        ).fetchall()
    else:
        rows = c.execute(
            """
            SELECT a.id,a.paper_id,a.actor,a.role,a.action,a.ip,a.detail,a.ts,a.event_hash,p.title
            FROM audit a LEFT JOIN papers p ON p.id=a.paper_id
            WHERE a.paper_id IS NULL OR p.author_id=? ORDER BY a.id DESC LIMIT 500
            """,
            (u["id"],),
        ).fetchall()
    c.close()
    return [dict(x) for x in rows]


@app.get("/api/exam/audit")
def exam_audit(request: Request):
    u = current_user(request)
    if u["role"] != "exam_centre":
        raise HTTPException(403, "Exam Centre access required")
    c = db()
    rows = c.execute(
        """
        SELECT a.id,a.paper_id,a.actor,a.role,a.action,a.ip,a.detail,a.ts,a.event_hash,p.title,pc.centre_id
        FROM audit a
        LEFT JOIN papers p ON p.id=a.paper_id
        LEFT JOIN paper_centres pc ON pc.paper_id=a.paper_id AND pc.centre_id=?
        WHERE (a.paper_id IS NULL AND a.actor=?) OR pc.centre_id=?
        ORDER BY a.id DESC LIMIT 500
        """,
        (u["centre_id"], u["username"], u["centre_id"]),
    ).fetchall()
    c.close()
    return [dict(x) for x in rows]


@app.get("/api/alerts")
def alerts(request: Request):
    u = current_user(request)
    require_setter(u)
    c = db()
    if u["role"] == "admin":
        rows = c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 300").fetchall()
    else:
        rows = c.execute(
            """
            SELECT a.* FROM alerts a LEFT JOIN papers p ON p.id=a.paper_id
            WHERE a.paper_id IS NULL OR p.author_id=? ORDER BY a.id DESC LIMIT 300
            """,
            (u["id"],),
        ).fetchall()
    c.close()
    return [dict(x) for x in rows]
