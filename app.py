import os
from werkzeug.utils import secure_filename

UPLOAD_DIR = os.path.join("static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}

def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXT

import random
import sqlite3
import re
import unicodedata
from flask import g
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Any, Dict, List, Tuple, Optional
from flask import send_from_directory
from flask import Response
from time import time
from math import ceil

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, abort
)
from werkzeug.security import generate_password_hash, check_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ✅ Render 디스크 우선(/var/data), 로컬은 프로젝트 폴더 phrases.db 사용
DEFAULT_DB = os.path.join(BASE_DIR, "phrases.db")
DB_PATH = os.environ.get("DB_PATH", "/var/data/app.db")

# ✅ 로컬에서 /var/data가 없으면 자동으로 DEFAULT_DB로
if DB_PATH.startswith("/var/data") and not os.path.isdir("/var/data"):
    DB_PATH = DEFAULT_DB

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY") or "a9f3c1f8f2d64b7f9f2c7e1a5d8b3c2f__CHANGE_ME_ONCE"


UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}

import os, smtplib
from email.mime.text import MIMEText

def send_reset_code_email(to_email: str, code: str):
    import os, smtplib
    from email.mime.text import MIMEText

    smtp_host = os.getenv("SMTP_HOST", "smtp.naver.com")
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    from_email = os.getenv("FROM_EMAIL", smtp_user)

    # 기본 포트는 465(SSL) 우선
    smtp_port = int(os.getenv("SMTP_PORT", "465"))

    if not (smtp_host and smtp_user and smtp_pass):
        print("[EMAIL] SMTP env not set. Skipping real send.")
        return False

    subject = "[JapaneseStudyRoom] 비밀번호 재설정 인증코드"
    body = f"""요청하신 비밀번호 재설정 인증코드입니다.

인증코드: {code}

- 유효시간: 10분
- 본인이 요청하지 않았다면 이 메일을 무시하세요.
"""

    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        # 1) 465 SSL 방식 (네이버에서 성공률 높음)
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as s:
                s.login(smtp_user, smtp_pass)
                s.sendmail(from_email, [to_email], msg.as_string())
            return True

        # 2) 587 STARTTLS 방식 (대안)
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(smtp_user, smtp_pass)
            s.sendmail(from_email, [to_email], msg.as_string())
        return True

    except Exception as e:
        print(f"[EMAIL ERROR] {repr(e)}")
        return False

def seo(title="", desc="", keywords=""):
    return {
        "seo_title": title,
        "seo_desc": desc,
        "seo_keywords": keywords
    }

def mark_attendance_today(user: dict):
    """로그인 유저가 오늘 첫 방문이면 출석 1회 기록"""
    if not user:
        return
    uid = user.get("id")
    if not uid:
        return

    today = datetime.now().strftime("%Y-%m-%d")

    conn = db()
    try:
        # UNIQUE(user_id, date) 덕분에 중복이면 그냥 무시되게 INSERT OR IGNORE
        conn.execute(
            "INSERT OR IGNORE INTO user_attendance (user_id, date) VALUES (?, ?)",
            (uid, today),
        )
        conn.commit()
    finally:
        conn.close()

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

_KST = timezone(timedelta(hours=9))
_db_inited = False

from datetime import datetime

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

# ✅ KST 날짜 문자열(YYYY-MM-DD) 만들기
def kst_today_ymd() -> str:
    kst = timezone(timedelta(hours=9))
    return datetime.now(kst).strftime("%Y-%m-%d")

# ✅ 관리자 판별 (너 프로젝트에 맞게 유연하게)
def is_admin_user(user: dict) -> bool:
    if not user:
        return False

    # 1) DB에 is_admin 컬럼이 있는 경우(가장 흔함)
    if str(user.get("is_admin", 0)) in ("1", "true", "True"):
        return True

    # 2) role/grade 같은 값으로 관리자를 구분하는 경우
    role = (user.get("role") or "").lower()
    if role in ("admin", "administrator"):
        return True

    grade = (user.get("grade") or user.get("author_grade") or "").lower()
    if "관리" in grade or "admin" in grade:
        return True

    # 3) 특정 user_id를 관리자 고정으로 쓰는 경우(예: 1번)
    try:
        if int(user.get("id", 0)) == 1:
            return True
    except:
        pass

    # 4) 환경변수로 관리자 id 목록 지정 (옵션)
    # Render 환경변수에 ADMIN_IDS="1,2,3" 이렇게 넣으면 됨
    ids = os.environ.get("ADMIN_IDS", "").strip()
    if ids:
        try:
            admin_ids = {int(x.strip()) for x in ids.split(",") if x.strip().isdigit()}
            if int(user.get("id", 0)) in admin_ids:
                return True
        except:
            pass

    return False

# ✅ 관리자 전용 데코레이터
def admin_required(view_func):
    from functools import wraps
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            # 로그인부터
            return redirect(url_for("login", next=request.path))
        if not isinstance(user, dict):
            user = dict(user)

        if not is_admin_user(user):
            abort(403)

        return view_func(*args, **kwargs)
    return wrapper


@app.get("/admin")
@admin_required
def admin_dashboard():
    user = current_user()
    if user and not isinstance(user, dict):
        user = dict(user)

    today = kst_today_ymd()  # "2026-01-29" 같은 형태

    conn = db()
    try:
        # ✅ 전체 회원 수
        total_users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]

        # ✅ 오늘 가입자 수 (users.created_at 이 ISO 문자열이라고 가정: 'YYYY-MM-DD ...')
        # created_at 컬럼명이 다르면 여기만 바꿔주면 됨.
        today_users = conn.execute(
            "SELECT COUNT(*) AS c FROM users WHERE COALESCE(created_at,'') LIKE ?",
            (today + "%",),
        ).fetchone()["c"]

        # ✅ 전체 게시글/댓글 수
        total_posts = conn.execute("SELECT COUNT(*) AS c FROM board_posts").fetchone()["c"]
        total_comments = conn.execute("SELECT COUNT(*) AS c FROM board_comments").fetchone()["c"]

        # ✅ 오늘 작성 게시글 수
        today_posts = conn.execute(
            "SELECT COUNT(*) AS c FROM board_posts WHERE COALESCE(created_at,'') LIKE ?",
            (today + "%",),
        ).fetchone()["c"]

        # ✅ 최근 가입자 (최신 10명)
        recent_users = conn.execute(
            """
            SELECT id,
                   COALESCE(nickname,'') AS nickname,
                   COALESCE(email,'') AS email,
                   COALESCE(created_at,'') AS created_at
            FROM users
            ORDER BY id DESC
            LIMIT 10
            """
        ).fetchall()

        # ✅ 최근 글 (최신 10개) - 공지 포함
        recent_posts = conn.execute(
            """
            SELECT id,
                   COALESCE(title,'') AS title,
                   COALESCE(author_nickname,'') AS author_nickname,
                   COALESCE(created_at,'') AS created_at,
                   COALESCE(views,0) AS views,
                   COALESCE(upvotes,0) AS upvotes,
                   COALESCE(is_notice,0) AS is_notice
            FROM board_posts
            ORDER BY id DESC
            LIMIT 10
            """
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "admin_dashboard.html",
        user=user,
        total_users=total_users,
        today_users=today_users,
        total_posts=total_posts,
        total_comments=total_comments,
        today_posts=today_posts,
        recent_users=recent_users,
        recent_posts=recent_posts,
        today=today,
    )



@app.get("/admin/users")
@admin_required
def admin_users():
    q = (request.args.get("q") or "").strip()

    conn = db()

    where = []
    params = []

    if q:
        where.append("(nickname LIKE ? OR email LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    rows = conn.execute(
        f"""
        SELECT id, nickname, email, created_at, COALESCE(points,0) AS points
        FROM users
        {where_sql}
        ORDER BY id DESC
        LIMIT 300
        """,
        params,
    ).fetchall()
    conn.close()

    users = []
    for r in rows:
        u = dict(r)
        u["grade_label"] = score_to_grade(u["points"])  # ✅ 네 기존 함수 그대로 사용
        users.append(u)

    return render_template("admin_users.html", user=current_user(), users=users, q=q)

@app.post("/admin/users/<int:user_id>/points")
@admin_required
def admin_user_change_points(user_id: int):
    delta_raw = (request.form.get("delta") or "").strip()

    try:
        delta = int(delta_raw)
    except:
        flash("점수는 숫자로 입력해 주세요. 예) 50, -30", "error")
        return redirect(request.referrer or url_for("admin_users"))

    # 관리자 본인/고정 관리자 보호(원하면 정책 변경)
    if user_id == 1:
        flash("관리자 계정 점수는 변경할 수 없습니다.", "error")
        return redirect(request.referrer or url_for("admin_users"))

    conn = db()
    try:
        # 현재 점수 조회
        row = conn.execute("SELECT COALESCE(points,0) AS p FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            flash("유저를 찾을 수 없습니다.", "error")
            return redirect(url_for("admin_users"))

        new_points = int(row["p"]) + delta
        if new_points < 0:
            new_points = 0  # 음수 방지(원하면 허용 가능)

        conn.execute("UPDATE users SET points=? WHERE id=?", (new_points, user_id))
        conn.commit()
    finally:
        conn.close()

    flash(f"점수 변경 완료: {delta:+d} → 현재 {new_points}점", "success")
    return redirect(request.referrer or url_for("admin_users"))


@app.post("/admin/users/<int:user_id>/delete")
@admin_required
def admin_user_delete(user_id: int):
    if user_id == 1:
        flash("관리자 계정은 삭제할 수 없습니다.", "error")
        return redirect(url_for("admin_users"))

    conn = db()
    try:
        # 사용자가 쓴 글/댓글을 어떻게 할지 정책 선택:
        # 1) 완전 삭제(깔끔)  2) 작성자만 익명처리(데이터 유지)
        # 여기선 “완전 삭제”로 구성

        conn.execute("DELETE FROM board_comments WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM board_posts WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM board_upvotes WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM notifications WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM favorites WHERE user_id=?", (user_id,))  # 있으면
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()

    flash("회원이 강제 탈퇴 처리되었습니다.", "success")
    return redirect(url_for("admin_users"))

# -------------------------
# Validation rules
# -------------------------
USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{2,19}$")  # 3~20, 영문으로 시작, 영문+숫자
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_naver_email(email: str) -> bool:
    email = (email or "").strip().lower()
    return email.endswith("@naver.com")


BANNED_NICK_PARTS = [
    "admin", "관리자", "운영자", "root",
    "sex", "porn", "19", "야동",
    "fuck", "shit", "bitch", "시발", "씨발", "병신", "좆", "ㅅㅂ",
    "나치", "테러",
    "ilbe", "일베",
    "토토", "카지노", "도박",
    "디시", "dcinside",
    "av", "xxx",
]
BANNED_NICK_RE = re.compile("|".join(map(re.escape, BANNED_NICK_PARTS)), re.IGNORECASE)


def nickname_allowed(nickname: str) -> bool:
    nick = (nickname or "").strip()
    if not (2 <= len(nick) <= 8):
        return False
    if re.search(r"\s", nick):
        return False
    if BANNED_NICK_RE.search(nick):
        return False
    return True


def kst_now_iso() -> str:
    return datetime.now(timezone.utc).astimezone(_KST).isoformat()

def ensure_word_favorites_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS word_favorites (
      user_id INTEGER NOT NULL,
      cat_key TEXT NOT NULL,
      jp TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(user_id, cat_key, jp)
    )
    """)

# -------------------------
# DB helpers
# -------------------------
def db() -> sqlite3.Connection:
    # /var/data면 폴더 생성 시도(로컬에서도 안전)
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def mark_attendance(user_id: int):
    today = datetime.now().strftime("%Y-%m-%d")
    conn = db()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO user_attendance (user_id, date) VALUES (?, ?)",
            (user_id, today),
        )
        conn.commit()
    finally:
        conn.close()


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None

def normalize_answer(s: str) -> str:
    """
    사용자 입력/정답 모두 이 함수로 정규화해서 비교.
    - 공백 제거
    - 기호 제거(.,!?・ー- 등)
    - 전각/반각 통일(NFKC)
    """
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = s.strip().lower()

    # 공백류 제거
    s = re.sub(r"\s+", "", s)

    # 장음/중점/하이픈/구두점 등 제거(필요시 더 추가 가능)
    s = re.sub(r"[・･\-\―\—\–ー＿_.,!?！？。、…:;\"'“”‘’（）()［］\[\]{}「」『』]", "", s)

    return s

def normalize_pron(s: str) -> str:
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = s.strip().lower()

    # 공백 제거
    s = re.sub(r"\s+", "", s)

    # 자주 쓰는 기호 제거 (발음 표기용)
    s = re.sub(r"[.\-―—–ー·・,!?！？。、…:;\"'“”‘’()（）\[\]{}「」『』]", "", s)

    return s
def table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [r["name"] for r in rows]


def kst_today_key() -> str:
    now_kst = datetime.now(timezone.utc).astimezone(_KST)
    return now_kst.strftime("%Y-%m-%d")


def migrate_users_table(conn: sqlite3.Connection) -> None:
    if not table_exists(conn, "users"):
        return

    cols = table_columns(conn, "users")
    if "password_hash" in cols and "nickname" in cols and "email" in cols:
        return  # already new

    cur = conn.cursor()
    cur.execute("ALTER TABLE users RENAME TO users_old")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            nickname TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            points INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )

    old_cols = table_columns(conn, "users_old")

    password_src = None
    for cand in ["password_hash", "password", "pw_hash", "pass_hash", "pw"]:
        if cand in old_cols:
            password_src = cand
            break

    username_src = "username" if "username" in old_cols else None
    nickname_src = "nickname" if "nickname" in old_cols else None
    email_src = "email" if "email" in old_cols else None
    created_src = "created_at" if "created_at" in old_cols else None
    points_src = "points" if "points" in old_cols else None

    if not username_src or not password_src:
        cur.execute("DROP TABLE users_old")
        return

    rows = conn.execute("SELECT * FROM users_old").fetchall()

    for r in rows:
        username = r[username_src]
        password_hash = r[password_src]
        nickname = r[nickname_src] if nickname_src else (username[:8] if username else "user")
        email = r[email_src] if email_src else f"{username}@naver.com"
        created_at = r[created_src] if created_src else kst_now_iso()
        points = r[points_src] if points_src else 0

        if not email:
            email = f"{username}_{random.randint(1000,9999)}@naver.com"

        if not password_hash or len(str(password_hash)) < 20:
            password_hash = generate_password_hash(str(password_hash or "changeme1234"))

        try:
            cur.execute(
                "INSERT OR IGNORE INTO users(username, password_hash, nickname, email, points, created_at) VALUES(?,?,?,?,?,?)",
                (username, password_hash, nickname, email.lower(), int(points), created_at),
            )
        except Exception:
            pass

    conn.commit()
    cur.execute("DROP TABLE users_old")
    conn.commit()


def migrate_favorites_table(conn: sqlite3.Connection) -> None:
    """
    favorites 테이블이 구버전 스키마(phrase_key 컬럼 없음 등)일 때 자동 마이그레이션.
    현재 코드가 SELECT phrase_key 를 하므로 반드시 존재해야 함.
    """
    if not table_exists(conn, "favorites"):
        return

    cols = table_columns(conn, "favorites")
    required = {"user_id", "phrase_key", "jp", "pron", "ko", "created_at"}
    if required.issubset(set(cols)):
        return  # already new enough

    cur = conn.cursor()
    cur.execute("ALTER TABLE favorites RENAME TO favorites_old")

    # 새 스키마로 생성
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            phrase_key TEXT NOT NULL,
            jp TEXT NOT NULL,
            pron TEXT NOT NULL,
            ko TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, phrase_key),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    old_cols = table_columns(conn, "favorites_old")
    rows = conn.execute("SELECT * FROM favorites_old").fetchall()

    # phrase_key 후보 컬럼들(이전 코드/실수로 이름이 달랐을 수 있어서)
    key_src = None
    for cand in ["phrase_key", "phraseKey", "key", "phrase_id", "phraseId"]:
        if cand in old_cols:
            key_src = cand
            break

    user_src = "user_id" if "user_id" in old_cols else None
    jp_src = "jp" if "jp" in old_cols else None
    pron_src = "pron" if "pron" in old_cols else None
    ko_src = "ko" if "ko" in old_cols else None
    created_src = "created_at" if "created_at" in old_cols else None

    # 최소한 user_id와 jp/ko 같은 내용이 없으면 복구가 의미 없으니 그냥 빈 테이블로 진행
    if not user_src or not jp_src or not pron_src or not ko_src:
        cur.execute("DROP TABLE favorites_old")
        conn.commit()
        return

    for idx, r in enumerate(rows, start=1):
        user_id = r[user_src]
        phrase_key = r[key_src] if key_src else None

        # phrase_key 없으면 임시 생성(중복 방지 위해 row 기반)
        if not phrase_key:
            phrase_key = f"legacy:{user_id}:{idx}"

        jp = r[jp_src] or ""
        pron = r[pron_src] or ""
        ko = r[ko_src] or ""
        created_at = r[created_src] if created_src else kst_now_iso()
        if not created_at:
            created_at = kst_now_iso()

        try:
            cur.execute(
                "INSERT OR IGNORE INTO favorites(user_id, phrase_key, jp, pron, ko, created_at) VALUES(?,?,?,?,?,?)",
                (int(user_id), str(phrase_key), str(jp), str(pron), str(ko), str(created_at)),
            )
        except Exception:
            pass

    conn.commit()
    cur.execute("DROP TABLE favorites_old")
    conn.commit()

def migrate_password_resets_table(conn):
    cur = conn.cursor()
    cols = table_columns(conn, "password_resets")

    # used_at
    if "used_at" not in cols:
        cur.execute("ALTER TABLE password_resets ADD COLUMN used_at TEXT")

    # request_ip
    cols = table_columns(conn, "password_resets")
    if "request_ip" not in cols:
        cur.execute("ALTER TABLE password_resets ADD COLUMN request_ip TEXT")

    # ✅ fail_count
    cols = table_columns(conn, "password_resets")
    if "fail_count" not in cols:
        cur.execute("ALTER TABLE password_resets ADD COLUMN fail_count INTEGER NOT NULL DEFAULT 0")

    # ✅ locked_until
    cols = table_columns(conn, "password_resets")
    if "locked_until" not in cols:
        cur.execute("ALTER TABLE password_resets ADD COLUMN locked_until TEXT")


# -------------------------
# DB init (FIXED)
# -------------------------

def init_db() -> None:
    conn = db()
    try:
        cur = conn.cursor()

        # 0) 기존 테이블 마이그레이션 (있으면)
        if table_exists(conn, "users"):
            migrate_users_table(conn)

        if table_exists(conn, "favorites"):
            migrate_favorites_table(conn)

        # 1) users (없으면 생성)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                nickname TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                points INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
         
        cur.execute("""
        CREATE TABLE IF NOT EXISTS user_attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(user_id, date)
        )
        """)

        # 2) users 컬럼 보강
        cols = table_columns(conn, "users")
        if "best_word_score" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN best_word_score INTEGER DEFAULT 0")

        cols = table_columns(conn, "users")
        if "best_word_score_at" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN best_word_score_at TEXT")

        cols = table_columns(conn, "users")
        if "last_login_at" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")

        cols = table_columns(conn, "users")
        if "last_seen_at" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN last_seen_at TEXT")

        # 3) daily_phrase
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS daily_phrase (
                day_key TEXT PRIMARY KEY,
                jp TEXT NOT NULL,
                pron TEXT NOT NULL,
                ko TEXT NOT NULL
            )
            """
        )

        # 4) favorites
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                phrase_key TEXT NOT NULL,
                jp TEXT NOT NULL,
                pron TEXT NOT NULL,
                ko TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, phrase_key),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        # 5) password_resets
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used_at TEXT,
                request_ip TEXT
            )
            """
        )

       # 6) board_posts
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS board_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                author_grade TEXT NOT NULL DEFAULT '일반',
                author_nickname TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                thumb_url TEXT,
                upvotes INTEGER NOT NULL DEFAULT 0,
                views INTEGER NOT NULL DEFAULT 0,
                is_notice INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )


        # 7) board_comments
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS board_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER,
                author_grade TEXT NOT NULL DEFAULT '일반',
                author_nickname TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (post_id) REFERENCES board_posts(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
        
        # 8) notifications (알림)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,          -- 알림 받을 사람
                type TEXT NOT NULL,                -- 예: 'comment'
                post_id INTEGER,
                comment_id INTEGER,
                from_user_id INTEGER,
                from_nickname TEXT,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        # 9) board_upvotes
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS board_upvotes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(post_id, user_id),
                FOREIGN KEY (post_id) REFERENCES board_posts(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )

        # 10) board_posts 컬럼 호환: likes -> upvotes
        cols = table_columns(conn, "board_posts")
        if "likes" in cols and "upvotes" not in cols:
            try:
                cur.execute("ALTER TABLE board_posts RENAME COLUMN likes TO upvotes")
            except Exception:
                # 구버전 sqlite는 RENAME COLUMN이 실패할 수 있음
                cur.execute("ALTER TABLE board_posts ADD COLUMN upvotes INTEGER NOT NULL DEFAULT 0")
                try:
                    cur.execute("UPDATE board_posts SET upvotes = COALESCE(likes, 0)")
                except Exception:
                    pass

        # 11) board_posts 누락 컬럼 보강(혹시 예전 DB에 없을 수 있어서)
        cols = table_columns(conn, "board_posts")
        if "views" not in cols:
            cur.execute("ALTER TABLE board_posts ADD COLUMN views INTEGER NOT NULL DEFAULT 0")

        cols = table_columns(conn, "board_posts")
        if "thumb_url" not in cols:
            cur.execute("ALTER TABLE board_posts ADD COLUMN thumb_url TEXT")
        cols = table_columns(conn, "board_posts")
        if "is_notice" not in cols:
            cur.execute("ALTER TABLE board_posts ADD COLUMN is_notice INTEGER NOT NULL DEFAULT 0")

        # 12) word_favorites
        ensure_word_favorites_table(conn)
        migrate_password_resets_table(conn)


        conn.commit()
    finally:
        conn.close()



@app.before_request
def ensure_db_once():
    global _db_inited
    if not _db_inited:
        init_db()
        _db_inited = True

    uid = session.get("user_id")
    if uid:
        conn = None
        try:
            conn = db()
            conn.execute(
                "UPDATE users SET last_seen_at=? WHERE id=?",
                (kst_now_iso(), uid),
            )
            conn.commit()
        except Exception:
            pass
        finally:
            if conn:
                conn.close()



# -------------------------
# Content
# -------------------------
DAILY_POOL = [
    {"jp": "ここは有名ですか？", "pron": "코코와 유메이데스카", "ko": "여기 유명해요?"},
    {"jp": "おすすめは何ですか？", "pron": "오스스메와 난데스카", "ko": "추천은 뭐예요?"},
    {"jp": "写真を撮ってもいいですか？", "pron": "샤신오 톳테모 이이데스카", "ko": "사진 찍어도 돼요?"},
    {"jp": "いくらですか？", "pron": "이쿠라데스카", "ko": "얼마예요?"},
    {"jp": "もう一度お願いします。", "pron": "모- 이치도 오네가이시마스", "ko": "한 번 더 부탁해요."},
    {"jp": "日本語があまり分かりません。", "pron": "니혼고가 아마리 와카리마센", "ko": "일본어를 잘 못해요."},
    {"jp": "これでお願いします。", "pron": "코레데 오네가이시마스", "ko": "이걸로 할게요."},
    {"jp": "助けてください。", "pron": "타스케테 쿠다사이", "ko": "도와주세요."},

    {"jp": "トイレはどこですか？", "pron": "토이레와 도코데스카", "ko": "화장실은 어디예요?"},
    {"jp": "駅までどうやって行きますか？", "pron": "에키마데 도얏테 이키마스카", "ko": "역까지 어떻게 가요?"},
    {"jp": "次の電車は何時ですか？", "pron": "츠기노 덴샤와 난지데스카", "ko": "다음 전철은 몇 시예요?"},
    {"jp": "これをください。", "pron": "코레오 쿠다사이", "ko": "이거 주세요."},
    {"jp": "カードは使えますか？", "pron": "카-도와 츠카에마스카", "ko": "카드 되나요?"},
    {"jp": "予約しています。", "pron": "요야쿠시테이마스", "ko": "예약했어요."},
    {"jp": "席は空いていますか？", "pron": "세키와 아이테이마스카", "ko": "자리 있나요?"},
    {"jp": "メニューを見せてください。", "pron": "메뉴오 미세테 쿠다사이", "ko": "메뉴 보여주세요."},
    {"jp": "水をください。", "pron": "미즈오 쿠다사이", "ko": "물 주세요."},
    {"jp": "辛くしないでください。", "pron": "카라쿠시나이데 쿠다사이", "ko": "맵지 않게 해주세요."},
    {"jp": "お会計お願いします。", "pron": "오카이케 오네가이시마스", "ko": "계산 부탁해요."},
    {"jp": "別々に払えますか？", "pron": "베츠베츠니 하라에마스카", "ko": "따로 계산할 수 있나요?"},

    {"jp": "写真を撮ってもらえますか？", "pron": "샤신오 톳테 모라에마스카", "ko": "사진 좀 찍어주시겠어요?"},
    {"jp": "ここに座ってもいいですか？", "pron": "코코니 스왓테모 이이데스카", "ko": "여기 앉아도 돼요?"},
    {"jp": "チェックアウトお願いします。", "pron": "체쿠아우토 오네가이시마스", "ko": "체크아웃 부탁해요."},
    {"jp": "部屋を変えられますか？", "pron": "헤야오 카에라레마스카", "ko": "방 바꿀 수 있나요?"},
    {"jp": "Wi-Fiはありますか？", "pron": "와이파이와 아리마스카", "ko": "와이파이 있나요?"},
    {"jp": "荷物を預けられますか？", "pron": "니모츠오 아즈케라레마스카", "ko": "짐 맡길 수 있나요?"},
    {"jp": "近くにコンビニはありますか？", "pron": "치카쿠니 콘비니와 아리마스카", "ko": "근처에 편의점 있어요?"},
    {"jp": "道に迷いました。", "pron": "미치니 마요이마시타", "ko": "길을 잃었어요."},
    {"jp": "ここから遠いですか？", "pron": "코코카라 토오이데스카", "ko": "여기서 멀어요?"},
    {"jp": "どのくらいかかりますか？", "pron": "도노쿠라이 카카리마스카", "ko": "얼마나 걸려요?"},

    {"jp": "英語を話せますか？", "pron": "에이고오 하나세마스카", "ko": "영어 할 수 있어요?"},
    {"jp": "ゆっくり話してください。", "pron": "윳쿠리 하나시테 쿠다사이", "ko": "천천히 말해주세요."},
    {"jp": "大丈夫です。", "pron": "다이죠부데스", "ko": "괜찮아요."},
    {"jp": "分かりました。", "pron": "와카리마시타", "ko": "알겠습니다."},
    {"jp": "ちょっと待ってください。", "pron": "촛토 맛테 쿠다사이", "ko": "잠시만요."},
    {"jp": "ありがとうございます。", "pron": "아리가토 고자이마스", "ko": "감사합니다."},
    {"jp": "すみません。", "pron": "스미마센", "ko": "실례합니다 / 죄송합니다."},
    {"jp": "問題ありません。", "pron": "몬다이 아리마센", "ko": "문제없어요."},
    {"jp": "もう少し安くなりますか？", "pron": "모- 스코시 야스쿠 나리마스카", "ko": "조금 더 싸질 수 있나요?"},
    {"jp": "これを探しています。", "pron": "코레오 사가시테이마스", "ko": "이거 찾고 있어요."},
    {"jp": "これは何ですか？", "pron": "코레와 난데스카", "ko": "이건 뭐예요?"},
    {"jp": "どこで買えますか？", "pron": "도코데 카에마스카", "ko": "어디서 살 수 있어요?"},
    {"jp": "もう売り切れですか？", "pron": "모- 우리키레데스카", "ko": "이미 다 팔렸나요?"},
    {"jp": "試してもいいですか？", "pron": "타메시테모 이이데스카", "ko": "시험해봐도 돼요?"},
    {"jp": "サイズはありますか？", "pron": "사이즈와 아리마스카", "ko": "사이즈 있나요?"},

    {"jp": "ここで食べられますか？", "pron": "코코데 타베라레마스카", "ko": "여기서 먹을 수 있나요?"},
    {"jp": "持ち帰りできますか？", "pron": "모치카에리 데키마스카", "ko": "포장되나요?"},
    {"jp": "人気ですか？", "pron": "닌키데스카", "ko": "인기 있나요?"},
    {"jp": "どれが一番おすすめですか？", "pron": "도레가 이치방 오스스메데스카", "ko": "어느 게 제일 추천이에요?"},
    {"jp": "甘いですか？", "pron": "아마이데스카", "ko": "달아요?"},

    {"jp": "辛いですか？", "pron": "카라이데스카", "ko": "매워요?"},
    {"jp": "今すぐ行きます。", "pron": "이마 스구 이키마스", "ko": "지금 바로 갈게요."},
    {"jp": "少し時間があります。", "pron": "스코시 지칸가 아리마스", "ko": "시간이 조금 있어요."},
    {"jp": "急いでいます。", "pron": "이소이데이마스", "ko": "급해요."},
    {"jp": "ゆっくりで大丈夫です。", "pron": "윳쿠리데 다이죠부데스", "ko": "천천히 해도 괜찮아요."},

    {"jp": "ここは初めてです。", "pron": "코코와 하지메테데스", "ko": "여기 처음이에요."},
    {"jp": "とてもきれいですね。", "pron": "토테모 키레이데스네", "ko": "정말 예쁘네요."},
    {"jp": "写真を見てもいいですか？", "pron": "샤신오 미테모 이이데스카", "ko": "사진 봐도 돼요?"},
    {"jp": "おすすめの場所はありますか？", "pron": "오스스메노 바쇼와 아리마스카", "ko": "추천 장소 있어요?"},
    {"jp": "近くですか？", "pron": "치카쿠데스카", "ko": "가까워요?"},

    {"jp": "遠くないですか？", "pron": "토오쿠 나이데스카", "ko": "멀지 않아요?"},
    {"jp": "歩いて行けますか？", "pron": "아루이테 이케마스카", "ko": "걸어서 갈 수 있어요?"},
    {"jp": "タクシーを呼べますか？", "pron": "타쿠시-오 요베마스카", "ko": "택시 불러줄 수 있나요?"},
    {"jp": "ここで待ちます。", "pron": "코코데 마치마스", "ko": "여기서 기다릴게요."},
    {"jp": "後で戻ります。", "pron": "아토데 모도리마스", "ko": "나중에 돌아올게요."},

    {"jp": "大丈夫だと思います。", "pron": "다이죠부다토 오모이마스", "ko": "괜찮을 것 같아요."},
    {"jp": "ちょっと難しいです。", "pron": "촛토 무즈카시이데스", "ko": "조금 어려워요."},
    {"jp": "簡単です。", "pron": "칸탄데스", "ko": "간단해요."},
    {"jp": "よく分かりました。", "pron": "요쿠 와카리마시타", "ko": "잘 알겠어요."},
    {"jp": "もう一つください。", "pron": "모- 히토츠 쿠다사이", "ko": "하나 더 주세요."},

    {"jp": "これで十分です。", "pron": "코레데 주-분데스", "ko": "이걸로 충분해요."},
    {"jp": "少し多いです。", "pron": "스코시 오오이데스", "ko": "조금 많아요."},
    {"jp": "少なくしてください。", "pron": "스쿠나쿠 시테 쿠다사이", "ko": "적게 해주세요."},
    {"jp": "もう終わりましたか？", "pron": "모- 오와리마시타카", "ko": "벌써 끝났나요?"},
    {"jp": "まだです。", "pron": "마다데스", "ko": "아직이에요."},

    {"jp": "すぐ終わります。", "pron": "스구 오와리마스", "ko": "금방 끝나요."},
    {"jp": "気に入りました。", "pron": "키니이리마시타", "ko": "마음에 들어요."},
    {"jp": "また来ます。", "pron": "마타 키마스", "ko": "또 올게요."},
    {"jp": "楽しかったです。", "pron": "타노시캇타데스", "ko": "재밌었어요."},
    {"jp": "いい思い出です。", "pron": "이이 오모이데데스", "ko": "좋은 추억이에요."},
]


Item = Tuple[str, str, str]

SITUATIONS: Dict[str, Dict[str, Any]] = {
    # 1) 공항
    "airport": {
        "title": "공항 필수 일본어 회화 문장 모음",
        "subs": {
            "checkin": {
                "title": "체크인/수하물",
                "items": [
                    ("チェックインをお願いします。", "체쿠인오 오네가이시마스", "체크인 부탁합니다."),
                    ("パスポートはこちらです。", "파스포-토와 코치라데스", "여권 여기 있습니다."),
                    ("預け荷物はこれです。", "아즈케니모츠와 코레데스", "부칠 짐은 이거예요."),
                    ("機内持ち込みはこれだけです。", "키나이모치코미와 코레다케데스", "기내 반입은 이것뿐이에요."),
                    ("座席は通路側がいいです。", "자세키와 츠-로가와가 이-데스", "좌석은 통로쪽이 좋아요."),
                    ("窓側は空いていますか？", "마도가와와 아이테이마스카", "창가 자리가 비어있나요?"),
                    ("何時に搭乗ですか？", "난지니 토-죠-데스카", "몇 시에 탑승인가요?"),
                    ("荷物の重量は大丈夫ですか？", "니모츠노 쥬-료-와 다이죠-부데스카", "짐 무게 괜찮나요?"),
                    ("乗り継ぎがあります。", "노리츠기가 아리마스", "환승이 있어요."),
                    ("チケットはスマホにあります。", "치켓토와 스마호니 아리마스", "티켓은 휴대폰에 있어요."),
                ],
            },
            "departure": {
                "title": "출국/탑승",
                "items": [
                    ("保安検査はどこですか？", "호안켄사와 도코데스카", "보안 검색은 어디예요?"),
                    ("ゲートは何番ですか？", "게-토와 난반데스카", "게이트는 몇 번인가요?"),
                    ("出発は何時ですか？", "슈파츠와 난지데스카", "출발은 몇 시인가요?"),
                    ("遅れていますか？", "오쿠레테이마스카", "지연되고 있나요?"),
                    ("搭乗口は変わりましたか？", "토-죠-구치와 카와리마시타카", "탑승구가 바뀌었나요?"),
                    ("優先搭乗はありますか？", "유-센토-죠-와 아리마스카", "우선 탑승 있나요?"),
                    ("もうすぐ搭乗ですか？", "모-스구 토-죠-데스카", "곧 탑승인가요?"),
                    ("この列で合っていますか？", "코노 레츠데 앗테이마스카", "이 줄이 맞나요?"),
                    ("トイレはどこですか？", "토이레와 도코데스카", "화장실은 어디예요?"),
                    ("案内をお願いします。", "안나이오 오네가이시마스", "안내 부탁해요."),
                ],
            },
        },
    },

    # 2) 호텔
    "hotel": {
        "title": "호텔 필수 일본어 회화 문장 모음",
        "subs": {
            "checkin": {
                "title": "체크인/입실",
                "items": [
                    ("予約しています。", "요야쿠시테이마스", "예약했어요."),
                    ("チェックインをお願いします。", "체쿠인오 오네가이시마스", "체크인 부탁해요."),
                    ("名前はキムです。", "나마에와 키무데스", "이름은 김입니다."),
                    ("パスポートをお見せします。", "파스포-토오 오미세시마스", "여권 보여드릴게요."),
                    ("禁煙室はありますか？", "킨엔시츠와 아리마스카", "금연실 있나요?"),
                    ("部屋は何階ですか？", "헤야와 난가이데스카", "방은 몇 층인가요?"),
                    ("朝食は何時からですか？", "초-쇼쿠와 난지카라데스카", "조식은 몇 시부터예요?"),
                    ("Wi-Fiのパスワードは？", "와이화이노 파스와-도와", "와이파이 비밀번호는요?"),
                    ("荷物を預けられますか？", "니모츠오 아즈케라레마스카", "짐 맡길 수 있나요?"),
                    ("レイトチェックアウトできますか？", "레-토 체쿠아우토 데키마스카", "레이트 체크아웃 가능해요?"),
                    ("すみません、フロントはどこですか？", "스미마센 후론토와 도코데스카", "프런트는 어디예요?"),
                    ("部屋の鍵をもう一枚ください。", "헤야노 카기오 모-이치마이 쿠다사이", "방 키 하나 더 주세요."),
                    ("チェックアウトを延長できますか？", "체쿠아우토오 엔초-데키마스카", "체크아웃 연장 가능해요?"),
                    ("タクシーを呼んでください。", "타쿠시-오 욘데 쿠다사이", "택시 불러주세요."),
                    ("モーニングコールをお願いします。", "모-닝구코-루오 오네가이시마스", "모닝콜 부탁해요."),
                    ("荷物を預けたいです。", "니모츠오 아즈케타이데스", "짐 맡기고 싶어요."),
                    ("近くのコンビニはどこですか？", "치카쿠노 콘비니와 도코데스카", "근처 편의점 어디예요?"),
                    ("地図をもらえますか？", "치즈오 모라에마스카", "지도 받을 수 있나요?"),
                ],
            },
            "problem": {
                "title": "요청/문제",
                "items": [
                    ("タオルを追加してください。", "타오루오 츠이카시테 쿠다사이", "수건 추가해주세요."),
                    ("部屋の掃除をお願いします。", "헤야노 소-지오 오네가이시마스", "방 청소 부탁해요."),
                    ("カードキーが反応しません。", "카-도키-가 한노-시마센", "카드키가 반응을 안 해요."),
                    ("部屋に入れません。", "헤야니 하이레마센", "방에 못 들어가요."),
                    ("エアコンが効きません。", "에아콘가 키키마센", "에어컨이 안 돼요."),
                    ("お湯が出ません。", "오유가 데마센", "뜨거운 물이 안 나와요."),
                    ("鍵をなくしました。", "카기오 나쿠시마시타", "열쇠를 잃어버렸어요."),
                    ("部屋を変えられますか？", "헤야오 카에라레마스카", "방 바꿀 수 있나요?"),
                    ("静かな部屋がいいです。", "시즈카나 헤야가 이-데스", "조용한 방이 좋아요."),
                    ("チェックアウトはどこですか？", "체쿠아우토와 도코데스카", "체크아웃은 어디서 하나요?"),
                    ("領収書をください。", "료-슈-쇼오 쿠다사이", "영수증 주세요."),
                    ("荷物を部屋まで運べますか？", "니모츠오 헤야마데 하코베마스카", "짐을 방까지 옮겨줄 수 있나요?"),
                ],
            },
        },
    },

    # 3) 교통
    "transport": {
        "title": "교통 필수 일본어 회화 문장 모음",
        "subs": {
            "train": {
                "title": "전철/지하철",
                "items": [
                    ("この電車は新宿に行きますか？", "코노 덴샤와 신주쿠니 이키마스카", "이 전철 신주쿠 가나요?"),
                    ("何番線ですか？", "난반센데스카", "몇 번 승강장이에요?"),
                    ("次はどこですか？", "츠기와 도코데스카", "다음은 어디예요?"),
                    ("乗り換えはどこですか？", "노리카에와 도코데스카", "환승은 어디서 해요?"),
                    ("この切符でいいですか？", "코노 킷푸데 이-데스카", "이 표로 되나요?"),
                    ("Suicaは使えますか？", "스이카와 츠카에마스카", "스이카 쓸 수 있나요?"),
                    ("出口はどちらですか？", "데구치와 도치라데스카", "출구는 어디예요?"),
                    ("最寄り駅はどこですか？", "모요리에키와 도코데스카", "가장 가까운 역이 어디예요?"),
                    ("急行は止まりますか？", "큐-코-와 토마리마스카", "급행은 정차하나요?"),
                    ("遅延していますか？", "치엔시테이마스카", "지연되고 있나요?"),
                    ("切符を買いたいです。", "킷푸오 카이타이데스", "표를 사고 싶어요."),
                    ("一番安い切符はどれですか？", "이치방 야스이 킷푸와 도레데스카", "가장 싼 표가 뭐예요?"),
                    ("〇〇までいくらですか？", "○○마데 이쿠라데스카", "○○까지 얼마예요?"),
                    ("チャージできますか？", "챠-지 데키마스카", "충전할 수 있나요?"),
                    ("残高が足りません。", "잔다카가 타리마센", "잔액이 부족해요."),
                    ("改札はどこですか？", "카이사츠와 도코데스카", "개찰구는 어디예요?"),
                    ("乗り換え時間は何分ですか？", "노리카에 지칸와 난푼데스카", "환승 시간 몇 분이에요?"),
                    ("最終電車は何時ですか？", "사이슈-덴샤와 난지데스카", "막차는 몇 시예요?"),
                    ("この電車は急行ですか？", "코노 덴샤와 큐-코-데스카", "이 전철 급행이에요?"),
                    ("次の駅で降ります。", "츠기노 에키데 오리마스", "다음 역에서 내릴게요."),
                ],
            },
            "taxi": {
                "title": "택시/길찾기",
                "items": [
                    ("ここまでお願いします。", "코코마데 오네가이시마스", "여기까지 부탁해요."),
                    ("この住所に行ってください。", "코노 쥬-쇼니 잇테 쿠다사이", "이 주소로 가주세요."),
                    ("いくらぐらいかかりますか？", "이쿠라구라이 카카리마스카", "얼마 정도 나와요?"),
                    ("領収書をください。", "료-슈-쇼오 쿠다사이", "영수증 주세요."),
                    ("急いでください。", "이소이데 쿠다사이", "서둘러 주세요."),
                    ("この道で合っていますか？", "코노 미치데 앗테이마스카", "이 길 맞나요?"),
                    ("ここで止めてください。", "코코데 토메테 쿠다사이", "여기서 세워주세요."),
                    ("近いですか？", "치카이데스카", "가까워요?"),
                    ("地図で見せます。", "치즈데 미세마스", "지도 보여드릴게요."),
                    ("駅はどこですか？", "에키와 도코데스카", "역은 어디예요?"),
                ],
            },
        },
    },

    # 4) 음식점
    "restaurant": {
        "title": "식당 필수 일본어 회화 문장 모음",
        "subs": {
            "order": {
                "title": "입장/주문",
                "items": [
                    ("二人です。", "후타리데스", "두 명이에요."),
                    ("予約しています。", "요야쿠시테이마스", "예약했어요."),
                    ("おすすめは何ですか？", "오스스메와 난데스카", "추천은 뭐예요?"),
                    ("これをください。", "코레오 쿠다사이", "이거 주세요."),
                    ("辛くしないでください。", "카라쿠시나이데 쿠다사이", "맵지 않게 해주세요."),
                    ("アレルギーがあります。", "아레루기-가 아리마스", "알레르기가 있어요."),
                    ("水をください。", "미즈오 쿠다사이", "물 주세요."),
                    ("おしぼりをください。", "오시보리오 쿠다사이", "물수건 주세요."),
                    ("別々にお願いします。", "베츠베츠니 오네가이시마스", "따로 부탁해요(각자 계산)."),
                    ("メニューを見せてください。", "메뉴-오 미세테 쿠다사이", "메뉴판 보여주세요."),
                    ("何名様ですか？", "난메-사마데스카", "몇 분이세요?"),
                    ("二人です。", "후타리데스", "두 명이에요."),
                    ("予約していません。", "요야쿠시테이마센", "예약 안 했어요."),
                    ("どのくらい待ちますか？", "도노쿠라이 마치마스카", "얼마나 기다려요?"),
                    ("先に注文できますか？", "사키니 츄-몬데키마스카", "먼저 주문할 수 있나요?"),
                    ("カウンター席でも大丈夫です。", "카운타-세키데모 다이죠-부데스", "카운터석도 괜찮아요."),
                    ("禁煙席をお願いします。", "킨엔세키오 오네가이시마스", "금연석 부탁해요."),
                    ("窓側がいいです。", "마도가와가 이-데스", "창가가 좋아요."),
                    ("子ども椅子はありますか？", "코도모 이스와 아리마스카", "아기 의자 있나요?"),
                    ("メニューは英語がありますか？", "메뉴-와 에-고가 아리마스카", "영어 메뉴 있어요?"),
                    ("すみません、注文いいですか？", "스미마센 츄-몬 이-데스카", "실례합니다, 주문할게요."),
                    ("これを追加でください。", "코레오 츠이카데 쿠다사이", "이거 추가로 주세요."),
                    ("おすすめを一つください。", "오스스메오 히토츠 쿠다사이", "추천 하나 주세요."),
                    ("辛さは控えめで。", "카라사와 히카에메데", "맵기는 약하게요."),
                    ("アレルギーがあるので確認してください。", "아레루기-가 아루노데 카쿠닌시테 쿠다사이", "알레르기 있어서 확인해주세요."),
                    ("これは何が入っていますか？", "코레와 나니가 하잇테이마스카", "이거 뭐 들어있어요?"),
                    ("水をもう一杯ください。", "미즈오 모-잇파이 쿠다사이", "물 한 잔 더 주세요."),
                    ("取り皿をください。", "토리자라오 쿠다사이", "앞접시 주세요."),
                    ("おしぼりをもう一つください。", "오시보리오 모-히토츠 쿠다사이", "물수건 하나 더 주세요."),
                    ("店員さん、すみません。", "테-인상, 스미마센", "저기요(직원분)."),
                ],
            },
            "pay": {
                "title": "계산/마무리",
                "items": [
                    ("お会計お願いします。", "오카이케- 오네가이시마스", "계산 부탁해요."),
                    ("カードは使えますか？", "카-도와 츠카에마스카", "카드 되나요?"),
                    ("現金だけですか？", "겐킨다케데스카", "현금만 되나요?"),
                    ("領収書をください。", "료-슈-쇼오 쿠다사이", "영수증 주세요."),
                    ("テイクアウトできますか？", "테이쿠아우토 데키마스카", "포장 가능해요?"),
                    ("袋をください。", "후쿠로오 쿠다사이", "봉투 주세요."),
                    ("とてもおいしかったです。", "토테모 오이시캇타데스", "정말 맛있었어요."),
                    ("ごちそうさまでした。", "고치소-사마데시타", "잘 먹었습니다."),
                    ("トイレはどこですか？", "토이레와 도코데스카", "화장실은 어디예요?"),
                    ("また来ます。", "마타 키마스", "또 올게요."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 6개 상황 (총 10개)
    # ---------------------------

    # 5) 관광/명소
    "sightseeing": {
        "title": "관광 필수 일본어 회화 문장 모음",
        "subs": {
            "tickets": {
                "title": "티켓/입장",
                "items": [
                    ("チケットはどこで買えますか？", "치켓토와 도코데 카에마스카", "티켓은 어디서 살 수 있나요?"),
                    ("一枚ください。", "이치마이 쿠다사이", "한 장 주세요."),
                    ("大人二人です。", "오토나 후타리데스", "성인 두 명이에요."),
                    ("学生割引はありますか？", "가쿠세- 와리비키와 아리마스카", "학생 할인 있나요?"),
                    ("何時まで開いていますか？", "난지마데 아이테이마스카", "몇 시까지 열어요?"),
                    ("最終入場は何時ですか？", "사이슈- 뉴-죠-와 난지데스카", "마지막 입장은 몇 시예요?"),
                    ("写真を撮ってもいいですか？", "샤신오 톳테모 이-데스카", "사진 찍어도 되나요?"),
                    ("ここは無料ですか？", "코코와 무료-데스카", "여기는 무료인가요?"),
                    ("パンフレットはありますか？", "판후렛토와 아리마스카", "팜플렛 있나요?"),
                    ("トイレはどこですか？", "토이레와 도코데스카", "화장실은 어디예요?"),
                    ("ここで撮っても大丈夫ですか？", "코코데 톳테모 다이죠-부데스카", "여기서 찍어도 괜찮나요?"),
                    ("フラッシュは使ってもいいですか？", "후랏슈와 츠캇테모 이-데스카", "플래시 써도 되나요?"),
                    ("動画を撮ってもいいですか？", "도-가오 톳테모 이-데스카", "영상 찍어도 되나요?"),
                    ("撮影禁止ですか？", "사츠에-킨시데스카", "촬영 금지인가요?"),
                    ("スタッフさんに確認します。", "스탓후상니 카쿠닌시마스", "직원에게 확인할게요."),
                    ("写真はだめです。", "샤신와 다메데스", "사진은 안 돼요."),
                    ("わかりました。ありがとうございます。", "와카리마시타 아리가토-고자이마스", "알겠습니다 감사합니다."),
                    ("すみません、もう一枚いいですか？", "스미마센 모-이치마이 이-데스카", "실례합니다, 한 장 더 괜찮을까요?"),
                    ("縦でお願いします。", "타테데 오네가이시마스", "세로로 부탁해요."),
                ],
            },
            "photo": {
                "title": "사진/부탁",
                "items": [
                    ("写真を撮ってください。", "샤신오 톳테 쿠다사이", "사진 찍어주세요."),
                    ("ここでお願いします。", "코코데 오네가이시마스", "여기서 부탁해요."),
                    ("もう一枚いいですか？", "모- 이치마이 이-데스카", "한 장 더 괜찮아요?"),
                    ("縦でお願いします。", "타테데 오네가이시마스", "세로로 부탁해요."),
                    ("横でお願いします。", "요코데 오네가이시마스", "가로로 부탁해요."),
                    ("バックを入れてください。", "박쿠오 이레테 쿠다사이", "배경도 넣어주세요."),
                    ("フラッシュはなしで。", "후랏슈와 나시데", "플래시는 없이요."),
                    ("すみません、お願いします。", "스미마센 오네가이시마스", "죄송한데 부탁해요."),
                    ("ありがとう！", "아리가토-", "고마워요!"),
                    ("撮り直してもいいですか？", "토리나오시테모 이-데스카", "다시 찍어도 될까요?"),
                ],
            },
        },
    },

    # 6) 카페
    "cafe": {
        "title": "카페 필수 일본어 회화 문장 모음",
        "subs": {
            "order": {
                "title": "주문",
                "items": [
                    ("おすすめは何ですか？", "오스스메와 난데스카", "추천은 뭐예요?"),
                    ("アイスでお願いします。", "아이스데 오네가이시마스", "아이스로 부탁해요."),
                    ("ホットでお願いします。", "홋토데 오네가이시마스", "따뜻한 걸로 부탁해요."),
                    ("砂糖なしで。", "사토-나시데", "설탕 없이요."),
                    ("ミルクを少なめに。", "미루쿠오 스쿠나메니", "우유 적게요."),
                    ("テイクアウトで。", "테이쿠아우토데", "테이크아웃이요."),
                    ("ここで飲みます。", "코코데 노미마스", "여기서 마실게요."),
                    ("サイズは大きいので。", "사이즈와 오-키이노데", "큰 사이즈로요."),
                    ("これをください。", "코레오 쿠다사이", "이거 주세요."),
                    ("名前はキムです。", "나마에와 키무데스", "이름은 김입니다."),
                    ("これをお願いします。", "코레오 오네가이시마스", "이거 부탁해요."),
                    ("カードでお願いします。", "카-도데 오네가이시마스", "카드로 부탁해요."),
                    ("現金で払います。", "겐킨데 하라이마스", "현금으로 낼게요."),
                    ("タッチ決済できますか？", "탓치 케-사이 데키마스카", "터치결제 되나요?"),
                    ("電子マネーは使えますか？", "덴시마네-와 츠카에마스카", "전자결제 되나요?"),
                    ("レシートください。", "레시-토 쿠다사이", "영수증 주세요."),
                    ("領収書をお願いします。", "료-슈-쇼오 오네가이시마스", "영수증(증빙) 부탁해요."),
                    ("袋はいりません。", "후쿠로와 이리마센", "봉투 필요 없어요."),
                    ("袋をください。", "후쿠로오 쿠다사이", "봉투 주세요."),
                    ("ポイントは使えますか？", "포인트와 츠카에마스카", "포인트 사용되나요?"),
                ],
            },
            "seat": {
                "title": "좌석/와이파이",
                "items": [
                    ("席は空いていますか？", "세키와 아이테이마스카", "자리 비었나요?"),
                    ("ここに座ってもいいですか？", "코코니 스왓테모 이-데스카", "여기 앉아도 돼요?"),
                    ("コンセントはありますか？", "콘센토와 아리마스카", "콘센트 있나요?"),
                    ("Wi-Fiはありますか？", "와이화이와 아리마스카", "와이파이 있나요?"),
                    ("パスワードは何ですか？", "파스와-도와 난데스카", "비밀번호가 뭐예요?"),
                    ("トイレはどこですか？", "토이레와 도코데스카", "화장실 어디예요?"),
                    ("もう少し静かな席はありますか？", "모-스코시 시즈카나 세키와 아리마스카", "좀 더 조용한 자리 있나요?"),
                    ("ここ、いいですか？", "코코 이-데스카", "여기 괜찮아요?"),
                    ("すみません。", "스미마센", "실례합니다."),
                    ("ありがとう。", "아리가토-", "감사합니다."),
                ],
            },
        },
    },

    # 7) 편의점/마트
    "convenience": {
        "title": "편의점/마트 필수 일본어 회화 문장 모음",
        "subs": {
            "buy": {
                "title": "구매/결제",
                "items": [
                    ("これください。", "코레 쿠다사이", "이거 주세요."),
                    ("袋をください。", "후쿠로오 쿠다사이", "봉투 주세요."),
                    ("温めてください。", "아타타메테 쿠다사이", "데워주세요."),
                    ("お箸をください。", "오하시오 쿠다사이", "젓가락 주세요."),
                    ("スプーンをください。", "스푸-노오 쿠다사이", "스푼 주세요."),
                    ("ポイントカードはありますか？", "포인트 카-도와 아리마스카", "포인트 카드 있나요?"),
                    ("レシートをください。", "레시-토오 쿠다사이", "영수증 주세요."),
                    ("カードで払えますか？", "카-도데 하라에마스카", "카드로 결제 가능해요?"),
                    ("現金で払います。", "겐킨데 하라이마스", "현금으로 낼게요."),
                    ("トイレを借りてもいいですか？", "토이레오 카리테모 이-데스카", "화장실 빌려도 될까요?"),
                    ("これをお願いします。", "코레오 오네가이시마스", "이거 부탁해요."),
                    ("カードでお願いします。", "카-도데 오네가이시마스", "카드로 부탁해요."),
                    ("現金で払います。", "겐킨데 하라이마스", "현금으로 낼게요."),
                    ("タッチ決済できますか？", "탓치 케-사이 데키마스카", "터치결제 되나요?"),
                    ("電子マネーは使えますか？", "덴시마네-와 츠카에마스카", "전자결제 되나요?"),
                    ("レシートください。", "레시-토 쿠다사이", "영수증 주세요."),
                    ("領収書をお願いします。", "료-슈-쇼오 오네가이시마스", "영수증(증빙) 부탁해요."),
                    ("袋はいりません。", "후쿠로와 이리마센", "봉투 필요 없어요."),
                    ("袋をください。", "후쿠로오 쿠다사이", "봉투 주세요."),
                    ("ポイントは使えますか？", "포인트와 츠카에마스카", "포인트 사용되나요?"),
                ],
            },
            "find": {
                "title": "상품찾기",
                "items": [
                    ("飲み物はどこですか？", "노미모노와 도코데스카", "음료는 어디예요?"),
                    ("おにぎりはありますか？", "오니기리와 아리마스카", "주먹밥 있나요?"),
                    ("おすすめはありますか？", "오스스메와 아리마스카", "추천 있어요?"),
                    ("これ、人気ですか？", "코레 닌키데스카", "이거 인기 있어요?"),
                    ("辛いものはありますか？", "카라이 모노와 아리마스카", "매운 거 있나요?"),
                    ("甘いものはありますか？", "아마이 모노와 아리마스카", "달달한 거 있나요?"),
                    ("水はどこですか？", "미즈와 도코데스카", "물은 어디예요?"),
                    ("薬はありますか？", "쿠스리와 아리마스카", "약 있어요?"),
                    ("充電器はありますか？", "쥬-덴키와 아리마스카", "충전기 있나요?"),
                    ("電子レンジは使えますか？", "덴시렌지와 츠카에마스카", "전자레인지 사용 가능해요?"),
                ],
            },
        },
    },

    # 8) 응급/병원
    "emergency": {
        "title": "응급/병원 필수 일본어 회화 문장 모음",
        "subs": {
            "pharmacy": {
                "title": "약국",
                "items": [
                    ("薬局はどこですか？", "야쿠쿄쿠와 도코데스카", "약국은 어디예요?"),
                    ("頭が痛いです。", "아타마가 이타이데스", "머리가 아파요."),
                    ("お腹が痛いです。", "오나카가 이타이데스", "배가 아파요."),
                    ("熱があります。", "네츠가 아리마스", "열이 있어요."),
                    ("喉が痛いです。", "노도가 이타이데스", "목이 아파요."),
                    ("咳が出ます。", "세키가 데마스", "기침이 나요."),
                    ("鼻水が出ます。", "하나미즈가 데마스", "콧물이 나요."),
                    ("下痢です。", "게리데스", "설사예요."),
                    ("便秘です。", "벤피데스", "변비예요."),
                    ("花粉症です。", "카훈쇼-데스", "꽃가루 알레르기예요."),
                    ("消毒できますか？", "쇼-도쿠 데키마스카", "소독할 수 있나요?"),
                    ("絆創膏をください。", "반소-코-오 쿠다사이", "밴드 주세요."),
                    ("酔い止めをください。", "요이도메오 쿠다사이", "멀미약 주세요."),
                    ("痛み止めはありますか？", "이타미도메와 아리마스카", "진통제 있나요?"),
                    ("風邪薬はありますか？", "카제구스리와 아리마스카", "감기약 있나요?"),
                    ("酔い止めはありますか？", "요이도메와 아리마스카", "멀미약 있나요?"),
                    ("絆創膏はありますか？", "반소-코-와 아리마스카", "밴드 있나요?"),
                    ("アレルギーがあります。", "아레루기-가 아리마스", "알레르기가 있어요."),
                    ("英語は話せますか？", "에-고와 하나세마스카", "영어 하실 수 있나요?"),
                    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
                    ("一日に何回ですか？", "이치니치니 난카이데스카", "하루에 몇 번이에요?"),
                    ("食後ですか？", "쇼쿠고데스카", "식후인가요?"),
                    ("眠くなりますか？", "네무쿠 나리마스카", "졸리게 되나요?"),
                    ("子どもでも使えますか？", "코도모데모 츠카에마스카", "아이도 사용할 수 있나요?"),
                    ("妊娠中でも大丈夫ですか？", "닌신츄-데모 다이죠-부데스카", "임신 중에도 괜찮나요?"),
                    ("アレルギーがあります。", "아레루기-가 아리마스", "알레르기가 있어요."),
                    ("どれがいいですか？", "도레가 이이데스카", "어느 게 좋아요?"),
                    ("おすすめはありますか？", "오스스메와 아리마스카", "추천 있어요?"),
                    ("これ、効きますか？", "코레, 키키마스카", "이거 효과 있나요?"),
                    ("もう少し強い薬はありますか？", "모-스코시 츠요이 쿠스리와 아리마스카", "조금 더 강한 약 있나요?"),
                ],
            },
            "hospital": {
                "title": "병원",
                "items": [
                    ("病院に行きたいです。", "뵤-인니 이키타이데스", "병원에 가고 싶어요."),
                    ("救急です。", "큐-큐-데스", "응급이에요."),
                    ("ここが痛いです。", "코코가 이타이데스", "여기가 아파요."),
                    ("気分が悪いです。", "키분가 와루이데스", "몸이 안 좋아요."),
                    ("めまいがします。", "메마이가 시마스", "어지러워요."),
                    ("吐きそうです。", "하키소-데스", "토할 것 같아요."),
                    ("薬を飲んでいます。", "쿠스리오 논데이마스", "약을 먹고 있어요."),
                    ("保険はありません。", "호켄와 아리마센", "보험이 없어요."),
                    ("通訳はいますか？", "츠-야쿠와 이마스카", "통역 있나요?"),
                    ("お願いします。", "오네가이시마스", "부탁합니다."),
                ],
            },
        },
    },

    # 9) 길거리/도움요청
    "help": {
        "title": "도움요청 필수 일본어 회화 문장 모음",
        "subs": {
            "lost": {
                "title": "길잃음",
                "items": [
                    ("すみません、道に迷いました。", "스미마센 미치니 마요이마시타", "죄송한데 길을 잃었어요."),
                    ("ここはどこですか？", "코코와 도코데스카", "여기가 어디예요?"),
                    ("この場所に行きたいです。", "코노 바쇼니 이키타이데스", "이곳에 가고 싶어요."),
                    ("地図を見せてもいいですか？", "치즈오 미세테모 이-데스카", "지도 보여드려도 될까요?"),
                    ("駅はどちらですか？", "에키와 도치라데스카", "역은 어느 쪽이에요?"),
                    ("近いですか？", "치카이데스카", "가까워요?"),
                    ("徒歩で何分ですか？", "토호데 난푼데스카", "걸어서 몇 분이에요?"),
                    ("右ですか、左ですか？", "미기데스카 히다리데스카", "오른쪽인가요 왼쪽인가요?"),
                    ("もう一度お願いします。", "모-이치도 오네가이시마스", "한 번 더 부탁해요."),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
            "lostitem": {
                "title": "분실/도난",
                "items": [
                    ("財布をなくしました。", "사이후오 나쿠시마시타", "지갑을 잃어버렸어요."),
                    ("スマホをなくしました。", "스마호오 나쿠시마시타", "휴대폰을 잃어버렸어요."),
                    ("パスポートをなくしました。", "파스포-토오 나쿠시마시타", "여권을 잃어버렸어요."),
                    ("盗まれました。", "누스마레마시타", "도난당했어요."),
                    ("警察はどこですか？", "케-사츠와 도코데스카", "경찰서는 어디예요?"),
                    ("交番はどこですか？", "코-반와 도코데스카", "파출소는 어디예요?"),
                    ("この人を見ましたか？", "코노 히토오 미마시타카", "이 사람 봤나요?"),
                    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
                    ("カードを止めたいです。", "카-도오 토메타이데스", "카드를 정지하고 싶어요."),
                    ("書類が必要ですか？", "쇼루이가 히츠요-데스카", "서류가 필요해요?"),
                    ("すみません、落とし物をしました。", "스미마센 오토시모노오 시마시타", "실례합니다, 물건을 잃어버렸어요."),
                    ("ここに忘れました。", "코코니 와스레마시타", "여기에 두고 왔어요."),
                    ("見つかりましたか？", "미츠카리마시타카", "찾았나요?"),
                    ("黒い財布です。", "쿠로이 사이후데스", "검은 지갑이에요."),
                    ("中にカードがあります。", "나카니 카-도가 아리마스", "안에 카드가 있어요."),
                    ("いつ頃なくしました。", "이츠고로 나쿠시마시타", "언제쯤 잃어버렸어요."),
                    ("連絡先を書きます。", "렌라쿠사키오 카키마스", "연락처 적을게요."),
                    ("身分証はあります。", "미분쇼-와 아리마스", "신분증 있어요."),
                    ("名前は〇〇です。", "나마에와 ○○데스", "이름은 ○○입니다."),
                    ("ありがとうございます。", "아리가토-고자이마스", "감사합니다."),
                ],
            },
        },
    },

    # 10) 통신/인터넷
    "internet": {
        "title": "통신/인터넷 필수 일본어 회화 문장 모음",
        "subs": {
            "sim": {
                "title": "유심/데이터",
                "items": [
                    ("SIMカードを買いたいです。", "심카-도오 카이타이데스", "유심을 사고 싶어요."),
                    ("データは何GBですか？", "데-타와 난 지-비-데스카", "데이터는 몇 GB예요?"),
                    ("何日間使えますか？", "난니치칸 츠카에마스카", "며칠 동안 쓸 수 있나요?"),
                    ("開通できますか？", "카이츠- 데키마스카", "개통해줄 수 있나요?"),
                    ("設定を手伝ってください。", "세테-오 테츠닷테 쿠다사이", "설정 좀 도와주세요."),
                    ("電話番号はありますか？", "덴와방고-와 아리마스카", "전화번호도 있나요?"),
                    ("テザリングはできますか？", "테자리ング와 데키마스카", "테더링 되나요?"),
                    ("このSIMは使えますか？", "코노 심와 츠카에마스카", "이 유심 사용 가능해요?"),
                    ("日本で使えますか？", "니혼데 츠카에마스카", "일본에서 쓸 수 있나요?"),
                    ("返金できますか？", "헨킨 데키마스카", "환불 가능해요?"),
                ],
            },
            "wifi": {
                "title": "와이파이/연결",
                "items": [
                    ("Wi-Fiはありますか？", "와이화이와 아리마스카", "와이파이 있나요?"),
                    ("パスワードは何ですか？", "파스와-도와 난데스카", "비밀번호가 뭐예요?"),
                    ("つながりません。", "츠나가리마센", "연결이 안 돼요."),
                    ("電波が弱いです。", "덴파가 요와이데스", "신호가 약해요."),
                    ("もう一度試します。", "모- 이치도 타메시마스", "다시 시도해볼게요."),
                    ("再起動してもいいですか？", "사이키도-시테모 이-데스카", "재부팅해도 될까요?"),
                    ("英語の案内はありますか？", "에-고노 안나이와 아리마스카", "영어 안내 있나요?"),
                    ("このQRでいいですか？", "코노 큐아-루데 이-데스카", "이 QR로 되나요?"),
                    ("ネットが遅いです。", "넷또가 오소이데스", "인터넷이 느려요."),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 11) 쇼핑/백화점
    # ---------------------------
    "shopping": {
        "title": "쇼핑/백화점 필수 일본어 회화 문장 모음",
        "subs": {
            "clothes": {
                "title": "의류/사이즈",
                "items": [
                    ("これを試着してもいいですか？", "코레오 시챠쿠시테모 이-데스카", "이거 입어봐도 될까요?"),
                    ("もう少し大きいサイズはありますか？", "모-스코시 오-키이 사이즈와 아리마스카", "조금 더 큰 사이즈 있나요?"),
                    ("別の色はありますか？", "베츠노 이로와 아리마스카", "다른 색상 있나요?"),
                    ("おすすめは何ですか？", "오스스메와 난데스카", "추천은 뭐예요?"),
                    ("これください。", "코레 쿠다사이", "이거 주세요."),
                    ("プレゼント用に包んでください。", "푸레젠토요-니 츠츤데 쿠다사이", "선물용으로 포장해 주세요."),
                    ("値段はいくらですか？", "네단와 이쿠라데스카", "가격이 얼마예요?"),
                    ("割引はありますか？", "와리비키와 아리마스카", "할인 있나요?"),
                    ("返品できますか？", "헨핀 데키마스카", "반품 가능해요?"),
                    ("レシートをください。", "레시-토오 쿠다사이", "영수증 주세요."),
                    ("これをお願いします。", "코레오 오네가이시마스", "이거 부탁해요."),
                    ("カードでお願いします。", "카-도데 오네가이시마스", "카드로 부탁해요."),
                    ("現金で払います。", "겐킨데 하라이마스", "현금으로 낼게요."),
                    ("タッチ決済できますか？", "탓치 케-사이 데키마스카", "터치결제 되나요?"),
                    ("電子マネーは使えますか？", "덴시마네-와 츠카에마스카", "전자결제 되나요?"),
                    ("レシートください。", "레시-토 쿠다사이", "영수증 주세요."),
                    ("領収書をお願いします。", "료-슈-쇼오 오네가이시마스", "영수증(증빙) 부탁해요."),
                    ("袋はいりません。", "후쿠로와 이리마센", "봉투 필요 없어요."),
                    ("袋をください。", "후쿠로오 쿠다사이", "봉투 주세요."),
                    ("ポイントは使えますか？", "포인트와 츠카에마스카", "포인트 사용되나요?"),
                ],
            },
            "cosmetics": {
                "title": "화장품/기념품/면세",
                "items": [
                    ("これに合う色はどれですか？", "코레니 아우 이로와 도레데스카", "이거랑 어울리는 색은 뭐예요?"),
                    ("テスターはありますか？", "테스타-와 아리마스카", "테스터 있나요?"),
                    ("敏感肌でも使えますか？", "빈칸하다데모 츠카에마스카", "민감성 피부도 쓸 수 있나요?"),
                    ("おすすめのファンデーションは？", "오스스메노 판데-숀와", "추천 파운데이션은요?"),
                    ("免税できますか？", "멘세- 데키마스카", "면세 되나요?"),
                    ("パスポートを見せればいいですか？", "파스포-토오 미세레바 이-데스카", "여권 보여주면 되나요?"),
                    ("カードは使えますか？", "카-도와 츠카에마스카", "카드 되나요?"),
                    ("袋をください。", "후쿠로오 쿠다사이", "봉투 주세요."),
                    ("これを二つください。", "코레오 후타츠 쿠다사이", "이거 두 개 주세요."),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                    ("免税できますか？", "멘세- 데키마스카", "면세 되나요?"),
                    ("パスポートが必要ですか？", "파스포-토가 히츠요-데스카", "여권이 필요해요?"),
                    ("お土産を探しています。", "오미야게오 사가시테이마스", "기념품을 찾고 있어요."),
                    ("人気の商品はどれですか？", "닌키노 쇼-힌와 도레데스카", "인기 상품은 뭐예요?"),
                    ("これを二つください。", "코레오 후타츠 쿠다사이", "이거 두 개 주세요."),
                    ("プレゼント用に包んでください。", "푸레젠토요-니 츠츤데 쿠다사이", "선물 포장해 주세요."),
                    ("賞味期限はいつまでですか？", "쇼-미키겐와 이츠마데데스카", "유통기한은 언제까지예요?"),
                    ("持ち込み制限はありますか？", "모치코미세-겐와 아리마스카", "반입 제한 있나요?"),
                    ("カードで払えますか？", "카-도데 하라에마스카", "카드로 결제 가능해요?"),
                    ("レシートをください。", "레시-토오 쿠다사이", "영수증 주세요."),

                ],
            },
        },
    },

    # ---------------------------
    #  추가 12) 길찾기/관광안내
    # ---------------------------
    "directions": {
        "title": "길찾기/관광안내 필수 일본어 회화 문장 모음",
        "subs": {
            "ask": {
                "title": "길 묻기",
                "items": [
                    ("すみません、道を教えてください。", "스미마센 미치오 오시에테 쿠다사이", "실례합니다, 길 좀 알려주세요."),
                    ("ここはどこですか？", "코코와 도코데스카", "여기는 어디예요?"),
                    ("駅までどうやって行きますか？", "에키마데 도-얏테 이키마스카", "역까지 어떻게 가나요?"),
                    ("この場所に行きたいです。", "코노 바쇼니 이키타이데스", "이 장소에 가고 싶어요."),
                    ("地図で見せてもいいですか？", "치즈데 미세테모 이-데스카", "지도 보여드려도 될까요?"),
                    ("右に曲がりますか？", "미기니 마가리마스카", "오른쪽으로 꺾나요?"),
                    ("まっすぐですか？", "맛스구데스카", "쭉 가면 되나요?"),
                    ("どのくらいかかりますか？", "도노쿠라이 카카리마스카", "얼마나 걸려요?"),
                    ("徒歩で行けますか？", "토호데 이케마스카", "걸어서 갈 수 있나요?"),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
            "spot": {
                "title": "관광지/사진",
                "items": [
                    ("おすすめの観光地はありますか？", "오스스메노 칸코-치와 아리마스카", "추천 관광지 있나요?"),
                    ("ここは何ですか？", "코코와 난데스카", "여긴 뭐예요?"),
                    ("入場料はいくらですか？", "뉴-죠-료-와 이쿠라데스카", "입장료는 얼마예요?"),
                    ("何時まで開いていますか？", "난지마데 아이테이마스카", "몇 시까지 열어요?"),
                    ("チケットはどこで買えますか？", "치켓토와 도코데 카에마스카", "티켓은 어디서 살 수 있나요?"),
                    ("写真を撮ってもいいですか？", "샤신오 톳테모 이-데스카", "사진 찍어도 되나요?"),
                    ("写真を撮ってください。", "샤신오 톳테 쿠다사이", "사진 찍어주세요."),
                    ("ここでお願いします。", "코코데 오네가이시마스", "여기서 부탁해요."),
                    ("もう一枚いいですか？", "모-이치마이 이-데스카", "한 장 더 괜찮아요?"),
                    ("助かりました。", "타스카리마시타", "도움이 됐어요."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 13) 대중교통(버스/정류장)
    # ---------------------------
    "bus": {
        "title": "버스/정류장 필수 일본어 회화 문장 모음",
        "subs": {
            "ride": {
                "title": "탑승/요금",
                "items": [
                    ("このバスは新宿に行きますか？", "코노 바스와 신주쿠니 이키마스카", "이 버스 신주쿠 가나요?"),
                    ("次はどこですか？", "츠기와 도코데스카", "다음은 어디예요?"),
                    ("ここで降ります。", "코코데 오리마스", "여기서 내릴게요."),
                    ("いくらですか？", "이쿠라데스카", "얼마예요?"),
                    ("ICカードは使えますか？", "아이시-카-도와 츠카에마스카", "IC카드 사용 가능해요?"),
                    ("両替できますか？", "료-가에 데키마스카", "환전(잔돈 교환) 가능해요?"),
                    ("この停留所で合っていますか？", "코노 테-류-죠데 앗테이마스카", "이 정류장 맞나요?"),
                    ("次のバスは何時ですか？", "츠기노 바스와 난지데스카", "다음 버스는 몇 시예요?"),
                    ("どこで乗ればいいですか？", "도코데 노레바 이-데스카", "어디서 타면 되나요?"),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
            "trouble": {
                "title": "문제/분실",
                "items": [
                    ("道に迷いました。", "미치니 마요이마시타", "길을 잃었어요."),
                    ("行き先がわかりません。", "이키사키가 와카리마센", "목적지를 모르겠어요."),
                    ("乗り過ごしました。", "노리스고시마시타", "정류장을 지나쳤어요."),
                    ("次で降りたいです。", "츠기데 오리타이데스", "다음에 내리고 싶어요."),
                    ("落とし物をしました。", "오토시모노오 시마시타", "물건을 떨어뜨렸어요."),
                    ("このバス停はどこですか？", "코노 바스테-와 도코데스카", "이 버스 정류장은 어디예요?"),
                    ("終点はどこですか？", "슈-텐와 도코데스카", "종점은 어디예요?"),
                    ("運転手さん、すみません。", "운텐슈상 스미마센", "기사님, 실례합니다."),
                    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
                    ("お願いします。", "오네가이시마스", "부탁해요."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 14) 경찰/분실신고
    # ---------------------------
    "police": {
        "title": "경찰/분실신고 필수 일본어 회화 문장 모음",
        "subs": {
            "lost": {
                "title": "분실/도난",
                "items": [
                    ("財布をなくしました。", "사이후오 나쿠시마시타", "지갑을 잃어버렸어요."),
                    ("スマホをなくしました。", "스마호오 나쿠시마시타", "휴대폰을 잃어버렸어요."),
                    ("パスポートをなくしました。", "파스포-토오 나쿠시마시타", "여권을 잃어버렸어요."),
                    ("盗まれました。", "누스마레마시타", "도난당했어요."),
                    ("落とした場所はここです。", "오토시타 바쇼와 코코데스", "떨어뜨린 곳은 여기예요."),
                    ("いつなくしましたか？", "이츠 나쿠시마시타카", "언제 잃어버렸나요?"),
                    ("この書類が必要ですか？", "코노 쇼루이가 히츠요-데스카", "이 서류가 필요해요?"),
                    ("連絡先を書きます。", "렌라쿠사키오 카키마스", "연락처 적을게요."),
                    ("日本語が苦手です。", "니혼고가 니가테데스", "일본어가 서툴러요."),
                    ("通訳はいますか？", "츠-야쿠와 이마스카", "통역 있나요?"),
                ],
            },
            "help": {
                "title": "도움요청",
                "items": [
                    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
                    ("ここで待っていいですか？", "코코데 맛테 이-데스카", "여기서 기다려도 되나요?"),
                    ("ホテルまで案内してください。", "호테루마데 안나이시테 쿠다사이", "호텔까지 안내해 주세요."),
                    ("危ないです。", "아부나이데스", "위험해요."),
                    ("迷子になりました。", "마이고니 나리마시타", "길을 잃었어요(미아)."),
                    ("この場所は安全ですか？", "코노 바쇼와 안젠데스카", "이 곳은 안전해요?"),
                    ("救急車を呼んでください。", "큐-큐-샤오 욘데 쿠다사이", "구급차 불러주세요."),
                    ("近くの交番はどこですか？", "치카쿠노 코-반와 도코데스카", "가까운 파출소 어디예요?"),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                    ("お願いします。", "오네가이시마스", "부탁해요."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 15) 놀이공원/테마파크
    # ---------------------------
    "themepark": {
        "title": "놀이공원 필수 일본어 회화 문장 모음",
        "subs": {
            "entry": {
                "title": "입장/티켓",
                "items": [
                    ("チケットを二枚ください。", "치켓토오 니마이 쿠다사이", "티켓 두 장 주세요."),
                    ("子ども料金はいくらですか？", "코도모료-킨와 이쿠라데스카", "어린이 요금은 얼마예요?"),
                    ("入場は何時までですか？", "뉴-죠-와 난지마데데스카", "입장은 몇 시까지예요?"),
                    ("再入場できますか？", "사이뉴-죠- 데키마스카", "재입장 가능해요?"),
                    ("地図はありますか？", "치즈와 아리마스카", "지도 있나요?"),
                    ("ロッカーはどこですか？", "롯카-와 도코데스카", "락커는 어디예요?"),
                    ("写真を撮ってもいいですか？", "샤신오 톳테모 이-데스카", "사진 찍어도 되나요?"),
                    ("トイレはどこですか？", "토이레와 도코데스카", "화장실은 어디예요?"),
                    ("案内してください。", "안나이시테 쿠다사이", "안내해 주세요."),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
            "ride": {
                "title": "어트랙션",
                "items": [
                    ("この乗り物は怖いですか？", "코노 노리모노와 코와이데스카", "이 놀이기구 무서워요?"),
                    ("待ち時間はどのくらいですか？", "마치지칸와 도노쿠라이데스카", "대기시간은 얼마나예요?"),
                    ("身長制限はありますか？", "신초-세-겐와 아리마스카", "키 제한 있나요?"),
                    ("次の回は何時ですか？", "츠기노 카이와 난지데스카", "다음 회차는 몇 시예요?"),
                    ("ここに並べばいいですか？", "코코니 나라베바 이-데스카", "여기 줄 서면 되나요?"),
                    ("優先レーンはありますか？", "유-센 레-은와 아리마스카", "우선 라인 있나요?"),
                    ("酔いやすいです。", "요이야스이데스", "멀미가 잘 나요."),
                    ("写真は買えますか？", "샤신와 카에마스카", "사진 살 수 있나요?"),
                    ("出口はどこですか？", "데구치와 도코데스카", "출구는 어디예요?"),
                    ("楽しかったです。", "타노시캇타데스", "재밌었어요."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 16) 영화관
    # ---------------------------
    "cinema": {
        "title": "영화관 필수 일본어 회화 문장 모음",
        "subs": {
            "ticket": {
                "title": "예매/좌석",
                "items": [
                    ("チケットを買いたいです。", "치켓토오 카이타이데스", "티켓을 사고 싶어요."),
                    ("二枚お願いします。", "니마이 오네가이시마스", "두 장 부탁해요."),
                    ("次の回は何時ですか？", "츠기노 카이와 난지데스카", "다음 회차는 몇 시예요?"),
                    ("この映画は何分ですか？", "코노 에-가와 난푼데스카", "이 영화는 몇 분이에요?"),
                    ("席はどこがいいですか？", "세키와 도코가 이-데스카", "자리 어디가 좋아요?"),
                    ("真ん中がいいです。", "만나카가 이-데스", "가운데가 좋아요."),
                    ("字幕はありますか？", "지마쿠와 아리마스카", "자막 있나요?"),
                    ("日本語が少しだけです。", "니혼고가 스코시다케데스", "일본어는 조금만 해요."),
                    ("ポップコーンください。", "폿푸코-은 쿠다사이", "팝콘 주세요."),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
            "inside": {
                "title": "상영관",
                "items": [
                    ("席はどこですか？", "세키와 도코데스카", "좌석은 어디예요?"),
                    ("このチケットで合っていますか？", "코노 치켓토데 앗테이마스카", "이 티켓 맞나요?"),
                    ("トイレはどこですか？", "토이레와 도코데스카", "화장실은 어디예요?"),
                    ("音が大きいです。", "오토가 오-키이데스", "소리가 커요."),
                    ("少し静かにしてください。", "스코시 시즈카니 시테 쿠다사이", "조금 조용히 해주세요."),
                    ("携帯電話は切ります。", "케-타이덴와오 키리마스", "휴대폰 끌게요."),
                    ("出口はどこですか？", "데구치와 도코데스카", "출구는 어디예요?"),
                    ("落とし物をしました。", "오토시모노오 시마시타", "물건을 잃어버렸어요."),
                    ("スタッフを呼んでください。", "스탓후오 욘데 쿠다사이", "직원을 불러주세요."),
                    ("すみません。", "스미마센", "죄송합니다."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 17) 코인락커/보관
    # ---------------------------
    "locker": {
        "title": "보관/코인락커 필수 일본어 회화 문장 모음",
        "subs": {
            "use": {
                "title": "사용/결제",
                "items": [
                    ("コインロッカーはどこですか？", "코인롯카-와 도코데스카", "코인락커는 어디예요?"),
                    ("空いていますか？", "아이테이마스카", "비어 있나요?"),
                    ("大きいサイズはありますか？", "오-키이 사이즈와 아리마스카", "큰 사이즈 있나요?"),
                    ("いくらですか？", "이쿠라데스카", "얼마예요?"),
                    ("使い方を教えてください。", "츠카이카타오 오시에테 쿠다사이", "사용법 알려주세요."),
                    ("硬貨が必要ですか？", "코-카가 히츠요-데스카", "동전이 필요해요?"),
                    ("両替できますか？", "료-가에 데키마스카", "환전 가능해요?"),
                    ("鍵が開きません。", "카기가 아키마센", "열쇠가 안 열려요."),
                    ("暗証番号を忘れました。", "안쇼-방고-오 와스레마시타", "비밀번호를 잊었어요."),
                    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
                ],
            },
            "pickup": {
                "title": "찾기/문제",
                "items": [
                    ("荷物を取りたいです。", "니모츠오 토리타이데스", "짐을 찾고 싶어요."),
                    ("このロッカーです。", "코노 롯카-데스", "이 락커예요."),
                    ("開けられません。", "아케라레마센", "열 수가 없어요."),
                    ("故障しています。", "코쇼-시테이마스", "고장났어요."),
                    ("スタッフはいますか？", "스탓후와 이마스카", "직원 있나요?"),
                    ("レシートはありますか？", "레시-토와 아리마스카", "영수증 있나요?"),
                    ("領収書をください。", "료-슈-쇼오 쿠다사이", "영수증 주세요."),
                    ("別のロッカーに移したいです。", "베츠노 롯카-니 우츠시타이데스", "다른 락커로 옮기고 싶어요."),
                    ("時間がありません。", "지칸가 아리마센", "시간이 없어요."),
                    ("お願いします。", "오네가이시마스", "부탁해요."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 18) 세탁소/코인세탁
    # ---------------------------
    "laundry": {
        "title": "세탁/코인세탁 필수 일본어 회화 문장 모음",
        "subs": {
            "wash": {
                "title": "세탁/건조",
                "items": [
                    ("コインランドリーはどこですか？", "코인란도리-와 도코데스카", "코인세탁소는 어디예요?"),
                    ("使い方を教えてください。", "츠카이카타오 오시에테 쿠다사이", "사용법 알려주세요."),
                    ("洗剤はありますか？", "센자이와 아리마스카", "세제 있나요?"),
                    ("乾燥機はありますか？", "칸소-키와 아리마스카", "건조기 있나요?"),
                    ("何分かかりますか？", "난푼 카카리마스카", "몇 분 걸려요?"),
                    ("いくらですか？", "이쿠라데스카", "얼마예요?"),
                    ("お金を入れました。", "오카네오 이레마시타", "돈 넣었어요."),
                    ("動きません。", "우고키마센", "작동 안 해요."),
                    ("止まりました。", "토마리마시타", "멈췄어요."),
                    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
                ],
            },
            "pickup": {
                "title": "찾기/분실",
                "items": [
                    ("洗濯物を忘れました。", "센타쿠모노오 와스레마시타", "세탁물을 두고 왔어요."),
                    ("これ、私のですか？", "코레 와타시노데스카", "이거 제 거예요?"),
                    ("他の人の服があります。", "호카노 히토노 후쿠가 아리마스", "다른 사람 옷이 있어요."),
                    ("取り違えました。", "토리치가에마시타", "잘못 가져갔어요."),
                    ("ここに置きました。", "코코니 오키마시타", "여기에 두었어요."),
                    ("袋はありますか？", "후쿠로와 아리마스카", "봉투 있나요?"),
                    ("連絡先はどこですか？", "렌라쿠사키와 도코데스카", "연락처는 어디예요?"),
                    ("すみません。", "스미마센", "죄송합니다."),
                    ("お願いします。", "오네가이시마스", "부탁해요."),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 19) 바/이자카야
    # ---------------------------
    "izakaya": {
        "title": "술집/이자카야 필수 일본어 회화 문장 모음",
        "subs": {
            "order": {
                "title": "주문/추천",
                "items": [
                    ("二人です。", "후타리데스", "두 명이에요."),
                    ("予約しています。", "요야쿠시테이마스", "예약했어요."),
                    ("おすすめは何ですか？", "오스스메와 난데스카", "추천은 뭐예요?"),
                    ("生ビールをください。", "나마비-루오 쿠다사이", "생맥주 주세요."),
                    ("これは何ですか？", "코레와 난데스카", "이건 뭐예요?"),
                    ("辛いですか？", "카라이데스카", "매워요?"),
                    ("アレルギーがあります。", "아레루기-가 아리마스", "알레르기가 있어요."),
                    ("お水をください。", "오미즈오 쿠다사이", "물 주세요."),
                    ("もう一杯ください。", "모-잇파이 쿠다사이", "한 잔 더 주세요."),
                    ("とてもおいしいです。", "토테모 오이시-데스", "정말 맛있어요."),
                ],
            },
            "pay": {
                "title": "계산/정리",
                "items": [
                    ("お会計お願いします。", "오카이케- 오네가이시마스", "계산 부탁해요."),
                    ("別々にお願いします。", "베츠베츠니 오네가이시마스", "각자 계산 부탁해요."),
                    ("カードは使えますか？", "카-도와 츠카에마스카", "카드 되나요?"),
                    ("現金で払います。", "겐킨데 하라이마스", "현금으로 낼게요."),
                    ("領収書をください。", "료-슈-쇼오 쿠다사이", "영수증 주세요."),
                    ("忘れ物はないですか？", "와스레모노와 나이데스카", "두고 간 거 없나요?"),
                    ("トイレはどこですか？", "토이레와 도코데스카", "화장실은 어디예요?"),
                    ("ありがとうございました。", "아리가토- 고자이마시타", "감사했습니다."),
                    ("また来ます。", "마타 키마스", "또 올게요."),
                    ("すみません。", "스미마센", "실례합니다."),
                ],
            },
        },
    },

    # ---------------------------
    #  추가 20) 숙소 체크아웃/이동
    # ---------------------------
    "checkout": {
        "title": "체크아웃/이동 필수 일본어 회화 문장 모음",
        "subs": {
            "leave": {
                "title": "체크아웃",
                "items": [
                    ("チェックアウトお願いします。", "체쿠아우토 오네가이시마스", "체크아웃 부탁해요."),
                    ("鍵を返します。", "카기오 카에시마스", "열쇠 반납할게요."),
                    ("追加料金はありますか？", "츠이카료-킨와 아리마스카", "추가 요금 있나요?"),
                    ("領収書をください。", "료-슈-쇼오 쿠다사이", "영수증 주세요."),
                    ("荷物を預けたいです。", "니모츠오 아즈케타이데스", "짐 맡기고 싶어요."),
                    ("タクシーを呼んでください。", "타쿠시-오 욘데 쿠다사이", "택시 불러주세요."),
                    ("駅までどのくらいですか？", "에키마데 도노쿠라이데스카", "역까지 얼마나 걸려요?"),
                    ("空港まで行きたいです。", "쿠-코-마데 이키타이데스", "공항까지 가고 싶어요."),
                    ("また来ます。", "마타 키마스", "또 올게요."),
                    ("ありがとうございました。", "아리가토- 고자이마시타", "감사했습니다."),
                    ("予約しています。", "요야쿠시테이마스", "예약했어요."),
                    ("チェックイン方法を教えてください。", "체쿠인 호-호-오 오시에테 쿠다사이", "체크인 방법 알려주세요."),
                    ("暗証番号はどこですか？", "안쇼-방고-와 도코데스카", "비밀번호는 어디에 있어요?"),
                    ("鍵が見つかりません。", "카기가 미츠카리마센", "열쇠를 못 찾겠어요."),
                    ("ドアが開きません。", "도아가 아키마센", "문이 안 열려요."),
                    ("到着しました。", "토-챠쿠시마시타", "도착했어요."),
                    ("少し遅れます。", "스코시 오쿠레마스", "조금 늦어요."),
                    ("Wi-Fiのパスワードは？", "와이화이노 파스와-도와", "와이파이 비밀번호는요?"),
                    ("タオルはどこですか？", "타오루와 도코데스카", "수건은 어디예요?"),
                    ("連絡できますか？", "렌라쿠데키마스카", "연락할 수 있을까요?"),

                ],
            },
            "luggage": {
                "title": "짐/배송",
                "items": [
                    ("荷物を送れますか？", "니모츠오 오쿠레마스카", "짐을 보낼 수 있나요?"),
                    ("この住所に送ってください。", "코노 쥬-쇼니 오쿠떼 쿠다사이", "이 주소로 보내주세요."),
                    ("いつ届きますか？", "이츠 토도키마스카", "언제 도착해요?"),
                    ("時間指定できますか？", "지칸시테- 데키마스카", "시간 지정 가능해요?"),
                    ("壊れ物です。", "코와레모노데스", "깨지기 쉬운 물건이에요."),
                    ("伝票はありますか？", "덴표-와 아리마스카", "운송장 있나요?"),
                    ("ここに書けばいいですか？", "코코니 카케바 이-데스카", "여기에 쓰면 되나요?"),
                    ("料金はいくらですか？", "료-킨와 이쿠라데스카", "요금은 얼마예요?"),
                    ("クレジットカードで払えますか？", "쿠레짓토카-도데 하라에마스카", "카드로 결제 가능해요?"),
                    ("お願いします。", "오네가이시마스", "부탁해요."),
                ],
            },
        },
    },
    "travel_type": {
        "title": "여행 유형별 회화 필수 일본어 회화 문장 모음",
        "subs": {
            "solo": {
                "title": "혼자 여행중일때",
                "items": [
                    ("写真を撮ってもらえますか？", "샤신오 톳테 모라에마스카", "사진 좀 찍어주실 수 있나요?"),
                    ("一人です。", "히토리데스", "혼자예요."),
                    ("ここに座ってもいいですか？", "코코니 스왓테모 이이데스카", "여기 앉아도 될까요?"),
                    ("おすすめは何ですか？", "오스스메와 난데스카", "추천 메뉴가 뭐예요?"),
                    ("一人でも大丈夫ですか？", "히토리데모 다이죠부데스카", "혼자라도 괜찮을까요?"),
                    ("カウンター席はありますか？", "카운타-세키와 아리마스카", "카운터 자리가 있나요?"),
                    ("もう一枚写真をお願いできますか？", "모- 이치마이 샤신오 오네가이데키마스카", "사진 한 장만 더 부탁해도 될까요?"),
                    ("静かな席はありますか？", "시즈카나 세키와 아리마스카", "조용한 자리가 있나요?"),
                    ("一人でも利用できますか？", "히토리데모 리요-데키마스카", "혼자서도 이용할 수 있나요?"),
                    ("一人で来ても大丈夫な場所ですか？", "히토리데 키테모 다이죠부나 바쇼데스카", "혼자 와도 괜찮은 곳인가요?")
                ],
            },

            "with_child": {
                "title": "아이와 여행중일때",
                "items": [
                    ("子供用のメニューはありますか？", "코도모요-노 메뉴-와 아리마스카", "아이용 메뉴가 있나요?"),
                    ("ベビーカーを使ってもいいですか？", "베비-카-오 츠캇테모 이이데스카", "유모차 사용해도 괜찮을까요?"),
                    ("子供が具合悪いです。", "코도모가 구아이 와루이데스", "아이가 아파요."),
                    ("子供用の椅子はありますか？", "코도모요-노 이스와 아리마스카", "아이 의자가 있나요?"),
                    ("子供と一緒に座ってもいいですか？", "코도모토 잇쇼니 스왓테모 이이데스카", "아이와 같이 앉아도 될까요?"),
                    ("子供が食べても大丈夫ですか？", "코도모가 타베테모 다이죠부데스카", "아이에게 먹여도 괜찮을까요?"),
                    ("おむつを替えられる場所はありますか？", "오무츠오 카에라레루 바쇼와 아리마스카", "기저귀 갈 수 있는 곳이 있나요?"),
                    ("子供と一緒に入ってもいいですか？", "코도모토 잇쇼니 하잇테모 이이데스카", "아이와 함께 들어가도 될까요?"),
                    ("子供の病院を探しています。", "코도모노 뵤-인오 사가시테이마스", "아이 병원을 찾고 있어요."),
                    ("子供のことで少し遅れそうです。", "코도모노 코토데 스코시 오쿠레소-데스", "아이 때문에 조금 늦을 것 같아요.")
                ],
            },
        },
    },
    "path_time": {
        "title": "길찾기/소요시간 필수 일본어 회화 문장 모음",
        "subs": {
            "direction": {
                "title": "길 물어보기",
                "items": [
                    ("ここから駅までどれくらいですか？", "코코카라 에키마데 도레쿠라이데스카", "여기서 역까지 얼마나 걸려요?"),
                    ("歩いて行けますか？", "아루이테 이케마스카", "걸어서 갈 수 있나요?"),
                    ("一番近い駅はどこですか？", "이치방 치카이 에키와 도코데스카", "가장 가까운 역이 어디예요?"),
                    ("この道で合っていますか？", "코노 미치데 앗테이마스카", "이 길이 맞나요?"),
                    ("反対方向ですか？", "한타이호-코-데스카", "반대 방향인가요?"),
                    ("地図で見せてください。", "치즈데 미세테 쿠다사이", "지도에서 보여주세요."),
                    ("右に曲がりますか？", "미기니 마가리마스카", "오른쪽으로 꺾나요?"),
                    ("信号を渡りますか？", "신고-오 와타리마스카", "신호등을 건너나요?"),
                    ("ここから遠いですか？", "코코카라 토오이데스카", "여기서 멀어요?"),
                    ("まっすぐ行けばいいですか？", "맛스구 이케바 이이데스카", "곧장 가면 되나요?"),
                    ("〇〇駅はどこですか？", "○○에키와 도코데스카", "○○역은 어디예요?"),
                    ("〇〇線はどこですか？", "○○센와 도코데스카", "○○선은 어디예요?"),
                    ("出口は何番ですか？", "데구치와 난반데스카", "출구는 몇 번인가요?"),
                    ("A出口はどちらですか？", "에-데구치와 도치라데스카", "A출구는 어느 쪽이에요?"),
                    ("ホームはどこですか？", "호-무와 도코데스카", "플랫폼은 어디예요?"),
                    ("この電車は〇〇に行きますか？", "코노 덴샤와 ○○니 이키마스카", "이 전철 ○○ 가나요?"),
                    ("反対方向ですか？", "한타이호-코-데스카", "반대 방향인가요?"),
                    ("一番近い出口はどこですか？", "이치방 치카이 데구치와 도코데스카", "가장 가까운 출구는 어디예요?"),
                    ("階段はどこですか？", "카이단와 도코데스카", "계단은 어디예요?"),
                    ("エレベーターはありますか？", "에레베-타-와 아리마스카", "엘리베이터 있나요?"),
                    ("ここから近いですか？", "코코카라 치카이데스카", "여기서 가까워요?"),
                    ("歩いて行けますか？", "아루이테 이케마스카", "걸어서 갈 수 있나요?"),
                    ("何分ぐらいですか？", "난푼구라이데스카", "몇 분 정도예요?"),
                    ("この道で合っていますか？", "코노 미치데 앗테이마스카", "이 길 맞나요?"),
                    ("この交差点を渡りますか？", "코노 코-사텐오 와타리마스카", "이 교차로를 건너나요?"),
                    ("右に曲がればいいですか？", "미기니 마가레바 이이데스카", "오른쪽으로 꺾으면 되나요?"),
                    ("左ですか？", "히다리데스카", "왼쪽인가요?"),
                    ("真っ直ぐですか？", "맛스구데스카", "쭉 가면 되나요?"),
                    ("次の信号ですか？", "츠기노 신고-데스카", "다음 신호등인가요?"),
                    ("地図で見せます。", "치즈데 미세마스", "지도 보여드릴게요."),
                ],
            },
        },
    },
    "luggage": {
        "title": "짐/보관/배송",
        "subs": {
            "storage": {
                "title": "짐 맡기기",
                "items": [
                    ("荷物を預けられますか？", "니모츠오 아즈케라레마스카", "짐 맡길 수 있나요?"),
                    ("何時まで預かってもらえますか？", "난지마데 아즈캇테 모라에마스카", "몇 시까지 맡아주나요?"),
                    ("この荷物はここに置いていいですか？", "코노 니모츠와 코코니 오이테 이이데스카", "이 짐 여기 둬도 되나요?"),
                    ("ロッカーはありますか？", "록카-와 아리마스카", "락커 있나요?"),
                    ("荷物を取りに戻ります。", "니모츠오 토리니 모도리마스", "짐 찾으러 올게요."),
                    ("配送できますか？", "하이소-데키마스카", "배송 가능해요?"),
                    ("ホテルまで送ってください。", "호테루마데 옷테 쿠다사이", "호텔로 보내주세요."),
                    ("壊れていませんか？", "코와레테이마센카", "깨지지 않았나요?"),
                    ("荷物が見つかりません。", "니모츠가 미츠카리마센", "짐이 안 보여요."),
                    ("タグはありますか？", "타구와 아리마스카", "태그 있나요?")
                ],
            },
        },
    },
    "reservation_change": {
        "title": "예약변경/취소 필수 일본어 회화 문장 모음",
        "subs": {
            "modify": {
                "title": "예약 수정",
                "items": [
                    ("予約を変更したいです。", "요야쿠오 헨코-시타이데스", "예약 변경하고 싶어요."),
                    ("時間を早められますか？", "지칸오 하야메라레마스카", "시간 앞당길 수 있나요?"),
                    ("遅れても大丈夫ですか？", "오쿠레테모 다이죠부데스카", "늦어도 괜찮나요?"),
                    ("人数を増やせますか？", "닌즈오 후야세마스카", "인원 늘릴 수 있나요?"),
                    ("キャンセルできますか？", "캰세루 데키마스카", "취소 가능해요?"),
                    ("手数料はかかりますか？", "테스료-와 카카리마스카", "수수료 있나요?"),
                    ("今日に変更できますか？", "쿄-니 헨코-데키마스카", "오늘로 변경 가능해요?"),
                    ("別の日でもいいですか？", "베츠노 히데모 이이데스카", "다른 날도 괜찮나요?"),
                    ("予約を確認したいです。", "요야쿠오 카쿠닌시타이데스", "예약 확인하고 싶어요."),
                    ("名前で予約しています。", "나마에데 요야쿠시테이마스", "이름으로 예약했어요.")
                ],
            },
        },
    },
    "food_request": {
        "title": "음식 요청/제한 필수 일본어 회화 문장 모음",
        "subs": {
            "allergy": {
                "title": "알레르기/요청",
                "items": [
                    ("アレルギーがあります。", "아레루기-가 아리마스", "알레르기가 있어요."),
                    ("辛くしないでください。", "카라쿠 시나이데 쿠다사이", "맵지 않게 해주세요."),
                    ("豚肉抜きでお願いします。", "부타니쿠 누키데 오네가이시마스", "돼지고기 빼주세요."),
                    ("ナッツは入っていますか？", "낫츠와 하잇테이마스카", "견과류 들어있나요?"),
                    ("ベジタリアンです。", "베지타리안데스", "채식주의자예요."),
                    ("砂糖少なめでお願いします。", "사토 스쿠나메데 오네가이시마스", "설탕 적게 부탁해요."),
                    ("塩控えめでお願いします。", "시오 히카에메데 오네가이시마스", "짠맛 줄여주세요."),
                    ("乳製品は大丈夫ですか？", "뉴-세힌와 다이죠부데스카", "유제품 괜찮나요?"),
                    ("生ものは食べられません。", "나마모노와 타베라레마센", "날것은 못 먹어요."),
                    ("別の料理にできますか？", "베츠노 료-리니 데키마스카", "다른 요리로 바꿀 수 있나요?")
                ],
            },
        },
    },
    "complaint": {
        "title": "문제/클레임 필수 일본어 회화 문장 모음",
        "subs": {
            "problem": {
                "title": "문제 발생",
                "items": [
                    ("動きません。", "우고키마센", "작동 안 돼요."),
                    ("壊れています。", "코와레테이마스", "고장났어요."),
                    ("注文と違います。", "츄-몬토 치가이마스", "주문이랑 달라요."),
                    ("お金が二重に引かれました。", "오카네가 니주-니 히카레마시타", "결제가 두 번 됐어요."),
                    ("間違っています。", "마치가엣테이마스", "잘못됐어요."),
                    ("交換できますか？", "코-칸 데키마스카", "교환 가능해요?"),
                    ("返金できますか？", "헨킨 데키마스카", "환불 가능해요?"),
                    ("確認してください。", "카쿠닌 시테 쿠다사이", "확인해주세요."),
                    ("説明してください。", "세츠메- 시테 쿠다사이", "설명해주세요."),
                    ("対応お願いします。", "타이오- 오네가이시마스", "조치 부탁해요.")
                ],
            },
        },
    },
    "photo_plus": {
        "title": "사진 요청 심화 필수 일본어 회화 문장 모음",
        "subs": {
            "request": {
                "title": "사진 부탁",
                "items": [
                    ("ここを背景にお願いします。", "코코오 하이케-니 오네가이시마스", "여기를 배경으로 부탁해요."),
                    ("縦で撮ってください。", "타테데 톳테 쿠다사이", "세로로 찍어주세요."),
                    ("もう一枚お願いします。", "모- 이치마이 오네가이시마스", "한 장 더 부탁해요."),
                    ("動画も撮れますか？", "도-가모 토레마스카", "영상도 찍어주실 수 있나요?"),
                    ("セルカも撮ってもいいですか？", "세루카모 톳테모 이이데스카", "셀카도 찍어도 될까요?"),
                    ("ズームしてください。", "즈-무 시테 쿠다사이", "확대해주세요."),
                    ("全身が入るようにお願いします。", "젠신가 하이루요-니 오네가이시마스", "전신 나오게 부탁해요."),
                    ("明るく撮ってください。", "아카루쿠 톳테 쿠다사이", "밝게 찍어주세요."),
                    ("横でお願いします。", "요코데 오네가이시마스", "가로로 부탁해요."),
                    ("ありがとう！", "아리가토-", "고마워요!")
                ],
            },
        },
    },
    "local_recommend": {
        "title": "현지 추천 필수 일본어 회화 문장 모음",
        "subs": {
            "tips": {
                "title": "추천 받기",
                "items": [
                    ("地元の人が行く店はどこですか？", "지모토노 히토가 이쿠 미세와 도코데스카", "현지 사람들이 가는 곳 어디예요?"),
                    ("観光客が少ない場所はありますか？", "칸코-캬쿠가 스쿠나이 바쇼와 아리마스카", "관광객 적은 곳 있나요?"),
                    ("安くておいしい店は？", "야스쿠테 오이시 미세와", "싸고 맛있는 곳은?"),
                    ("今人気のメニューは？", "이마 닌키노 메뉴-와", "요즘 인기 메뉴는?"),
                    ("おすすめスポットは？", "오스스메 스폿토와", "추천 장소는?"),
                    ("穴場はありますか？", "아나바와 아리마스카", "숨은 명소 있나요?"),
                    ("初めてならどこがいいですか？", "하지메테나라 도코가 이이데스카", "처음이면 어디가 좋아요?"),
                    ("夜に行くならどこですか？", "요루니 이쿠나라 도코데스카", "밤에 갈 곳은 어디예요?"),
                    ("家族向けはありますか？", "카조쿠무케와 아리마스카", "가족용 추천 있나요?"),
                    ("写真がきれいな場所は？", "샤신가 키레이나 바쇼와", "사진 예쁜 곳은?")
                ],
            },
        },
    },
    "weather_response": {
        "title": "날씨 대응 필수 일본어 회화 문장 모음",
        "subs": {
            "forecast": {
                "title": "날씨 대처",
                "items": [
                    ("今日は雨が降りますか？", "쿄-와 아메가 후리마스카", "오늘 비 와요?"),
                    ("傘が必要ですか？", "카사가 히츠요-데스카", "우산 필요해요?"),
                    ("寒くなりますか？", "사무쿠 나리마스카", "추워질까요?"),
                    ("暑くなりますか？", "아츠쿠 나리마스카", "더워질까요?"),
                    ("雪は降りますか？", "유키와 후리마스카", "눈 와요?"),
                    ("天気はどうですか？", "텐키와 도-데스카", "날씨 어때요?"),
                    ("風が強いですか？", "카제가 츠요이데스카", "바람 세요?"),
                    ("晴れそうですか？", "하레소-데스카", "맑아질까요?"),
                    ("寒いので上着が必要です。", "사무이노데 우와기 가 히츠요-데스", "추워서 겉옷 필요해요."),
                    ("天気予報を見ました。", "텐키요호-오 미마시타", "일기예보 봤어요.")
                ],
            },
        },
    },
        # (특별) 애니 명대사
    "anime_quotes": {
        "title": "애니 명대사",
        "subs": {
            "quotes": {  # ✅ 소분류 key (아무거나 가능)
                "title": "명대사 모음",
                "items": [
                    # 1) 진격의 거인
                    ("この世界から、一匹残らず…全部駆逐してやる！", "코노 세카이카라, 잇피키 노코라즈... 젠부 쿠치쿠시테 야루!", "이 세상에서 한 마리도 남기지 않고 전부 구축해주마!", "진격의 거인 명대사"),

                    # 2) 강철의 연금술사
                    ("前に進め。お前には立派な足がついてるだろ。", "마에니 스스메. 오마에니와 릿파나 아시가 츠이테루다로.", "앞으로 나아가. 너한텐 훌륭한 다리가 붙어있잖아.", "강철의 연금술사 명대사"),

                    # 3) 주술회전
                    ("大丈夫。俺、最強だから。", "다이죠부. 오레, 사이쿄-다카라.", "걱정 마. 난 최강이니까.", "주술회전 명대사"),

                    # 4) 슬램덩크
                    ("あきらめたらそこで試合終了だよ。", "아키라메타라 소코데 시아이 슈-료-다요.", "포기하는 순간 시합은 끝이다.", "슬램덩크 명대사"),

                    # 5) 하이큐
                    ("才能は咲かせるもの。センスは磨くもの！", "사이노-와 사카세루모노. 센스와 미가쿠모노!", "재능은 꽃 피우는 것, 센스는 갈고닦는 것!", "하이큐 명대사"),

                    # 6) 원피스
                    ("愛してくれてありがとう。", "아이시테쿠레테 아리가토-.", "사랑해줘서 고마워.", "원피스 명대사"),

                    # 7) Re:제로부터 시작하는 이세계 생활
                    ("ここから始めよう。1から…いや、0から！", "코코카라 하지메요-. 이치카라... 이야, 제로카라!", "여기서부터 시작하죠. 하나부터... 아니 제로부터!", "Re:제로부터 시작하는 이세계 생활 명대사"),

                    # 8) 귀멸의 칼날
                    ("弱い者を助けるのが強い者の務めだ！", "요와이모노오 타스케루노가 츠요이모노노 츠토메다!", "약한 사람을 돕는 것이 강한 자의 의무다!", "귀멸의 칼날 명대사"),

                    # 9) 클라나드
                    ("一番大切なものほど、気づくのはいつも遅い。", "이치반 타이세츠나 모노호도, 키즈쿠노와 이츠모 오소이.", "가장 소중한 것은 언제나 너무 늦게 깨닫게 된다.", "클라나드 명대사"),

                    # 10) 나루토
                    ("自分を信じない奴なんか、努力する価値もない。", "지분오 신지나이 야츠난카, 도료쿠스루 카치모 나이.", "자신을 믿지 않는 녀석따위는 노력할 가치도 없다.", "나루토 명대사"),

                    # 11) 코드 기아스
                    ("撃っていいのは、撃たれる覚悟のある奴だけだ。", "웃테 이이노와, 우타레루 카쿠고노 아루 야츠다케다.", "총을 쏴도 되는 건, 총에 맞을 각오가 되어 있는 자뿐이다.", "코드 기아스 명대사"),

                    # 12) 은혼
                    ("俺の剣が届く範囲が、俺の国だ。", "오레노 켄가 토도쿠 한이-가, 오레노 쿠니다.", "나의 검이 닿는 범위가 내 나라다.", "은혼 명대사"),

                    # 13) 짱구는 못말려(극장판)
                    ("夢は逃げない。逃げるのはいつも自分だ。", "유메와 니게나이. 니게루노와 이츠모 지분다.", "꿈은 도망가지 않아. 도망가는 건 언제나 자신이다.", "짱구는 못말려(극장판) 명대사"),

                    # 14) 블리치
                    ("あまり強い言葉を使うなよ。弱く見えるぞ。", "아마리 츠요이 코토바오 츠카우나요. 요와쿠 미에루조.", "너무 강한 말은 하지 마. 약해 보이거든.", "블리치 명대사"),

                    # 15) 노게임 노라이프
                    ("何も持たずに生まれた。だから何にだってなれる。", "나니모 모타즈니 우마레타. 다카라 나니니닷테 나레루.", "아무것도 갖고 태어나지 않았기에 무엇이든 될 수 있다.", "노게임 노라이프 명대사"),

                    # 16) 암살교실
                    ("澄んだ水でも泥水でも、前へ泳ぐ魚は美しく育つ。", "슨다 미즈데모 도로미즈데모, 마에에 오요구 사카나와 우츠쿠시쿠 소다츠.", "맑은물에서 살든 시궁창에서 살든 앞으로 헤엄치는 물고기는 아름답게 자란다.", "암살교실 명대사"),

                    # 17) 너의 이름은
                    ("君が誰でも、俺は君を探す。", "키미가 다레데모, 오레와 키미오 사가스.", "네가 누구든 나는 널 찾을 거야.", "너의 이름은 명대사"),

                    # 18) 소드아트온라인
                    ("ゲームでも、ここは俺たちの世界だ。", "게-무데모, 코코와 오레타치노 세카이다.", "게임이어도 여긴 우리의 세계야.", "소드아트온라인 명대사"),

                    # 19) 공의 경계
                    ("生きることは、死なないこととは違う。", "이키루 코토와, 신나이 코토토와 치가우.", "살아간다는 건 죽지 않는 것과는 달라.", "공의 경계 명대사"),

                    # 20) 카우보이 비밥
                    ("死にに行くんじゃない。本当に生きてるか確かめに行くんだ。", "시니니 이쿤쟈나이. 혼토-니 이키테루카 타시카메니 이쿤다.", "죽으러 가는 게 아니야. 내가 정말 살아있는지 확인하러 가는 거야.", "카우보이 비밥 명대사"),

                    # 21) 강철의 연금술사
                    ("痛みを伴わない教訓には意味がない。", "이타미오 토모나와나이 쿄-쿤니와 이미가 나이.", "아픔을 동반하지 않는 교훈은 의미가 없다.", "강철의 연금술사 명대사"),

                    # 22) 어떤 과학의 초전자포
                    ("失敗を誰かのせいにするのか、それとも…もう一度手を差し伸べるのか。", "싯파이오 다레카노 세이니 스루노카, 소레토모... 모-이치도 테오 사시노베루노카.", "한번 실패했다고 남에게 떠넘길 건지, 실패했어도 다시 손을 내밀 건지.", "어떤 과학의 초전자포 명대사"),

                    # 23) 진격의 거인
                    ("俺は自由を求める！", "오레와 지유-오 모토메루!", "난 자유를 원해!", "진격의 거인 명대사"),

                    # 24) 진격의 거인
                    ("世界は残酷だ。それでも、美しい。", "세카이와 잔코쿠다. 소레데모, 우츠쿠시이.", "세상은 잔혹하지만 그래도 아름다워.", "진격의 거인 명대사"),

                    # 25) 바람의 검심
                    ("この世に無駄な人間なんていない。", "코노 요니 무다나 닌겐난테 이나이.", "이 세상에 불필요한 사람은 없어.", "바람의 검심 명대사"),

                    # 26) 원피스
                    ("最高の瞬間は、まだ来てない！", "사이코-노 슌칸와, 마다 키테나이!", "최고의 순간은 아직 오지 않았어!", "원피스 명대사"),

                    # 27) 하이큐
                    ("バレーは！いつだって上を向くスポーツだ！", "바레-와! 이츠닷테 우에오 무쿠 스포-츠다!", "배구는! 언제나 위를 보는 스포츠다!", "하이큐 명대사"),

                    # 28) 암살교실
                    ("誰にでも平等に与えられ、いつか平等に失う才能がある。それは若さだ。", "다레니데모 뵤-도-니 아타에라레, 이츠카 뵤-도-니 우시나우 사이노-가 아루. 소레와 와카사다.", "누구에게나 평등하게 주어지고 언젠가 평등하게 잃는 재능이 있어요. 그건 젊음입니다.", "암살교실 명대사"),

                    # 29) 짱구는 못말려
                    ("生きてりゃいいこともあるし、悲しいこともある。それが人生だ。", "이키테랴 이이 코토모 아루시, 카나시이 코토모 아루. 소레가 진세이다.", "살다보면 좋은 일도 있고 슬픈 일도 있어. 그게 인생이야.", "짱구는 못말려 명대사"),

                    # 30) 늑대와 향신료
                    ("追い詰められた時にしか見えない道もある。", "오이츠메라레타 토키니시카 미에나이 미치모 아루.", "궁지에 몰렸을 때만 보이는 길도 있을 거야.", "늑대와 향신료 명대사"),

                    # 31) 명탐정 코난
                    ("それでも逃げたくない。逃げたら勝てない。絶対に！", "소레데모 니게타쿠나이. 니게타라 카테나이. 젯타이니!", "그래도 도망치고 싶지 않아. 도망치면 이길 수 없잖아. 절대로!", "명탐정 코난 명대사"),

                    # 32) 케이온
                    ("大事なものほど、いつもそばにある。慣れると気づけなくなるけど。", "다이지나 모노호도, 이츠모 소바니 아루. 나레루토 키즈케나쿠나루케도.", "귀중하고 소중한 건 언제나 곁에 있어. 하지만 당연해지면 알지 못하게 돼.", "케이온 명대사"),

                    # 33) 마루코는 아홉살
                    ("無意味なことをいっぱいするのが人生なんだよ。", "무이미나 코토오 잇파이 스루노가 진세난다요.", "의미없는 걸 잔뜩 하는 게 인생이란다.", "마루코는 아홉살 명대사"),

                    # 34) 주술회전
                    ("失礼だな。純愛だよ。", "시츠레이다나. 준아이 다요.", "무례하긴. 순애거든.", "주술회전 명대사"),

                    # 35) 명탐정 코난
                    ("記憶じゃない…思い出だ。真っ黒に焼けちまったけどな。", "키오쿠쟈나이... 오모이데다. 맛쿠로니 야케치맛타케도나.", "기억이 아니야… 추억이야. 새까맣게 타버렸지만.", "명탐정 코난 명대사"),

                    # 36) 진격의 거인
                    ("何も捨てられない人には、何も変えられない。", "나니모 스테라레나이 히토니와, 나니모 카에라레나이.", "아무것도 버리지 못하는 사람은 아무것도 바꿀 수 없어.", "진격의 거인 명대사"),

                    # 37) 나의 히어로 아카데미아
                    ("いつまでも甘く見てると、自分の弱さに気づけなくなる。", "이츠마데모 아마쿠 미테루토, 지분노 요와사니 키즈케나쿠나루.", "언제까지나 얕보고만 있으면 자기 약함을 깨닫지 못하게 된다.", "나의 히어로 아카데미아 명대사"),

                    # 38) 도쿄 리벤저스
                    ("生まれた環境を憎むな。", "우마레타 칸쿄-오 니쿠무나.", "네가 태어난 환경을 미워하지 마.", "도쿄 리벤저스 명대사"),

                    # 39) 귀멸의 칼날
                    ("胸を張って生きろ。", "무네오 핫테 이키로.", "가슴을 펴고 살아라.", "귀멸의 칼날 명대사"),

                    # 40) 귀멸의 칼날
                    ("できるかできないかじゃない。やらなきゃいけないことがある。", "데키루카 데키나이카쟈나이. 야라나캬 이케나이 코토가 아루.", "할 수 있느냐 없느냐가 아니야. 해야만 하는 일이 있어.", "귀멸의 칼날 명대사"),
                ],
            },
        },
    },
        # 흡연/금연(매너)
    "smoking": {
        "title": "흡연/금연 필수 일본어 회화 문장 모음",
        "subs": {
            "rule": {
                "title": "흡연구역/규칙",
                "items": [
                    ("喫煙所はどこですか？", "키츠엔죠와 도코데스카", "흡연구역은 어디예요?"),
                    ("ここは禁煙ですか？", "코코와 킨엔데스카", "여기는 금연인가요?"),
                    ("電子タバコは大丈夫ですか？", "덴시타바코와 다이죠부데스카", "전자담배는 괜찮나요?"),
                    ("この建物は禁煙です。", "코노 타테모노와 킨엔데스", "이 건물은 금연이에요."),
                    ("外で吸ってもいいですか？", "소토데 슷테모 이-데스카", "밖에서 피워도 되나요?"),
                    ("灰皿はありますか？", "하이자라와 아리마스카", "재떨이 있나요?"),
                    ("すみません、煙が苦手です。", "스미마센 케무리가 니가테데스", "죄송한데 담배연기가 힘들어요."),
                    ("少し離れてもらえますか？", "스코시 하나레테 모라에마스카", "조금 떨어져 주실 수 있나요?"),
                    ("こちらは禁煙席です。", "코치라와 킨엔세키데스", "여기는 금연석이에요."),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
        },
    },

    #  사진관/인화
    "photo_print": {
        "title": "사진관/인화 필수 일본어 회화 문장 모음",
        "subs": {
            "print": {
                "title": "인화/파일",
                "items": [
                    ("写真をプリントしたいです。", "샤신오 푸린토시타이데스", "사진 인화하고 싶어요."),
                    ("このデータを印刷してください。", "코노 데-타오 인사츠시테 쿠다사이", "이 데이터 출력해주세요."),
                    ("サイズはLでお願いします。", "사이즈와 에루데 오네가이시마스", "사이즈는 L로 부탁해요."),
                    ("光沢ありにできますか？", "코-타쿠아리니 데키마스카", "유광으로 가능해요?"),
                    ("マットにできますか？", "맛토니 데키마스카", "무광(매트)으로 가능해요?"),
                    ("今日受け取れますか？", "쿄- 우케토레마스카", "오늘 받을 수 있나요?"),
                    ("何分ぐらいかかりますか？", "난푼구라이 카카리마스카", "몇 분 정도 걸려요?"),
                    ("USBは使えますか？", "유-에스비-와 츠카에마스카", "USB 사용 가능해요?"),
                    ("スマホから送れますか？", "스마호카라 오쿠레마스카", "휴대폰에서 전송할 수 있나요?"),
                    ("料金はいくらですか？", "료-킨와 이쿠라데스카", "요금은 얼마예요?"),
                ],
            },
        },
    },
        #  약속/만남(연락/지각)
    "meetup": {
        "title": "약속/만남 필수 일본어 회화 문장 모음",
        "subs": {
            "late": {
                "title": "지각/연락",
                "items": [
                    ("今どこですか？", "이마다 코코데스카", "지금 어디예요?"),
                    ("もうすぐ着きます。", "모-스구 츠키마스", "곧 도착해요."),
                    ("少し遅れます。", "스코시 오쿠레마스", "조금 늦어요."),
                    ("何分ぐらい遅れますか？", "난푼구라이 오쿠레마스카", "몇 분 정도 늦어요?"),
                    ("場所を間違えました。", "바쇼오 마치가에마시타", "장소를 잘못 왔어요."),
                    ("改札の前にいます。", "카이사츠노 마에니 이마스", "개찰구 앞에 있어요."),
                    ("目印は何ですか？", "메지루시와 난데스카", "눈에 띄는 표시는 뭐예요?"),
                    ("電話してもいいですか？", "덴와시테모 이-데스카", "전화해도 될까요?"),
                    ("また連絡します。", "마타 렌라쿠시마스", "또 연락할게요."),
                    ("会えてよかったです。", "아에테 요캇타데스", "만나서 반가워요."),
                ],
            },
        },
    },

    #  공공화장실/위생(비데/시설)
    "toilet_public": {
        "title": "공공화장실/위생 필수 일본어 회화 문장 모음",
        "subs": {
            "use": {
                "title": "이용/문제",
                "items": [
                    ("トイレはどこですか？", "토이레와 도코데스카", "화장실 어디예요?"),
                    ("ここ、使えますか？", "코코 츠카에마스카", "여기 사용 가능해요?"),
                    ("紙がありません。", "카미가 아리마센", "휴지가 없어요."),
                    ("手を洗う場所はどこですか？", "테오 아라우 바쇼와 도코데스카", "손 씻는 곳은 어디예요?"),
                    ("消毒はありますか？", "쇼-도쿠와 아리마스카", "소독제 있나요?"),
                    ("鍵がかかりません。", "카기가 카카리마센", "문이 잠기지 않아요."),
                    ("水が流れません。", "미즈가 나가레마센", "물이 안 내려가요."),
                    ("使い方がわかりません。", "츠카이카타가 와카리마센", "사용법을 모르겠어요."),
                    ("すみません、手伝ってください。", "스미마센 테츠닷테 쿠다사이", "죄송한데 도와주세요."),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
        },
    },
        #  미용실/헤어
    "hair_salon": {
        "title": "미용실/헤어 필수 일본어 회화 문장 모음",
        "subs": {
            "cut": {
                "title": "컷/스타일",
                "items": [
                    ("予約しています。", "요야쿠시테이마스", "예약했어요."),
                    ("カットだけお願いします。", "캇토다케 오네가이시마스", "컷만 부탁해요."),
                    ("少し短くしてください。", "스코시 미지카쿠 시테 쿠다사이", "조금 짧게 해주세요."),
                    ("前髪は残してください。", "마에가미와 노코시테 쿠다사이", "앞머리는 남겨주세요."),
                    ("この写真みたいにしてください。", "코노 샤신미타이니 시테 쿠다사이", "이 사진처럼 해주세요."),
                    ("すきバサミは使わないでください。", "스키바사미와 츠카와나이데 쿠다사이", "숱가위는 쓰지 말아주세요."),
                    ("シャンプーはありますか？", "샴푸-와 아리마스카", "샴푸도 하나요?"),
                    ("カラーもできますか？", "카라-모 데키마스카", "염색도 가능해요?"),
                    ("どのくらいかかりますか？", "도노쿠라이 카카리마스카", "얼마나 걸려요?"),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
        },
    },
        #  재난/지진 대응
    "disaster": {
        "title": "재난/지진 대응 필수 일본어 회화 문장 모음",
        "subs": {
            "earthquake": {
                "title": "지진/대피",
                "items": [
                    ("地震ですか？", "지신데스카", "지진인가요?"),
                    ("大丈夫ですか？", "다이죠부데스카", "괜찮아요?"),
                    ("安全な場所はどこですか？", "안젠나 바쇼와 도코데스카", "안전한 곳은 어디예요?"),
                    ("避難所はどこですか？", "히난죠와 도코데스카", "대피소는 어디예요?"),
                    ("外に出たほうがいいですか？", "소토니 데타호-가 이-데스카", "밖으로 나가는 게 좋나요?"),
                    ("ここで待ってもいいですか？", "코코데 맛테모 이-데스카", "여기서 기다려도 될까요?"),
                    ("電車は動いていますか？", "덴샤와 우고이테이마스카", "전철은 운행하나요?"),
                    ("連絡が取れません。", "렌라쿠가 토레마센", "연락이 안 돼요."),
                    ("水をください。", "미즈오 쿠다사이", "물 주세요."),
                    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
                ],
            },
        },
    },
        #  축제/이벤트
    "festival_event": {
        "title": "축제/이벤트 필수 일본어 회화 문장 모음",
        "subs": {
            "food_stall": {
                "title": "야시장/포장마차",
                "items": [
                    ("これはいくらですか？", "코레와 이쿠라데스카", "이거 얼마예요?"),
                    ("二つください。", "후타츠 쿠다사이", "두 개 주세요."),
                    ("辛いですか？", "카라이데스카", "매워요?"),
                    ("おすすめはどれですか？", "오스스메와 도레데스카", "추천은 뭐예요?"),
                    ("持ち帰りできますか？", "모치카에리 데키마스카", "포장 가능해요?"),
                    ("袋をください。", "후쿠로오 쿠다사이", "봉투 주세요."),
                    ("おつりをください。", "오츠리오 쿠다사이", "거스름돈 주세요."),
                    ("現金だけですか？", "겐킨다케데스카", "현금만 돼요?"),
                    ("写真を撮ってもいいですか？", "샤신오 톳테모 이-데스카", "사진 찍어도 되나요?"),
                    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
                ],
            },
            "crowd": {
                "title": "인파/만남",
                "items": [
                    ("人が多いですね。", "히토가 오-이데스네", "사람이 많네요."),
                    ("ここで待ち合わせです。", "코코데 마치아와세데스", "여기서 만나기로 했어요."),
                    ("迷子になりました。", "마이고니 나리마시타", "길을 잃었어요(미아)."),
                    ("入口はどこですか？", "이리구치와 도코데스카", "입구는 어디예요?"),
                    ("出口はどこですか？", "데구치와 도코데스카", "출구는 어디예요?"),
                    ("トイレはどこですか？", "토이레와 도코데스카", "화장실은 어디예요?"),
                    ("救護所はどこですか？", "큐-고쇼와 도코데스카", "의무실은 어디예요?"),
                    ("落とし物をしました。", "오토시모노오 시마시타", "물건을 떨어뜨렸어요."),
                    ("写真をお願いします。", "샤신오 오네가이시마스", "사진 부탁해요."),
                    ("また来ます。", "마타 키마스", "또 올게요."),
                ],
            },
        },
    },
        #  박물관/수족관
    "museum_aquarium": {
        "title": "박물관/수족관 필수 일본어 회화 문장 모음",
        "subs": {
            "entry": {
                "title": "입장/관람",
                "items": [
                    ("チケットを買いたいです。", "치켓토오 카이타이데스", "티켓을 사고 싶어요."),
                    ("何時まで開いていますか？", "난지마데 아이테이마스카", "몇 시까지 열어요?"),
                    ("最終入場は何時ですか？", "사이슈-뉴-죠-와 난지데스카", "마지막 입장은 몇 시예요?"),
                    ("割引はありますか？", "와리비키와 아리마스카", "할인 있나요?"),
                    ("写真はだめですか？", "샤신와 다메데스카", "사진은 안 되나요?"),
                    ("フラッシュはだめですか？", "후랏슈와 다메데스카", "플래시는 안 되나요?"),
                    ("音声ガイドはありますか？", "온세-가이도와 아리마스카", "오디오 가이드 있나요?"),
                    ("日本語が少しだけです。", "니혼고가 스코시다케데스", "일본어는 조금만 해요."),
                    ("おすすめの展示はどれですか？", "오스스메노 텐지와 도레데스카", "추천 전시는 뭐예요?"),
                    ("出口はどこですか？", "데구치와 도코데스카", "출구는 어디예요?"),
                ],
            },
        },
    },
        # 료칸/가이세키
    "ryokan": {
        "title": "료칸/가이세키 필수 일본어 회화 문장 모음",
        "subs": {
            "stay": {
                "title": "체크인/시설",
                "items": [
                    ("予約しています。", "요야쿠시테이마스", "예약했어요."),
                    ("旅館は初めてです。", "료칸와 하지메테데스", "료칸은 처음이에요."),
                    ("浴衣はどこですか？", "유카타와 도코데스카", "유카타는 어디예요?"),
                    ("部屋食ですか？", "헤야쇼쿠데스카", "객실 식사인가요?"),
                    ("夕食は何時ですか？", "유-쇼쿠와 난지데스카", "저녁은 몇 시예요?"),
                    ("朝食は何時ですか？", "초-쇼쿠와 난지데스카", "아침은 몇 시예요?"),
                    ("布団をお願いします。", "후톤오 오네가이시마스", "이불 부탁해요."),
                    ("鍵はここですか？", "카기와 코코데스카", "열쇠는 여기인가요?"),
                    ("館内の地図はありますか？", "칸나이노 치즈와 아리마스카", "관내 지도 있나요?"),
                    ("温泉はどこですか？", "온센와 도코데스카", "온천은 어디예요?"),
                ],
            },
            "meal": {
                "title": "식사/요청",
                "items": [
                    ("これは何ですか？", "코레와 난데스카", "이건 뭐예요?"),
                    ("食べられないものがあります。", "타베라레나이 모노가 아리마스", "못 먹는 게 있어요."),
                    ("アレルギーがあります。", "아레루기-가 아리마스", "알레르기가 있어요."),
                    ("量を少なめにできますか？", "료-오 스쿠나메니 데키마스카", "양을 적게 할 수 있나요?"),
                    ("飲み物をください。", "노미모노오 쿠다사이", "음료 주세요."),
                    ("お茶をお願いします。", "오챠오 오네가이시마스", "차 부탁해요."),
                    ("箸をください。", "하시오 쿠다사이", "젓가락 주세요."),
                    ("とてもおいしいです。", "토테모 오이시-데스", "정말 맛있어요."),
                    ("ごちそうさまでした。", "고치소-사마데시타", "잘 먹었습니다."),
                    ("部屋に持って行ってもいいですか？", "헤야니 못테잇테모 이-데스카", "방으로 가져가도 될까요?"),
                ],
            },
        },
    },
        #  온천/대욕장
    "onsen": {
        "title": "온천/대욕장 필수 일본어 회화 문장 모음",
        "subs": {
            "rules": {
                "title": "이용/규칙",
                "items": [
                    ("温泉は何時までですか？", "온센와 난지마데데스카", "온천은 몇 시까지예요?"),
                    ("タオルはありますか？", "타오루와 아리마스카", "수건 있나요?"),
                    ("どこで脱げばいいですか？", "도코데 누게바 이-데스카", "어디서 옷 벗으면 되나요?"),
                    ("ロッカーはありますか？", "롯카-와 아리마스카", "락커 있나요?"),
                    ("シャンプーはありますか？", "샴푸-와 아리마스카", "샴푸 있나요?"),
                    ("入れ墨はだめですか？", "이레즈미와 다메데스카", "문신은 안 되나요?"),
                    ("写真はだめですか？", "샤신와 다메데스카", "사진은 안 되나요?"),
                    ("水分をとったほうがいいですか？", "스이분오 톳타호-가 이-데스카", "수분 섭취하는 게 좋나요?"),
                    ("サウナはありますか？", "사우나와 아리마스카", "사우나 있나요?"),
                    ("休憩所はどこですか？", "큐-케-죠와 도코데스카", "휴게실은 어디예요?"),
                ],
            },
            "trouble": {
                "title": "문제/도움",
                "items": [
                    ("気分が悪いです。", "키분가 와루이데스", "몸이 안 좋아요."),
                    ("めまいがします。", "메마이가 시마스", "어지러워요."),
                    ("水をください。", "미즈오 쿠다사이", "물 주세요."),
                    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
                    ("鍵をなくしました。", "카기오 나쿠시마시타", "열쇠를 잃어버렸어요."),
                    ("ロッカーが開きません。", "롯카-가 아키마센", "락커가 안 열려요."),
                    ("忘れ物をしました。", "와스레모노오 시마시타", "두고 온 게 있어요."),
                    ("スタッフはいますか？", "스탓후와 이마스카", "직원 있나요?"),
                    ("ここで待っていいですか？", "코코데 맛테 이-데스카", "여기서 기다려도 될까요?"),
                    ("お願いします。", "오네가이시마스", "부탁합니다."),
                ],
            },
        },
    },
         #  신칸센/특급
    "shinkansen": {
        "title": "신칸센/특급 필수 일본어 회화 문장 모음",
        "subs": {
            "ticket": {
                "title": "예약/표",
                "items": [
                    ("新幹線の切符を買いたいです。", "신칸센노 킷푸오 카이타이데스", "신칸센 표를 사고 싶어요."),
                    ("指定席はありますか？", "시테-세키와 아리마스카", "지정석 있나요?"),
                    ("自由席でいいです。", "지유-세키데 이-데스", "자유석이면 돼요."),
                    ("往復でお願いします。", "오-후쿠데 오네가이시마스", "왕복으로 부탁해요."),
                    ("何時発がありますか？", "난지하츠가 아리마스카", "몇 시 출발이 있어요?"),
                    ("乗車券と特急券が必要ですか？", "죠-샤켄토 톳큐-켄가 히츠요-데스카", "승차권이랑 특급권이 필요해요?"),
                    ("この切符で乗れますか？", "코노 킷푸데 노레마스카", "이 표로 탈 수 있나요?"),
                    ("ホームは何番ですか？", "호-무와 난반데스카", "플랫폼은 몇 번이에요?"),
                    ("乗り場はどちらですか？", "노리바와 도치라데스카", "탑승장은 어디예요?"),
                    ("発車は何時ですか？", "핫샤와 난지데스카", "출발은 몇 시예요?"),
                ],
            },
            "onboard": {
                "title": "탑승/좌석",
                "items": [
                    ("この席は合っていますか？", "코노 세키와 앗테이마스카", "이 좌석 맞나요?"),
                    ("荷物置き場はありますか？", "니모츠오키바와 아리마스카", "짐 보관하는 곳 있나요?"),
                    ("すみません、通ります。", "스미마센 토오리마스", "실례합니다, 지나갈게요."),
                    ("窓側がいいです。", "마도가와가 이-데스", "창가가 좋아요."),
                    ("通路側がいいです。", "츠-로가와가 이-데스", "통로쪽이 좋아요."),
                    ("車内販売はありますか？", "샤나이한바이와 아리마스카", "차내 판매 있나요?"),
                    ("次はどこですか？", "츠기와 도코데스카", "다음은 어디예요?"),
                    ("降りる駅はここですか？", "오리루 에키와 코코데스카", "내릴 역이 여기인가요?"),
                    ("遅れていますか？", "오쿠레테이마스카", "지연되고 있나요?"),
                    ("出口はどちらですか？", "데구치와 도치라데스카", "출구는 어디예요?"),
                ],
            },
        },
    },
        #  렌터카
    "car_rental": {
        "title": "렌터카 필수 일본어 회화 문장 모음",
        "subs": {
            "pickup": {
                "title": "대여/보험",
                "items": [
                    ("予約しています。", "요야쿠시테이마스", "예약했어요."),
                    ("運転免許証はこちらです。", "운텐멘쿄쇼-와 코치라데스", "운전면허증 여기 있습니다."),
                    ("国際免許は必要ですか？", "코쿠사이멘쿄와 히츠요-데스카", "국제면허가 필요해요?"),
                    ("保険は入ったほうがいいですか？", "호켄와 하잇타호-가 이-데스카", "보험 드는 게 좋나요?"),
                    ("ナビはありますか？", "나비와 아리마스카", "내비게이션 있나요?"),
                    ("ETCカードは借りられますか？", "이-티-시-카-도와 카리라레마스카", "ETC카드 빌릴 수 있나요?"),
                    ("満タン返しですか？", "만탄가에시데스카", "만땅 반납인가요?"),
                    ("車に傷はありませんか？", "쿠루마니 키즈와 아리마센카", "차에 흠집 없나요?"),
                    ("ここにサインしますか？", "코코니 사인시마스카", "여기에 사인하나요?"),
                    ("出発してもいいですか？", "슈파츠시테모 이-데스카", "출발해도 될까요?"),
                ],
            },
            "return": {
                "title": "반납/문제",
                "items": [
                    ("返却したいです。", "헨캬쿠시타이데스", "반납하고 싶어요."),
                    ("ガソリンスタンドは近くにありますか？", "가소린스탄도와 치카쿠니 아리마스카", "주유소 근처에 있나요?"),
                    ("返却場所はここで合っていますか？", "헨캬쿠바쇼와 코코데 앗테이마스카", "반납 장소가 여기 맞나요?"),
                    ("延長できますか？", "엔초- 데키마스카", "연장 가능해요?"),
                    ("遅れそうです。", "오쿠레소-데스", "늦을 것 같아요."),
                    ("事故を起こしました。", "지코오 오코시마시타", "사고가 났어요."),
                    ("故障しました。", "코쇼-시마시타", "고장났어요."),
                    ("レッカーを呼んでください。", "렛카-오 욘데 쿠다사이", "견인차 불러주세요."),
                    ("連絡先はどこですか？", "렌라쿠사키와 도코데스카", "연락처가 어디예요?"),
                    ("追加料金はありますか？", "츠이카료-킨와 아리마스카", "추가요금 있나요?"),
                ],
            },
        },
    },
        #  ATM/현금 인출
    "atm_cash": {
        "title": "ATM/현금 인출 필수 일본어 회화 문장 모음",
        "subs": {
            "withdraw": {
                "title": "인출/오류",
                "items": [
                    ("ATMはどこですか？", "에-티-에무와 도코데스카", "ATM은 어디예요?"),
                    ("現金を下ろしたいです。", "겐킨오 오로시타이데스", "현금 인출하고 싶어요."),
                    ("このカードは使えますか？", "코노 카-도와 츠카에마스카", "이 카드 사용 가능해요?"),
                    ("暗証番号を忘れました。", "안쇼-방고-오 와스레마시타", "비밀번호를 잊었어요."),
                    ("エラーが出ました。", "에라-가 데마시타", "에러가 떴어요."),
                    ("お金が出てきません。", "오카네가 데테키마센", "돈이 안 나와요."),
                    ("カードが戻りません。", "카-도가 모도리마센", "카드가 안 돌아와요."),
                    ("引き出し限度額はありますか？", "히키다시 겐도-가쿠와 아리마스카", "인출 한도가 있나요?"),
                    ("手数料はいくらですか？", "테스료-와 이쿠라데스카", "수수료는 얼마예요?"),
                    ("スタッフを呼んでください。", "스탓후오 욘데 쿠다사이", "직원을 불러주세요."),
                ],
            },
        },
    },
        #  환전/환율
    "money_exchange": {
        "title": "환전/환율 필수 일본어 회화 문장 모음",
        "subs": {
            "exchange": {
                "title": "환전/수수료",
                "items": [
                    ("両替したいです。", "료-가에 시타이데스", "환전하고 싶어요."),
                    ("円に両替できますか？", "엔니 료-가에 데키마스카", "엔으로 환전할 수 있나요?"),
                    ("手数料はいくらですか？", "테스료-와 이쿠라데스카", "수수료는 얼마예요?"),
                    ("このお金は使えますか？", "코노 오카네와 츠카에마스카", "이 돈 사용 가능한가요?"),
                    ("小さいお札にできますか？", "치-사이 오사츠니 데키마스카", "작은 지폐로 바꿀 수 있나요?"),
                    ("いくらから両替できますか？", "이쿠라카라 료-가에 데키마스카", "얼마부터 환전 가능해요?"),
                    ("今日のレートはいくらですか？", "쿄-노 레-토와 이쿠라데스카", "오늘 환율이 얼마예요?"),
                    ("パスポートが必要ですか？", "파스포-토가 히츠요-데스카", "여권이 필요해요?"),
                    ("現金で受け取ります。", "겐킨데 우케토리마스", "현금으로 받을게요."),
                    ("明細をください。", "메-사이오 쿠다사이", "내역서 주세요."),
                ],
            },
        },
    },
        # 30) 휴대폰/번역/사진 보여주기(현지에서 진짜 많이 씀)
    "phone_help": {
        "title": "휴대폰/번역/화면 보여주기 일본어 문장 모음",
        "subs": {
            "show": {
                "title": "화면/번역",
                "items": [
                    ("これを見せてもいいですか？", "코레오 미세테모 이-데스카", "이거 보여드려도 될까요?"),
                    ("スマホで見せます。", "스마호데 미세마스", "휴대폰으로 보여드릴게요."),
                    ("翻訳します。", "혼야쿠시마스", "번역할게요."),
                    ("この画面を見てください。", "코노 가멘오 미테 쿠다사이", "이 화면 봐주세요."),
                    ("ここを押せばいいですか？", "코코오 오세바 이-데스카", "여기 누르면 되나요?"),
                    ("使い方がわかりません。", "츠카이카타가 와카리마센", "사용법을 모르겠어요."),
                    ("すみません、助けてもらえますか？", "스미마센 타스케테모라에마스카", "실례합니다, 도와주실 수 있나요?"),
                    ("写真を見せます。", "샤신오 미세마스", "사진 보여드릴게요."),
                    ("ここに行きたいです。", "코코니 이키타이데스", "여기 가고 싶어요."),
                    ("この住所です。", "코노 쥬-쇼데스", "이 주소예요."),
                ],
            },
        },
    },
}    

# ---------------------------
# 
# - 구조: WORDS[카테고리키] = { title, items[(jp, pron, ko), ...] }
# - pron(발음)은 "한글식 발음"만 사용 (일본어 섞지 않음)
# ---------------------------

WORDS: Dict[str, Dict[str, Any]] = {
        # 1) 숫자
        "numbers": {
            "title": "숫자",
            "items": [
                ("1", "이치", "1"),
                ("2", "니", "2"),
                ("3", "산", "3"),
                ("4", "욘", "4"),
                ("5", "고", "5"),
                ("6", "로쿠", "6"),
                ("7", "나나", "7"),
                ("8", "하치", "8"),
                ("9", "큐", "9"),
                ("10", "쥬", "10"),
                ("11", "쥬이치", "11"),
                ("12", "쥬니", "12"),
                ("20", "니쥬", "20"),
                ("30", "산쥬", "30"),
                ("50", "고쥬", "50"),
                ("100", "햐쿠", "100"),
                ("1000", "센", "1000"),
                ("10000", "만", "10000(만)"),
                ("～円", "엔", "~엔"),
                ("～人", "닌", "~명(사람 수)"),

                # 🔽 실전 단위 추가
                ("1つ", "히토츠", "한 개"),
                ("2つ", "후타츠", "두 개"),
                ("3つ", "밋츠", "세 개"),
                ("4つ", "욧츠", "네 개"),
                ("5つ", "이츠츠", "다섯 개"),
                ("6つ", "뭇츠", "여섯 개"),
                ("7つ", "나나츠", "일곱 개"),
                ("8つ", "얏츠", "여덟 개"),
                ("9つ", "코코노츠", "아홉 개"),
                ("10つ", "토오", "열 개"),

                ("～歳", "사이", "~살(나이)"),
                ("～階", "카이", "~층"),
                ("～本", "혼", "~개(긴 물건)"),
                ("～枚", "마이", "~장"),
                ("～匹", "히키", "~마리"),
                ("～台", "다이", "~대"),
                ("～杯", "하이", "~잔"),
                ("～冊", "사츠", "~권"),
                ("～回", "카이", "~번"),
                ("～個", "코", "~개"),
                ("1歳", "잇사이", "1살"),
                ("2歳", "니사이", "2살"),
                ("1階", "잇카이", "1층"),
                ("1本", "잇폰", "1개(긴 물건)"),
                ("1枚", "이치마이", "1장"),
                ("1匹", "잇피키", "1마리"),
                ("1杯", "잇파이", "1잔"),
                ("1冊", "잇사츠", "1권"),
                ("1回", "잇카이", "1번"),
                ("1個", "잇코", "1개"),
            ],
        },


        "time": {
            "title": "시간",
            "items": [
                ("今", "이마", "지금"),
                ("今日", "쿄", "오늘"),
                ("昨日", "키노", "어제"),
                ("明日", "아시타", "내일"),
                ("朝", "아사", "아침"),
                ("昼", "히루", "점심/낮"),
                ("夜", "요루", "밤"),
                ("何時", "난지", "몇 시"),
                ("～時", "지", "~시"),
                ("～分", "푼", "~분"),
                ("～秒", "뵤", "~초"),

                # ⏱ 분 (1~10분)
                ("1分", "잇푼", "1분"),
                ("2分", "니푼", "2분"),
                ("3分", "산푼", "3분"),
                ("4分", "욘푼", "4분"),
                ("5分", "고푼", "5분"),
                ("6分", "롯푼", "6분"),
                ("7分", "나나푼", "7분"),
                ("8分", "핫푼", "8분"),
                ("9分", "큐푼", "9분"),
                ("10分", "쥬푼", "10분"),

                # 🕒 시 (1~12시)
                ("1時", "이치지", "1시"),
                ("2時", "니지", "2시"),
                ("3時", "산지", "3시"),
                ("4時", "요지", "4시"),
                ("5時", "고지", "5시"),
                ("6時", "로쿠지", "6시"),
                ("7時", "시치지", "7시"),
                ("8時", "하치지", "8시"),
                ("9時", "쿠지", "9시"),
                ("10時", "쥬지", "10시"),
                ("11時", "쥬이치지", "11시"),
                ("12時", "쥬니지", "12시"),

                # ⏳ 시간 (1~24시간)
                ("1時間", "잇지칸", "1시간"),
                ("2時間", "니지칸", "2시간"),
                ("3時間", "산지칸", "3시간"),
                ("4時間", "욘지칸", "4시간"),
                ("5時間", "고지칸", "5시간"),
                ("6時間", "로쿠지칸", "6시간"),
                ("7時間", "나나지칸", "7시간"),
                ("8時間", "하치지칸", "8시간"),
                ("9時間", "큐지칸", "9시간"),
                ("10時間", "쥬지칸", "10시간"),
                ("11時間", "쥬이치지칸", "11시간"),
                ("12時間", "쥬니지칸", "12시간"),
                ("13時間", "쥬산지칸", "13시간"),
                ("14時間", "쥬욘지칸", "14시간"),
                ("15時間", "쥬고지칸", "15시간"),
                ("16時間", "쥬로쿠지칸", "16시간"),
                ("17時間", "쥬나나지칸", "17시간"),
                ("18時間", "쥬하치지칸", "18시간"),
                ("19時間", "쥬큐지칸", "19시간"),
                ("20時間", "니쥬지칸", "20시간"),
                ("21時間", "니쥬이치지칸", "21시간"),
                ("22時間", "니쥬니지칸", "22시간"),
                ("23時間", "니쥬산지칸", "23시간"),
                ("24時間", "니쥬욘지칸", "24시간"),

                # 🧠 실전 조합 예시
                ("3時15分", "산지 쥬고푼", "3시 15분"),
                ("5時27分", "고지 니쥬나나푼", "5시 27분"),
                ("13分50秒", "쥬산푼 고쥬뵤", "13분 50초"),
                ("2時20分", "니지 니쥬푼", "2시 20분"),
                ("15分25秒", "쥬고푼 니쥬고뵤", "15분 25초"),

                ("ちょっと", "촛토", "잠깐/조금"),
                ("すぐ", "스구", "바로/곧"),
            ],
        },


        # 3) 날짜/요일
        "date": {
            "title": "날짜/요일",
            "items": [
                ("月曜日", "게츠요비", "월요일"),
                ("火曜日", "카요비", "화요일"),
                ("水曜日", "스이요비", "수요일"),
                ("木曜日", "모쿠요비", "목요일"),
                ("金曜日", "킨요비", "금요일"),
                ("土曜日", "도요비", "토요일"),
                ("日曜日", "니치요비", "일요일"),
                ("今週", "콘슈", "이번 주"),
                ("来週", "라이슈", "다음 주"),
                ("今月", "콘게츠", "이번 달"),
                ("来月", "라이게츠", "다음 달"),
                ("～日", "니치", "~일(날짜)"),
                ("1月1日", "이치가츠 츠이타치", "1월 1일"),
                ("2月20日", "니가츠 하츠카", "2월 20일"),
                ("3月3日", "산가츠 밋카", "3월 3일"),
                ("4月10日", "욘가츠 토오카", "4월 10일"),
                ("5月5日", "고가츠 이츠카", "5월 5일"),
                ("6月15日", "로쿠가츠 쥬고니치", "6월 15일"),
                ("7月7日", "시치가츠 나노카", "7월 7일"),
                ("8月8日", "하치가츠 요오카", "8월 8일"),
                ("9月9日", "쿠가츠 코코노카", "9월 9일"),
                ("12月31日", "쥬니가츠 산쥬이치니치", "12월 31일"),
            ],
        },

        # 4) 교통
        "transport": {
            "title": "교통",
            "items": [
                ("駅", "에키", "역"),
                ("電車", "덴샤", "전철"),
                ("地下鉄", "치카테츠", "지하철"),
                ("バス", "바스", "버스"),
                ("タクシー", "타쿠시", "택시"),
                ("車", "쿠루마", "자동차"),
                ("停留所", "테이류조", "정류장"),
                ("出口", "데구치", "출구"),
                ("入口", "이리구치", "입구"),
                ("切符", "킷푸", "표/티켓"),
                ("改札", "카이사츠", "개찰구"),
                ("ホーム", "호무", "승강장/플랫폼"),
                ("乗り場", "노리바", "승차장"),
                ("乗り換え", "노리카에", "환승"),
                ("到着", "토착", "도착"),
                ("出発", "슈팟츠", "출발"),
                ("料金", "료킨", "요금"),
                ("行き", "이키", "~행"),
                ("方面", "호멘", "~방면"),
                ("終電", "슈덴", "막차"),
                ("時刻表", "지코쿠효", "시간표"),
                ("急行", "큐코", "급행열차"),
            ],
        },

        # 5) 위치/방향
        "location": {
            "title": "위치/방향",
            "items": [
                ("ここ", "코코", "여기"),
                ("そこ", "소코", "거기"),
                ("あそこ", "아소코", "저기"),
                ("右", "미기", "오른쪽"),
                ("左", "히다리", "왼쪽"),
                ("前", "마에", "앞"),
                ("後ろ", "우시로", "뒤"),
                ("上", "우에", "위"),
                ("下", "시타", "아래"),
                ("近く", "치카쿠", "근처"),
                ("遠い", "토오이", "멀다"),
                ("地図", "치즈", "지도"),
            ],
        },

        # 6) 일상 동작
        "actions": {
            "title": "일상 동작",
            "items": [
                ("行く", "이쿠", "가다"),
                ("来る", "쿠루", "오다"),
                ("食べる", "타베루", "먹다"),
                ("飲む", "노무", "마시다"),
                ("見る", "미루", "보다"),
                ("買う", "카우", "사다"),
                ("使う", "츠카우", "쓰다/사용하다"),
                ("待つ", "마츠", "기다리다"),
                ("休む", "야스무", "쉬다"),
                ("寝る", "네루", "자다"),
                ("起きる", "오키루", "일어나다"),
                ("歩く", "아루쿠", "걷다"),
            ],
        },

        # 7) 감정/상태
        "feelings": {
            "title": "감정/상태",
            "items": [
                ("いい", "이", "좋다/괜찮다"),
                ("だめ", "다메", "안 된다"),
                ("大丈夫", "다이죠부", "괜찮아요"),
                ("疲れた", "츠카레타", "피곤해요"),
                ("お腹すいた", "오나카스이타", "배고파요"),
                ("のどが渇いた", "노도가 카와이타", "목말라요"),
                ("痛い", "이타이", "아파요"),
                ("怖い", "코와이", "무서워요"),
                ("うれしい", "우레시", "기뻐요"),
                ("悲しい", "카나시", "슬퍼요"),
            ],
        },

        # 8) 쇼핑
        "shopping": {
            "title": "쇼핑",
            "items": [
                ("安い", "야스이", "싸다"),
                ("高い", "타카이", "비싸다"),
                ("割引", "와리비키", "할인"),
                ("値段", "네단", "가격"),
                ("サイズ", "사이즈", "사이즈"),
                ("色", "이로", "색"),
                ("試着", "시챠쿠", "시착"),
                ("レジ", "레지", "계산대"),
                ("領収書", "료슈쇼", "영수증"),
                ("袋", "후쿠로", "봉투"),
                ("おすすめ", "오스스메", "추천"),
                ("現金", "겐킨", "현금"),
                ("カード", "카도", "카드"),
                ("支払い", "시하라이", "결제"),
                ("在庫", "자이코", "재고"),
                ("売り切れ", "우리키레", "품절"),
                ("返品", "헨핀", "환불"),
                ("交換", "코칸", "교환"),
                ("免税", "멘제이", "면세"),
                ("開ける", "아케루", "열다"),
                ("閉める", "시메루", "닫다"),
            ],
        },

        # 9) 음식
        "food": {
            "title": "음식",
            "items": [
                ("魚", "사카나", "생선"),
                ("刺身", "사시미", "회"),
                ("寿司", "스시", "초밥"),
                ("牛肉", "규-니쿠", "소고기"),
                ("豚肉", "부타니쿠", "돼지고기"),
                ("鶏肉", "토리니쿠", "닭고기"),
                ("野菜", "야사이", "채소"),
                ("ご飯", "고한", "밥"),
                ("味噌汁", "미소시루", "된장국"),
                ("天ぷら", "텐푸라", "튀김"),
                ("ラーメン", "라-멘", "라면"),
                ("うどん", "우동", "우동"),
                ("そば", "소바", "메밀국수"),
                ("カレー", "카레-", "카레"),
                ("焼肉", "야키니쿠", "불고기"),
                ("お好み焼き", "오코노미야키", "오코노미야키"),
                ("たこ焼き", "타코야키", "타코야키"),
                ("弁当", "벤토-", "도시락"),
                ("サラダ", "사라다", "샐러드"),
                ("パン", "팡", "빵"),
            ],
        },

        # 10) 카페/음료
        "cafe": {
            "title": "카페/음료",
            "items": [
                ("コーヒー", "코히", "커피"),
                ("アメリカーノ", "아메리카노", "아메리카노"),
                ("ラテ", "라테", "라떼"),
                ("お茶", "오챠", "차"),
                ("アイス", "아이스", "아이스"),
                ("ホット", "홋토", "뜨거운/핫"),
                ("砂糖", "사토", "설탕"),
                ("ミルク", "미루쿠", "우유"),
                ("持ち帰り", "모치카에리", "테이크아웃"),
                ("店内", "텐나이", "매장 안"),
                ("席", "세키", "자리"),
            ],
        },

        # 11) 숙소
        "hotel": {
            "title": "숙소",
            "items": [
                ("ホテル", "호테루", "호텔"),
                ("部屋", "헤야", "방"),
                ("鍵", "카기", "열쇠"),
                ("予約", "요야쿠", "예약"),
                ("チェックイン", "체쿠인", "체크인"),
                ("チェックアウト", "체쿠아우토", "체크아웃"),
                ("タオル", "타오루", "수건"),
                ("掃除", "소지", "청소"),
                ("荷物", "니모츠", "짐"),
                ("Wi-Fi", "와이화이", "와이파이"),
                ("パスワード", "파스와도", "비밀번호"),
                ("朝食", "초쇼쿠", "조식/아침식사"),
                ("延泊", "엔파쿠", "숙박 연장"),
                ("キャンセル", "캰세루", "취소"),
                ("空室", "쿠우시츠", "빈 방"),
                ("満室", "만시츠", "만실"),
                ("フロント", "후론토", "프런트(접수처)"),
                ("シャワー", "샤와", "샤워"),
                ("お湯", "오유", "뜨거운 물"),
                ("エアコン", "에아콘", "에어컨"),
                ("修理", "슈리", "수리"),
            ],
        },

        # 12) 응급/건강
        "emergency": {
            "title": "응급/건강",
            "items": [
                ("病院", "뵤인", "병원"),
                ("薬局", "야쿄쿠", "약국"),
                ("薬", "쿠스리", "약"),
                ("救急", "큐큐", "응급"),
                ("熱", "네츠", "열"),
                ("頭", "아타마", "머리"),
                ("お腹", "오나카", "배"),
                ("痛い", "이타이", "아파요"),
                ("助けて", "타스케테", "도와줘요"),
                ("保険", "호켄", "보험"),
                ("めまい", "메마이", "어지럼증"),
                ("吐き気", "하키케", "메스꺼움"),
                ("咳", "세키", "기침"),
                ("のど", "노도", "목"),
                ("骨", "호네", "뼈"),
                ("けが", "케가", "부상"),
                ("血", "치", "피"),
                ("アレルギー", "아레루기", "알레르기"),
                ("薬をください", "쿠스리오 쿠다사이", "약 주세요"),
                ("救急車", "큐큐샤", "구급차"),
            ],
        },

        # 13) 날씨
        "weather": {
            "title": "날씨",
            "items": [
                ("晴れ", "하레", "맑음"),
                ("雨", "아메", "비"),
                ("雪", "유키", "눈"),
                ("曇り", "쿠모리", "흐림"),
                ("暑い", "아츠이", "덥다"),
                ("寒い", "사무이", "춥다"),
                ("風", "카제", "바람"),
                ("傘", "카사", "우산"),
                ("天気", "텐키", "날씨"),
                ("温度", "온도", "온도"),
                ("暖かい", "아타타카이", "따뜻하다"),
                ("涼しい", "스즈시이", "시원하다"),
                ("蒸し暑い", "무시아츠이", "무덥다"),
                ("大雨", "오오아메", "폭우"),
                ("台風", "타이후", "태풍"),
                ("雷", "카미나리", "천둥"),
                ("霧", "키리", "안개"),
                ("湿度", "시츠도", "습도"),
                ("予報", "요호", "예보"),
                ("寒波", "칸파", "한파"),
            ],
        },

        # 14) 예의/기본표현
        "polite": {
            "title": "예의/기본표현",
            "items": [
                ("こんにちは", "곤니치와", "안녕하세요(낮)"),
                ("ありがとうございます", "아리가토 고자이마스", "감사합니다"),
                ("すみません", "스미마센", "죄송합니다/실례합니다"),
                ("お願いします", "오네가이시마스", "부탁합니다"),
                ("大丈夫です", "다이죠부데스", "괜찮아요"),
                ("わかりました", "와카리마시타", "알겠습니다"),
                ("もう一度", "모 이치도", "한 번 더"),
                ("ゆっくり", "윳쿠리", "천천히"),
                ("ちょっと待って", "촛토 맛테", "잠깐만요"),
                ("助かりました", "타스카리마시타", "도움 됐어요"),
                ("おはようございます", "오하요 고자이마스", "안녕하세요(아침)"),
                ("こんばんは", "곤방와", "안녕하세요(저녁)"),
                ("失礼します", "시츠레이시마스", "실례합니다"),
                ("どういたしまして", "도이타시마시테", "천만에요"),
                ("問題ありません", "몬다이 아리마센", "문제 없습니다"),
                ("わかりません", "와카리마센", "모르겠습니다"),
                ("大丈夫ですか", "다이죠부데스카", "괜찮으세요?"),
                ("お願いしますか", "오네가이시마스카", "부탁드려도 될까요?"),
                ("すごいですね", "스고이데스네", "대단하네요"),
                ("気をつけて", "키오츠케테", "조심하세요"),
            ],
        },

        # 15) 식당
        "restaurant": {
            "title": "식당",
            "items": [
                ("おいしい", "오이시", "맛있다"),
                ("まずい", "마즈이", "맛없다"),
                ("辛い", "카라이", "맵다"),
                ("甘い", "아마이", "달다"),
                ("しょっぱい", "쇼파이", "짜다"),
                ("注文", "츄-몬", "주문"),
                ("メニュー", "메뉴-", "메뉴"),
                ("おすすめ", "오스스메", "추천"),
                ("会計", "카이케-", "계산"),
                ("レシート", "레시-토", "영수증"),
                ("席", "세키", "자리"),
                ("予約", "요야쿠", "예약"),
                ("満席", "만세키", "만석"),
                ("空席", "쿠-세키", "빈자리"),
                ("店員", "텐인", "점원"),
                ("水", "미즈", "물"),
                ("追加", "츠이카", "추가"),
                ("取り分け", "토리와케", "나눠 담기"),
                ("持ち帰り", "모치카에리", "포장"),
                ("支払い", "시하라이", "지불"),
            ],
        },

        # 16) 공항/비행기
        "airplane": {
            "title": "공항/비행기",
            "items": [
                ("搭乗券", "토-죠-켄", "탑승권"),
                ("パスポート", "파스포-토", "여권"),
                ("手荷物", "테니모츠", "기내 반입 짐"),
                ("預け荷物", "아즈케니모츠", "부치는 짐"),
                ("機内", "키나이", "기내"),
                ("座席", "자세키", "좌석"),
                ("窓側", "마도가와", "창가 쪽"),
                ("通路側", "츠-로가와", "통로 쪽"),
                ("遅延", "치엔", "지연"),
                ("到着", "토-챠쿠", "도착"),
                ("チェックインカウンター", "체쿠인 카운타", "체크인 카운터"),
                ("保安検査", "호안 켄사", "보안 검색"),
                ("出国審査", "슈코쿠 신사", "출국 심사"),
                ("搭乗口", "토죠구치", "탑승 게이트"),
                ("出発", "슈팟츠", "출발"),
                ("乗り継ぎ", "노리츠기", "환승"),
                ("遅刻", "치코쿠", "지각"),
                ("欠航", "켓코", "결항"),
                ("案内", "안나이", "안내"),
                ("荷物受取所", "니모츠 우케토리조", "수하물 찾는 곳"),
            ],
        },

        # 17) 돈/결제/환전
        "money": {
            "title": "돈/결제/환전",
            "items": [
                ("現金", "겐킨", "현금"),
                ("カード", "카-도", "카드"),
                ("クレジットカード", "쿠레짓토카-도", "신용카드"),
                ("電子マネー", "덴시마네-", "전자결제"),
                ("両替", "료-가에", "환전"),
                ("レシート", "레시-토", "영수증"),
                ("おつり", "오츠리", "거스름돈"),
                ("手数料", "테스-료-", "수수료"),
                ("値段", "네단", "가격"),
                ("割引", "와리비키", "할인"),
            ],
        },

        # 18) 사진/카메라/스마트폰
        "phone_camera": {
            "title": "사진/카메라/스마트폰",
            "items": [
                ("写真", "샤신", "사진"),
                ("カメラ", "카메라", "카메라"),
                ("撮影", "사츠에-", "촬영"),
                ("動画", "도-가", "영상"),
                ("充電", "쥬-덴", "충전"),
                ("電池", "덴치", "배터리"),
                ("バッテリー", "밧테리-", "배터리(외래어)"),
                ("通信", "츠-신", "통신"),
                ("容量", "요-료-", "용량/저장공간"),
                ("設定", "세테-", "설정"),
            ],
        },

        # 19) 의류/패션/신발
        "fashion": {
            "title": "의류/패션/신발",
            "items": [
                ("服", "후쿠", "옷"),
                ("靴", "쿠츠", "신발"),
                ("試着", "시챠쿠", "시착"),
                ("サイズ", "사이즈", "사이즈"),
                ("大きい", "오-키이", "크다"),
                ("小さい", "치-사이", "작다"),
                ("長い", "나가이", "길다"),
                ("短い", "미지카이", "짧다"),
                ("似合う", "니아우", "어울리다"),
                ("売り場", "우리바", "매장/판매 코너"),
            ],
        },

        # 20) 숙소 문제/요청(심화)
        "hotel_trouble": {
            "title": "숙소 문제/요청",
            "items": [
                ("壊れた", "코와레타", "고장났다"),
                ("故障", "코쇼-", "고장"),
                ("うるさい", "우루사이", "시끄럽다"),
                ("寒い", "사무이", "춥다"),
                ("暑い", "아츠이", "덥다"),
                ("汚い", "키타나이", "더럽다"),
                ("におい", "니오이", "냄새"),
                ("交換", "코-칸", "교환"),
                ("追加", "츠이카", "추가"),
                ("修理", "슈-리", "수리"),
            ],
        },

        # 21) 아이/가족 여행
        "family": {
            "title": "아이/가족 여행",
            "items": [
                ("子ども", "코도모", "아이"),
                ("家族", "카조쿠", "가족"),
                ("迷子", "마이고", "미아/길 잃은 아이"),
                ("ベビーカー", "베비카-", "유모차"),
                ("危ない", "아부나이", "위험하다"),
                ("気をつけて", "키오츠케테", "조심해"),
                ("おむつ", "오무츠", "기저귀"),
                ("ミルク", "미루쿠", "우유/분유"),
                ("熱", "네츠", "열"),
                ("薬", "쿠스리", "약"),
            ],
        },

        # 22) 긴급/도움요청(심화)
        "emergency_plus": {
            "title": "긴급/도움요청",
            "items": [
                ("助けて", "타스케테", "도와줘"),
                ("救急車", "큐-큐-샤", "구급차"),
                ("警察", "케-사츠", "경찰"),
                ("病院", "뵤-인", "병원"),
                ("危険", "키켄", "위험"),
                ("けが", "케가", "부상"),
                ("痛い", "이타이", "아프다"),
                ("気分", "키분", "기분/컨디션"),
                ("失礼", "시츠레이", "실례"),
                ("緊急", "킨큐-", "긴급"),
            ],
        },

        # 23) SNS/인터넷/QR
        "sns_internet": {
            "title": "SNS/인터넷/QR",
            "items": [
                ("Wi-Fi", "와이화이", "와이파이"),
                ("パスワード", "파스와-도", "비밀번호"),
                ("QRコード", "큐아-루코-도", "QR코드"),
                ("アプリ", "아푸리", "앱"),
                ("インストール", "인스토-루", "설치"),
                ("ログイン", "로구인", "로그인"),
                ("登録", "토-로쿠", "등록"),
                ("認証", "닌쇼-", "인증"),
                ("リンク", "린쿠", "링크"),
                ("投稿", "토-코-", "게시/업로드"),
            ],
        },

        # 24) 온천/자연/관광지(단어)
        "nature_spots": {
            "title": "자연/관광지",
            "items": [
                ("海", "우미", "바다"),
                ("山", "야마", "산"),
                ("川", "카와", "강"),
                ("公園", "코-엔", "공원"),
                ("景色", "케시키", "풍경"),
                ("展望台", "텐보-다이", "전망대"),
                ("神社", "진쟈", "신사"),
                ("お寺", "오테라", "절"),
                ("温泉", "온센", "온천"),
                ("入場料", "뉴-죠-료-", "입장료"),              
                ("大浴場", "다이요쿠죠-", "대욕장"),
                ("露天風呂", "로텐부로", "노천탕"),
                ("入浴", "뉴-요쿠", "목욕"),
                ("入浴料", "뉴-요쿠료-", "입욕료"),
                ("営業時間", "에-교-지칸", "영업시간"),
                ("タオル", "타오루", "수건"),
                ("シャンプー", "샴푸-", "샴푸"),
                ("ボディソープ", "보디소-푸", "바디워시"),
                ("脱衣所", "다쓰이죠", "탈의실"),
                ("ロッカー", "롯카-", "락커"),
                ("鍵", "카기", "열쇠"),
                ("洗い場", "아라이바", "씻는 곳"),
                ("熱い", "아츠이", "뜨겁다"),
                ("ぬるい", "누루이", "미지근하다"),
                ("湯船", "유부네", "탕"),
            ],
        },

        # 25) 일본 문화/매너(필수)
        "japan_manners": {
            "title": "일본 문화/매너",
            "items": [
                ("お辞儀", "오지기", "인사(절)"),
                ("靴を脱ぐ", "쿠츠오 누구", "신발을 벗다"),
                ("土足禁止", "도소쿠킨시", "신발 신고 출입금지"),
                ("畳", "타타미", "다다미"),
                ("静かに", "시즈카니", "조용히"),
                ("マナー", "마나-", "매너"),
                ("順番", "준반", "순서"),
                ("並ぶ", "나라부", "줄 서다"),
                ("禁煙", "킨엔", "금연"),
                ("ごみ箱", "고미바코", "쓰레기통"),
            ],
        },
        # 26) 문제/트러블
        "trouble": {
            "title": "문제/트러블",
            "items": [
                ("紛失", "분시츠", "분실"),
                ("故障", "코쇼-", "고장"),
                ("エラー", "에라-", "오류"),
                ("キャンセル", "캰세루", "취소"),
                ("変更", "헨코-", "변경"),
                ("遅延", "치엔", "지연"),
                ("連絡", "렌라쿠", "연락"),
                ("助け", "타스케", "도움"),
                ("危険", "키켄", "위험"),
                ("事故", "지코", "사고"),
            ],
        },
        # 27) 편의점
        "convenience_store": {
            "title": "편의점",
            "items": [
                ("袋", "후쿠로", "봉투"),
                ("温め", "아타타메", "데우기"),
                ("箸", "하시", "젓가락"),
                ("フォーク", "포-쿠", "포크"),
                ("スプーン", "스푸-은", "숟가락"),
                ("会計", "카이케-", "계산"),
                ("ポイント", "포인트", "포인트"),
                ("レシート", "레시-토", "영수증"),
                ("現金", "겐킨", "현금"),
                ("カード", "카-도", "카드"),
                ("新商品", "신쇼힌", "신상품"),
                ("人気", "닌키", "인기"),
                ("割引", "와리비키", "할인"),
                ("電子マネー", "덴시 마네", "전자결제"),
                ("返品", "헨핀", "환불"),
                ("棚", "타나", "진열대"),
                ("飲み物", "노미모노", "음료"),
                ("コンビニ", "콘비니", "편의점"),
                ("スーパー", "스-파-", "슈퍼마켓"),
                ("レジ", "레지", "계산대"),
                ("袋", "후쿠로", "봉투"),
                ("ポイントカード", "포인트카-도", "포인트카드"),
                ("レシート", "레시-토", "영수증"),
                ("温めますか", "아타타메마스카", "데워드릴까요?"),
                ("箸", "하시", "젓가락"),
                ("スプーン", "스푸-은", "스푼"),
                ("フォーク", "포-쿠", "포크"),
                ("ナプキン", "나푸킨", "냅킨"),
                ("現金", "겐킨", "현금"),
                ("カード", "카-도", "카드"),
                ("電子マネー", "덴시마네-", "전자결제"),
                ("支払い", "시하라이", "결제/지불"),
                ("小銭", "코제니", "동전"),
                ("両替", "료-가에", "환전/거슬러주기"),
            ],
        },
        # 28) 시설/장소
        "facility_place": {
            "title": "시설/장소",
            "items": [
                ("トイレ", "토이레", "화장실"),
                ("出口", "데구치", "출구"),
                ("入口", "이리구치", "입구"),
                ("階段", "카이단", "계단"),
                ("エレベーター", "에레베-타-", "엘리베이터"),
                ("エスカレーター", "에스카레-타-", "에스컬레이터"),
                ("券売機", "켄바이키", "발권기"),
                ("案内所", "안나이죠", "안내소"),
                ("待合室", "마치아이시츠", "대기실"),
                ("休憩所", "큐-케-죠", "휴게실"),
            ],
        },
        # 29) 혼자 여행
        "solo_travel": {
            "title": "혼자 여행",
            "items": [
                ("一人", "히토리", "혼자"),
                ("写真", "샤신", "사진"),
                ("お願い", "오네가이", "부탁"),
                ("おすすめ", "오스스메", "추천"),
                ("静か", "시즈카", "조용함"),
                ("席", "세키", "자리"),
                ("カウンター", "카운타-", "카운터"),
                ("待ち", "마치", "대기"),
                ("予約", "요야쿠", "예약"),
                ("利用", "리요-", "이용"),
            ],
        },
        
        # 32) 학교
        "school": {
            "title": "학교",
            "items": [
                ("学校", "각코-", "학교"),
                ("学生", "가쿠세이", "학생"),
                ("先生", "센세-", "선생님"),
                ("教室", "쿄-시츠", "교실"),
                ("黒板", "코쿠반", "칠판"),
                ("チョーク", "쵸-쿠", "분필"),
                ("ノート", "노-토", "노트"),
                ("鉛筆", "엔피츠", "연필"),
                ("消しゴム", "케시고무", "지우개"),
                ("本", "혼", "책"),
                ("机", "츠쿠에", "책상"),
                ("椅子", "이스", "의자"),
                ("授業", "쥬교-", "수업"),
                ("宿題", "슈쿠다이", "숙제"),
                ("試験", "시켄", "시험"),
                ("休み時間", "야스미지칸", "쉬는 시간"),
                ("図書館", "토쇼칸", "도서관"),
                ("体育館", "타이이쿠칸", "체육관"),
            ],
        },
        # 33) 회사/직장
        "office": {
            "title": "회사/직장",
            "items": [
                ("会社", "카이샤", "회사"),
                ("社員", "샤인", "사원"),
                ("上司", "죠-시", "상사"),
                ("同僚", "도-료-", "동료"),
                ("会議", "카이기", "회의"),
                ("資料", "시료-", "자료"),
                ("パソコン", "파소콘", "컴퓨터"),
                ("メール", "메-루", "이메일"),
                ("電話", "덴와", "전화"),
                ("仕事", "시고토", "일"),
                ("出勤", "슈-킨", "출근"),
                ("退勤", "타이킨", "퇴근"),
                ("残業", "잔교-", "야근"),
                ("休憩", "큐-케-", "휴식"),
                ("予定", "요테-", "일정"),
                ("締め切り", "시메키리", "마감"),
                ("報告", "호-코쿠", "보고"),
                ("給料", "큐-료-", "월급"),
            ],
        },
        # 34) 놀이공원
        "amusement_park": {
            "title": "놀이공원",
            "items": [
                ("遊園地", "유-엔치", "놀이공원"),
                ("チケット", "치켓토", "티켓"),
                ("入場券", "뉴-죠-켄", "입장권"),
                ("アトラクション", "아토라쿠숀", "놀이기구"),
                ("ジェットコースター", "젯토코-스타-", "롤러코스터"),
                ("観覧車", "칸란샤", "대관람차"),
                ("お土産", "오미야게", "기념품"),
                ("売店", "바이텐", "매점"),
                ("ポップコーン", "폿푸코-ン", "팝콘"),
                ("アイスクリーム", "아이스쿠리-무", "아이스크림"),
                ("列", "레츠", "줄"),
                ("並ぶ", "나라부", "줄 서다"),
                ("混雑", "콘자츠", "혼잡"),
                ("写真", "샤신", "사진"),
                ("案内", "안나이", "안내"),
                ("地図", "치즈", "지도"),
                ("出口", "데구치", "출구"),
                ("休憩所", "큐-케-죠", "휴게소"),
            ],
        },
        # 35) 수족관
        "aquarium": {
            "title": "수족관",
            "items": [
                ("水族館", "스이조쿠칸", "수족관"),
                ("魚", "사카나", "물고기"),
                ("イルカ", "이루카", "돌고래"),
                ("サメ", "사메", "상어"),
                ("クラゲ", "쿠라게", "해파리"),
                ("ペンギン", "펜긴", "펭귄"),
                ("アシカ", "아시카", "바다사자"),
                ("ショー", "쇼-", "공연"),
                ("水槽", "스이소-", "수조"),
                ("餌", "에사", "먹이"),
                ("餌やり", "에사야리", "먹이 주기"),
                ("写真", "샤신", "사진"),
                ("展示", "텐지", "전시"),
                ("入口", "이리구치", "입구"),
                ("出口", "데구치", "출구"),
                ("案内", "안나이", "안내"),
                ("子ども", "코도모", "아이"),
                ("人気", "닌키", "인기"),
            ],
        },
        # 36) 여행지/관광
        "travel_spots": {
            "title": "여행지/관광",
            "items": [
                ("観光地", "칸코-치", "관광지"),
                ("名所", "메이쇼", "명소"),
                ("写真", "샤신", "사진"),
                ("景色", "케시키", "경치"),
                ("展望台", "텐보-다이", "전망대"),
                ("公園", "코-엔", "공원"),
                ("神社", "진쟈", "신사"),
                ("お寺", "오테라", "절"),
                ("市場", "이치바", "시장"),
                ("街", "마치", "거리"),
                ("案内所", "안나이죠", "안내소"),
                ("地図", "치즈", "지도"),
                ("入場料", "뉴-죠-료-", "입장료"),
                ("開店", "카이텐", "개점"),
                ("閉店", "헤이텐", "폐점"),
                ("混雑", "콘자츠", "혼잡"),
                ("空いている", "아이테이루", "한산하다"),
                ("おすすめ", "오스스메", "추천"),
                ("割引", "와리비키", "할인"),
                ("学生", "가쿠세이", "학생"),
                ("子ども料金", "코도모료-킨", "아동요금"),
                ("営業時間", "에-교-지칸", "영업시간"),
                ("定休日", "테-큐-비", "휴무일"),
            ],
        },
        # 37) 슈퍼/마트
        "supermarket": {
            "title": "슈퍼/마트",
            "items": [
                ("スーパー", "스-파-", "슈퍼마켓"),
                ("ドラッグストア", "도랏구스토아", "드럭스토어(약/화장품)"),
                ("買い物かご", "카이모노카고", "장바구니(바구니)"),
                ("カート", "카-토", "카트"),
                ("レジ", "레지", "계산대"),
                ("セルフレジ", "세루후레지", "셀프 계산대"),
                ("値札", "네후다", "가격표"),
                ("セール", "세-루", "세일"),
                ("割引", "와리비키", "할인"),
                ("特売", "토쿠바이", "특가판매"),
                ("賞味期限", "쇼-미키겐", "상미기한(유통기한)"),
                ("消費期限", "쇼-히키겐", "소비기한"),
                ("冷蔵", "레이조-", "냉장"),
                ("冷凍", "레-토-", "냉동"),
                ("常温", "죠-온", "상온"),
                ("野菜", "야사이", "채소"),
                ("果物", "쿠다모노", "과일"),
                ("肉", "니쿠", "고기"),
                ("魚", "사카나", "생선"),
                ("飲み物", "노미모노", "음료"),
            ],
        },
        # 38) 술/이자카야
        "izakaya": {
            "title": "술/이자카야",
            "items": [
                ("居酒屋", "이자카야", "이자카야"),
                ("予約", "요야쿠", "예약"),
                ("乾杯", "칸파이", "건배"),
                ("ビール", "비-루", "맥주"),
                ("生ビール", "나마비-루", "생맥주"),
                ("ハイボール", "하이보-루", "하이볼"),
                ("日本酒", "니혼슈", "사케"),
                ("焼酎", "쇼-츄-", "소주(일본식)"),
                ("梅酒", "우메슈", "매실주"),
                ("ワイン", "와인", "와인"),
                ("ノンアルコール", "논아루코-루", "무알콜"),
                ("おつまみ", "오츠마미", "안주"),
                ("おすすめ", "오스스메", "추천"),
                ("おかわり", "오카와리", "한 잔 더"),
                ("お通し", "오토-시", "기본 안주"),
                ("喫煙席", "키츠엔세키", "흡연석"),
                ("禁煙席", "킨엔세키", "금연석"),
                ("酔った", "욧타", "취했어요"),
                ("会計", "카이케-", "계산"),
                ("レシート", "레시-토", "영수증"),
            ],
        },
        # 39) 화장실/위생
        "toilet_hygiene": {
            "title": "화장실/위생",
            "items": [
                ("トイレ", "토이레", "화장실"),
                ("お手洗い", "오테아라이", "화장실(정중)"),
                ("男性", "단세-", "남성"),
                ("女性", "죠세-", "여성"),
                ("多目的トイレ", "타모쿠테키토이레", "다목적 화장실"),
                ("空いている", "아이테이루", "비어 있다"),
                ("使用中", "시요-츄-", "사용 중"),
                ("紙", "카미", "종이"),
                ("トイレットペーパー", "토이렛토페-파-", "휴지"),
                ("石けん", "세켄", "비누"),
                ("消毒", "쇼-도쿠", "소독"),
                ("消毒液", "쇼-도쿠에키", "소독액"),
                ("手洗い", "테아라이", "손 씻기"),
                ("ハンドソープ", "한도소-푸", "핸드워시"),
                ("タオル", "타오루", "수건"),
                ("ハンカチ", "한카치", "손수건"),
                ("ゴミ箱", "고미바코", "쓰레기통"),
                ("流す", "나가스", "물 내리다"),
                ("便座", "벤자", "변좌"),
                ("ウォシュレット", "워슈렛토", "비데"),
            ],
        },
        
        # 41) 분실/찾기
        "lost_found": {
            "title": "분실/찾기",
            "items": [
                ("落とし物", "오토시모노", "분실물"),
                ("忘れ物", "와스레모노", "두고 온 물건"),
                ("紛失", "분시츠", "분실"),
                ("なくした", "나쿠시타", "잃어버렸어요"),
                ("探す", "사가스", "찾다"),
                ("見つかる", "미츠카루", "찾아지다"),
                ("見つける", "미츠케루", "찾아내다"),
                ("どこで", "도코데", "어디에서"),
                ("いつ", "이츠", "언제"),
                ("警察", "케-사츠", "경찰"),
                ("交番", "코-반", "파출소"),
                ("駅員", "에키인", "역무원"),
                ("案内所", "안나이죠", "안내소"),
                ("遺失物センター", "이시츠부츠센타-", "분실물 센터"),
                ("身分証", "미분쇼-", "신분증"),
                ("財布", "사이후", "지갑"),
                ("携帯", "케-타이", "휴대폰"),
                ("鍵", "카기", "열쇠"),
                ("かばん", "카방", "가방"),
                ("届ける", "토도케루", "신고하다"),
            ],
        },
        # 42) 드럭스토어/화장품
        "drugstore_cosmetics": {
            "title": "드럭스토어/화장품",
            "items": [
                ("ドラッグストア", "도랏구스토아", "드럭스토어"),
                ("薬", "쿠스리", "약"),
                ("風邪薬", "카제구스리", "감기약"),
                ("痛み止め", "이타미도메", "진통제"),
                ("絆創膏", "반소-코-", "반창고"),
                ("のど飴", "노도아메", "목캔디"),
                ("目薬", "메구스리", "안약"),
                ("マスク", "마스쿠", "마스크"),
                ("化粧品", "케쇼-힌", "화장품"),
                ("クレンジング", "쿠렌징구", "클렌징"),
                ("洗顔", "센간", "세안"),
                ("化粧水", "케쇼-스이", "스킨"),
                ("乳液", "뉴-에키", "로션"),
                ("クリーム", "쿠리-무", "크림"),
                ("日焼け止め", "히야케도메", "선크림"),
                ("シャンプー", "샴푸-", "샴푸"),
                ("リンス", "린스", "컨디셔너"),
                ("ハンドクリーム", "한도쿠리-무", "핸드크림"),
                ("香水", "코-스이", "향수"),
                ("免税", "멘제-", "면세"),
                ("ドラッグストア", "도랏구스토아", "드럭스토어"),
                ("化粧品", "케쇼-힌", "화장품"),
                ("日焼け止め", "히야케도메", "선크림"),
                ("クレンジング", "쿠렌진구", "클렌징"),
                ("洗顔", "센간", "세안"),
                ("化粧水", "케쇼-스이", "스킨/토너"),
                ("乳液", "뉴-에키", "로션/에멀전"),
                ("クリーム", "쿠리-무", "크림"),
                ("パック", "팟쿠", "팩/마스크"),
                ("香水", "코-스이", "향수"),
                ("薬", "쿠스리", "약"),
                ("絆創膏", "반소-코-", "밴드"),
                ("目薬", "메구스리", "안약"),
                ("風邪薬", "카제구스리", "감기약"),
                ("痛み止め", "이타미도메", "진통제"),
                ("酔い止め", "요이도메", "멀미약"),
            ],
        },
        # 43) 가족/친척(호칭)
        "family_relatives": {
            "title": "가족/친척(호칭)",
            "items": [
                # ─────────────────────────
                # 내 가족을 말할 때(겸양형)
                # ─────────────────────────
                ("父", "치치", "아버지(내)  | 예문: 父は会社にいます。= 제 아버지는 회사에 계세요."),
                ("母", "하하", "어머니(내)  | 예문: 母は料理が上手です。= 제 어머니는 요리를 잘하세요."),
                ("両親", "료-신", "부모님(내) | 예문: 両親は韓国にいます。= 우리 부모님은 한국에 계세요."),
                ("兄", "아니", "형/오빠(내) | 예문: 兄は日本に住んでいます。= 제 형(오빠)은 일본에 살아요."),
                ("姉", "아네", "누나/언니(내) | 예문: 姉は学生です。= 제 누나(언니)는 학생이에요."),
                ("弟", "오토-토", "남동생 | 예문: 弟は背が高いです。= 제 남동생은 키가 커요."),
                ("妹", "이모-토", "여동생 | 예문: 妹は高校生です。= 제 여동생은 고등학생이에요."),
                ("夫", "옷토", "남편(내) | 예문: 夫は今、仕事中です。= 제 남편은 지금 일하는 중이에요."),
                ("妻", "츠마", "아내(내) | 예문: 妻は買い物に行きました。= 제 아내는 쇼핑하러 갔어요."),
                ("息子", "무스코", "아들(내) | 예문: 息子は5歳です。= 제 아들은 5살이에요."),
                ("娘", "무스메", "딸(내) | 예문: 娘はピアノを習っています。= 제 딸은 피아노를 배우고 있어요."),
                ("祖父", "소후", "할아버지(내) | 예문: 祖父は元気です。= 제 할아버지는 건강하세요."),
                ("祖母", "소보", "할머니(내) | 예문: 祖母は毎朝散歩します。= 제 할머니는 매일 아침 산책하세요."),
                ("孫", "마고", "손자/손녀 | 예문: 孫に会いたいです。= 손주를 만나고 싶어요."),

                # ─────────────────────────
                # 가족을 부를 때/상대 가족(존칭형)
                # ─────────────────────────
                ("お父さん", "오토-상", "아빠/아버지(부를 때) | 예문: お父さん、ちょっと待って！= 아빠, 잠깐만!"),
                ("お母さん", "오카-상", "엄마/어머니(부를 때) | 예문: お母さん、ありがとう。= 엄마, 고마워."),
                ("お兄さん", "오니-상", "형/오빠(부를 때·상대) | 예문: お兄さん、こちらです。= 형(오빠), 이쪽이에요."),
                ("お姉さん", "오네-상", "누나/언니(부를 때·상대) | 예문: お姉さん、すみません。= 누나(언니), 실례합니다."),
                ("おじいさん", "오지-상", "할아버지(부를 때·상대) | 예문: おじいさん、大丈夫ですか。= 할아버지, 괜찮으세요?"),
                ("おばあさん", "오바-상", "할머니(부를 때·상대) | 예문: おばあさん、気をつけて。= 할머니, 조심하세요."),
                ("ご両親", "고료-신", "부모님(상대) | 예문: ご両親はお元気ですか。= 부모님은 잘 지내세요?"),
                ("ご主人", "고슈진", "남편(상대의 남편) | 예문: ご主人はどちらですか。= 남편분은 어디 계세요?"),
                ("奥さん", "오쿠상", "아내/부인(상대) | 예문: 奥さんは日本人ですか。= 부인께서는 일본 분이세요?"),

                # ─────────────────────────
                # 친척/관계(중립/일반)
                # ─────────────────────────
                ("おじ", "오지", "삼촌(일반) | 예문: おじは大阪に住んでいます。= 삼촌은 오사카에 살아요."),
                ("おば", "오바", "이모/고모(일반) | 예문: おばに会いに行きます。= 이모(고모) 만나러 갈 거예요."),
                ("いとこ", "이토코", "사촌 | 예문: いとこと旅行しました。= 사촌과 여행했어요."),
                ("親戚", "신세키", "친척 | 예문: 親戚が日本にいます。= 일본에 친척이 있어요."),

                # ─────────────────────────
                # 결혼으로 생긴 가족(시가/처가)
                # ─────────────────────────
                ("義父", "기후", "시아버지/장인(내) | 예문: 義父に挨拶します。= 장인(시아버지)께 인사해요."),
                ("義母", "기보", "시어머니/장모(내) | 예문: 義母に電話します。= 장모(시어머니)께 전화해요."),
                ("義理の兄", "기리노 아니", "형부/시아주버니 | 예문: 義理の兄は優しいです。= 형부(시아주버니)는 친절해요."),
                ("義理の姉", "기리노 아네", "처형/시누이 | 예문: 義理の姉に会いました。= 처형(시누이)을 만났어요."),

                # ─────────────────────────
                # 연인(참고)
                # ─────────────────────────
                ("彼氏", "카레시", "남자친구 | 예문: 彼氏と旅行します。= 남자친구와 여행해요."),
                ("彼女", "카노죠", "여자친구 | 예문: 彼女は日本語が上手です。= 제 여자친구는 일본어를 잘해요."),
                ("旦那", "단나", "남편(구어) | 예문: 旦那は今、家にいます。= 남편은 지금 집에 있어요."),
            ],
        },

        "travel_verbs": {
            "title": "여행 필수 동사",
            "items": [
                ("探す", "사가스", "찾다"),
                ("迷う", "마요우", "헤매다"),
                ("予約する", "요야쿠스루", "예약하다"),
                ("変更する", "헨코-스루", "변경하다"),
                ("キャンセルする", "캰세루스루", "취소하다"),
                ("確認する", "카쿠닌스루", "확인하다"),
                ("案内する", "안나이스루", "안내하다"),
                ("払う", "하라우", "지불하다"),
                ("乗る", "노루", "타다"),
                ("降りる", "오리루", "내리다"),
                ("降りる場所", "오리루 바쇼", "내릴 곳"),
                ("開ける", "아케루", "열다"),
                ("閉める", "시메루", "닫다"),
                ("入る", "하이루", "들어가다"),
                ("出る", "데루", "나가다"),
                ("撮る", "토루", "찍다"),
                ("送る", "오쿠루", "보내다"),
                ("借りる", "카리루", "빌리다"),
                ("返す", "카에스", "돌려주다"),
                ("使う", "츠카우", "사용하다"),
                ("止める", "토메루", "멈추다"),
                ("待つ", "마츠", "기다리다"),
                ("急ぐ", "이소구", "서두르다"),
                ("並ぶ", "나라부", "줄 서다"),
                ("入れる", "이레루", "넣다"),
                ("出す", "다스", "꺼내다/제출하다"),
                ("預ける", "아즈케루", "맡기다"),
                ("受け取る", "우케토루", "받다"),
                ("見せる", "미세루", "보여주다"),
                ("探し出す", "사가시다스", "찾아내다"),
                ("間違える", "마치가에루", "틀리다"),
                ("困る", "코마루", "곤란하다"),
                ("忘れる", "와스레루", "잊다"),
                ("落とす", "오토스", "떨어뜨리다"),
                ("壊れる", "코와레루", "고장나다"),
                ("直す", "나오스", "고치다"),
                ("助ける", "타스케루", "도와주다"),
                ("注文する", "츄-몬스루", "주문하다"),
                ("頼む", "타노무", "부탁하다"),
                ("選ぶ", "에라부", "고르다"),
                ("比べる", "쿠라베루", "비교하다"),
                ("探し回る", "사가시마와루", "찾아다니다"),
                ("向かう", "무카우", "향하다"),
                ("到着する", "토-챠쿠스루", "도착하다"),
                ("出発する", "슈빠츠스루", "출발하다"),
                ("泊まる", "토마루", "묵다"),
                ("案内される", "안나이사레루", "안내받다"),
                ("乗り換える", "노리카에루", "환승하다"),
                ("通る", "토오루", "지나다"),
                ("曲がる", "마가루", "돌다"),
                ("続ける", "츠즈케루", "계속하다"),
                ("止まる", "토마루", "서다"),
                ("混む", "코무", "붐비다"),
                ("空く", "아쿠", "비다"),
                ("集まる", "아츠마루", "모이다"),
                ("離れる", "하나레루", "떠나다"),
                ("戻る", "모도루", "돌아오다"),
                ("調べる", "시라베루", "찾아보다/조사하다"),
                ("覚える", "오보에루", "외우다"),
                ("忘れ物する", "와스레모노스루", "물건을 두고 오다"),
                ("運ぶ", "하코부", "나르다"),
                ("置く", "오쿠", "두다"),
                ("取る", "토루", "집다/받다"),
                ("渡す", "와타스", "건네주다"),
                ("片付ける", "카타즈케루", "정리하다"),
                ("入れ替える", "이레카에루", "바꾸다"),
                ("確認できる", "카쿠닌데키루", "확인할 수 있다"),
            ],
        },

}




def get_daily_phrase() -> Dict[str, str]:
    day_key = kst_today_key()
    conn = db()
    row = conn.execute(
        "SELECT jp, pron, ko FROM daily_phrase WHERE day_key=?",
        (day_key,),
    ).fetchone()

    if row:
        conn.close()
        return {"jp": row["jp"], "pron": row["pron"], "ko": row["ko"]}

    phrase = random.choice(DAILY_POOL)
    conn.execute(
        "INSERT OR REPLACE INTO daily_phrase(day_key, jp, pron, ko) VALUES (?, ?, ?, ?)",
        (day_key, phrase["jp"], phrase["pron"], phrase["ko"]),
    )
    conn.commit()
    conn.close()
    return phrase


# -------------------------
# Auth helpers
# -------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return dict(u) if u else None



def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("로그인이 필요합니다.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

@app.get("/mypage")
@login_required
def mypage():
    user = current_user()
    if user and not isinstance(user, dict):
        user = dict(user)

    post_cnt = 0
    comment_cnt = 0
    received_cnt = 0
    unread_cnt = 0
    recent = []

    conn = db()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM board_posts WHERE user_id=?",
            (user["id"],),
        ).fetchone()
        post_cnt = int(row["cnt"] or 0) if row else 0

        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM board_comments WHERE user_id=?",
            (user["id"],),
        ).fetchone()
        comment_cnt = int(row["cnt"] or 0) if row else 0

        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM board_comments c
            JOIN board_posts p ON p.id = c.post_id
            WHERE p.user_id=? AND c.user_id != ?
            """,
            (user["id"], user["id"]),
        ).fetchone()
        received_cnt = int(row["cnt"] or 0) if row else 0

        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM notifications WHERE user_id=? AND is_read=0",
            (user["id"],),
        ).fetchone()
        unread_cnt = int(row["cnt"] or 0) if row else 0

        recent = conn.execute(
            """
            SELECT id, type, post_id, from_nickname, message, is_read, created_at
            FROM notifications
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT 10
            """,
            (user["id"],),
        ).fetchall()

    finally:
        conn.close()

    # ✅ 공통 로직으로 통일
    grade = get_user_grade_label(user)
    score = get_user_score(user)
    prog = score_progress_info(score)

    return render_template(
        "mypage.html",
        user=user,
        grade=grade,
        score=score,   # ✅ 템플릿에서 보여주고 싶으면 사용
        prog=prog,
        post_cnt=post_cnt,
        comment_cnt=comment_cnt,
        received_cnt=received_cnt,
        unread_cnt=unread_cnt,
        recent=recent,
    )


ADMIN_USERNAME = "cjswoaostk"

def is_admin(user):
    if not user:
        return False
    un = (user.get("username") or "").strip()
    nn = (user.get("nickname") or "").strip()
    cg = (user.get("custom_grade") or "").strip()

    # ✅ 기존 관리자 아이디 + 너가 쓰는 ADMIN 계정 + 닉네임 SW + custom_grade에 관리자 계열 들어가면 관리자 처리
    if un == ADMIN_USERNAME:
        return True
    if un.upper() == "ADMIN":
        return True
    if nn == "SW":
        return True
    if ("관리자" in cg) or ("총관리자" in cg) or ("왕관리" in cg):
        return True

    return False


def get_user_score(user: dict) -> int:
    """
    경험치 = (출석일수 * 3) + (글 10개당 3점)
    """
    if not user or not user.get("id"):
        return 0

    uid = user["id"]
    conn = db()
    try:
        # 출석일수
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM user_attendance WHERE user_id=?",
            (uid,),
        ).fetchone()
        attendance_days = int(row["cnt"] or 0) if row else 0

        # 작성 글 수
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM board_posts WHERE user_id=?",
            (uid,),
        ).fetchone()
        post_cnt = int(row["cnt"] or 0) if row else 0

    finally:
        conn.close()

    score = attendance_days * 3 + (post_cnt // 10) * 3
    return int(score)

def score_to_grade(score: int) -> str:
    # ✅ 계급 구간 (요청한 이모지)
    if score >= 1001:
        return "마스터 🎖️"
    elif score >= 501:
        return "다이아 💎"
    elif score >= 201:
        return "골드 🥇"
    elif score >= 51:
        return "실버 🥈"
    elif score >= 11:
        return "브론즈 🥉"
    else:
        return "입문 🌱"

def score_progress_info(score: int) -> dict:
    """
    현재 점수(score)를 기준으로
    - 현재 계급 / 다음 계급 / 다음 계급까지 남은 점수 / 진행률(0~100)
    을 계산해서 dict로 반환
    """
    # (구간, 라벨) : "해당 점수 이상이면 이 계급"
    tiers = [
        (0, "입문 🌱"),
        (11, "브론즈 🥉"),
        (51, "실버 🥈"),
        (201, "골드 🥇"),
        (501, "다이아 💎"),
        (1001, "마스터 🎖️"),
    ]

    score = int(score or 0)

    # 현재 구간 찾기
    cur_idx = 0
    for i in range(len(tiers) - 1, -1, -1):
        if score >= tiers[i][0]:
            cur_idx = i
            break

    cur_floor, cur_label = tiers[cur_idx]

    # 이미 최종 계급이면
    if cur_idx == len(tiers) - 1:
        return {
            "cur_grade": cur_label,
            "next_grade": None,
            "cur_floor": cur_floor,
            "next_threshold": None,
            "remain": 0,
            "pct": 100,
            "score": score,
        }

    next_threshold, next_label = tiers[cur_idx + 1]

    span = max(1, next_threshold - cur_floor)
    progressed = min(span, max(0, score - cur_floor))
    pct = int(round((progressed / span) * 100))

    remain = max(0, next_threshold - score)

    return {
        "cur_grade": cur_label,
        "next_grade": next_label,
        "cur_floor": cur_floor,
        "next_threshold": next_threshold,
        "remain": remain,
        "pct": pct,
        "score": score,
    }

def get_user_grade_label(user: dict) -> str:
    """
    - 관리자: users.custom_grade 있으면 그걸, 없으면 '총관리자 👑'
    - 일반: 출석/글 기반 score로 계급 산정
    """
    if not user or not user.get("id"):
        return "입문 🌱"

    uid = user["id"]
    conn = db()
    try:
        row = conn.execute(
            "SELECT custom_grade FROM users WHERE id=?",
            (uid,),
        ).fetchone()
        custom_grade = (row["custom_grade"] if row and row["custom_grade"] else None)
    finally:
        conn.close()

    if is_admin(user):
        return custom_grade or "총관리자 👑"

    score = get_user_score(user)
    return score_to_grade(score)



def pick_phrase_from_situations(cat_key=None, sub_key=None):
    """
    네 문장목록에서 (jp, pron, ko) 하나를 뽑는다.
    cat_key/sub_key 지정하면 그 범위에서만 뽑기.
    (jp, pron, ko, source)처럼 4개 튜플도 안전 처리
    """
    candidates = []

    for ck, cat in SITUATIONS.items():
        if cat_key and ck != cat_key:
            continue

        subs = cat.get("subs", {})
        for sk, sub in subs.items():
            if sub_key and sk != sub_key:
                continue

            for item in sub.get("items", []):
                # item이 (jp, pron, ko) 또는 (jp, pron, ko, source) 모두 대응
                jp, pron, ko = item[:3]
                source = item[3] if len(item) > 3 else None

                candidates.append({
                    "cat": ck, "sub": sk,
                    "jp": jp, "pron": pron, "ko": ko,
                    "source": source
                })

    return random.choice(candidates) if candidates else None


def pick_phrase_from_category(cat_key: str, sub_key: str = None):
    cat = SITUATIONS.get(cat_key)
    if not cat:
        return None

    candidates = []

    for sk, sub in cat.get("subs", {}).items():
        if sub_key and sk != sub_key:
            continue

        for item in sub.get("items", []):
            jp, pron, ko = item[:3]
            source = item[3] if len(item) > 3 else None

            candidates.append({
                "jp": jp,
                "pron": pron,
                "ko": ko,
                "source": source,
            })

    return random.choice(candidates) if candidates else None

@app.before_request
def _auto_attendance():
    user = current_user()
    if user:
        mark_attendance_today(user)


@app.route("/games/dialog_typing/school")
def dialog_typing_school():
    partner = pick_phrase_from_category("school_dialog", "classroom")
    answer = pick_phrase_from_category("school_dialog", "classroom")

    quiz = {
        "scene_title": "학교 대화 퀴즈",
        "image": "/static/dialog_quiz/bg_school.png",  # 배경이미지 넣기
        "partner_jp": partner["jp"],
        "partner_pron": partner["pron"],

        # 정답은 발음(pron) 입력
        "answer_pron": answer["pron"],
        "answer_ko": answer["ko"],

        # (원하면 표시용) 정답 일본어도 같이 숨겨둘 수 있음
        "answer_jp": answer["jp"],
    }
    return render_template("dialog_typing_pron.html", quiz=quiz)


@app.route("/games/dialog_typing/check_pron", methods=["POST"])
def dialog_typing_check_pron():
    user_input = request.form.get("user_input", "")
    answer_pron = request.form.get("answer_pron", "")
    answer_ko = request.form.get("answer_ko", "")
    answer_jp = request.form.get("answer_jp", "")

    ok = normalize_pron(user_input) == normalize_pron(answer_pron)

    return jsonify({
        "ok": ok,
        "answer_pron": answer_pron,
        "answer_jp": answer_jp,
        "answer_ko": answer_ko,
    })



def normalize_author_grade(grade: str) -> str:
    """공백/None 방어용"""
    g = (grade or "").strip()
    return g if g else "일반"


@app.post("/mypage/grade", endpoint="mypage_grade_update")
@login_required
def mypage_grade_update():
    user = current_user()
    if user and not isinstance(user, dict):
        user = dict(user)

    if not is_admin(user):
        abort(403)

    new_grade = (request.form.get("custom_grade") or "").strip()

    # 길이 제한
    if len(new_grade) > 30:
        flash("계급은 30자 이하로 입력해주세요.", "error")
        return redirect(url_for("mypage"))

    conn = db()
    try:
        conn.execute(
            "UPDATE users SET custom_grade=? WHERE id=?",
            (new_grade if new_grade else None, user["id"]),
        )
        conn.commit()
    finally:
        conn.close()

    flash("관리자 계급이 변경됐어요.", "success")
    return redirect(url_for("mypage"))


# -------------------------
# Validation helpers
# -------------------------
def validate_username_format(username: str) -> Optional[str]:
    if not USERNAME_RE.match(username or ""):
        return "아이디는 3~20자 영문+숫자이며, 영문으로 시작해야 합니다."
    return None


def validate_password_format(password: str) -> Optional[str]:
    if not (8 <= len(password or "") <= 16):
        return "비밀번호는 8~16자로 입력해주세요."
    return None


def validate_email_format(email: str) -> Optional[str]:
    if not EMAIL_RE.match(email or ""):
        return "이메일 형식이 올바르지 않습니다."
    if not is_naver_email(email):
        return "naver.com 이메일만 가입 가능합니다."
    return None


def username_exists(username: str) -> bool:
    conn = db()
    row = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row is not None


def email_exists(email: str) -> bool:
    conn = db()
    row = conn.execute("SELECT 1 FROM users WHERE email=?", (email.lower(),)).fetchone()
    conn.close()
    return row is not None

@app.before_request
def load_global_unread():
    g.unread_cnt = 0
    u = current_user()
    if not u:
        return
    conn = db()
    try:
        g.unread_cnt = conn.execute(
            "SELECT COUNT(*) AS cnt FROM notifications WHERE user_id=? AND is_read=0",
            (u["id"],),
        ).fetchone()["cnt"]
    finally:
        conn.close()


@app.before_request
def touch_last_seen():
    u = current_user()
    if not u:
        return

    last_touch = session.get("_last_seen_touch")
    now_ts = datetime.now(timezone.utc).timestamp()
    if last_touch and (now_ts - float(last_touch) < 300):
        return

    session["_last_seen_touch"] = now_ts

    conn = db()
    try:
        conn.execute(
            "UPDATE users SET last_seen_at=? WHERE id=?",
            (kst_now_iso(), u["id"]),
        )
        conn.commit()
    finally:
        conn.close()




# -------------------------
# Routes
# -------------------------
@app.route("/")
def index():
    user = current_user()
    try:
        daily = get_daily_phrase()
    except Exception:
        daily = {"jp": "", "pron": "", "ko": ""}

    return render_template(
        "index.html",
        user=user,
        daily=daily,   # ✅ 이 한 줄 추가
        **seo(
            title="일본 여행 회화 공부방 | 상황별 일본어 회화 · 단어 · 퀴즈 학습",
            desc="일본 여행에서 바로 쓰는 필수 일본어 회화와 단어를 상황별로 학습하세요. 퀴즈와 학습노트로 빠르게 실력을 높일 수 있는 무료 공부방입니다.",
            keywords="일본 여행 회화, 일본어 회화 공부, 여행 일본어 표현, 일본어 단어, 일본어 퀴즈"
        )
    )


@app.route("/words")
def words_categories():
    user = current_user()

    categories = []
    for k, v in (WORDS or {}).items():
        items = v.get("items", [])
        categories.append({
            "key": k,
            "title": v.get("title", k),
            "count": len(items),
        })

    ctx = build_words_seo()

    return render_template(
        "words_categories.html",
        user=user,
        categories=categories,
        **ctx
    )


@app.route("/words/<cat_key>")
def words_detail(cat_key):
    user = current_user()
    q = (request.args.get("q") or "").strip()  # ✅ 검색어

    cat = (WORDS or {}).get(cat_key)
    if not cat:
        ctx = build_words_seo("단어")
        return render_template(
            "words_detail.html",
            user=user,
            title="없음",
            cat_key=cat_key,
            rows=[],
            fav_jp_set=set(),
            q=q,  # ✅ 템플릿에서 값 유지
            **ctx
        )

    title = cat.get("title", cat_key)
    rows_all = cat.get("items", [])

    # ✅ rows 필터링: jp/pron/ko 중 하나라도 q 포함하면 통과
    if q:
        qq = q.lower()
        rows = []
        for r in rows_all:
            # items가 [jp, pron, ko] 형태일 가능성이 높음
            jp = r[0] if len(r) > 0 else ""
            pron = r[1] if len(r) > 1 else ""
            ko = r[2] if len(r) > 2 else ""

            if (qq in (jp or "").lower()
                or qq in (pron or "").lower()
                or qq in (ko or "").lower()):
                rows.append(r)
    else:
        rows = rows_all

    fav_jp_set = set()
    if user:
        conn = db()
        try:
            ensure_word_favorites_table(conn)
            fav_rows = conn.execute(
                "SELECT jp FROM word_favorites WHERE user_id=? AND cat_key=?",
                (user["id"], cat_key),
            ).fetchall()
            fav_jp_set = {r["jp"] for r in fav_rows}
        finally:
            conn.close()

    # ✅ SEO: 검색 중이면 타이틀/설명도 검색형으로(선택 but 추천)
    if q:
        ctx = build_words_seo(f"{title} 검색: {q}")
    else:
        ctx = build_words_seo(title)

    return render_template(
        "words_detail.html",
        user=user,
        title=title,
        cat_key=cat_key,
        rows=rows,
        fav_jp_set=fav_jp_set,
        q=q,  # ✅ 템플릿에서 값 유지
        **ctx
    )
@app.get("/words/search")
def words_search():
    user = current_user()
    q = (request.args.get("q") or "").strip()

    results = []
    if q:
        qq = q.lower()
        for cat_key, cat in (WORDS or {}).items():
            cat_title = cat.get("title", cat_key)
            for row in (cat.get("items", []) or []):
                jp = row[0] if len(row) > 0 else ""
                pron = row[1] if len(row) > 1 else ""
                ko = row[2] if len(row) > 2 else ""

                if (qq in (jp or "").lower()
                    or qq in (pron or "").lower()
                    or qq in (ko or "").lower()):
                    results.append({
                        "cat_key": cat_key,
                        "cat_title": cat_title,
                        "jp": jp,
                        "pron": pron,
                        "ko": ko,
                    })

    return render_template("words_search.html", user=user, q=q, results=results)


def build_words_seo(cat_title: str | None = None):
    """
    단어모음 SEO + 소개문 자동 생성
    - cat_title 없으면: /words(카테고리 목록)
    - cat_title 있으면: /words/<cat_key>(상세)
    """
    if cat_title:
        # 상세 페이지
        title = f"일본 여행 필수 일본어 단어 모음 | {cat_title}"
        desc = (
            f"일본 여행에서 자주 쓰는 {cat_title} 필수 일본어 단어를 정리했습니다. "
            f"단어, 발음, 뜻을 한 번에 확인하고 빠르게 암기해보세요."
        )
        keywords = f"일본어 단어, 일본 여행 단어, {cat_title} 일본어, 일본어 발음, 일본어 뜻"
        page_intro = (
            f"일본 여행 중 자주 쓰는 {cat_title} 필수 일본어 단어를 정리했습니다. "
            f"단어/발음/뜻을 함께 보면서 빠르게 외울 수 있어요."
        )
    else:
        # 목록 페이지
        title = "일본 여행 필수 일본어 단어 모음 | 숫자·시간·교통·쇼핑 단어"
        desc = "일본 여행에서 바로 쓰는 필수 일본어 단어를 분류별로 모았습니다. 숫자, 시간, 교통, 쇼핑 등 핵심 단어를 빠르게 학습하세요."
        keywords = "일본어 단어, 일본 여행 단어, 일본어 단어 모음, 여행 일본어 단어, 일본어 발음"
        page_intro = "일본 여행에서 자주 쓰는 필수 일본어 단어를 분류별로 한 곳에 정리했습니다."

    ctx = seo(title=title, desc=desc, keywords=keywords)
    ctx["page_intro"] = page_intro
    return ctx


@app.get("/situations")
def situations():
    user = current_user()   # ✅ 이거 추가

    ctx = seo(
        title="상황별 일본 여행 회화 | 공항·호텔·교통·식당·응급",
        desc="공항, 호텔, 교통, 음식점 등 상황별 일본 여행 필수 회화를 모아 쉽고 재미있게 학습하세요.",
        keywords="상황별 일본어, 일본 여행 회화, 공항 일본어, 호텔 일본어, 식당 일본어"
    )
    ctx["page_intro"] = "공항, 호텔, 교통, 음식점 등 일본 여행에서 자주 마주치는 상황별 일본어 회화를 한 곳에 정리했습니다."

    return render_template(
        "situation.html",
        user=user,                 # ✅ 핵심!!
        **ctx,
        situations=SITUATIONS
    )


@app.get("/situations/<main_key>/<sub_key>")
def situation_detail(main_key: str, sub_key: str):
    user = current_user()

    q = (request.args.get("q") or "").strip()   # ✅ 검색어

    cat = SITUATIONS.get(main_key)
    if not cat:
        abort(404)

    sub = (cat.get("subs") or {}).get(sub_key)
    if not sub:
        abort(404)

    items = []
    for i, t in enumerate(sub.get("items", [])):
        jp = t[0]
        pron = t[1]
        ko = t[2]

        # ✅ 검색 필터: jp/pron/ko 중 하나라도 포함되면 통과
        if q:
            qq = q.lower()
            if (qq not in (jp or "").lower()
                and qq not in (pron or "").lower()
                and qq not in (ko or "").lower()):
                continue

        items.append({
            "phrase_key": f"{main_key}:{sub_key}:{i}",
            "jp": jp,
            "pron": pron,
            "ko": ko,
            "source": None,
            "is_fav": False,
        })

    cat_title = cat.get("title", "")
    sub_title = sub.get("title", "")

    if main_key == "anime_quotes":
        page_intro = None
    else:
        page_intro = f"일본 여행 중 {cat_title}에서 {sub_title} 상황에 자주 사용하는 일본어 회화 표현을 정리했습니다."

    return render_template(
        "situation_detail.html",
        user=user,
        cat_title=cat_title,
        sub_title=sub_title,
        main_key=main_key,
        sub_key=sub_key,
        items=items,
        page_intro=page_intro,
        q=q,  # ✅ 템플릿에서 검색창 값 유지용
    )


@app.get("/situations/search")
def situations_search():
    user = current_user()
    q = (request.args.get("q") or "").strip()

    results = []
    if q:
        qq = q.lower()

        for main_key, cat in (SITUATIONS or {}).items():
            cat_title = cat.get("title", main_key)
            subs = (cat.get("subs") or {})
            for sub_key, sub in subs.items():
                sub_title = sub.get("title", sub_key)

                for t in (sub.get("items", []) or []):
                    jp = t[0] if len(t) > 0 else ""
                    pron = t[1] if len(t) > 1 else ""
                    ko = t[2] if len(t) > 2 else ""

                    if (qq in (jp or "").lower()
                        or qq in (pron or "").lower()
                        or qq in (ko or "").lower()):
                        results.append({
                            "main_key": main_key,
                            "sub_key": sub_key,
                            "cat_title": cat_title,
                            "sub_title": sub_title,
                            "jp": jp,
                            "pron": pron,
                            "ko": ko,
                        })

    return render_template("situations_search.html", user=user, q=q, results=results)


def build_situation_seo(main_key: str, sub_key: str | None = None):
    """
    SITUATIONS 기반으로 페이지마다 고유 title/desc/keywords/intro 자동 생성
    """
    main = SITUATIONS.get(main_key)
    if not main:
        # fallback
        title = "상황별 일본 여행 회화 | 일본여행 회화 공부방"
        intro = "일본 여행 중 자주 사용하는 상황별 일본어 회화 표현을 정리했습니다. 실전 문장과 발음, 뜻을 함께 학습할 수 있습니다."
        return title, intro

    main_title_ko = main.get("title", "상황별 회화")

    # sub(세부상황) 있을 때
    sub_title_ko = None
    if sub_key:
        sub = (main.get("subs") or {}).get(sub_key)
        if sub:
            sub_title_ko = sub.get("title")

    # 1) 고유 Title 생성
    if sub_title_ko:
        # 예: "일본 호텔 체크인 일본어 회화 | 여행 필수 표현"
        title = f"일본 {main_title_ko} {sub_title_ko} 일본어 회화 | 여행 필수 표현"
        intro = (
            f"일본 여행 중 {main_title_ko}에서 {sub_title_ko} 상황에 자주 사용하는 일본어 회화 표현을 정리했습니다. "
            f"현지에서 바로 쓸 수 있는 실전 문장과 발음, 뜻을 함께 학습할 수 있습니다."
        )
    else:
        # 예: "일본 공항 일본어 회화 | 상황별 필수 표현"
        title = f"일본 {main_title_ko} 일본어 회화 | 상황별 필수 표현"
        intro = (
            f"일본 여행 중 {main_title_ko} 상황에서 자주 사용하는 일본어 회화 표현을 정리했습니다. "
            f"필수 문장과 발음, 뜻을 상황별로 쉽고 빠르게 학습할 수 있습니다."
        )

    return title, intro

@app.route("/quiz")
def quiz():
    user = current_user()
    return render_template(
        "quiz.html",
        user=user,
        **seo(
            title="일본어 회화 퀴즈 게임 | 재미있게 배우는 일본 여행 일본어",
            desc="일본 여행 회화와 단어를 퀴즈 게임으로 재미있게 복습하세요. 빠르게 기억에 남는 일본어 학습 사이트입니다.",
            keywords="일본어 퀴즈, 일본 여행 일본어, 일본어 회화 게임, 일본어 단어 퀴즈"
        )
    )

# =========================
# Quiz - Word Game
# =========================

@app.get("/quiz/word_game")
@login_required
def word_game():
    user = current_user()
    return render_template("word_game.html", user=user)


@app.get("/api/game_words")
def api_game_words():
    """
    단어게임에서 사용할 단어 풀 반환
    - 기본: WORDS 전체 카테고리에서 flatten
    - query:
        n=200 (기본 200)
        cats=daily,polite,time (cat_key 콤마)
    반환 형식:
        { ok: true, items: [ {cat_key, cat_title, jp, pron, ko}, ... ] }
    """
    n = request.args.get("n", type=int) or 200
    cats_raw = (request.args.get("cats") or "").strip()

    selected = None
    if cats_raw:
        selected = {c.strip() for c in cats_raw.split(",") if c.strip()}

    items = []
    for cat_key, cat in (WORDS or {}).items():
        if selected and cat_key not in selected:
            continue

        cat_title = (cat or {}).get("title", cat_key)

        for row in (cat or {}).get("items", []) or []:
            jp, pron, ko = row[:3]  # ✅ (jp, pron, ko, ...) 여분 있어도 안전
            items.append({
                "cat_key": cat_key,
                "cat_title": cat_title,
                "jp": str(jp),
                "pron": str(pron),
                "ko": str(ko),
            })

    random.shuffle(items)
    if n > 0:
        items = items[:n]

    return jsonify({"ok": True, "items": items})



@app.route("/board/write", methods=["GET", "POST"])
@login_required
def board_write():
    user = current_user()
    if user and not isinstance(user, dict):
        user = dict(user)

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        content = (request.form.get("content") or "").strip()

        #  관리자만 공지 설정 가능
        is_notice = 0
        if user and (user["nickname"] == "SW" or user["id"] == 1):
            is_notice = 1 if (request.form.get("is_notice") == "1") else 0

        file = request.files.get("image")
        thumb_url = None

        if file and file.filename:
            if not allowed_file(file.filename):
                flash("이미지 파일(png/jpg/jpeg/gif/webp)만 업로드할 수 있어요.", "error")
                return render_template("board_write.html", user=user, form=request.form)

            filename = secure_filename(file.filename)
            stamp = datetime.now(timezone.utc).astimezone(_KST).strftime("%Y%m%d%H%M%S")
            save_name = f"user{user['id']}_{stamp}_{filename}"
            save_path = os.path.join(UPLOAD_FOLDER, save_name)
            file.save(save_path)
            thumb_url = f"/static/uploads/{save_name}"

        if not title or not content:
            flash("제목과 내용을 입력해주세요.", "error")
            return render_template("board_write.html", user=user, form=request.form)

        author_grade = normalize_author_grade(get_user_grade_label(user))
        author_nickname = user["nickname"]


        conn = db()
        try:
            conn.execute(
                """
                INSERT INTO board_posts
                (user_id, author_grade, author_nickname, title, content, thumb_url, upvotes, views, created_at, is_notice)
                VALUES (?,?,?,?,?,?,0,0,?,?)
                """,
                (user["id"], author_grade, author_nickname, title, content, thumb_url, kst_now_iso(), is_notice),
            )
            conn.commit()
        finally:
            conn.close()

        flash("글이 등록되었습니다.", "success")
        return redirect(url_for("board"))

    return render_template("board_write.html", user=user, form={})


def get_post_or_404(post_id: int):
    conn = db()
    row = conn.execute(
        """
        SELECT id, user_id, title, content, thumb_url,
               COALESCE(is_notice,0) AS is_notice
        FROM board_posts
        WHERE id=?
        """,
        (post_id,),
    ).fetchone()
    conn.close()

    if not row:
        abort(404)

    return dict(row)



@app.get("/board/<int:post_id>")
def board_detail(post_id: int):
    user = current_user()

    n_id = request.args.get("n")
    if user and n_id and str(n_id).isdigit():
        conn_tmp = db()
        try:
            conn_tmp.execute(
                "UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?",
                (int(n_id), user["id"]),
            )
            conn_tmp.commit()
        finally:
            conn_tmp.close()

    conn = db()

    # ✅ 조회수 중복 방지: 같은 세션에서 10분(600초) 내 재조회는 카운트 X
    now = int(time())
    key = f"viewed_post_{post_id}"
    last = session.get(key)

    if not last or (now - int(last)) > 600:
        conn.execute(
            "UPDATE board_posts SET views = COALESCE(views,0) + 1 WHERE id=?",
            (post_id,),
        )
        conn.commit()
        session[key] = now

    post = conn.execute(
        """
        SELECT
          id, user_id, title, content, author_grade, author_nickname,
          created_at, views, upvotes, thumb_url,
          COALESCE(is_notice,0) AS is_notice
        FROM board_posts
        WHERE id=?
        """,
        (post_id,),
    ).fetchone()

    if not post:
        conn.close()
        abort(404)

    # ✅ (추천 UX용) 내가 이미 추천했는지 체크해서 템플릿에 전달
    user_has_upvoted = False
    if user:
        r = conn.execute(
            "SELECT 1 FROM board_upvotes WHERE post_id=? AND user_id=?",
            (post_id, user["id"]),
        ).fetchone()
        user_has_upvoted = bool(r)

    comments_rows = conn.execute(
        """
        SELECT id, post_id, user_id, author_grade, author_nickname, content, created_at
        FROM board_comments
        WHERE post_id=?
        ORDER BY id DESC
        """,
        (post_id,),
    ).fetchall()

    conn.close()

    comments = []
    for c in comments_rows:
        comments.append({
            "id": c["id"],
            "post_id": c["post_id"],
            "user_id": c["user_id"],
            "author_grade": c["author_grade"],
            "author_nickname": c["author_nickname"],
            "content": c["content"],
            "created_at": c["created_at"],
            "is_owner": bool(user and c["user_id"] and user["id"] == c["user_id"]),
        })

    is_owner = bool(user and post["user_id"] and user["id"] == post["user_id"])

    return render_template(
        "board_detail.html",
        user=user,
        post=post,
        comments=comments,
        is_owner=is_owner,
        user_has_upvoted=user_has_upvoted,  # ✅ 추가
    )


@app.route("/board/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def board_edit(post_id: int):
    user = current_user()
    if user and not isinstance(user, dict):
        user = dict(user)

    post = get_post_or_404(post_id)

    # 공지글 여부
    is_notice = int(post.get("is_notice") or 0)

    # 공지글이면 "관리자만" 수정 가능
    is_admin = bool(user and (user.get("nickname") == "SW" or user.get("id") == 1))
    if is_notice == 1 and not is_admin:
        abort(403)

    # 수정 화면에서 체크박스 보여주기/변경 가능은 관리자만
    show_notice_toggle = is_admin

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        content = (request.form.get("content") or "").strip()

        if not title or not content:
            flash("제목과 내용을 입력해주세요.", "error")
            return render_template(
                "board_edit.html",
                user=user,
                post=post,
                show_notice_toggle=show_notice_toggle,
                is_notice=is_notice,
            )

        # 이미지 변경(선택)
        file = request.files.get("image")
        thumb_url = post.get("thumb_url")

        if file and file.filename:
            if not allowed_file(file.filename):
                flash("이미지 파일(png/jpg/jpeg/gif/webp)만 업로드할 수 있어요.", "error")
                return render_template(
                    "board_edit.html",
                    user=user,
                    post=post,
                    show_notice_toggle=show_notice_toggle,
                    is_notice=is_notice,
                )

            filename = secure_filename(file.filename)
            stamp = datetime.now(timezone.utc).astimezone(_KST).strftime("%Y%m%d%H%M%S")
            save_name = f"user{user['id']}_{stamp}_{filename}"
            save_path = os.path.join(UPLOAD_FOLDER, save_name)
            file.save(save_path)
            thumb_url = f"/static/uploads/{save_name}"

        # 공지글 체크는 관리자만 반영
        new_is_notice = is_notice
        if is_admin:
            new_is_notice = 1 if request.form.get("is_notice") == "1" else 0

        conn = db()
        try:
            conn.execute(
                """
                UPDATE board_posts
                SET title=?, content=?, thumb_url=?, is_notice=?
                WHERE id=?
                """,
                (title, content, thumb_url, new_is_notice, post_id),
            )
            conn.commit()
        finally:
            conn.close()

        flash("수정되었습니다.", "success")
        return redirect(url_for("board_detail", post_id=post_id))

    # GET
    return render_template(
        "board_edit.html",
        user=user,
        post=post,
        show_notice_toggle=show_notice_toggle,
        is_notice=is_notice,
    )


@app.post("/board/<int:post_id>/delete")
def board_delete(post_id):
    user = current_user()
    if not user:
        flash("로그인이 필요합니다.", "error")
        return redirect(url_for("login", next=url_for("board_detail", post_id=post_id)))

    conn = db()
    try:
        post = conn.execute(
            """
            SELECT id, user_id, COALESCE(is_notice,0) AS is_notice
            FROM board_posts
            WHERE id=?
            """,
            (post_id,),
        ).fetchone()

        if not post:
            flash("게시글이 존재하지 않습니다.", "error")
            return redirect(url_for("board"))

        # 권한 체크 (관리자 or 글쓴이)
        if (not is_admin(user)) and (post["user_id"] != user["id"]):
            flash("삭제 권한이 없습니다.", "error")
            return redirect(url_for("board_detail", post_id=post_id))

        #  댓글 먼저 삭제 → 게시글 삭제
        conn.execute("DELETE FROM board_comments WHERE post_id=?", (post_id,))
        conn.execute("DELETE FROM board_posts WHERE id=?", (post_id,))
        conn.commit()

        flash("게시글과 댓글이 함께 삭제되었습니다.", "success")
        return redirect(url_for("board"))

    finally:
        conn.close()

@app.route("/privacy")
def privacy():
    user = current_user()
    return render_template("privacy.html", user=user)

@app.route("/terms")
def terms():
    user = current_user()
    return render_template("terms.html", user=user)

@app.route("/about")
def about():
    user = current_user()
    return render_template("about.html", user=user)

@app.route("/contact")
def contact():
    user = current_user()
    return render_template("contact.html", user=user)

# -------------------------
# Auth: register/login/logout
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    user = current_user()
    if user:
        return redirect(url_for("index"))

    form = {"username": "", "nickname": "", "email": "", "email2": ""}
    errors: Dict[str, str] = {}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        nickname = request.form.get("nickname", "").strip()
        email = request.form.get("email", "").strip().lower()
        email2 = request.form.get("email2", "").strip().lower()

        form.update({"username": username, "nickname": nickname, "email": email, "email2": email2})

        msg = validate_username_format(username)
        if msg:
            errors["username"] = msg
        elif username_exists(username):
            errors["username"] = "이미 사용 중인 아이디입니다."

        msg = validate_password_format(password)
        if msg:
            errors["password"] = msg
        elif password != password2:
            errors["password2"] = "비밀번호가 일치하지 않습니다."

        if not (2 <= len(nickname) <= 8):
            errors["nickname"] = "닉네임은 2~8자 이내로 입력해주세요."
        elif not nickname_allowed(nickname):
            errors["nickname"] = "사용할 수 없는 닉네임입니다. (정치/욕설/성적/반사회/특정 사이트 언급 금지)"

        if email != email2:
            errors["email2"] = "이메일 주소가 서로 일치하지 않습니다."
        else:
            msg = validate_email_format(email)
            if msg:
                errors["email"] = msg
            elif email_exists(email):
                errors["email"] = "이미 사용 중인 이메일입니다."

        if errors:
            flash("입력값을 다시 확인해주세요.", "error")
            return render_template("register.html", user=user, form=form, errors=errors)


        pw_hash = generate_password_hash(password)
        created_at = kst_now_iso()

        conn = db()
        try:
            conn.execute(
                "INSERT INTO users(username, password_hash, nickname, email, created_at) VALUES(?,?,?,?,?)",
                (username, pw_hash, nickname, email, created_at),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("이미 사용 중인 아이디 또는 이메일입니다.", "error")
            return render_template("register.html", user=None, form=form, errors={"_": "중복 데이터가 있습니다."})
        conn.close()

        flash("회원가입 완료! 로그인 해주세요.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", user=None, form=form, errors=errors)


@app.route("/login", methods=["GET", "POST"])
def login():
    user = current_user()
    if user:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("아이디와 비밀번호를 입력해주세요.", "error")
            return redirect(url_for("login"))

        conn = db()
        u = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()

        # ❌ 계정 없음 or 비밀번호 틀림
        if not u or not check_password_hash(u["password_hash"], password):
            conn.close()
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
            return redirect(url_for("login"))

        # 🚫 탈퇴 또는 비활성 계정 차단
        deleted_at = u["deleted_at"] if ("deleted_at" in u.keys()) else None
        is_active = u["is_active"] if ("is_active" in u.keys()) else 1

        if (is_active == 0) or (deleted_at is not None and str(deleted_at).strip() != ""):
            conn.close()
            flash("탈퇴 처리된 계정입니다.", "error")
            return redirect(url_for("login"))


        session["user_id"] = u["id"]

        mark_attendance(u["id"])

        conn.execute(
            "UPDATE users SET last_login_at=? WHERE id=?",
            (kst_now_iso(), u["id"])
        )
        conn.commit()
        conn.close()

        flash("로그인 완료!", "success")
        next_url = request.args.get("next")
        return redirect(next_url or url_for("index"))

    return render_template("login.html", user=None)


def send_username_email(to_email: str, username: str):
    import os, smtplib
    from email.mime.text import MIMEText

    smtp_host = os.getenv("SMTP_HOST", "smtp.naver.com")
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    from_email = os.getenv("FROM_EMAIL", smtp_user)
    smtp_port = int(os.getenv("SMTP_PORT", "465"))

    if not (smtp_host and smtp_user and smtp_pass):
        print("[EMAIL] SMTP env not set. Skipping real send.")
        return False

    subject = "[JapaneseStudyRoom] 아이디 찾기 안내"
    body = f"""요청하신 아이디 정보입니다.

회원님의 아이디: {username}

본인이 요청하지 않았다면 이 메일을 무시하세요.
"""

    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as s:
                s.login(smtp_user, smtp_pass)
                s.sendmail(from_email, [to_email], msg.as_string())
            return True

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(smtp_user, smtp_pass)
            s.sendmail(from_email, [to_email], msg.as_string())
        return True

    except Exception as e:
        print(f"[EMAIL ERROR] {repr(e)}")
        return False



@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("로그아웃 완료!", "success")
    return redirect(url_for("index"))

@app.route("/find-id", methods=["GET", "POST"])
def find_id():
    # GET: 페이지 보여주기
    if request.method == "GET":
        return render_template("find_id.html")

    # POST: 이메일로 아이디 전송
    email = (request.form.get("email") or "").strip().lower()

    if not email:
        flash("이메일을 입력해주세요.", "error")
        return redirect(url_for("find_id"))

    conn = db()
    try:
        row = conn.execute(
        """
        SELECT username
        FROM users
        WHERE lower(email)=?
        AND (is_active=1 OR is_active IS NULL)
        AND (deleted_at IS NULL OR deleted_at='')
        """,
        (email,)
    ).fetchone()

    finally:
        conn.close()

    # 보안상 존재 여부를 자세히 말하지 않는 문구로 통일(추천)
    if row and row["username"]:
        ok = send_username_email(email, row["username"])
        if ok:
            flash("입력한 이메일로 아이디를 전송했습니다. (스팸함도 확인해주세요)", "success")
        else:
            flash("메일 전송에 실패했습니다. 잠시 후 다시 시도해주세요.", "error")
    else:
        # 계정 존재 여부 노출 방지
        flash("입력한 이메일로 아이디를 전송했습니다.", "success")

    return redirect(url_for("find_id"))


# -------------------------
# Password reset
# -------------------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    user = current_user()
    if user:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()

        if not username or not email:
            flash("아이디와 이메일을 입력해주세요.", "error")
            return redirect(url_for("forgot_password"))

        if not is_naver_email(email):
            flash("naver.com 이메일만 가능합니다.", "error")
            return redirect(url_for("forgot_password"))

        conn = db()
        try:
            # 1) 계정 확인
            u = conn.execute(
                "SELECT * FROM users WHERE username=? AND email=?",
                (username, email),
            ).fetchone()

            if not u:
                flash("일치하는 계정을 찾을 수 없습니다.", "error")
                return redirect(url_for("forgot_password"))

            now = datetime.now(timezone.utc).astimezone(_KST)

            # 2) 쿨다운(60초)
            latest = conn.execute(
                """
                SELECT created_at FROM password_resets
                WHERE username=? AND email=?
                ORDER BY id DESC LIMIT 1
                """,
                (username, email),
            ).fetchone()

            if latest:
                try:
                    last_time = datetime.fromisoformat(latest["created_at"])
                    if (now - last_time).total_seconds() < 60:
                        flash("잠시 후 다시 시도해주세요. (재요청 대기 60초)", "error")
                        return redirect(url_for("forgot_password"))
                except Exception:
                    pass

            # 3) 요청 제한(예: email 기준 5회/5분)
            five_min_ago = (now - timedelta(minutes=5)).isoformat()
            cnt = conn.execute(
                """
                SELECT COUNT(*) AS c FROM password_resets
                WHERE email=? AND created_at >= ?
                """,
                (email, five_min_ago),
            ).fetchone()["c"]

            if cnt >= 5:
                flash("요청이 너무 많습니다. 5분 후 다시 시도해주세요.", "error")
                return redirect(url_for("forgot_password"))

            # ✅ 3.5) 이전 미사용 인증코드 전부 무효화(가장 중요)
            conn.execute(
                """
                UPDATE password_resets
                SET used_at=?
                WHERE username=? AND email=? AND used_at IS NULL
                """,
                (now.isoformat(), username, email),
            )

            # 4) 코드 발급/저장
            code = f"{random.randint(0, 999999):06d}"
            code_hash = generate_password_hash(code)
            expires_at = (now + timedelta(minutes=10)).isoformat()
            request_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

            conn.execute(
                """
                INSERT INTO password_resets(username, email, code_hash, expires_at, created_at, request_ip)
                VALUES(?,?,?,?,?,?)
                """,
                (username, email, code_hash, expires_at, now.isoformat(), request_ip),
            )
            conn.commit()

        finally:
            conn.close()

        # 5) 이메일 전송 (DB 닫은 뒤에 해도 OK)
        sent = send_reset_code_email(email, code)

        if sent:
            flash("인증코드를 이메일로 발송했습니다. (유효시간 10분)", "success")
            return redirect(url_for("reset_password"))
        else:
            print(f"[EMAIL SEND FAIL] username={username} email={email}")
            flash("이메일 발송에 실패했습니다. 잠시 후 다시 시도해주세요.", "error")
            return redirect(url_for("forgot_password"))

    # ✅ GET 요청은 항상 템플릿 반환
    return render_template("forgot.html", user=None)


MAX_CODE_FAILS = 5
LOCK_MINUTES = 5


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    user = current_user()
    if not user:
        flash("로그인이 필요합니다.", "error")
        return redirect(url_for("login"))

    # users 테이블의 비밀번호 컬럼 자동 탐색
    def _get_pw_col(conn):
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        for cand in ("password", "password_hash", "pw_hash", "pass_hash", "hashed_password"):
            if cand in cols:
                return cand
        return None

    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not current_pw or not new_pw or not confirm_pw:
            flash("모든 항목을 입력해주세요.", "error")
            return redirect(url_for("change_password"))

        if new_pw != confirm_pw:
            flash("새 비밀번호가 일치하지 않습니다.", "error")
            return redirect(url_for("change_password"))

        if len(new_pw) < 8:
            flash("새 비밀번호는 8자 이상으로 설정해주세요.", "error")
            return redirect(url_for("change_password"))

        conn = db()
        try:
            pw_col = _get_pw_col(conn)
            if not pw_col:
                flash("서버 설정 문제로 비밀번호 변경을 진행할 수 없습니다.", "error")
                return redirect(url_for("change_password"))

            row = conn.execute(
                f"SELECT {pw_col} AS pw FROM users WHERE id=?",
                (user["id"],)
            ).fetchone()

            if not row or not row["pw"]:
                flash("계정 정보를 찾을 수 없습니다.", "error")
                return redirect(url_for("change_password"))

            if not check_password_hash(row["pw"], current_pw):
                flash("현재 비밀번호가 올바르지 않습니다.", "error")
                return redirect(url_for("change_password"))

            new_hash = generate_password_hash(new_pw)
            conn.execute(
                f"UPDATE users SET {pw_col}=? WHERE id=?",
                (new_hash, user["id"])
            )
            conn.commit()

        finally:
            conn.close()

        flash("비밀번호가 변경되었습니다.", "success")
        return redirect(url_for("mypage"))

    return render_template("change_password.html", user=user)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    user = current_user()
    if user:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        code = request.form.get("code", "").strip()
        new_password = request.form.get("new_password", "")
        new_password2 = request.form.get("new_password2", "")

        if not (username and email and code and new_password and new_password2):
            flash("모든 항목을 입력해주세요.", "error")
            return redirect(url_for("reset_password"))

        if not is_naver_email(email):
            flash("naver.com 이메일만 가능합니다.", "error")
            return redirect(url_for("reset_password"))

        if new_password != new_password2:
            flash("새 비밀번호가 일치하지 않습니다.", "error")
            return redirect(url_for("reset_password"))

        if not (8 <= len(new_password) <= 16):
            flash("새 비밀번호는 8~16자로 입력해주세요.", "error")
            return redirect(url_for("reset_password"))

        conn = db()
        now = datetime.now(timezone.utc).astimezone(_KST)

        # ✅ 아직 사용되지 않은 최신 인증 요청만
        row = conn.execute(
            """
            SELECT * FROM password_resets
            WHERE username=? AND email=? AND used_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (username, email),
        ).fetchone()

        if not row:
            conn.close()
            flash("사용 가능한 인증코드가 없습니다. 먼저 인증코드를 다시 받아주세요.", "error")
            return redirect(url_for("forgot_password"))

        # ✅ 잠금 상태 체크
        locked_until_raw = row["locked_until"] if "locked_until" in row.keys() else None
        if locked_until_raw:
            try:
                locked_until = datetime.fromisoformat(locked_until_raw)
                if now < locked_until:
                    conn.close()
                    flash("인증 시도가 너무 많습니다. 5분 후 다시 시도해주세요.", "error")
                    return redirect(url_for("reset_password"))
            except Exception:
                pass

        # ✅ 만료 체크
        expires_at = datetime.fromisoformat(row["expires_at"])
        if now > expires_at:
            conn.execute("UPDATE password_resets SET used_at=? WHERE id=?", (now.isoformat(), row["id"]))
            conn.commit()
            conn.close()
            flash("인증코드가 만료되었습니다. 다시 요청해주세요.", "error")
            return redirect(url_for("forgot_password"))

        # ✅ 코드 불일치면 fail_count 증가 + 5회면 5분 잠금
        if not check_password_hash(row["code_hash"], code):
            new_fail = int(row["fail_count"] or 0) + 1
            locked_until = None
            if new_fail >= MAX_CODE_FAILS:
                locked_until = (now + timedelta(minutes=LOCK_MINUTES)).isoformat()

            conn.execute(
                "UPDATE password_resets SET fail_count=?, locked_until=? WHERE id=?",
                (new_fail, locked_until, row["id"]),
            )
            conn.commit()
            conn.close()

            if new_fail >= MAX_CODE_FAILS:
                flash("인증코드 입력을 5회 실패했습니다. 5분 후 다시 시도해주세요.", "error")
            else:
                flash(f"인증코드가 올바르지 않습니다. (실패 {new_fail}/{MAX_CODE_FAILS})", "error")
            return redirect(url_for("reset_password"))

        # ✅ 성공: 비밀번호 변경 + 인증코드 1회용 처리
        pw_hash = generate_password_hash(new_password)

        conn.execute(
            "UPDATE users SET password_hash=? WHERE username=? AND email=?",
            (pw_hash, username, email),
        )
        conn.execute(
            "UPDATE password_resets SET used_at=?, fail_count=?, locked_until=? WHERE id=?",
            (now.isoformat(), 0, None, row["id"]),
        )

        conn.commit()
        conn.close()

        flash("비밀번호가 변경되었습니다. 로그인해주세요.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", user=None)

@app.route("/withdraw", methods=["GET", "POST"])
def withdraw():
    user = current_user()
    if not user:
        flash("로그인이 필요합니다.", "error")
        return redirect(url_for("login"))

    # (선택) 관리자 탈퇴 막기 - 원하면 유지
    try:
        if is_admin(user):
            flash("관리자 계정은 회원탈퇴가 제한됩니다.", "error")
            return redirect(url_for("mypage"))
    except Exception:
        pass

    def _cols(conn):
        return [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]

    def _ensure_columns(conn):
        cols = _cols(conn)
        if "deleted_at" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN deleted_at TEXT")
        if "is_active" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
        conn.commit()

    def _pick_first(cols, candidates):
        for c in candidates:
            if c in cols:
                return c
        return None

    if request.method == "POST":
        confirm_pw = request.form.get("password", "")
        agree = request.form.get("agree", "")

        if agree != "yes":
            flash("안내 사항에 동의해 주세요.", "error")
            return redirect(url_for("withdraw"))

        conn = db()
        try:
            _ensure_columns(conn)
            cols = _cols(conn)

            pw_col = _pick_first(cols, ("password", "password_hash", "pw_hash", "pass_hash", "hashed_password"))
            if not pw_col:
                flash("서버 설정 문제로 회원탈퇴를 진행할 수 없습니다. (비밀번호 컬럼 없음)", "error")
                return redirect(url_for("withdraw"))

            email_col = _pick_first(cols, ("email", "user_email"))
            public_col = _pick_first(cols, ("nickname", "display_name", "name"))

            row = conn.execute(
                f"SELECT id, {pw_col} AS pw FROM users WHERE id=?",
                (user["id"],)
            ).fetchone()

            if not row or not row["pw"]:
                flash("계정 정보를 찾을 수 없습니다.", "error")
                return redirect(url_for("withdraw"))

            if not check_password_hash(row["pw"], confirm_pw):
                flash("비밀번호가 올바르지 않습니다.", "error")
                return redirect(url_for("withdraw"))

            now = datetime.now(timezone.utc).isoformat()
            dead_hash = generate_password_hash(f"deleted:{user['id']}:{now}")

            updates = []
            params = []

            # 탈퇴 처리 + 비활성화
            updates.append("deleted_at=?")
            params.append(now)
            updates.append("is_active=0")

            # 비밀번호 무력화
            updates.append(f"{pw_col}=?")
            params.append(dead_hash)

            # 닉네임/이름이 있으면 '탈퇴회원' 처리
            if public_col:
                updates.append(f"{public_col}=?")
                params.append("탈퇴회원")

            # 이메일이 있으면 마스킹(아이디찾기/비번찾기 차단)
            if email_col:
                updates.append(f"{email_col}=?")
                params.append(f"deleted+{user['id']}@invalid.local")

            params.append(user["id"])
            conn.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id=?",
                tuple(params)
            )
            conn.commit()

        finally:
            conn.close()

        # 로그아웃
        session.pop("user_id", None)
        flash("회원탈퇴가 완료되었습니다.", "success")
        return redirect(url_for("index"))

    return render_template("withdraw.html", user=user)

@app.route("/word_game/ranking")
def word_game_ranking():
    return redirect(url_for("word_game_ranking_page"))



@app.get("/quiz/word_game/ranking")
def word_game_ranking_page():
    user = current_user()

    conn = db()

    rows = conn.execute(
        """
        SELECT nickname, best_word_score, best_word_score_at
        FROM users
        WHERE best_word_score IS NOT NULL AND best_word_score > 0
        ORDER BY best_word_score DESC, COALESCE(best_word_score_at, '') ASC
        LIMIT 50
        """
    ).fetchall()

    top = []
    for r in rows:
        # sqlite Row면 key 접근, 튜플이면 index 접근
        if hasattr(r, "keys"):
            nickname = r["nickname"]
            score = r["best_word_score"]
            at = r["best_word_score_at"]
        else:
            nickname = r[0]
            score = r[1]
            at = r[2]

        top.append({
            "nickname": str(nickname or ""),
            "score": int(score or 0),
            "at": str(at or "")
        })

    my_rank = None
    my_best = 0
    my_best_at = None

    if user:
        me = conn.execute(
            "SELECT best_word_score, best_word_score_at FROM users WHERE id=?",
            (user["id"],),
        ).fetchone()

        if me:
            my_best = int(me["best_word_score"] or 0)
            my_best_at = me["best_word_score_at"]

        if my_best > 0:
            r = conn.execute(
                """
                SELECT 1 + COUNT(*) AS rk
                FROM users
                WHERE best_word_score > ?
                """,
                (my_best,),
            ).fetchone()
            my_rank = int(r["rk"]) if r else None

    conn.close()

    return render_template(
        "word_game_ranking.html",
        user=user,
        top=top,              
        my_rank=my_rank,
        my_best=my_best,
        my_best_at=my_best_at,
    )




@app.post("/board/<int:post_id>/upvote")
@login_required
def board_upvote(post_id: int):
    user = current_user()
    if user and not isinstance(user, dict):
        user = dict(user)

    conn = db()
    try:
        post = conn.execute(
            "SELECT id, COALESCE(is_notice,0) AS is_notice, COALESCE(upvotes,0) AS upvotes "
            "FROM board_posts WHERE id=?",
            (post_id,),
        ).fetchone()

        if not post:
            return jsonify(ok=False, msg="게시글이 없습니다."), 404

        if post["is_notice"] == 1:
            return jsonify(ok=False, msg="공지글은 추천할 수 없어요.", upvotes=post["upvotes"]), 403

        # ✅ 이미 추천했는지 체크
        already = conn.execute(
            "SELECT 1 FROM board_upvotes WHERE post_id=? AND user_id=?",
            (post_id, user["id"]),
        ).fetchone()

        if already:
            return jsonify(ok=False, msg="이미 추천한 글이에요.", upvotes=post["upvotes"]), 400

        # ✅ 추천 기록 저장 (UNIQUE로 2중 방어)
        conn.execute(
            "INSERT INTO board_upvotes (post_id, user_id, created_at) VALUES (?,?,?)",
            (post_id, user["id"], kst_now_iso()),
        )

        # ✅ 게시글 추천수 +1
        conn.execute(
            "UPDATE board_posts SET upvotes = COALESCE(upvotes,0) + 1 WHERE id=?",
            (post_id,),
        )
        conn.commit()

        row = conn.execute(
            "SELECT COALESCE(upvotes,0) AS upvotes FROM board_posts WHERE id=?",
            (post_id,),
        ).fetchone()

        return jsonify(ok=True, msg="추천 완료!", upvotes=row["upvotes"])

    except Exception as e:
        conn.rollback()
        # UNIQUE 위반이면 이미 추천한 상태
        if "UNIQUE" in str(e).upper():
            row = conn.execute(
                "SELECT COALESCE(upvotes,0) AS upvotes FROM board_posts WHERE id=?",
                (post_id,),
            ).fetchone()
            return jsonify(ok=False, msg="이미 추천한 글이에요.", upvotes=row["upvotes"] if row else 0), 400

        return jsonify(ok=False, msg="서버 오류가 발생했습니다."), 500

    finally:
        conn.close()


@app.post("/board/<int:post_id>/comment")
@login_required
def board_comment_create(post_id: int):
    user = current_user()
    if user and not isinstance(user, dict):
        user = dict(user)

    conn = db()
    try:
        post = conn.execute(
            "SELECT id, COALESCE(is_notice,0) AS is_notice FROM board_posts WHERE id=?",
            (post_id,),
        ).fetchone()

        if not post:
            abort(404)

        if post["is_notice"] == 1:
            flash("공지글에는 댓글을 작성할 수 없어요.", "error")
            return redirect(url_for("board_detail", post_id=post_id))

        content = (request.form.get("content") or "").strip()
        if not content:
            flash("댓글 내용을 입력해주세요.", "error")
            return redirect(url_for("board_detail", post_id=post_id))

        conn.execute(
            """
            INSERT INTO board_comments (post_id, user_id, author_grade, author_nickname, content, created_at)
            VALUES (?,?,?,?,?,?)
            """,
            (post_id, user["id"], normalize_author_grade(get_user_grade_label(user)), user["nickname"], content, kst_now_iso()),
        )
        conn.commit()

    finally:
        conn.close()

    flash("댓글이 등록되었습니다.", "success")
    return redirect(url_for("board_detail", post_id=post_id))


@app.post("/board/comment/<int:comment_id>/delete")
@login_required
def board_comment_delete(comment_id: int):
    user = current_user()

    conn = db()
    row = conn.execute(
        "SELECT id, post_id, user_id FROM board_comments WHERE id=?",
        (comment_id,),
    ).fetchone()

    if not row:
        conn.close()
        abort(404)

    # 본인 댓글만 삭제
    if not row["user_id"] or row["user_id"] != user["id"]:
        conn.close()
        abort(403)

    post_id = row["post_id"]
    conn.execute("DELETE FROM board_comments WHERE id=?", (comment_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("board_detail", post_id=post_id))

@app.post("/api/word_game/submit_score")
def submit_word_game_score():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login_required"}), 401

    data = request.get_json(silent=True) or {}
    score = int(data.get("score") or 0)

    if score < 0:
        score = 0

    conn = db()
    row = conn.execute("SELECT best_word_score FROM users WHERE id=?", (user["id"],)).fetchone()
    prev = int(row["best_word_score"] or 0) if row else 0

    updated = False
    if score > prev:
        conn.execute(
            "UPDATE users SET best_word_score=?, best_word_score_at=? WHERE id=?",
            (score, kst_now_iso(), user["id"])
        )
        conn.commit()
        updated = True

    conn.close()
    return jsonify({"ok": True, "updated": updated, "prev": prev, "best": max(prev, score)})


# -------------------------
# Note (login-only)
# -------------------------
@app.route("/note")
@login_required
def note():
    user = current_user()

    # 1) 문장 즐겨찾기
    conn = db()
    rows = conn.execute(
        "SELECT phrase_key, jp, pron, ko, created_at FROM favorites WHERE user_id=? ORDER BY id DESC",
        (user["id"],),
    ).fetchall()
    conn.close()

    fav_items = [
        {
            "phrase_key": r["phrase_key"],
            "jp": r["jp"],
            "pron": r["pron"],
            "ko": r["ko"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]

    # 2) 단어 즐겨찾기 (word_favorites)
    word_fav_items = []
    conn = db()
    wrows = []  # ✅ wrows 기본값
    try:
        ensure_word_favorites_table(conn)
        wrows = conn.execute(
            "SELECT cat_key, jp, created_at FROM word_favorites WHERE user_id=? ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
    finally:
        conn.close()

    for wr in wrows:
        ck = wr["cat_key"]
        jp = wr["jp"]
        cat = (WORDS or {}).get(ck) or {}
        cat_title = cat.get("title", ck)

        pron = ""
        ko = ""
        for (w_jp, w_pron, w_ko) in (cat.get("items") or []):
            if w_jp == jp:
                pron, ko = w_pron, w_ko
                break

        word_fav_items.append(
            {
                "cat_key": ck,
                "cat_title": cat_title,
                "jp": jp,
                "pron": pron,
                "ko": ko,
                "created_at": wr["created_at"],
            }
        )

    # ✅ return은 반드시 함수 마지막(반복문 밖)
    return render_template(
        "note.html",
        user=user,
        fav_items=fav_items,
        word_fav_items=word_fav_items,
        **seo(
            title="나만의 일본어 학습노트 | 즐겨찾기 회화·단어 암기 공부",
            desc="자주 쓰는 일본어 회화와 단어를 저장하고 가리기 기능으로 암기하세요. 나만의 일본어 공부 노트 공간입니다.",
            keywords="일본어 학습노트, 일본어 암기, 일본어 단어장, 일본어 회화 저장"
        )
    )



# -------------------------
# Favorites API (login required)
# -------------------------
@app.route("/api/favorites", methods=["POST"])
@login_required
def api_favorites_post():
    user = current_user()

    data = request.get_json(silent=True) or {}
    action = data.get("action")
    phrase_key = (data.get("phrase_key") or "").strip()
    jp = (data.get("jp") or "").strip()
    pron = (data.get("pron") or "").strip()
    ko = (data.get("ko") or "").strip()

    if not phrase_key:
        return jsonify({"ok": False, "error": "BAD_REQUEST"}), 400

    conn = db()
    if action == "add":
        conn.execute(
            "INSERT OR IGNORE INTO favorites(user_id, phrase_key, jp, pron, ko, created_at) VALUES(?,?,?,?,?,?)",
            (user["id"], phrase_key, jp, pron, ko, kst_now_iso()),
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})

    if action == "remove":
        conn.execute(
            "DELETE FROM favorites WHERE user_id=? AND phrase_key=?",
            (user["id"], phrase_key),
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})

    conn.close()
    return jsonify({"ok": False, "error": "BAD_REQUEST"}), 400

from flask import request, jsonify

@app.get("/api/word_fav")
def api_word_fav_list():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "LOGIN_REQUIRED"}), 401

    conn = db()
    try:
        ensure_word_favorites_table(conn)

        rows = conn.execute("""
            SELECT cat_key, jp
            FROM word_favorites
            WHERE user_id=?
            ORDER BY created_at DESC
        """, (user["id"],)).fetchall()

        favs = [{"cat_key": r["cat_key"], "jp": r["jp"]} for r in rows]
        return jsonify({"ok": True, "items": favs})
    finally:
        conn.close()

@app.get("/api/notifications/recent")
@login_required
def api_notifications_recent():
    user = current_user()
    conn = db()
    try:
        rows = conn.execute(
            """
            SELECT id, post_id, from_nickname, message, is_read, created_at
            FROM notifications
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT 5
            """,
            (user["id"],),
        ).fetchall()
    finally:
        conn.close()

    # Row를 JSON으로 변환
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "post_id": r["post_id"],
            "from_nickname": r["from_nickname"] or "",
            "message": r["message"],
            "is_read": int(r["is_read"]),
            "created_at": r["created_at"],
        })
    return jsonify({"ok": True, "items": out})


@app.post("/api/word_fav")
def api_word_fav_post():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "LOGIN_REQUIRED"}), 401

    data = request.get_json(silent=True) or {}
    cat_key = (data.get("cat_key") or "").strip()
    jp = (data.get("jp") or "").strip()
    action = (data.get("action") or "").strip()

    if not cat_key or not jp or action not in ("add", "remove"):
        return jsonify({"ok": False, "error": "BAD_REQUEST"}), 400

    conn = db()
    try:
        ensure_word_favorites_table(conn)

        if action == "add":
            conn.execute("""
                INSERT OR IGNORE INTO word_favorites(user_id, cat_key, jp)
                VALUES(?, ?, ?)
            """, (user["id"], cat_key, jp))
            conn.commit()
            return jsonify({"ok": True})

        if action == "remove":
            conn.execute("""
                DELETE FROM word_favorites
                WHERE user_id=? AND cat_key=? AND jp=?
            """, (user["id"], cat_key, jp))
            conn.commit()
            return jsonify({"ok": True})

        return jsonify({"ok": False, "error": "BAD_REQUEST"}), 400
    finally:
        conn.close()

@app.get("/api/word_game/rankings")
def word_game_rankings():
    conn = db()
    rows = conn.execute("""
        SELECT id, nickname, best_word_score, best_word_score_at
        FROM users
        WHERE COALESCE(best_word_score, 0) > 0
        ORDER BY best_word_score DESC, best_word_score_at ASC
        LIMIT 50
    """).fetchall()
    conn.close()

    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "nickname": r["nickname"],
            "score": int(r["best_word_score"] or 0),
            "at": r["best_word_score_at"]
        })

    return jsonify(ok=True, items=items)


# -------------------------
# Live validation APIs (for register)
# -------------------------
@app.get("/api/validate/username")
def api_validate_username():
    username = (request.args.get("u") or "").strip()
    msg = validate_username_format(username)
    if msg:
        return jsonify({"ok": False, "msg": msg, "available": False})

    if username_exists(username):
        return jsonify({"ok": False, "msg": "이미 사용 중인 아이디입니다.", "available": False})

    return jsonify({"ok": True, "msg": "사용 가능한 아이디입니다.", "available": True})


@app.get("/api/validate/nickname")
def api_validate_nickname():
    nickname = (request.args.get("n") or "").strip()

    if not (2 <= len(nickname) <= 8):
        return jsonify({"ok": False, "msg": "닉네임은 2~8자 이내로 입력해주세요.", "available": False})

    if not nickname_allowed(nickname):
        return jsonify({"ok": False, "msg": "사용할 수 없는 닉네임입니다.", "available": False})

    return jsonify({"ok": True, "msg": "사용 가능한 닉네임입니다.", "available": True})


@app.get("/api/validate/email")
def api_validate_email():
    email = (request.args.get("e") or "").strip().lower()
    msg = validate_email_format(email)
    if msg:
        return jsonify({"ok": False, "msg": msg, "available": False})

    if email_exists(email):
        return jsonify({"ok": False, "msg": "이미 사용 중인 이메일입니다.", "available": False})

    return jsonify({"ok": True, "msg": "사용 가능한 이메일입니다.", "available": True})

@app.get("/board")
def board():
    user = current_user()
    q = (request.args.get("q") or "").strip()

    conn = db()
    try:
        if q:
            posts = conn.execute(
                """
                SELECT id, title, content, thumb_url, author_grade, author_nickname,
                       COALESCE(upvotes,0) AS upvotes,
                       COALESCE(views,0) AS views,
                       created_at,
                       COALESCE(is_notice,0) AS is_notice
                FROM board_posts
                WHERE title LIKE ? OR content LIKE ? OR author_nickname LIKE ?
                ORDER BY COALESCE(is_notice,0) DESC, id DESC
                """,
                (f"%{q}%", f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            posts = conn.execute(
                """
                SELECT id, title, content, thumb_url, author_grade, author_nickname,
                       COALESCE(upvotes,0) AS upvotes,
                       COALESCE(views,0) AS views,
                       created_at,
                       COALESCE(is_notice,0) AS is_notice
                FROM board_posts
                ORDER BY COALESCE(is_notice,0) DESC, id DESC
                """
            ).fetchall()
    finally:
        conn.close()

    return render_template("board.html", user=user, posts=posts, q=q)

from datetime import datetime

@app.template_filter("mmdd")
def mmdd_filter(iso_str):
    if not iso_str:
        return ""
    try:
        # "2026-01-20T12:34:56" 같은 형태도 처리
        dt = datetime.fromisoformat(str(iso_str).replace("Z", "+00:00"))
        return dt.strftime("%m/%d")
    except Exception:
        s = str(iso_str)
        # "2026-01-20 ..." 형태면 앞 10자리만 잘라서 처리
        if len(s) >= 10 and s[4] == "-" and s[7] == "-":
            return f"{s[5:7]}/{s[8:10]}"
        return s

from flask import jsonify, request

@app.get("/api/member_card")
def api_member_card():
    nick = (request.args.get("nick") or "").strip()
    if not nick:
        return jsonify(ok=False, error="nick_required"), 400

    def table_cols(conn, table: str):
        try:
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
            return {r["name"] if isinstance(r, dict) else r[1] for r in rows}
        except Exception:
            return set()

    def pick_first(cols, candidates):
        for c in candidates:
            if c in cols:
                return c
        return None

    conn = db()
    try:
        u = conn.execute(
            """
            SELECT id, username, nickname, custom_grade, last_login_at, last_seen_at
            FROM users
            WHERE nickname=?
            """,
            (nick,),
        ).fetchone()

        if not u:
            return jsonify(ok=False, error="not_found"), 404

        u = dict(u)

        # ---- 게시글/댓글 테이블 컬럼 자동 감지 ----
        post_cols = table_cols(conn, "board_posts")
        cmt_cols  = table_cols(conn, "board_comments")

        # 보통: user_id / author_id / writer_id 등으로 되어있을 수 있음
        post_uid_col = pick_first(post_cols, ["user_id", "author_id", "writer_id", "member_id"])
        post_nick_col = pick_first(post_cols, ["author_nickname", "nickname", "writer_nickname", "member_nickname"])
        post_user_col = pick_first(post_cols, ["author_username", "username", "writer_username", "member_username"])

        cmt_uid_col = pick_first(cmt_cols, ["user_id", "author_id", "writer_id", "member_id"])
        cmt_nick_col = pick_first(cmt_cols, ["author_nickname", "nickname", "writer_nickname", "member_nickname"])
        cmt_user_col = pick_first(cmt_cols, ["author_username", "username", "writer_username", "member_username"])

        # ---- 작성글 수 계산 (id 우선, 없으면 nickname/username로 폴백) ----
        where_post = []
        params_post = []

        if post_uid_col:
            where_post.append(f"{post_uid_col}=?")
            params_post.append(u["id"])
        if post_nick_col:
            where_post.append(f"{post_nick_col}=?")
            params_post.append(u["nickname"])
        if post_user_col and u.get("username"):
            where_post.append(f"{post_user_col}=?")
            params_post.append(u["username"])

        post_cnt = 0
        if where_post:
            row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM board_posts WHERE " + " OR ".join(where_post),
                tuple(params_post),
            ).fetchone()
            post_cnt = int(row["cnt"] or 0) if row else 0

        # ---- 작성댓글 수 계산 ----
        where_cmt = []
        params_cmt = []

        if cmt_uid_col:
            where_cmt.append(f"{cmt_uid_col}=?")
            params_cmt.append(u["id"])
        if cmt_nick_col:
            where_cmt.append(f"{cmt_nick_col}=?")
            params_cmt.append(u["nickname"])
        if cmt_user_col and u.get("username"):
            where_cmt.append(f"{cmt_user_col}=?")
            params_cmt.append(u["username"])

        comment_cnt = 0
        if where_cmt:
            row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM board_comments WHERE " + " OR ".join(where_cmt),
                tuple(params_cmt),
            ).fetchone()
            comment_cnt = int(row["cnt"] or 0) if row else 0

        # ---- 계급/경험치 ----
        grade = get_user_grade_label({"id": u["id"], "username": u.get("username")})
        score = get_user_score({"id": u["id"], "username": u.get("username")})

        return jsonify(
            ok=True,
            member={
                "id": u["id"],
                "username": u.get("username"),
                "nickname": u.get("nickname"),
                "grade": grade,
                "score": score,
                "post_cnt": post_cnt,
                "comment_cnt": comment_cnt,
                "last_login_at": u.get("last_login_at"),
                "last_seen_at": u.get("last_seen_at"),
            }
        )


    finally:
        conn.close()


# =========================
# Quiz - Dialog Situation (객관식)
# =========================

DIALOG_SCENE_QUIZZES = [
    {
        "id": 1,
        "title": "- 1번문제 -",
        "image": "dialog_quiz/park_photo.png",
        "lines": [
            {"role": "남자", "jp": "すみません、写真を撮ってもらえますか？", "pron": "스미마센, 샤신오 톳테 모라에마스카", "ko": "저기 실례합니다. 사진 좀 찍어주실 수 있나요?"},
            {"role": "여자", "jp": "はい、もちろんです。", "pron": "하이, 모치론데스", "ko": "네, 물론이죠."},
            {"role": "남자", "jp": "ありがとうございます。", "pron": "아리가토-고자이마스", "ko": "감사합니다."},
        ],
        "choices": [
            "손 잡아도 되는지 물어보고 있다.",
            "공원 출구가 어디인지 물어보고 있다.",
            "사진을 찍어달라고 부탁하고 있다.",
            "근처에 맛집이 있는지 물어보고 있다.",
        ],
        "answer": 3,
        "explain_ko": "남자가 \"写真を撮ってもらえますか？\"(사진을 찍어주실 수 있나요?)라고 부탁하고, 여자가 \"はい、もちろんです。\"(네, 물론이죠)라고 수락한 뒤 남자가 감사 인사를 하는 흐름이므로 ‘사진을 찍어달라고 부탁하고 있다’가 정답입니다."
    },   # ✅ 반드시 필요

    {
        "id": 2,
        "title": "- 2번문제 -",
        "image": "dialog_quiz/hotel_checkout.png",

        "lines": [
            {
                "role": "손님",
                "jp": "すみません、チェックアウトお願いします。",
                "pron": "스미마센, 체쿠아우토 오네가이시마스",
                "ko": "저기요, 체크아웃 부탁드립니다."
            },
            {
                "role": "직원",
                "jp": "かしこまりました。",
                "pron": "카시코마리마시타",
                "ko": "알겠습니다."
            },
            {
                "role": "직원",
                "jp": "お部屋番号をお願いします。",
                "pron": "오헤야 방고오 오네가이시마스",
                "ko": "객실 번호를 알려주세요."
            }
        ],

        "choices": [
            "호텔 프런트에서 체크아웃을 요청하고 있다.",
            "호텔 프런트에서 체크인을 요청하고 있다.",
            "호텔에서 방 청소를 부탁하고 있다.",
            "객실 키를 다시 발급받고 있다.",
        ],

        "answer": 1,

        "explain_ko": "손님이 체크아웃을 부탁하는 표현(チェックアウトお願いします)이 나오고, 직원이 객실 번호를 요청하는 전형적인 호텔 체크아웃 상황입니다."
        },

    {
        "id": 3,
        "title": "- 3번문제 -",
        "image": "dialog_quiz/bus_time.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、次のバスは何時ですか？",
                "pron": "스미마센, 츠기노 바스와 난지데스카",
                "ko": "저기요, 다음 버스는 몇 시인가요?"
            },
            {
                "role": "여자",
                "jp": "10分後に来ますよ。",
                "pron": "줍뿐고니 키마스요",
                "ko": "10분 후에 와요."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "버스 요금이 얼마인지 물어보고 있다.",
            "버스가 몇 시에 오는지 물어보고 있다.",     
            "버스가 어디로 가는지 물어보고 있다.",
            "막차 시간을 확인하고 있다.",
        ],

        "answer": 2,

        "explain_ko": "다음 버스 시간을 묻는 표현(次のバスは何時ですか？)이 등장하고, 상대가 '10분 후에 온다'고 답하고 있어 버스 도착 시간을 묻는 상황입니다."
        },

    {
        "id": 4,
        "title": "- 4번문제 -",
        "image": "dialog_quiz/entrance_fee.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、入場料はいくらですか？",
                "pron": "스미마센, 뉴-죠-료-와 이쿠라데스카",
                "ko": "저기요, 입장료는 얼마인가요?"
            },
            {
                "role": "직원",
                "jp": "大人は1,000円です。",
                "pron": "오토나와 센엔데스",
                "ko": "어른은 1,000엔입니다."
            },
            {
                "role": "남자",
                "jp": "わかりました。ありがとうございます。",
                "pron": "와카리마시타, 아리가토- 고자이마스",
                "ko": "알겠습니다, 감사합니다."
            }
        ],

        "choices": [
            "입장 요금이 얼마인지 물어보고 있다.",
            "입장권을 환불할 수 있는지 물어보고 있다.",
            "운영 시간이 언제인지 물어보고 있다.",
            "단체 할인 여부를 물어보고 있다.",
        ],

        "answer": 1,

        "explain_ko": "입장료를 뜻하는 표현(入場料はいくらですか？)이 사용되었고, 직원이 금액을 답하고 있어 요금을 묻는 상황입니다."
        },
    {
        "id": 5,
        "title": "- 5번문제 -",
        "image": "dialog_quiz/to_station.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、駅までどうやって行きますか？",
                "pron": "스미마센, 에키마데 도-얏테 이키마스카",
                "ko": "저기요, 역까지 어떻게 가나요?"
            },
            {
                "role": "여자",
                "jp": "この道をまっすぐ行って、二つ目の信号を右です。",
                "pron": "코노 미치오 맛스구 잇테, 후타츠메노 신고오오 미기데스",
                "ko": "이 길로 쭉 가서 두 번째 신호등에서 오른쪽이에요."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。助かりました。",
                "pron": "아리가토- 고자이마스, 타스카리마시타",
                "ko": "감사합니다, 큰 도움이 됐어요."
            }
        ],

        "choices": [
            "근처 식당 위치를 물어보고 있다.",
            "버스 요금이 얼마인지 묻고 있다.",
            "관광 명소가 어디인지 묻고 있다.",
            "역으로 가는 길을 물어보고 있다.",
        ],

        "answer": 4,

        "explain_ko": "‘駅までどうやって行きますか？’는 목적지까지 가는 방법을 묻는 표현으로, 길 안내 대화임을 알 수 있습니다."
        },
    {
        "id": 6,
        "title": "- 6번문제 -",
        "image": "dialog_quiz/card_payment.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、カードは使えますか？",
                "pron": "스미마센, 카-도와 츠카에마스카",
                "ko": "저기요, 카드 사용할 수 있나요?"
            },
            {
                "role": "직원",
                "jp": "はい、クレジットカードをご利用いただけます。",
                "pron": "하이, 크레짓토 카-도오 고리요- 이타다케마스",
                "ko": "네, 신용카드 사용 가능합니다."
            },
            {
                "role": "남자",
                "jp": "よかったです。お願いします。",
                "pron": "요캇타데스, 오네가이시마스",
                "ko": "다행이네요, 부탁합니다."
            }
        ],

        "choices": [
            "현금만 가능한지 확인하고 있다.",
            "물건 환불이 가능한지 묻고 있다.",
            "카드 결제가 가능한지 물어보고 있다.",
            "영업시간을 물어보고 있다.",
        ],

        "answer": 3,

        "explain_ko": "‘カードは使えますか？’는 카드 사용 가능 여부를 묻는 표현으로, 결제 방법을 확인하는 상황입니다."
        },
    {
        "id": 7,
        "title": "- 7번문제 -",
        "image": "dialog_quiz/fitting_room.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、これを試着してもいいですか？",
                "pron": "스미마센, 코레오 시챠쿠시테모 이-데스카",
                "ko": "저기요, 이거 입어봐도 될까요?"
            },
            {
                "role": "직원",
                "jp": "はい、試着室はこちらです。",
                "pron": "하이, 시챠쿠시츠와 코치라데스",
                "ko": "네, 피팅룸은 이쪽입니다."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "옷을 입어봐도 되는지 물어보고 있다.",
            "옷 가격을 확인하고 있다.",
            "사이즈 교환이 가능한지 묻고 있다.",
            "환불이 가능한지 물어보고 있다.",
        ],

        "answer": 1,

        "explain_ko": "‘試着してもいいですか？’는 옷을 입어봐도 되는지 정중하게 묻는 표현으로 쇼핑할 때 자주 사용됩니다."
        },
    {
        "id": 8,
        "title": "- 8번문제 -",
        "image": "dialog_quiz/lost_phone_police.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、スマホをなくしました。",
                "pron": "스미마센, 스마호오 나쿠시마시타",
                "ko": "저기요, 휴대폰을 잃어버렸어요."
            },
            {
                "role": "경찰",
                "jp": "それは大変ですね。いつ気づきましたか？",
                "pron": "소레와 타이헨데스네. 이츠 키즈키마시타카",
                "ko": "그건 큰일이네요. 언제 알아차리셨나요?"
            },
            {
                "role": "남자",
                "jp": "さっき、この交差点でです。",
                "pron": "삭키, 코노 코-사텐데 데스",
                "ko": "조금 전에 이 교차로에서요."
            }
        ],

        "choices": [
            "길을 물어보고 있다.",
            "교통사고를 신고하고 있다.",
            "지갑을 찾고 있다.",
            "경찰에게 휴대폰 분실을 신고하고 있다.",
            
        ],

        "answer": 4,

        "explain_ko": "‘スマホをなくしました’는 휴대폰을 잃어버렸다는 뜻으로, 경찰에게 분실 사실을 알릴 때 사용하는 표현입니다."
        },
    {
        "id": 9,
        "title": "- 9번문제 -",
        "image": "dialog_quiz/stomach_pain_pharmacy.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、お腹が痛いです。",
                "pron": "스미마센, 오나카가 이타이데스",
                "ko": "저기요, 배가 아파요."
            },
            {
                "role": "약사",
                "jp": "いつから痛みますか？",
                "pron": "이츠카라 이타미마스카",
                "ko": "언제부터 아프셨나요?"
            },
            {
                "role": "남자",
                "jp": "今朝からです。",
                "pron": "케사카라 데스",
                "ko": "오늘 아침부터요."
            }
        ],

        "choices": [
            "병원 예약을 하고 있다.",
            "감기약을 찾고 있다.",
            "약국에서 배가 아픈 증상을 설명하고 있다.",
            "두통에 대해 상담하고 있다.",
        ],

        "answer": 3,

        "explain_ko": "‘お腹が痛いです’는 배가 아프다는 뜻으로, 약사에게 증상을 설명하는 상황입니다."
    },
    {
        "id": 10,
        "title": "- 10번문제 -",
        "image": "dialog_quiz/park_bench_seat.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、ここに座ってもいいですか？",
                "pron": "스미마센, 코코니 스왓테모 이이데스카",
                "ko": "죄송한데, 여기 앉아도 될까요?"
            },
            {
                "role": "남자2",
                "jp": "はい、どうぞ。",
                "pron": "하이, 도-조",
                "ko": "네, 앉으세요."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "자리를 예약하려고 하고 있다.",
            "벤치에 앉아도 되는지 정중하게 묻고 있다.",
            "길을 물어보고 있다.",
            "사진을 찍어달라고 부탁하고 있다."
        ],

        "answer": 2,

        "explain_ko": "처음 만난 사람에게 벤치에 앉아도 되는지 정중하게 묻고 허락을 받은 상황입니다."
    },
    {
        "id": 11,
        "title": "- 11번문제 -",
        "image": "dialog_quiz/ryokan_dinner_time.png",

        "lines": [
            {
                "role": "투숙객",
                "jp": "夕食は何時ですか？",
                "pron": "유-쇼쿠와 난지데스카",
                "ko": "저녁은 몇 시예요?"
            },
            {
                "role": "직원",
                "jp": "午後六時からご用意しています。",
                "pron": "고고 로쿠지카라 고요-이 시테이마스",
                "ko": "오후 6시부터 준비되어 있습니다."
            },
            {
                "role": "투숙객",
                "jp": "部屋で食べられますか？",
                "pron": "헤야데 타베라레마스카",
                "ko": "방에서 먹을 수 있나요?"
            },
            {
                "role": "직원",
                "jp": "はい、お部屋にお持ちします。",
                "pron": "하이, 오헤야니 오모치시마스",
                "ko": "네, 방으로 가져다드려요."
            }
        ],

        "choices": [
            "체크인 절차를 진행하고 있다.",
            "온천 이용 시간을 묻고 있다.",
            "저녁 식사 시간과 장소를 확인하고 있다.",
            "요금 할인을 요청하고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘夕食は何時ですか’로 저녁 시간을 묻고, 방에서 먹을 수 있는지도 확인하는 상황입니다."
    },
    {
        "id": 12,
        "title": "- 12번문제 -",
        "image": "dialog_quiz/amusement_ticket.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、チケットはどこで買えますか？",
                "pron": "스미마센, 치켓토와 도코데 카에마스카",
                "ko": "저기 실례합니다, 티켓은 어디서 살 수 있나요?"
            },
            {
                "role": "직원",
                "jp": "入口の右側にチケット売り場があります。",
                "pron": "이리구치노 미기 가와니 치켓토 우리바가 아리마스",
                "ko": "입구 오른쪽에 티켓 판매소가 있어요."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "놀이기구 줄이 어디인지 묻고 있다.",
            "놀이공원 출구 위치를 확인하고 있다.",
            "티켓을 어디서 구매하는지 묻고 있다.",
            "화장실 위치를 물어보고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘チケットはどこで買えますか？’는 티켓을 어디에서 살 수 있는지 묻는 표현이며, 직원이 판매소 위치를 안내하는 대화로 상황이 명확해집니다."
    },
    {
        "id": 13,
        "title": "- 13번문제 -",
        "image": "dialog_quiz/hotel_change_room.png",

        "lines": [
            {
                "role": "손님",
                "jp": "すみません、部屋を変えられますか？",
                "pron": "스미마센, 헤야오 카에라레마스카",
                "ko": "저기 실례합니다, 방을 바꿀 수 있을까요?"
            },
            {
                "role": "직원",
                "jp": "はい、空いているお部屋を確認いたします。",
                "pron": "하이, 아이테이루 오헤야오 카쿠닌 이타시마스",
                "ko": "네, 빈 방을 확인해 드리겠습니다."
            },
            {
                "role": "손님",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "체크아웃 시간을 연장하려고 하고 있다.",
            "방을 다른 곳으로 바꾸고 싶어 하고 있다.",
            "추가 수건을 요청하고 있다.",
            "조식 장소를 묻고 있다.",
        ],

        "answer": 2,

        "explain_ko": "‘部屋を変えられますか？’는 방을 바꿀 수 있는지 묻는 표현으로, 객실 변경 요청 상황입니다."
    },
    {
        "id": 14,
        "title": "- 14번문제 -",
        "image": "dialog_quiz/airport_security.png",

        "lines": [
            {
                "role": "여행자",
                "jp": "すみません、保安検査はどこですか？",
                "pron": "스미마센, 호안켄사와 도코데스카",
                "ko": "저기 실례합니다, 보안 검색은 어디인가요?"
            },
            {
                "role": "직원",
                "jp": "まっすぐ行って右側にあります。",
                "pron": "맛스구 잇테 미기카와니 아리마스",
                "ko": "곧장 가시면 오른쪽에 있습니다."
            },
            {
                "role": "여행자",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "출국 수속 창구를 찾고 있다.",
            "수하물 찾는 곳을 묻고 있다.",
            "보안 검색 위치를 물어보고 있다.",
            "환전소가 어디인지 묻고 있다.",
        ],

        "answer": 3,

        "explain_ko": "‘保安検査はどこですか？’는 공항에서 보안 검색 장소를 묻는 표현입니다."
    },
    {
        "id": 15,
        "title": "- 15번문제 -",
        "image": "dialog_quiz/train_transfer.png",

        "lines": [
            {
                "role": "여행자",
                "jp": "すみません、乗り換えはどこですか？",
                "pron": "스미마센, 노리카에와 도코데스카",
                "ko": "저기 실례합니다, 환승은 어디서 하나요?"
            },
            {
                "role": "직원",
                "jp": "5番線の向こう側です。",
                "pron": "고반센노 무코-가와데스",
                "ko": "5번 승강장 건너편입니다."
            },
            {
                "role": "여행자",
                "jp": "助かりました、ありがとうございます。",
                "pron": "타스카리마시타, 아리가토- 고자이마스",
                "ko": "도움 됐어요, 감사합니다."
            }
        ],

        "choices": [
            "출구가 어디인지 묻고 있다.",
            "환승 장소를 물어보고 있다.",
            "표를 어디서 사는지 묻고 있다.",
            "화장실 위치를 묻고 있다.",
        ],

        "answer": 2,

        "explain_ko": "‘乗り換えはどこですか？’는 기차나 지하철에서 환승 위치를 묻는 표현입니다."
    },
    {
        "id": 16,
        "title": "- 16번문제 -",
        "image": "dialog_quiz/taxi_fare.png",

        "lines": [
            {
                "role": "승객",
                "jp": "すみません、いくらぐらいかかりますか？",
                "pron": "스미마센, 이쿠라구라이 카카리마스카",
                "ko": "저기 실례합니다, 얼마 정도 나와요?"
            },
            {
                "role": "기사",
                "jp": "だいたい2,300円くらいです。",
                "pron": "다이타이 니센 산뱌쿠엔 쿠라이데스",
                "ko": "대략 2,300엔 정도입니다."
            },
            {
                "role": "승객",
                "jp": "わかりました、お願いします。",
                "pron": "와카리마시타, 오네가이시마스",
                "ko": "알겠습니다, 부탁할게요."
            }
        ],

        "choices": [
            "길이 막히는지 묻고 있다.",
            "도착 시간을 묻고 있다.",
            "목적지가 맞는지 확인하고 있다.",
            "택시 요금이 얼마나 나오는지 묻고 있다.",
        ],

        "answer": 4,

        "explain_ko": "‘いくらぐらいかかりますか？’는 비용이 얼마나 드는지 물을 때 쓰는 표현으로, 택시 요금을 묻는 상황입니다."
    },
    {
        "id": 17,
        "title": "- 17번문제 -",
        "image": "dialog_quiz/no_spicy_order.png",

        "lines": [
            {
                "role": "손님",
                "jp": "これをお願いします。",
                "pron": "코레오 오네가이시마스",
                "ko": "이거 주세요."
            },
            {
                "role": "손님",
                "jp": "辛くしないでください。",
                "pron": "카라쿠 시나이데 쿠다사이",
                "ko": "맵지 않게 해주세요."
            },
            {
                "role": "직원",
                "jp": "はい、辛くしませんね。",
                "pron": "하이, 카라쿠 시마센네",
                "ko": "네, 맵지 않게 해드릴게요."
            }
        ],

        "choices": [
            "음식을 포장해달라고 부탁하고 있다.",
            "추천 메뉴를 물어보고 있다.",
            "음식을 맵지 않게 해달라고 요청하고 있다.",
            "주문을 취소하고 있다.",
        ],

        "answer": 3,

        "explain_ko": "‘辛くしないでください’는 음식이 맵지 않게 해달라는 뜻으로, 매운 정도를 조절해달라고 요청하는 상황입니다."
    },
    {
        "id": 18,
        "title": "- 18번문제 -",
        "image": "dialog_quiz/ask_for_bill.png",

        "lines": [
            {
                "role": "손님",
                "jp": "すみません、お会計お願いします。",
                "pron": "스미마센, 오카이케 오네가이시마스",
                "ko": "저기요, 계산 부탁해요."
            },
            {
                "role": "직원",
                "jp": "はい、ただいまお持ちします。",
                "pron": "하이, 타다이마 오모치시마스",
                "ko": "네, 바로 가져다드릴게요."
            }
        ],

        "choices": [
            "메뉴를 추천해 달라고 요청하고 있다.",
            "계산을 해달라고 부탁하고 있다.",
            "포장을 부탁하고 있다.",
            "예약 여부를 확인하고 있다.",
        ],

        "answer": 2,

        "explain_ko": "‘お会計お願いします’는 식사 후 계산을 요청할 때 쓰는 대표적인 표현입니다."
    },
    {
        "id": 19,
        "title": "- 19번문제 -",
        "image": "dialog_quiz/ask_about_product.png",

        "lines": [
            {
                "role": "손님",
                "jp": "すみません、これは何ですか？",
                "pron": "스미마센, 코레와 난데스카",
                "ko": "저기요, 이건 뭐예요?"
            },
            {
                "role": "직원",
                "jp": "それは新しく入ったジュースです。",
                "pron": "소레와 아타라시쿠 하잇타 주스데스",
                "ko": "그건 새로 들어온 주스예요."
            },
            {
                "role": "손님",
                "jp": "甘いですか？",
                "pron": "아마이데스카",
                "ko": "달아요?"
            },
            {
                "role": "직원",
                "jp": "はい、とても人気がありますよ。",
                "pron": "하이, 토테모 닌키가 아리마스요",
                "ko": "네, 아주 인기가 많아요."
            }
        ],

        "choices": [
            "계산대가 어디 있는지 묻고 있다.",
            "상품이 얼마인지 가격을 확인하고 있다.",
            "물건이 무엇인지 물어보고 있다.",
            "환불이 가능한지 문의하고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘これは何ですか？’는 물건을 가리키며 ‘이건 무엇인가요?’라고 물을 때 사용하는 기본 표현입니다."
    },
    {
        "id": 20,
        "title": "- 20번문제 -",
        "image": "dialog_quiz/ask_how_long.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、駅までどのくらいかかりますか？",
                "pron": "스미마센, 에키마데 도노쿠라이 카카리마스카",
                "ko": "저기요, 역까지 얼마나 걸려요?"
            },
            {
                "role": "여자",
                "jp": "歩いて10分くらいです。",
                "pron": "아루이테 쥬푼 쿠라이데스",
                "ko": "걸어서 10분 정도예요."
            },
            {
                "role": "남자",
                "jp": "遠いですか？",
                "pron": "토오이데스카",
                "ko": "멀어요?"
            },
            {
                "role": "여자",
                "jp": "いいえ、すぐ着きますよ。",
                "pron": "이에, 스구 츠키마스요",
                "ko": "아니요, 금방 도착해요."
            }
        ],

        "choices": [
            "길이 막히는 시간대를 묻고 있다.",
            "근처 식당 위치를 물어보고 있다.",
            "교통수단 요금을 확인하고 있다.",
            "목적지까지 걸리는 시간을 묻고 있다."
        ],

        "answer": 4,

        "explain_ko": "‘どのくらいかかりますか？’는 시간이나 거리 등 소요 시간을 물을 때 사용하는 표현입니다."
    },
    {
        "id": 21,
        "title": "- 21번문제 -",
        "image": "dialog_quiz/buy_sim_card.png",

        "lines": [
            {
                "role": "손님",
                "jp": "このSIMカードは何日間使えますか？",
                "pron": "코노 시무 카도와 난니치칸 츠카에마스카",
                "ko": "이 SIM 카드는 며칠 동안 사용할 수 있나요?"
            },
            {
                "role": "직원",
                "jp": "7日間使えます。",
                "pron": "나노카칸 츠카에마스",
                "ko": "7일 동안 사용할 수 있습니다."
            },
            {
                "role": "손님",
                "jp": "データは十分ありますか？",
                "pron": "데에타와 쥬우분 아리마스카",
                "ko": "데이터는 충분한가요?"
            },
            {
                "role": "직원",
                "jp": "はい、旅行には問題ありません。",
                "pron": "하이, 료코오니와 몬다이 아리마센",
                "ko": "네, 여행용으로 충분합니다."
            }
        ],

        "choices": [
            "요금 환불이 가능한지 묻고 있다.",
            "SIM 카드 사용 기간을 확인하고 있다.",
            "와이파이 비밀번호를 물어보고 있다.",
            "휴대폰 수리 여부를 문의하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘何日間使えますか？’는 서비스나 물건을 며칠 동안 사용할 수 있는지 기간을 물을 때 쓰는 표현입니다."
    },
    {
        "id": 22,
        "title": "- 22번문제 -",
        "image": "dialog_quiz/choose_movie_seat.png",

        "lines": [
            {
                "role": "손님",
                "jp": "チケットを2枚ください。",
                "pron": "치켓토오 니마이 쿠다사이",
                "ko": "표 두 장 주세요."
            },
            {
                "role": "직원",
                "jp": "お席はどちらがよろしいですか？",
                "pron": "오세키와 도치라가 요로시이데스카",
                "ko": "좌석은 어디가 좋으신가요?"
            },
            {
                "role": "손님",
                "jp": "真ん中がいいです。",
                "pron": "만나카가 이이데스",
                "ko": "가운데가 좋아요."
            },
            {
                "role": "직원",
                "jp": "かしこまりました。",
                "pron": "카시코마리마시타",
                "ko": "알겠습니다."
            }
        ],

        "choices": [
            "영화 시작 시간을 확인하고 있다.",
            "좌석 위치를 선택하고 있다.",
            "영화 줄거리를 물어보고 있다.",
            "환불이 가능한지 묻고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘真ん中がいいです’는 좌석이나 위치를 고를 때 ‘가운데가 좋아요’라고 선택 의사를 표현하는 말입니다."
    },
    {
        "id": 23,
        "title": "- 23번문제 -",
        "image": "dialog_quiz/forgot_password_locker.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、暗証番号を忘れました。",
                "pron": "스미마센, 안쇼-방고-오 와스레마시타",
                "ko": "저기요, 비밀번호를 잊어버렸어요."
            },
            {
                "role": "직원",
                "jp": "ロッカーの番号は覚えていますか？",
                "pron": "롯카아노 방고와 오보에테이마스카",
                "ko": "보관함 번호는 기억하시나요?"
            },
            {
                "role": "남자",
                "jp": "はい、15番です。",
                "pron": "하이, 쥬우고방데스",
                "ko": "네, 15번이에요."
            },
            {
                "role": "직원",
                "jp": "確認して開けますね。",
                "pron": "카쿠닌시테 아케마스네",
                "ko": "확인하고 열어드릴게요."
            }
        ],

        "choices": [
            "열쇠를 분실했다고 말하고 있다.",
            "보관함 위치를 묻고 있다.",
            "비밀번호를 잊어버렸다고 도움을 요청하고 있다.",
            "요금을 얼마나 내야 하는지 묻고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘暗証番号を忘れました’는 비밀번호나 PIN 번호를 잊어버렸을 때 사용하는 표현입니다."
    },
    {
        "id": 24,
        "title": "- 24번문제 -",
        "image": "dialog_quiz/ask_discount_museum.png",

        "lines": [
            {
                "role": "손님",
                "jp": "すみません、チケットはいくらですか？",
                "pron": "스미마센, 치켓토와 이쿠라데스카",
                "ko": "저기요, 티켓은 얼마인가요?"
            },
            {
                "role": "직원",
                "jp": "大人は2000円です。",
                "pron": "오토나와 니센엔데스",
                "ko": "성인은 2,000엔입니다."
            },
            {
                "role": "손님",
                "jp": "割引はありますか？",
                "pron": "와리비키와 아리마스카",
                "ko": "할인은 있나요?"
            },
            {
                "role": "직원",
                "jp": "学生割引がありますよ。",
                "pron": "가쿠세이 와리비키가 아리마스요",
                "ko": "학생 할인 있습니다."
            }
        ],

        "choices": [
            "전시 시간이 언제인지 묻고 있다.",
            "사진 촬영이 가능한지 확인하고 있다.",
            "티켓 가격 할인을 문의하고 있다.",
            "환불 규정을 묻고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘割引はありますか？’는 요금이나 티켓에 할인 혜택이 있는지 물을 때 사용하는 표현입니다."
    },
    {
        "id": 25,
        "title": "- 25번문제 -",
        "image": "dialog_quiz/ask_exit_festival.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、出口はどこですか？",
                "pron": "스미마센, 데구치와 도코데스카",
                "ko": "저기요, 출구는 어디예요?"
            },
            {
                "role": "남자",
                "jp": "あそこをまっすぐ行ってください。",
                "pron": "아소코오 맛스구 잇테 쿠다사이",
                "ko": "저쪽으로 곧장 가세요."
            },
            {
                "role": "남자",
                "jp": "右ですか？",
                "pron": "미기데스카",
                "ko": "오른쪽인가요?"
            },
            {
                "role": "남자",
                "jp": "いいえ、左側です。",
                "pron": "이에, 히다리가와데스",
                "ko": "아니요, 왼쪽이에요."
            }
        ],

        "choices": [
            "화장실 위치를 묻고 있다.",
            "출구 위치를 물어보고 있다.",
            "음식 가게 추천을 요청하고 있다.",
            "행사 시작 시간을 확인하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘出口はどこですか？’는 건물이나 행사장에서 나가는 길, 즉 출구 위치를 물을 때 사용하는 표현입니다."
    },
    {
        "id": 26,
        "title": "- 26번문제 -",
        "image": "dialog_quiz/ask_spicy_food.png",

        "lines": [
            {
                "role": "손님",
                "jp": "すみません、これは辛いですか？",
                "pron": "스미마센, 코레와 카라이데스카",
                "ko": "저기요, 이거 매워요?"
            },
            {
                "role": "직원",
                "jp": "少し辛いですが、おいしいですよ。",
                "pron": "스코시 카라이데스가, 오이시이데스요",
                "ko": "조금 맵지만 맛있어요."
            },
            {
                "role": "손님",
                "jp": "子どもでも食べられますか？",
                "pron": "코도모데모 타베라레마스카",
                "ko": "아이도 먹을 수 있나요?"
            },
            {
                "role": "직원",
                "jp": "はい、大丈夫ですよ。",
                "pron": "하이, 다이죠부데스요",
                "ko": "네, 괜찮아요."
            }
        ],

        "choices": [
            "음식이 얼마나 비싼지 묻고 있다.",
            "음식이 매운지 확인하고 있다.",
            "포장이 가능한지 물어보고 있다.",
            "재료가 무엇인지 질문하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘辛いですか？’는 음식의 매운 정도를 물을 때 사용하는 아주 기본적인 표현입니다."
    },
    {
        "id": 27,
        "title": "- 27번문제 -",
        "image": "dialog_quiz/no_toilet_paper.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、紙がありません。",
                "pron": "스미마센, 카미가 아리마센",
                "ko": "저기요, 휴지가 없어요."
            },
            {
                "role": "직원",
                "jp": "少々お待ちください。",
                "pron": "쇼오쇼오 오마치 쿠다사이",
                "ko": "잠시만 기다려 주세요."
            },
            {
                "role": "남자",
                "jp": "こちらのトイレです。",
                "pron": "코치라노 토이레데스",
                "ko": "이쪽 화장실이에요."
            },
            {
                "role": "직원",
                "jp": "すぐ持ってきます。",
                "pron": "스구 못테 키마스",
                "ko": "바로 가져올게요."
            }
        ],

        "choices": [
            "화장실 위치를 묻고 있다.",
            "휴지가 없다고 말하고 있다.",
            "청소 시간을 확인하고 있다.",
            "물이 고장 났다고 신고하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘紙がありません’는 화장실 휴지나 종이가 없을 때 부족함을 알리는 기본 표현입니다."
    },
    {
        "id": 28,
        "title": "- 28번문제 -",
        "image": "dialog_quiz/ask_current_location.png",

        "lines": [
            {
                "role": "친구",
                "jp": "今どこですか？",
                "pron": "이마다 도코데스카",
                "ko": "지금 어디예요?"
            },
            {
                "role": "남자",
                "jp": "駅の前にいます。",
                "pron": "에키노 마에니 이마스",
                "ko": "역 앞에 있어요."
            },
            {
                "role": "친구",
                "jp": "もう着きましたか？",
                "pron": "모오 츠키마시타카",
                "ko": "벌써 도착했어요?"
            },
            {
                "role": "남자",
                "jp": "はい、待ち合わせ場所です。",
                "pron": "하이, 마치아와세 바쇼데스",
                "ko": "네, 약속 장소예요."
            }
        ],

        "choices": [
            "현재 위치를 확인하고 있다.",
            "열차 시간을 묻고 있다.",
            "길이 막혔는지 질문하고 있다.",
            "만날 사람의 이름을 확인하고 있다."
        ],

        "answer": 1,

        "explain_ko": "‘今どこですか？’는 전화나 메시지에서 상대방의 현재 위치를 물을 때 가장 많이 쓰는 표현입니다."
    },
    {
        "id": 29,
        "title": "- 29번문제 -",
        "image": "dialog_quiz/no_smoking_area_notice.png",

        "lines": [
            {
                "role": "친구",
                "jp": "すみませんが、ここではタバコを吸ってはいけません。",
                "pron": "스미마센가, 코코데와 타바코오 슷테와 이케마센",
                "ko": "죄송하지만 여기서는 담배를 피우면 안 돼요."
            },
            {
                "role": "남자",
                "jp": "ここは禁煙ですか？",
                "pron": "코코와 킨엔데스카",
                "ko": "여기는 금연인가요?"
            },
            {
                "role": "친구",
                "jp": "はい、禁煙エリアです。",
                "pron": "하이, 킨엔 에리아데스",
                "ko": "네, 금연 구역이에요."
            },
            {
                "role": "남자",
                "jp": "わかりました。",
                "pron": "와카리마시타",
                "ko": "알겠습니다."
            }
        ],

        "choices": [
            "흡연이 허용된 장소를 찾고 있다.",
            "담배 가격을 묻고 있다.",
            "이곳은 금연 구역이라 알려주고 있다.",
            "라이터를 빌려 달라고 요청하고 있다."
        ],

        "answer": 3,

        "explain_ko": "대화에서 흡연이 금지된 장소임을 알리고 ‘禁煙ですか？’로 금연 여부를 확인하는 상황입니다."
    },
    {
        "id": 30,
        "title": "- 30번문제 -",
        "image": "dialog_quiz/ask_weather_window.png",

        "lines": [
            {
                "role": "남자",
                "jp": "天気はどうですか？",
                "pron": "텐키와 도-데스카",
                "ko": "날씨 어때요?"
            },
            {
                "role": "친구",
                "jp": "今日は暖かくて、外で活動するのにいいですよ。",
                "pron": "쿄오와 아타타카쿠테, 소토데 카츠도오 스루노니 이이데스요",
                "ko": "오늘은 따뜻해서 밖에서 활동하기 좋아요."
            },
            {
                "role": "남자",
                "jp": "それはよかったですね。",
                "pron": "소레와 요캇타데스네",
                "ko": "그건 잘됐네요."
            },
            {
                "role": "남자",
                "jp": "外で過ごせそうです。",
                "pron": "소토데 스고세소오데스",
                "ko": "밖에서 활동할 수 있겠어요."
            }
        ],

        "choices": [
            "날씨 상태를 묻고 대화하고 있다.",
            "약속 장소를 정하고 있다.",
            "옷차림을 추천하고 있다.",
            "비 오는지 확인하고 있다."
        ],

        "answer": 1,

        "explain_ko": "대화에서 날씨를 묻고 따뜻해서 야외 활동하기 좋다는 상황을 이야기하고 있습니다."
    },
    {
        "id": 31,
        "title": "- 31번문제 -",
        "image": "dialog_quiz/ask_hidden_spot_park.png",

        "lines": [
            {
                "role": "남자",
                "jp": "この近くに穴場はありますか？",
                "pron": "코노 치카쿠니 아나바와 아리마스카",
                "ko": "이 근처에 숨은 명소가 있나요?"
            },
            {
                "role": "여자",
                "jp": "はい、あの奥に静かな庭園がありますよ。",
                "pron": "하이, 아노 오쿠니 시즈카나 테이엔가 아리마스요",
                "ko": "네, 저 안쪽에 조용한 정원이 있어요."
            },
            {
                "role": "남자",
                "jp": "人は多くないですか？",
                "pron": "히토와 오오쿠 나이데스카",
                "ko": "사람은 많지 않나요?"
            },
            {
                "role": "여자",
                "jp": "あまり知られていないので空いています。",
                "pron": "아마리 시라레테 이나이노데 아이테이마스",
                "ko": "잘 알려지지 않아서 한적해요."
            }
        ],

        "choices": [
            "근처 식당을 추천해 달라고 하고 있다.",
            "사진 찍기 좋은 장소를 묻고 있다.",
            "숨은 명소가 있는지 물어보고 있다.",
            "길이 막히는지 확인하고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘穴場はありますか？’는 사람들이 잘 모르는 숨은 명소나 좋은 장소를 물을 때 쓰는 표현입니다."
    },
    {
        "id": 32,
        "title": "- 32번문제 -",
        "image": "dialog_quiz/wrong_order_restaurant.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、注文と違います。",
                "pron": "스미마센, 츄-몬토 치가이마스",
                "ko": "저기요, 주문이랑 달라요."
            },
            {
                "role": "직원",
                "jp": "申し訳ありません。どちらをご注文されましたか？",
                "pron": "모오시아케 아리마센, 도치라오 고츄우몬 사레마시타카",
                "ko": "죄송합니다, 어떤 것을 주문하셨나요?"
            },
            {
                "role": "남자",
                "jp": "この定食を頼みました。",
                "pron": "코노 테이쇼쿠오 타노미마시타",
                "ko": "이 정식을 주문했어요."
            },
            {
                "role": "직원",
                "jp": "すぐにお持ちします。",
                "pron": "스구니 오모치시마스",
                "ko": "바로 가져다 드릴게요."
            }
        ],

        "choices": [
            "음식이 너무 맵다고 말하고 있다.",
            "추가 주문을 하고 있다.",
            "주문한 음식과 다르다고 말하고 있다.",
            "계산을 요청하고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘注文と違います’는 식당에서 나온 음식이 주문한 것과 다를 때 정중하게 말하는 표현입니다."
    },
    {
    "id": 33,
        "title": "- 33번문제 -",
        "image": "dialog_quiz/restaurant_reservation_name.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、名前で予約しています。",
                "pron": "스미마센, 나마에데 요야쿠시테이마스",
                "ko": "저기요, 이름으로 예약했어요."
            },
            {
                "role": "직원",
                "jp": "お名前を教えていただけますか？",
                "pron": "오나마에오 오시에테 이타다케마스카",
                "ko": "성함을 알려주시겠어요?"
            },
            {
                "role": "남자",
                "jp": "キムです。",
                "pron": "키무데스",
                "ko": "김입니다."
            },
            {
                "role": "직원",
                "jp": "はい、こちらへどうぞ。",
                "pron": "하이, 코치라에 도오조",
                "ko": "네, 이쪽으로 오세요."
            }
        ],

        "choices": [
            "메뉴를 추천해 달라고 하고 있다.",
            "예약 여부를 확인하고 있다.",
            "계산을 요청하고 있다.",
            "포장을 부탁하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘名前で予約しています’는 식당이나 호텔에서 이름으로 예약했음을 알릴 때 사용하는 자연스러운 표현입니다."
    },
    {
        "id": 34,
        "title": "- 34번문제 -",
        "image": "dialog_quiz/luggage_not_found_airport.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、荷物が見つかりません。",
                "pron": "스미마센, 니모츠가 미츠카리마센",
                "ko": "저기요, 짐이 안 보여요."
            },
            {
                "role": "직원",
                "jp": "どの便で到着されましたか？",
                "pron": "도노 빈데 토오차쿠 사레마시타카",
                "ko": "어느 비행편으로 도착하셨나요?"
            },
            {
                "role": "남자",
                "jp": "ソウルからの便です。",
                "pron": "소우루카라노 빈데스",
                "ko": "서울에서 온 비행편이에요."
            },
            {
                "role": "직원",
                "jp": "確認いたしますので少々お待ちください。",
                "pron": "카쿠닌 이타시마스노데 쇼오쇼오 오마치 쿠다사이",
                "ko": "확인해 드릴 테니 잠시만 기다려 주세요."
            }
        ],

        "choices": [
            "출구 위치를 묻고 있다.",
            "짐이 사라졌다고 신고하고 있다.",
            "비행기 시간을 확인하고 있다.",
            "환전을 요청하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘荷物が見つかりません’는 공항에서 수하물이 보이지 않을 때 도움을 요청하는 기본 표현입니다."
    },
    {
        "id": 35,
        "title": "- 35번문제 -",
        "image": "dialog_quiz/check_opposite_direction_map.png",

        "lines": [
            {
                "role": "남자",
                "jp": "この道で駅に行けますか？",
                "pron": "코노 미치데 에키니 이케마스카",
                "ko": "이 길로 역에 갈 수 있나요?"
            },
            {
                "role": "현지인",
                "jp": "いいえ、その道は違いますよ。",
                "pron": "이에, 소노 미치와 치가이마스요",
                "ko": "아니요, 그 길은 아니에요."
            },
            {
                "role": "남자",
                "jp": "反対方向ですか？",
                "pron": "한타이호-코-데스카",
                "ko": "반대 방향인가요?"
            },
            {
                "role": "현지인",
                "jp": "はい、向こうに戻ってください。",
                "pron": "하이, 무코오니 모돗테 쿠다사이",
                "ko": "네, 저쪽으로 돌아가세요."
            }
        ],

        "choices": [
            "버스 시간을 확인하고 있다.",
            "목적지 요금을 묻고 있다.",
            "방향이 맞는지 확인하고 있다.",
            "식당 위치를 찾고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘反対方向ですか？’는 가려는 길이 맞는지, 아니면 반대 방향인지 확인할 때 사용하는 표현입니다."
    },
    {
        "id": 36,
        "title": "- 36번문제 -",
        "image": "dialog_quiz/lost_item_theater.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、落とし物をしました。",
                "pron": "스미마센, 오토시모노오 시마시타",
                "ko": "죄송한데, 물건을 잃어버렸어요."
            },
            {
                "role": "직원",
                "jp": "どんな物ですか？",
                "pron": "돈나 모노데스카",
                "ko": "어떤 물건인가요?"
            },
            {
                "role": "남자",
                "jp": "黒い財布です。",
                "pron": "쿠로이 사이후데스",
                "ko": "검은 지갑이에요."
            }
        ],

        "choices": [
            "영화 시간을 묻고 있다.",
            "좌석 위치를 바꾸고 있다.",
            "잃어버린 물건을 찾고 있다.",
            "표를 환불하고 있다."
        ],

        "answer": 3,

        "explain_ko": "극장 직원에게 분실한 물건(지갑)에 대해 설명하며 찾고 있는 상황입니다."
    },
    {
        "id": 37,
        "title": "- 37번문제 -",
        "image": "dialog_quiz/restroom_amusement_park.png",

        "lines": [
            {
                "role": "여자",
                "jp": "すみません、トイレはどこですか？",
                "pron": "스미마센, 토이레와 도코데스카",
                "ko": "죄송한데 화장실은 어디예요?"
            },
            {
                "role": "직원",
                "jp": "あちらをまっすぐ行ってください。",
                "pron": "아치라오 맛스구 잇테 쿠다사이",
                "ko": "저쪽으로 곧장 가세요."
            },
            {
                "role": "여자",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "놀이기구 시간을 묻고 있다.",
            "음식점 위치를 묻고 있다.",
            "출구를 찾고 있다.",
            "화장실 위치를 묻고 있다."
        ],

        "answer": 4,

        "explain_ko": "놀이공원 직원에게 화장실이 어디 있는지 길을 묻는 상황입니다."
    },
    {
        "id": 38,
        "title": "- 38번문제 -",
        "image": "dialog_quiz/child_ticket_price.png",

        "lines": [
            {
                "role": "여자",
                "jp": "すみません、子ども料金はいくらですか？",
                "pron": "스미마센, 코도모 료-킨와 이쿠라데스카",
                "ko": "죄송한데 어린이 요금은 얼마예요?"
            },
            {
                "role": "직원",
                "jp": "子どもは三千円です。",
                "pron": "코도모와 산젠엔데스",
                "ko": "어린이는 3,000엔입니다."
            },
            {
                "role": "여자",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "놀이기구 이용 시간을 묻고 있다.",
            "어린이 입장 요금을 묻고 있다.",
            "할인 여부를 확인하고 있다.",
            "출구 위치를 묻고 있다."
        ],

        "answer": 2,

        "explain_ko": "매표소 직원에게 어린이 요금이 얼마인지 가격을 묻는 상황입니다."
    },
    {
        "id": 39,
        "title": "- 39번문제 -",
        "image": "dialog_quiz/japanese_street_help.png",

        "lines": [
            {
                "role": "남자1",
                "jp": "すみません、日本語が苦手です。この看板には何と書いてありますか？",
                "pron": "스미마센, 니혼고가 니가테데스. 코노 칸반니와 난토 카이테 아리마스카",
                "ko": "죄송한데 일본어가 서툴러요. 이 간판에 뭐라고 적혀 있나요?"
            },
            {
                "role": "남자2",
                "jp": "これはラーメン屋さんですよ。",
                "pron": "코레와 라-멘야상데스요",
                "ko": "이건 라멘 가게예요."
            },
            {
                "role": "남자1",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "영화 시간을 묻고 있다.",
            "간판 내용을 물어보고 있다.",
            "가격을 흥정하고 있다.",
            "길을 찾고 있다."
        ],

        "answer": 2,

        "explain_ko": "일본어를 잘 못해 간판에 적힌 내용을 물어보고 설명을 듣는 상황입니다."
    },
    {
        "id": 40,
        "title": "- 40번문제 -",
        "image": "dialog_quiz/bus_shinjuku_question.png",

        "lines": [
            {
                "role": "남자1",
                "jp": "すみません、このバスは新宿に行きますか？",
                "pron": "스미마센, 코노 바스와 신주쿠니 이키마스카",
                "ko": "죄송한데 이 버스 신주쿠 가나요?"
            },
            {
                "role": "남자2",
                "jp": "はい、新宿まで行きますよ。",
                "pron": "하이, 신주쿠마데 이키마스요",
                "ko": "네, 신주쿠까지 가요."
            },
            {
                "role": "남자1",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "버스 요금을 물어보고 있다.",
            "신주쿠로 가는지 확인하고 있다.",
            "좌석이 있는지 묻고 있다.",
            "다음 정류장을 묻고 있다."
        ],

        "answer": 2,

        "explain_ko": "남자가 버스가 신주쿠로 가는지 다른 승객에게 확인하고 있다."
    },
    {
        "id": 41,
        "title": "- 41번문제 -",
        "image": "dialog_quiz/tourist_ticket_place.png",

        "lines": [
            {
                "role": "남자1",
                "jp": "すみません、チケットはどこで買えますか？",
                "pron": "스미마센, 치켓토와 도코데 카에마스카",
                "ko": "죄송한데 티켓은 어디서 살 수 있나요?"
            },
            {
                "role": "남자2",
                "jp": "あそこにある窓口で買えますよ。",
                "pron": "아소코니 아루 마도구치데 카에마스요",
                "ko": "저기 있는 매표소에서 살 수 있어요."
            },
            {
                "role": "남자1",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "화장실 위치를 묻고 있다.",
            "입장 시간을 확인하고 있다.",
            "티켓 구매 장소를 물어보고 있다.",
            "길을 잃어서 도움을 요청하고 있다."
        ],

        "answer": 3,

        "explain_ko": "남자가 관광지에서 티켓을 어디서 사는지 다른 사람에게 묻고 있다."
    },
    {
        "id": 42,
        "title": "- 42번문제 -",
        "image": "dialog_quiz/map_direction_help.png",

        "lines": [
            {
                "role": "남자1",
                "jp": "すみません、この場所に行きたいです。",
                "pron": "스미마센, 코노 바쇼니 이키타이데스",
                "ko": "죄송한데 이 장소에 가고 싶어요."
            },
            {
                "role": "남자2",
                "jp": "この道をまっすぐ行って、右に曲がってください。",
                "pron": "코노 미치오 맛스구 잇테, 미기니 마갓테 쿠다사이",
                "ko": "이 길로 쭉 가서 오른쪽으로 도세요."
            },
            {
                "role": "남자1",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "식당을 추천받고 있다.",
            "길을 물어보고 안내받고 있다.",
            "티켓 가격을 확인하고 있다.",
            "버스 시간을 묻고 있다."
        ],

        "answer": 2,

        "explain_ko": "지도를 보여주며 목적지로 가는 길을 물어보고 있다."
    },
    {
        "id": 43,
        "title": "- 43번문제 -",
        "image": "dialog_quiz/store_two_items.png",

        "lines": [
            {
                "role": "손님",
                "jp": "これを二つください。",
                "pron": "코레오 후타츠 쿠다사이",
                "ko": "이거 두 개 주세요."
            },
            {
                "role": "직원",
                "jp": "かしこまりました。",
                "pron": "카시코마리마시타",
                "ko": "알겠습니다."
            }
        ],

        "choices": [
            "물건 가격을 묻고 있다.",
            "물건 환불을 요청하고 있다.",
            "같은 물건 2개를 달라고 말하고 있다.",
            "물건 할인 여부를 묻고 있다."
        ],

        "answer": 3,

        "explain_ko": "물건을 가리키며 두 개 달라고 주문하는 상황이다."
    },
    {
        "id": 44,
        "title": "- 44번문제 -",
        "image": "dialog_quiz/rentacar_navigation.png",
        "lines": [
            {"role": "남자", "jp": "すみません、ナビはありますか？", "pron": "스미마센, 나비와 아리마스카", "ko": "죄송한데, 내비게이션 있나요?"},
            {"role": "직원", "jp": "はい、すべての車に付いています。", "pron": "하이, 스베테노 쿠루마니 츠이테이마스", "ko": "네, 모든 차량에 달려 있어요."},
            {"role": "남자", "jp": "よかったです。お願いします。", "pron": "요캇타데스, 오네가이시마스", "ko": "다행이네요, 부탁합니다."}
        ],
        "choices": [
            "차를 언제 반납해야 하는지 묻고 있다.",
            "차 보험이 포함되어 있는지 묻고 있다.",
            "차에 내비게이션이 있는지 묻고 있다.",
            "주차장이 어디인지 묻고 있다."
        ],
        "answer": 3,
        "explain_ko": "남자가 ‘ナビはありますか？’라고 말했는데, 여기서 ‘ナビ’는 차량 내비게이션(길 안내)을 뜻합니다. 즉 렌터카에 내비게이션이 있는지 확인하는 상황이므로 3번이 정답입니다."
    },
    {
        "id": 45,
        "title": "- 45번문제 -",
        "image": "dialog_quiz/money_exchange_rate.png",
        "lines": [
            {"role": "남자", "jp": "すみません、今日のレートはいくらですか？", "pron": "스미마센, 쿄-노 레-토와 이쿠라데스카", "ko": "죄송한데, 오늘 환율이 얼마인가요?"},
            {"role": "직원", "jp": "1ドルは150円です。", "pron": "이치도루와 햐쿠고쥬-엔데스", "ko": "1달러는 150엔입니다."},
            {"role": "남자", "jp": "わかりました。両替お願いします。", "pron": "와카리마시타, 료-가에 오네가이시마스", "ko": "알겠습니다, 환전 부탁합니다."}
        ],
        "choices": [
            "돈을 빌려달라고 요청하고 있다.",
            "환전 수수료를 묻고 있다.",
            "환율이 얼마인지 물어보고 있다.",
            "은행 영업시간을 묻고 있다."
        ],
        "answer": 3,
        "explain_ko": "남자가 ‘今日のレートはいくらですか？’라고 말하며 오늘의 환율(레이트)을 묻고 있고, 직원이 환율을 숫자로 설명해 주고 있으므로 환율을 확인하는 상황이다."
    },
    {
        "id": 46,
        "title": "- 46번문제 -",
        "image": "dialog_quiz/convenience_store_atm.png",
        "lines": [
            {
                "role": "남자",
                "jp": "すみません、現金を下ろしたいです。",
                "pron": "스미마센, 겐킨오 오로시타이데스",
                "ko": "죄송한데, 현금 인출하고 싶어요."
            },
            {
                "role": "직원",
                "jp": "ATMはあちらにあります。",
                "pron": "에이티엠와 아치라니 아리마스",
                "ko": "ATM은 저쪽에 있습니다."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],
        "choices": [
            "계산을 부탁하고 있다.",
            "환전을 요청하고 있다.",
            "현금을 인출하려고 하고 있다.",
            "카드 결제를 하고 있다."
        ],
        "answer": 3,
        "explain_ko": "‘現金を下ろしたいです’는 ATM에서 돈을 찾고 싶을 때 쓰는 표현으로, 편의점 ATM 위치를 안내받는 상황이다."
    },
    {
        "id": 47,
        "title": "- 47번문제 -",
        "image": "dialog_quiz/shinkansen_ticket_check.png",

        "lines": [
            {
                "role": "남자",
                "jp": "この切符で乗れますか？",
                "pron": "코노 킷푸데 노레마스카",
                "ko": "이 표로 탈 수 있나요?"
            },
            {
                "role": "직원",
                "jp": "はい、そのままご乗車いただけます。",
                "pron": "하이, 소노마마 고죠-샤 이타다케마스",
                "ko": "네, 그대로 탑승하시면 됩니다."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。",
                "pron": "아리가토- 고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "좌석 위치를 변경하려고 하고 있다.",
            "표를 환불하려고 하고 있다.",
            "이 표로 탑승 가능한지 확인하고 있다.",
            "출구 위치를 묻고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘この切符で乗れますか？’는 가지고 있는 표로 해당 열차에 탈 수 있는지 확인할 때 쓰는 표현으로, 직원이 탑승 가능하다고 안내하는 상황이다."
    },
    {
        "id": 48,
        "title": "- 48번문제 -",
        "image": "dialog_quiz/ryokan_lost_key.png",

        "lines": [
            {
                "role": "투숙객",
                "jp": "鍵をなくしました。",
                "pron": "카기오 나쿠시마시타",
                "ko": "열쇠를 잃어버렸어요."
            },
            {
                "role": "직원",
                "jp": "大丈夫です。お部屋番号を教えてください。",
                "pron": "다이죠-부데스. 오헤야 방고오 오시에테 쿠다사이",
                "ko": "괜찮습니다. 객실 번호를 알려주세요."
            },
            {
                "role": "투숙객",
                "jp": "305号室です。",
                "pron": "산마루고 고-시츠데스",
                "ko": "305호실입니다."
            }
        ],

        "choices": [
            "체크아웃을 요청하고 있다.",
            "온천 이용 시간을 묻고 있다.",
            "객실 열쇠를 잃어버렸다고 말하고 있다.",
            "수건을 추가로 요청하고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘鍵をなくしました’는 숙소에서 방 열쇠를 분실했을 때 사용하는 표현으로, 직원이 객실 번호를 확인하는 전형적인 분실 대응 상황이다."
    },
    {
        "id": 49,
        "title": "- 49번문제 -",
        "image": "dialog_quiz/museum_open_time.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、何時まで開いていますか？",
                "pron": "스미마센, 난지마데 아이테이마스카",
                "ko": "실례합니다, 몇 시까지 열어요?"
            },
            {
                "role": "여자",
                "jp": "午後六時までです。",
                "pron": "고고 로쿠지마데데스",
                "ko": "오후 6시까지예요."
            },
            {
                "role": "남자",
                "jp": "まだ時間がありますね。",
                "pron": "마다 지칸가 아리마스네",
                "ko": "아직 시간이 있네요."
            }
        ],

        "choices": [
            "입장 요금을 묻고 있다.",
            "전시 설명을 요청하고 있다.",
            "사진 촬영이 가능한지 묻고 있다.",
            "운영 종료 시간을 물어보고 있다."
        ],

        "answer": 4,

        "explain_ko": "‘すみません、何時まで開いていますか？’는 처음 보는 사람에게 정중하게 운영 종료 시간을 물을 때 쓰는 매우 자연스러운 일본어 표현이다."
    },
    {
        "id": 50,
        "title": "- 50번문제 -",
        "image": "dialog_quiz/festival_photo.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、写真を撮ってもいいですか？",
                "pron": "스미마센, 샤신오 톳테모 이이데스카",
                "ko": "실례합니다, 사진 찍어도 되나요?"
            },
            {
                "role": "여자",
                "jp": "はい、大丈夫ですよ。",
                "pron": "하이, 다이죠부데스요",
                "ko": "네, 괜찮아요."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。",
                "pron": "아리가토고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "기념품 가격을 묻고 있다.",
            "사진 촬영 허락을 받고 있다.",
            "축제 시간을 확인하고 있다.",
            "길 안내를 요청하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘写真を撮ってもいいですか？’는 사진 촬영 허락을 정중하게 구할 때 쓰는 표현이며, 앞에 ‘すみません’을 붙이면 더욱 공손해진다."
    },
    {
        "id": 51,
        "title": "- 51번문제 -",
        "image": "dialog_quiz/help_restroom.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、手伝ってください。",
                "pron": "스미마센, 테츠닷테 쿠다사이",
                "ko": "실례합니다, 도와주세요."
            },
            {
                "role": "직원",
                "jp": "はい、どうしましたか？",
                "pron": "하이, 도-시마시타카",
                "ko": "네, 무슨 일이세요?"
            },
            {
                "role": "남자",
                "jp": "使い方がわかりません。",
                "pron": "츠카이카타가 와카리마센",
                "ko": "사용법을 모르겠어요."
            }
        ],

        "choices": [
            "기계 사용 방법을 몰라 도움을 요청하고 있다.",
            "화장실 청소를 부탁하고 있다.",
            "길을 잃어버려 안내를 받고 있다.",
            "물건을 교환하려고 하고 있다."
        ],

        "answer": 1,

        "explain_ko": "‘使い方がわかりません’은 ‘사용법을 모르겠습니다’라는 뜻으로, 기계나 시설 이용 방법을 몰라 도움을 요청하는 상황이다."
    },
    {
        "id": 52,
        "title": "- 52번문제 -",
        "image": "dialog_quiz/exchange_minimum.png",

        "lines": [
            {
                "role": "손님",
                "jp": "いくらから両替できますか？",
                "pron": "이쿠라카라 료-가에 데키마스카",
                "ko": "얼마부터 환전 가능해요?"
            },
            {
                "role": "직원",
                "jp": "1万円から両替できます。",
                "pron": "이치만엔카라 료-가에 데키마스",
                "ko": "1만 엔부터 환전 가능합니다."
            },
            {
                "role": "손님",
                "jp": "わかりました。ありがとうございます。",
                "pron": "와카리마시타. 아리가토-고자이마스",
                "ko": "알겠습니다. 감사합니다."
            }
        ],

        "choices": [
            "환전 수수료를 묻고 있다.",
            "환전 가능한 최소 금액을 묻고 있다.",
            "환율이 얼마인지 묻고 있다.",
            "환전을 취소하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘いくらから’는 ‘얼마부터’라는 뜻으로, 환전 가능한 최소 금액을 묻는 표현이다."
    },
    {
        "id": 53,
        "title": "- 53번문제 -",
        "image": "dialog_quiz/ask_gas_station.png",

        "lines": [
            {
                "role": "여자",
                "jp": "すみません、ガソリンスタンドは近くにありますか？",
                "pron": "스미마센, 가소린스탄도와 치카쿠니 아리마스카",
                "ko": "실례지만, 주유소 근처에 있나요?"
            },
            {
                "role": "남자",
                "jp": "はい、この道をまっすぐ行くとあります。",
                "pron": "하이, 코노 미치오 맛스구 이쿠토 아리마스",
                "ko": "네, 이 길을 쭉 가면 있어요."
            },
            {
                "role": "여자",
                "jp": "ありがとうございます。",
                "pron": "아리가토-고자이마스",
                "ko": "감사합니다."
            }
        ],

        "choices": [
            "주차할 수 있는 곳을 묻고 있다.",
            "주유소 위치를 묻고 있다.",
            "차를 빌릴 수 있는지 묻고 있다.",
            "길이 막히는지 확인하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘ガソリンスタンドは近くにありますか？’는 주유소가 근처에 있는지 물을 때 쓰는 표현이다."
    },
    {
        "id": 54,
        "title": "- 54번문제 -",
        "image": "dialog_quiz/train_pass_through.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、通ります。",
                "pron": "스미마센 토오리마스",
                "ko": "실례합니다, 지나갈게요."
            },
            {
                "role": "여자",
                "jp": "はい、どうぞ。",
                "pron": "하이, 도-조",
                "ko": "네, 지나가세요."
            }
        ],

        "choices": [
            "자리에 앉아도 되는지 묻고 있다.",
            "지나가도 되는지 양해를 구하고 있다.",
            "다음 역 이름을 확인하고 있다.",
            "출입문 위치를 묻고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘すみません、通ります。’는 사람이 많은 전철이나 버스 안에서 지나가겠다는 뜻으로 양해를 구할 때 쓰며, 상대는 ‘どうぞ’로 자연스럽게 응답한다."
    },
    {
        "id": 55,
        "title": "- 55번문제 -",
        "image": "dialog_quiz/ask_for_water.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、水をください。",
                "pron": "스미마센, 미즈오 쿠다사이",
                "ko": "실례합니다, 물 주세요."
            },
            {
                "role": "직원",
                "jp": "はい、少々お待ちください。",
                "pron": "하이, 쇼-쇼- 오마치 쿠다사이",
                "ko": "네, 잠시만 기다려 주세요."
            }
        ],

        "choices": [
            "메뉴를 보고 주문하고 있다.",
            "물을 요청하고 있다.",
            "계산을 부탁하고 있다.",
            "자리를 옮길 수 있는지 묻고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘水をください’는 식당이나 카페에서 물을 요청할 때 쓰는 기본적인 표현이며, 직원은 보통 ‘少々お待ちください’로 응답한다."
    },
    {
        "id": 56,
        "title": "- 56번문제 -",
        "image": "dialog_quiz/lost_item_report.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、落とし物をしました。",
                "pron": "스미마센, 오토시모노오 시마시타",
                "ko": "실례합니다, 물건을 떨어뜨렸어요."
            },
            {
                "role": "경찰",
                "jp": "どんな物ですか？",
                "pron": "돈나 모노 데스카",
                "ko": "어떤 물건인가요?"
            },
            {
                "role": "남자",
                "jp": "黒い財布です。",
                "pron": "쿠로이 사이후 데스",
                "ko": "검은색 지갑이에요."
            }
        ],

        "choices": [
            "길을 묻고 있다.",
            "분실물을 신고하고 있다.",
            "사건 신고를 하고 있다.",
            "도난당한 상황을 설명하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘落とし物をしました’는 물건을 잃어버렸을 때 경찰이나 안내소에서 분실 신고할 때 쓰는 표현이다."
    },
    {
        "id": 57,
        "title": "- 57번문제 -",
        "image": "dialog_quiz/ask_recommend_menu.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、おすすめはどれですか？",
                "pron": "스미마센, 오스스메와 도레데스카",
                "ko": "실례합니다, 추천은 뭐예요?"
            },
            {
                "role": "주인",
                "jp": "この焼き鳥が人気ですよ。",
                "pron": "코노 야키토리가 닌키데스요",
                "ko": "이 야키토리가 인기가 많아요."
            },
            {
                "role": "남자",
                "jp": "じゃあ、それをください。",
                "pron": "자아, 소레오 쿠다사이",
                "ko": "그럼, 그걸로 주세요."
            }
        ],

        "choices": [
            "가격을 묻고 있다.",
            "음식 추천을 부탁하고 있다.",
            "조리 방법을 묻고 있다.",
            "포장 여부를 확인하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘おすすめはどれですか？’는 식당이나 가게에서 추천 메뉴를 물을 때 매우 자주 쓰이는 표현이다."
    },




]

@app.get("/robots.txt")
def robots_txt():
    content = "\n".join([
        "User-agent: *",
        "Allow: /",
        "Sitemap: https://japanesestudyroom.com/sitemap.xml",
    ])
    return Response(content, mimetype="text/plain")


def _absolute(path: str) -> str:
    return "https://japanesestudyroom.com" + path


@app.get("/sitemap.xml")
def sitemap_xml():
    urls = []

    urls += [
        (_absolute("/"), "daily", "1.0"),
        (_absolute("/situations"), "weekly", "0.9"),
        (_absolute("/quiz"), "weekly", "0.8"),
        (_absolute("/words"), "weekly", "0.8"),
        (_absolute("/board"), "daily", "0.6"),
    ]

    try:
        for cat, obj in SITUATIONS.items():
            for sub in obj["subs"].keys():
                urls.append((_absolute(f"/situations/{cat}/{sub}"), "monthly", "0.7"))
    except:
        pass

    try:
        urls.append((_absolute("/quiz/dialog"), "weekly", "0.7"))
        for q in DIALOG_SCENE_QUIZZES:
            urls.append((_absolute(f"/quiz/dialog/{q['id']}"), "monthly", "0.6"))
    except:
        pass

    xml = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']

    for loc, freq, prio in urls:
        xml += [
            "  <url>",
            f"    <loc>{loc}</loc>",
            f"    <changefreq>{freq}</changefreq>",
            f"    <priority>{prio}</priority>",
            "  </url>",
        ]

    xml.append("</urlset>")
    return Response("\n".join(xml), mimetype="application/xml")


@app.get("/quiz/dialog")
def quiz_dialog_list():
    user = current_user()

    # ✅ 1번부터 오름차순 (id 기준 정렬)
    items = sorted(DIALOG_SCENE_QUIZZES, key=lambda x: x["id"])
    quizzes_all = [{"id": q["id"], "title": q["title"]} for q in items]

    # ✅ 페이지네이션
    per_page = 20
    page = request.args.get("page", 1, type=int)

    total = len(quizzes_all)
    total_pages = max(1, ceil(total / per_page))

    # ✅ page 범위 보정
    if page < 1:
        page = 1
    if page > total_pages:
        page = total_pages

    start = (page - 1) * per_page
    end = start + per_page
    quizzes = quizzes_all[start:end]

    return render_template(
        "dialog_quiz_list.html",
        user=user,
        quizzes=quizzes,
        page=page,
        total_pages=total_pages,
        **seo(
            title="일본 여행 상황별 회화 퀴즈 | 실전 일본어 대화 연습",
            desc="일본 여행에서 바로 쓰는 상황별 일본어 회화를 퀴즈로 재미있게 연습하세요. 실전 대화 중심 일본어 공부 사이트입니다.",
            keywords="일본 여행 회화 퀴즈, 일본어 대화 연습, 상황별 일본어 퀴즈, 일본어 회화 게임"
        )
    )


@app.get("/quiz/dialog/<int:quiz_id>")
def dialog_quiz_play(quiz_id: int):
    user = current_user()

    # ✅ id 순서 보장 (중요)
    quizzes = sorted(DIALOG_SCENE_QUIZZES, key=lambda x: x["id"])

    # ✅ 현재 퀴즈 찾기 + index 찾기
    idx = next((i for i, x in enumerate(quizzes) if x["id"] == quiz_id), None)
    if idx is None:
        abort(404)

    q = quizzes[idx]

    # ✅ 다음 문제 id 계산
    next_id = quizzes[idx + 1]["id"] if (idx + 1) < len(quizzes) else None

    title = f"{q['title']} 일본어 회화 퀴즈 | 여행 일본어 실전 연습"
    desc = f"{q['title']} 상황에서 사용하는 일본어 회화를 퀴즈로 연습하세요. 일본 여행에서 바로 써먹는 실전 표현을 쉽게 익힐 수 있습니다."
    keywords = f"{q['title']} 일본어, 일본 여행 회화, 일본어 퀴즈, 상황별 일본어 표현"

    return render_template(
        "dialog_quiz_play.html",
        user=user,
        quiz=q,
        next_id=next_id,  # ✅ 이 줄 추가
        **seo(
            title=title,
            desc=desc,
            keywords=keywords
        )
    )

@app.post("/quiz/dialog/check")
def quiz_dialog_check():
    data = request.get_json(silent=True) or {}

    quiz_id = int(data.get("quiz_id") or 0)
    selected = int(data.get("selected") or 0)   # ✅ 프론트에서 selected로 보냄

    q = next((x for x in DIALOG_SCENE_QUIZZES if int(x.get("id")) == quiz_id), None)
    if not q:
        return jsonify(ok=False, error="not_found"), 404

    correct_no = int(q.get("answer") or 0)
    correct = (selected == correct_no)

    choices = q.get("choices") or []
    correct_text = ""
    if 1 <= correct_no <= len(choices):
        correct_text = choices[correct_no - 1]

    return jsonify(
        ok=True,
        correct=correct,
        answer=correct_no,            # ✅ 프론트가 이 키를 봄
        correct_text=correct_text,    # ✅ 프론트가 이 키를 봄
        explain_ko=q.get("explain_ko", "")
    )

@app.context_processor
def inject_helpers():
    return {"is_admin": is_admin}

if __name__ == "__main__":
    init_db()
    app.run(debug=True)

with app.app_context():
    init_db()

@app.route("/favicon.ico")
@app.route("/favicon.png")
def favicon():
    return send_from_directory(
        app.static_folder,
        "favicon.png",
        mimetype="image/png"
    )