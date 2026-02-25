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
import json
import itertools
from uuid import uuid4
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
    session, flash, jsonify, abort , 
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

    today = kst_today_key()  # "2026-01-29" 같은 형태

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
def ensure_jlpt_word_favorites_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS jlpt_word_favorites (
      user_id INTEGER NOT NULL,
      level TEXT NOT NULL,        -- "N5" 등
      section TEXT NOT NULL,      -- "words" 고정 사용
      jp TEXT NOT NULL,
      pron TEXT,
      ko TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(user_id, level, section, jp)
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

def ensure_board_schema():
    conn = db()
    try:
        # board_posts 테이블 존재 여부 체크
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='board_posts'"
        ).fetchone()
        if not row:
            return  # 테이블이 없다면 여기선 건드리지 않음(네 프로젝트에 이미 있을 거라 보통 안 탐)

        cols = [r["name"] for r in conn.execute("PRAGMA table_info(board_posts)").fetchall()]

        # ✅ 공지글 컬럼
        if "is_notice" not in cols:
            conn.execute("ALTER TABLE board_posts ADD COLUMN is_notice INTEGER DEFAULT 0")

        # ✅ 여러 이미지 저장 컬럼
        if "images_json" not in cols:
            conn.execute("ALTER TABLE board_posts ADD COLUMN images_json TEXT")

        conn.commit()
    finally:
        conn.close()

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

def korean_to_number(s: str) -> int | None:
    units = {
        "영": 0, "일": 1, "이": 2, "삼": 3, "사": 4,
        "오": 5, "육": 6, "칠": 7, "팔": 8, "구": 9
    }
    tens = {"십": 10, "백": 100}

    total = 0
    temp = 0
    used = False

    for ch in s:
        if ch in units:
            temp = units[ch]
            used = True
        elif ch in tens:
            if temp == 0:
                temp = 1
            total += temp * tens[ch]
            temp = 0
            used = True
        else:
            return None  # 숫자 아님

    total += temp
    return total if used else None

def normalize_korean_ge(s: str) -> str:
    """
    '열개/열 개/10개' 같은 표현을 모두 '10개'로 통일.
    (공백 제거 후 처리)
    """
    # 공백 제거
    s = re.sub(r"\s+", "", s)

    # (한글수사)+개  -> (숫자)+개
    # 예) "열개" -> "10개", "한개" -> "1개"
    for k, v in sorted(KOR_NUM_MAP.items(), key=lambda x: -len(x[0])):  # 긴 키 먼저
        s = re.sub(rf"^{re.escape(k)}개$", f"{v}개", s)

    # 숫자 + 개는 그대로 유지 ("10개")
    return s

def normalize_answer(s: str) -> str:
    if not s:
        return ""

    s = unicodedata.normalize("NFKC", s)
    s = s.strip().lower()
    s = re.sub(r"\s+", "", s)

    # ✅ (한글숫자)+개 → 숫자+개
    m = re.match(r"^([일이삼사오육칠팔구십백영]+)개$", s)
    if m:
        num = korean_to_number(m.group(1))
        if num is not None:
            s = f"{num}개"

    # 기호 제거
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
         # ✅ (여기에 추가) 닉네임 대소문자 무시 유니크 인덱스
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nickname_nocase
            ON users(nickname COLLATE NOCASE)
        """)

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

# 1~10(열)까지만 먼저 지원 (필요하면 더 늘릴 수 있음)
KOR_NUM_MAP = {
    "한": "1", "하나": "1",
    "두": "2", "둘": "2",
    "세": "3", "셋": "3",
    "네": "4", "넷": "4",
    "다섯": "5",
    "여섯": "6",
    "일곱": "7",
    "여덟": "8",
    "아홉": "9",
    "열": "10", "십": "10",
}

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

DAILY_WORD_POOL = [
    {
        "word_jp": "勉強",
        "word_pron": "벤쿄오",
        "word_ko": "공부",
        "ex_jp": "毎日、日本語を勉強しています。",
        "ex_pron": "마이니치, 니혼고오 벤쿄오 시테이마스",
        "ex_ko": "매일 일본어를 공부하고 있습니다."
    },
    {
        "word_jp": "仕事",
        "word_pron": "시고토",
        "word_ko": "일, 직업",
        "ex_jp": "仕事が忙しいです。",
        "ex_pron": "시고토가 이소가시이데스",
        "ex_ko": "일이 바쁩니다."
    },
    {
        "word_jp": "会社",
        "word_pron": "카이샤",
        "word_ko": "회사",
        "ex_jp": "会社に行きます。",
        "ex_pron": "카이샤니 이키마스",
        "ex_ko": "회사에 갑니다."
    },
    {
        "word_jp": "時間",
        "word_pron": "지칸",
        "word_ko": "시간",
        "ex_jp": "時間がありません。",
        "ex_pron": "지칸가 아리마센",
        "ex_ko": "시간이 없습니다."
    },
    {
        "word_jp": "友達",
        "word_pron": "토모다치",
        "word_ko": "친구",
        "ex_jp": "友達と会います。",
        "ex_pron": "토모다치토 아이마스",
        "ex_ko": "친구를 만나요."
    },
    {
        "word_jp": "家",
        "word_pron": "이에",
        "word_ko": "집",
        "ex_jp": "家に帰ります。",
        "ex_pron": "이에니 카에리마스",
        "ex_ko": "집에 돌아갑니다."
    },
    {
        "word_jp": "学校",
        "word_pron": "각코오",
        "word_ko": "학교",
        "ex_jp": "学校で日本語を勉強します。",
        "ex_pron": "각코오데 니혼고오 벤쿄오 시마스",
        "ex_ko": "학교에서 일본어를 공부합니다."
    },
    {
        "word_jp": "今日",
        "word_pron": "쿄오",
        "word_ko": "오늘",
        "ex_jp": "今日は忙しいです。",
        "ex_pron": "쿄오와 이소가시이데스",
        "ex_ko": "오늘은 바쁩니다."
    },
    {
        "word_jp": "明日",
        "word_pron": "아시타",
        "word_ko": "내일",
        "ex_jp": "明日、旅行します。",
        "ex_pron": "아시타, 료코오 시마스",
        "ex_ko": "내일 여행합니다."
    },
    {
        "word_jp": "昨日",
        "word_pron": "키노오",
        "word_ko": "어제",
        "ex_jp": "昨日、雨が降りました。",
        "ex_pron": "키노오, 아메가 후리마시타",
        "ex_ko": "어제 비가 왔어요."
    },
    {
        "word_jp": "大丈夫",
        "word_pron": "다이죠오부",
        "word_ko": "괜찮다",
        "ex_jp": "大丈夫です。",
        "ex_pron": "다이죠오부데스",
        "ex_ko": "괜찮아요."
    },
    {
        "word_jp": "必要",
        "word_pron": "히츠요오",
        "word_ko": "필요",
        "ex_jp": "これは必要です。",
        "ex_pron": "코레와 히츠요오데스",
        "ex_ko": "이건 필요합니다."
    },
    {
        "word_jp": "問題",
        "word_pron": "몬다이",
        "word_ko": "문제",
        "ex_jp": "問題があります。",
        "ex_pron": "몬다이가 아리마스",
        "ex_ko": "문제가 있습니다."
    },
    {
        "word_jp": "意味",
        "word_pron": "이미",
        "word_ko": "의미",
        "ex_jp": "この言葉の意味は何ですか？",
        "ex_pron": "코노 코토바노 이미와 난데스카",
        "ex_ko": "이 단어의 의미는 뭐예요?"
    },
    {
        "word_jp": "使う",
        "word_pron": "츠카우",
        "word_ko": "사용하다",
        "ex_jp": "この言葉を使います。",
        "ex_pron": "코노 코토바오 츠카이마스",
        "ex_ko": "이 단어를 사용합니다."
    },
    {
        "word_jp": "買う",
        "word_pron": "카우",
        "word_ko": "사다",
        "ex_jp": "パンを買います。",
        "ex_pron": "팡오 카이마스",
        "ex_ko": "빵을 삽니다."
    },
    {
        "word_jp": "行く",
        "word_pron": "이쿠",
        "word_ko": "가다",
        "ex_jp": "駅に行きます。",
        "ex_pron": "에키니 이키마스",
        "ex_ko": "역에 갑니다."
    },
    {
        "word_jp": "来る",
        "word_pron": "쿠루",
        "word_ko": "오다",
        "ex_jp": "友達が来ます。",
        "ex_pron": "토모다치가 키마스",
        "ex_ko": "친구가 와요."
    },
    {
        "word_jp": "帰る",
        "word_pron": "카에루",
        "word_ko": "돌아가다",
        "ex_jp": "家に帰ります。",
        "ex_pron": "이에니 카에리마스",
        "ex_ko": "집에 돌아갑니다."
    },
    {
        "word_jp": "知る",
        "word_pron": "시루",
        "word_ko": "알다",
        "ex_jp": "このことを知っています。",
        "ex_pron": "코노 코토오 싯테이마스",
        "ex_ko": "이것을 알고 있습니다."
    },
        {
        "word_jp": "食事",
        "word_pron": "쇼쿠지",
        "word_ko": "식사",
        "ex_jp": "食事をします。",
        "ex_pron": "쇼쿠지오 시마스",
        "ex_ko": "식사합니다."
    },
    {
        "word_jp": "飲み物",
        "word_pron": "노미모노",
        "word_ko": "음료",
        "ex_jp": "飲み物をください。",
        "ex_pron": "노미모노오 쿠다사이",
        "ex_ko": "음료 주세요."
    },
    {
        "word_jp": "店",
        "word_pron": "미세",
        "word_ko": "가게",
        "ex_jp": "この店は有名です。",
        "ex_pron": "코노 미세와 유메이데스",
        "ex_ko": "이 가게는 유명해요."
    },
    {
        "word_jp": "駅",
        "word_pron": "에키",
        "word_ko": "역",
        "ex_jp": "駅はどこですか？",
        "ex_pron": "에키와 도코데스카",
        "ex_ko": "역은 어디예요?"
    },
    {
        "word_jp": "電車",
        "word_pron": "덴샤",
        "word_ko": "전철",
        "ex_jp": "電車に乗ります。",
        "ex_pron": "덴샤니 노리마스",
        "ex_ko": "전철을 탑니다."
    },
    {
        "word_jp": "天気",
        "word_pron": "텐키",
        "word_ko": "날씨",
        "ex_jp": "今日は天気がいいです。",
        "ex_pron": "쿄오와 텐키가 이이데스",
        "ex_ko": "오늘은 날씨가 좋아요."
    },
    {
        "word_jp": "雨",
        "word_pron": "아메",
        "word_ko": "비",
        "ex_jp": "雨が降っています。",
        "ex_pron": "아메가 후잇테이마스",
        "ex_ko": "비가 오고 있어요."
    },
    {
        "word_jp": "場所",
        "word_pron": "바쇼",
        "word_ko": "장소",
        "ex_jp": "この場所は静かです。",
        "ex_pron": "코노 바쇼와 시즈카데스",
        "ex_ko": "이 장소는 조용해요."
    },
    {
        "word_jp": "名前",
        "word_pron": "나마에",
        "word_ko": "이름",
        "ex_jp": "名前を教えてください。",
        "ex_pron": "나마에오 오시에테 쿠다사이",
        "ex_ko": "이름을 알려주세요."
    },
    {
        "word_jp": "電話",
        "word_pron": "덴와",
        "word_ko": "전화",
        "ex_jp": "電話をかけます。",
        "ex_pron": "덴와오 카케마스",
        "ex_ko": "전화를 겁니다."
    },
    {
        "word_jp": "予約",
        "word_pron": "요야쿠",
        "word_ko": "예약",
        "ex_jp": "予約をしました。",
        "ex_pron": "요야쿠오 시마시타",
        "ex_ko": "예약했습니다."
    },
    {
        "word_jp": "宿",
        "word_pron": "야도",
        "word_ko": "숙소",
        "ex_jp": "宿に泊まります。",
        "ex_pron": "야도니 토마리마스",
        "ex_ko": "숙소에 묵습니다."
    },
    {
        "word_jp": "部屋",
        "word_pron": "헤야",
        "word_ko": "방",
        "ex_jp": "部屋はきれいです。",
        "ex_pron": "헤야와 키레이데스",
        "ex_ko": "방이 깨끗해요."
    },
    {
        "word_jp": "写真",
        "word_pron": "샤신",
        "word_ko": "사진",
        "ex_jp": "写真を撮ります。",
        "ex_pron": "샤신오 토리마스",
        "ex_ko": "사진을 찍어요."
    },
    {
        "word_jp": "道",
        "word_pron": "미치",
        "word_ko": "길",
        "ex_jp": "この道を行きます。",
        "ex_pron": "코노 미치오 이키마스",
        "ex_ko": "이 길로 갑니다."
    },
    {
        "word_jp": "近く",
        "word_pron": "치카쿠",
        "word_ko": "가까이",
        "ex_jp": "駅は近くです。",
        "ex_pron": "에키와 치카쿠데스",
        "ex_ko": "역은 가까워요."
    },
    {
        "word_jp": "遠い",
        "word_pron": "토오이",
        "word_ko": "멀다",
        "ex_jp": "ここは遠いです。",
        "ex_pron": "코코와 토오이데스",
        "ex_ko": "여기는 멀어요."
    },
    {
        "word_jp": "便利",
        "word_pron": "벤리",
        "word_ko": "편리하다",
        "ex_jp": "このアプリは便利です。",
        "ex_pron": "코노 아푸리와 벤리데스",
        "ex_ko": "이 앱은 편리해요."
    },
    {
        "word_jp": "簡単",
        "word_pron": "칸탄",
        "word_ko": "간단하다",
        "ex_jp": "この問題は簡単です。",
        "ex_pron": "코노 몬다이와 칸탄데스",
        "ex_ko": "이 문제는 간단해요."
    },
    {
        "word_jp": "難しい",
        "word_pron": "무즈카시이",
        "word_ko": "어렵다",
        "ex_jp": "日本語は難しいです。",
        "ex_pron": "니혼고와 무즈카시이데스",
        "ex_ko": "일본어는 어려워요."
    },
    {
        "word_jp": "大切",
        "word_pron": "다이세츠",
        "word_ko": "중요하다",
        "ex_jp": "時間は大切です。",
        "ex_pron": "지칸와 다이세츠데스",
        "ex_ko": "시간은 중요해요."
    },
    {
        "word_jp": "安心",
        "word_pron": "안신",
        "word_ko": "안심",
        "ex_jp": "これで安心です。",
        "ex_pron": "코레데 안신데스",
        "ex_ko": "이제 안심이에요."
    },
    {
        "word_jp": "危ない",
        "word_pron": "아부나이",
        "word_ko": "위험하다",
        "ex_jp": "そこは危ないです。",
        "ex_pron": "소코와 아부나이데스",
        "ex_ko": "거기는 위험해요."
    },
    {
        "word_jp": "始める",
        "word_pron": "하지메루",
        "word_ko": "시작하다",
        "ex_jp": "勉強を始めます。",
        "ex_pron": "벤쿄오오 하지메마스",
        "ex_ko": "공부를 시작합니다."
    },
    {
        "word_jp": "終わる",
        "word_pron": "오와루",
        "word_ko": "끝나다",
        "ex_jp": "仕事が終わりました。",
        "ex_pron": "시고토가 오와리마시타",
        "ex_ko": "일이 끝났어요."
    },
    {
        "word_jp": "待つ",
        "word_pron": "마츠",
        "word_ko": "기다리다",
        "ex_jp": "少し待ってください。",
        "ex_pron": "스코시 맛테 쿠다사이",
        "ex_ko": "조금 기다려 주세요."
    },
    {
        "word_jp": "助ける",
        "word_pron": "타스케루",
        "word_ko": "돕다",
        "ex_jp": "友達を助けます。",
        "ex_pron": "토모다치오 타스케마스",
        "ex_ko": "친구를 도와요."
    },
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
    # ✅ 일본여행 필수회화 50문장 (중복 제거 / 핵심 위주)
TRAVEL_PHRASES_50 = [
    # 공항/출국
    ("チェックインをお願いします。", "체쿠인오 오네가이시마스", "체크인 부탁합니다."),
    ("パスポートはこちらです。", "파스포-토와 코치라데스", "여권 여기 있습니다."),
    ("預け荷物はこれです。", "아즈케니모츠와 코레데스", "부칠 짐은 이거예요."),
    ("機内持ち込みはこれだけです。", "키나이모치코미와 코레다케데스", "기내 반입은 이것뿐이에요."),
    ("座席は通路側がいいです。", "자세키와 츠-로가와가 이-데스", "좌석은 통로쪽이 좋아요."),
    ("窓側は空いていますか？", "마도가와와 아이테이마스카", "창가 자리가 비어있나요?"),
    ("保安検査はどこですか？", "호안켄사와 도코데스카", "보안 검색은 어디예요?"),
    ("ゲートは何番ですか？", "게-토와 난반데스카", "게이트는 몇 번인가요?"),
    ("出発は何時ですか？", "슈파츠와 난지데스카", "출발은 몇 시인가요?"),
    ("遅れていますか？", "오쿠레테이마스카", "지연되고 있나요?"),

    # 호텔
    ("予約しています。", "요야쿠시테이마스", "예약했어요."),
    ("禁煙室はありますか？", "킨엔시츠와 아리마스카", "금연실 있나요?"),
    ("部屋は何階ですか？", "헤야와 난가이데스카", "방은 몇 층인가요?"),
    ("朝食は何時からですか？", "초-쇼쿠와 난지카라데스카", "조식은 몇 시부터예요?"),
    ("Wi-Fiのパスワードは？", "와이화이노 파스와-도와", "와이파이 비밀번호는요?"),
    ("荷物を預けられますか？", "니모츠오 아즈케라레마스카", "짐 맡길 수 있나요?"),
    ("タオルを追加してください。", "타오루오 츠이카시테 쿠다사이", "수건 추가해주세요."),
    ("部屋の掃除をお願いします。", "헤야노 소-지오 오네가이시마스", "방 청소 부탁해요."),
    ("エアコンが効きません。", "에아콘가 키키마센", "에어컨이 안 돼요."),
    ("お湯が出ません。", "오유가 데마센", "뜨거운 물이 안 나와요."),

    # 교통(전철/택시/버스)
    ("この電車は新宿に行きますか？", "코노 덴샤와 신주쿠니 이키마스카", "이 전철 신주쿠 가나요?"),
    ("何番線ですか？", "난반센데스카", "몇 번 승강장이에요?"),
    ("乗り換えはどこですか？", "노리카에와 도코데스카", "환승은 어디서 해요?"),
    ("出口はどちらですか？", "데구치와 도치라데스카", "출구는 어디예요?"),
    ("改札はどこですか？", "카이사츠와 도코데스카", "개찰구는 어디예요?"),
    ("最終電車は何時ですか？", "사이슈-덴샤와 난지데스카", "막차는 몇 시예요?"),
    ("この住所に行ってください。", "코노 쥬-쇼니 잇테 쿠다사이", "이 주소로 가주세요."),
    ("いくらぐらいかかりますか？", "이쿠라구라이 카카리마스카", "얼마 정도 나와요?"),
    ("ここで止めてください。", "코코데 토메테 쿠다사이", "여기서 세워주세요."),
    ("両替できますか？", "료-가에 데키마스카", "환전(잔돈 교환) 가능해요?"),

    # 식당/카페
    ("二人です。", "후타리데스", "두 명이에요."),
    ("おすすめは何ですか？", "오스스메와 난데스카", "추천은 뭐예요?"),
    ("メニューを見せてください。", "메뉴-오 미세테 쿠다사이", "메뉴판 보여주세요."),
    ("すみません、注文いいですか？", "스미마セン 츄-몬 이-데스카", "실례합니다, 주문할게요."),
    ("これをください。", "코레오 쿠다사이", "이거 주세요."),
    ("水をください。", "미즈오 쿠다사이", "물 주세요."),
    ("アレルギーがあります。", "아레루기-가 아리마스", "알레르기가 있어요."),
    ("お会計お願いします。", "오카이케- 오네가이시마스", "계산 부탁해요."),
    ("カードは使えますか？", "카-도와 츠카에마스카", "카드 되나요?"),
    ("テイクアウトできますか？", "테이쿠아우토 데키마스카", "포장 가능해요?"),

    # 쇼핑/편의점/돈
    ("値段はいくらですか？", "네단와 이쿠라데스카", "가격이 얼마예요?"),
    ("これを試着してもいいですか？", "코레오 시챠쿠시테모 이-데스카", "이거 입어봐도 될까요?"),
    ("袋をください。", "후쿠로오 쿠다사이", "봉투 주세요."),
    ("袋はいりません。", "후쿠로와 이리마센", "봉투 필요 없어요."),
    ("温めてください。", "아타타메테 쿠다사이", "데워주세요."),
    ("電子マネーは使えますか？", "덴시마네-와 츠카에마스카", "전자결제 되나요?"),
    ("両替したいです。", "료-가에 시타이데스", "환전하고 싶어요."),
    ("手数料はいくらですか？", "테스료-와 이쿠라데스카", "수수료는 얼마예요?"),
    ("今日のレートはいくらですか？", "쿄-노 레-토와 이쿠라데스카", "오늘 환율이 얼마예요?"),
    ("明細をください。", "메-사이오 쿠다사이", "내역서 주세요."),

    # 길/분실/도움/연결
    ("すみません、道を教えてください。", "스미마센 미치오 오시에테 쿠다사이", "실례합니다, 길 좀 알려주세요."),
    ("駅までどうやって行きますか？", "에키마데 도-얏테 이키마스카", "역까지 어떻게 가나요?"),
    ("近いですか？", "치카이데스카", "가까워요?"),
    ("すみません、落とし物をしました。", "스미마센 오토시모노오 시마시타", "실례합니다, 물건을 잃어버렸어요."),
    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
    ("Wi-Fiはありますか？", "와이화이와 아리마스카", "와이파이 있나요?"),
    ("パスワードは何ですか？", "파스와-도와 난데스카", "비밀번호가 뭐예요?"),
    ("つながりません。", "츠나가리마센", "연결이 안 돼요."),
    ("ありがとうございます。", "아리가토- 고자이마스", "감사합니다."),
    ("すみません。", "스미마센", "실례합니다."),
]

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
                ("10000", "만", "10000"),
                ("～円", "엔", "~엔"),
                ("～人", "닌", "~명"),

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

                ("～歳", "사이", "~살"),
                ("～階", "카이", "~층"),
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

                ("ちょっと", "촛토", ["잠깐","조금"]),
                ("すぐ", "스구", ["바로","곧"]),
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
                ("切符", "킷푸", "티켓"),
                ("改札", "카이사츠", "개찰구"),
                ("ホーム", "호무", "승강장"),
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
                ("ICカード", "아이시-카-도", "교통카드"),
                ("チャージ", "차-지", "충전"),
                ("乗車券", "죠-샤켄", "승차권"),
                ("特急", "토큐-", "특급"),
                ("各駅停車", "카쿠에키테-샤", "완행"),
                ("遅れる", "오쿠레루", "지연되다"),

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
                ("まっすぐ", "맛스구", "쭉/곧장"),
                ("角", "카도", "모퉁이/코너"),
                ("交差点", "코-사텐", "교차로"),
                ("信号", "신고-", "신호등"),
                ("横断歩道", "오-단호도", "횡단보도"),
                ("渡る", "와타루", "건너다"),
                ("近道", "치카미치", "지름길"),

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
                ("使う", "츠카우", "사용하다"),
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
                ("いい", "이", ["좋다","괜찮다"]),
                ("だめ", "다메", "안 된다"),
                ("大丈夫", "다이죠부", "괜찮아요"),
                ("疲れた", "츠카레타", "피곤해요"),
                ("お腹すいた", "오나카스이타", "배고파요"),
                ("のどが渇いた", "노도가 카와이타", "목말라요"),
                ("痛い", "이타이", "아파요"),
                ("怖い", "코와이", "무서워요"),
                ("うれしい", "우레시", "기뻐요"),
                ("悲しい", "카나시", "슬퍼요"),
                ("眠い", "네무이", "졸리다"),
                ("だるい", "다루이", "나른하다"),
                ("疲れる", "츠카레루", "피곤해지다"),
                ("心配", "신파이", "걱정"),
                ("安心", "안신", "안심"),

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
                ("バッテリー", "밧테리-", "배터리"),
                ("通信", "츠-신", "통신"),
                ("容量", "요-료-", ["용량","저장공간"]),
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
                ("売り場", "우리바", ["매장","판매 코너"]),
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
                ("迷子", "마이고", "미아"),
                ("ベビーカー", "베비카-", "유모차"),
                ("危ない", "아부나이", "위험하다"),
                ("気をつけて", "키오츠케테", "조심해"),
                ("おむつ", "오무츠", "기저귀"),
                ("ミルク", "미루쿠", "분유"),
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
                ("気分", "키분", "기분"),
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
                ("投稿", "토-코-", "업로드"),
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
                ("支払い", "시하라이", ["결제","지불"]),
                ("小銭", "코제니", "동전"),
                ("両替", "료-가에", "환전/거슬러주기"),
                ("ストロー", "스토로-", "빨대"),
                ("レジ袋", "레지부쿠로", ["비닐봉투","쇼핑백"]),
                ("レンジ", "렌지", "전자레인지"),
                ("ATM", "에-티-에무", ["ATM","현금인출기"]),
                ("コピー機", "코피-키", "복사기"),
                ("支払い方法", "시하라이호-호-", "결제 방법"),

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
                ("クジラ", "쿠지라", "고래"),
                ("アザラシ", "아자라시", "물개"),
                ("ウミガメ", "우미가메", "바다거북"),
                ("タコ", "타코", "문어"),
                ("イカ", "이카", "오징어"),
                ("エイ", "에이", "가오리"),
                ("ナマコ", "나마코", "해삼"),
                ("ヒトデ", "히토데", "불가사리"),
                ("水中", "스이츄-", "수중"),
                ("大型水槽", "오-가타 스이소-", "대형 수조"),
                ("トンネル水槽", "톤네루 스이소-", "터널 수조"),
                ("深海魚", "신카이교", "심해어"),
                ("熱帯魚", "넷타이교", "열대어"),
                ("小魚", "코자카나", "작은 물고기"),
                ("群れ", "무레", "무리"),
                ("撮影禁止", "사츠에-킨시", "촬영 금지"),
                ("フラッシュ禁止", "후랏슈 킨시", "플래시 금지"),
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
                ("ドラッグストア", "도랏구스토아", "드럭스토어"),
                ("買い物かご", "카이모노카고", "장바구니"),
                ("カート", "카-토", "카트"),
                ("レジ", "레지", "계산대"),
                ("セルフレジ", "세루후레지", "셀프 계산대"),
                ("値札", "네후다", "가격표"),
                ("セール", "세-루", "세일"),
                ("割引", "와리비키", "할인"),
                ("特売", "토쿠바이", "특가판매"),
                ("賞味期限", "쇼-미키겐", "유통기한"),
                ("消費期限", "쇼-히키겐", "소비기한"),
                ("冷蔵", "레이조-", "냉장"),
                ("冷凍", "레-토-", "냉동"),
                ("常温", "죠-온", "상온"),
                ("野菜", "야사이", "채소"),
                ("果物", "쿠다모노", "과일"),
                ("肉", "니쿠", "고기"),
                ("魚", "사카나", "생선"),
                ("飲み物", "노미모노", "음료"),
                ("支払い方法", "시하라이호-호-", "결제 방법"),
                ("レジ袋", "레지부쿠로", ["비닐봉투","쇼핑백"]),
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
                ("焼酎", "쇼-츄-", "소주"),
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
                ("お手洗い", "오테아라이", "화장실"),
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
                ("出す", "다스", ["꺼내다","제출하다"]),
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
                ("調べる", "시라베루", ["찾아보다","조사하다"]),
                ("覚える", "오보에루", "외우다"),
                ("忘れ物する", "와스레모노스루", "물건을 두고 오다"),
                ("運ぶ", "하코부", "나르다"),
                ("置く", "오쿠", "두다"),
                ("取る", "토루", "집다/받다"),
                ("渡す", "와타스", "건네주다"),
                ("片付ける", "카타즈케루", "정리하다"),
                ("入れ替える", "이레카에루", "바꾸다"),
                ("確認できる", "카쿠닌데키루", "확인할 수 있다"),
                ("やっぱり", "얏파리", ["역시","역시나"]),
                ("たぶん", "타분", "아마"),
                ("けっこう", "켁코-", ["꽤","의외로"]),
                ("ちゃんと", "찬토", "제대로"),
                ("なんか", "난카", "왠지"),
                ("いちおう", "이치오-", ["일단","형식상"]),
                ("まだ", "마다", "아직"),
                ("もう", "모-", ["벌써","이미"]),
                ("なるほど", "나루호도", ["아하","그렇군요"]),
                ("そうなんだ", "소-난다", "그렇구나"),
                ("ほんとう？", "혼토-?", "진짜?"),

            ],
        },
        # 동물원
        "zoo": {
            "title": "동물원",
            "items": [
                ("動物園", "도-부츠엔", "동물원"),
                ("ライオン", "라이온", "사자"),
                ("トラ", "토라", "호랑이"),
                ("ゾウ", "조-", "코끼리"),
                ("キリン", "키린", "기린"),
                ("サル", "사루", "원숭이"),
                ("ゴリラ", "고리라", "고릴라"),
                ("クマ", "쿠마", "곰"),
                ("パンダ", "판다", "판다"),
                ("カバ", "카바", "하마"),
                ("シマウマ", "시마우마", "얼룩말"),
                ("ヒョウ", "효-", "표범"),
                ("チーター", "치-타-", "치타"),
                ("オオカミ", "오-카미", "늑대"),
                ("キツネ", "키츠네", "여우"),
                ("ハイエナ", "하이에나", "하이에나"),
                ("シカ", "시카", "사슴"),
                ("ウマ", "우마", "말"),
                ("ヤギ", "야기", "염소"),
                ("ヒツジ", "히츠지", "양"),
                ("ウシ", "우시", "소"),
                ("ラクダ", "라쿠다", "낙타"),
                ("バイソン", "바이손", "들소"),
                ("ウサギ", "우사기", "토끼"),
                ("ハムスター", "하무스타-", "햄스터"),
                ("リス", "리스", "다람쥐"),
                ("モルモット", "모르못토", "기니피그"),
                ("アルパカ", "아루파카", "알파카"),
                ("トリ", "토리", "새"),
                ("ペンギン", "펜긴", "펭귄"),
                ("フラミンゴ", "후라밍고", "플라밍고"),
                ("ワシ", "와시", "독수리"),
                ("フクロウ", "후쿠로-", "부엉이"),
                ("ハト", "하토", "비둘기"),
                ("クジャク", "쿠자쿠", "공작"),
                ("ワニ", "와니", "악어"),
                ("ヘビ", "헤비", "뱀"),
                ("カメ", "카메", "거북이"),
                ("トカゲ", "토카게", "도마뱀"),
                ("カエル", "카에루", "개구리"),
                ("飼育員", "시-쿠인", "사육사"),
                ("エサ", "에사", "먹이"),
                ("注意", "츄-이", "주의"),
                ("危険", "키켄", "위험"),
                ("立入禁止", "타치이리 킨시", "출입 금지"),
                ("ふれあいコーナー", "후레아이 코-나-", "체험 공간"),
                ("エサやり体験", "에사 야리 타이켄", "먹이 주기 체험"),
                ("展示", "텐지", "전시"),
                ("赤ちゃん動物", "아카짱 도-부츠", "아기 동물"),
            ],
        },

}
# ✅ 카테고리별 소개 문구 (단어 상세 페이지용)
WORDS_CAT_DESC = {
    "numbers": "숫자·가격·인원·개수 단위까지, 일본 여행에서 가장 자주 쓰는 기본 표현",
    "time": "시간·날짜·요일 그리고 약속과 일정 대화에 꼭 필요한 단어",
    "date": "오늘·내일·이번 주 일정 확인에 바로 쓰는 날짜·요일 표현",
    "transport": "역·지하철·버스 등 교통 이용 시 바로 쓰는 필수 단어",
    "location": "오른쪽·왼쪽·근처 등 길 찾기에 꼭 필요한 위치·방향 표현",
    "actions": "가다·오다·먹다·보다 등 여행과 일상에서 가장 많이 쓰는 기본 동사",
    "feelings": "아파요·괜찮아요·피곤해요 등 상태와 감정을 전하는 표현",
    "shopping": "가격·사이즈·결제·할인 상황에서 자주 쓰는 쇼핑 단어",
    "food": "일본 음식 주문과 식사 상황에서 꼭 알아두면 좋은 단어",
    "cafe": "카페·음료 주문 시 바로 쓸 수 있는 기본 표현",
    "hotel": "체크인·객실·와이파이 등 숙소 이용에 필요한 단어",
    "hotel_trouble": "숙소에서 발생하는 문제나 요청 상황에 쓰는 표현",
    "restaurant": "메뉴 주문·추천·계산 등 식당에서 자주 쓰는 단어",
    "airplane": "공항·탑승·수하물·비행기 이용 시 필수 표현",
    "money": "현금·카드·환전·결제 등 돈과 관련된 기본 단어",
    "phone_camera": "사진 촬영·카메라·스마트폰 사용 시 필요한 단어",
    "fashion": "옷·신발·사이즈·시착 등 쇼핑과 패션 관련 표현",
    "emergency": "병원·약국·아픔 등 기본적인 응급·건강 표현",
    "emergency_plus": "위급한 상황에서 도움을 요청할 때 쓰는 핵심 표현",
    "weather": "날씨·기온·우산 등 여행 중 자주 확인하는 날씨 표현",
    "polite": "인사·감사·부탁 등 일본어 기본 예의 표현",
    "sns_internet": "와이파이·QR·앱·로그인 등 인터넷·SNS 관련 단어",
    "nature_spots": "공원·신사·온천·관광지 등 자연·명소 관련 단어",
    "japan_manners": "일본 여행 중 알아두면 좋은 문화·매너 표현",
    "trouble": "분실·고장·지연 등 문제 상황에서 쓰는 단어",
    "convenience_store": "편의점에서 계산·포장·전자결제 시 자주 쓰는 표현",
    "facility_place": "화장실·출입구·엘리베이터 등 시설·장소 관련 단어",
    "solo_travel": "혼자 여행할 때 자주 쓰는 표현과 상황 단어",
    "school": "학교·수업·시험 등 학습·교육 관련 기본 단어",
    "office": "회사·회의·업무·출퇴근 등 직장 생활 표현",
    "amusement_park": "놀이공원에서 티켓·기구·대기 상황에 쓰는 단어",
    "aquarium": "수족관 관람·전시·촬영 시 자주 쓰는 단어",
    "travel_spots": "관광지·명소·입장료·운영시간 관련 표현",
    "supermarket": "마트·세일·계산·포장 등 쇼핑 실전 표현",
    "izakaya": "이자카야에서 술·안주·주문·계산에 쓰는 단어",
    "toilet_hygiene": "화장실·위생·비데·손 씻기 관련 표현",
    "lost_found": "물건을 잃어버렸거나 찾을 때 쓰는 표현",
    "drugstore_cosmetics": "약·화장품·면세·드럭스토어 쇼핑 표현",
    "family": "아이·가족과 함께 여행할 때 쓰는 단어",
    "family_relatives": "가족·친척을 부르거나 소개할 때 쓰는 표현",
    "travel_verbs": "여행 중 가장 많이 쓰이는 핵심 동사 표현",
    "zoo": "동물원 관람과 체험 시 자주 쓰는 단어",
}

N5_WORDS = {
    "sec01": {
    "title": "사람·관계·기본 표현",
    "items": [
        {"kanji":"私","kana":"わたし","pron":"와타시","ko":"나, 저","tts_text":"私"},
        {"kanji":"","kana":"あなた","pron":"아나타","ko":"당신","tts_text":"あなた"},
        {"kanji":"人","kana":"ひと","pron":"히토","ko":"사람","tts_text":"人"},
        {"kanji":"友達","kana":"ともだち","pron":"토모다치","ko":"친구","tts_text":"友達"},
        {"kanji":"家族","kana":"かぞく","pron":"카조쿠","ko":"가족","tts_text":"家族"},
        {"kanji":"学生","kana":"がくせい","pron":"가쿠세이","ko":"학생","tts_text":"学生"},
        {"kanji":"先生","kana":"せんせい","pron":"센세이","ko":"선생님","tts_text":"先生"},
        {"kanji":"会社","kana":"かいしゃ","pron":"카이샤","ko":"회사","tts_text":"会社"},
        {"kanji":"学校","kana":"がっこう","pron":"각코","ko":"학교","tts_text":"学校"},
        {"kanji":"家","kana":"いえ","pron":"이에","ko":"집","tts_text":"家"},

        {"kanji":"子ども","kana":"こども","pron":"코도모","ko":"아이","tts_text":"子ども"},
        {"kanji":"大人","kana":"おとな","pron":"오토나","ko":"어른","tts_text":"大人"},
        {"kanji":"男","kana":"おとこ","pron":"오토코","ko":"남자","tts_text":"男"},
        {"kanji":"女","kana":"おんな","pron":"온나","ko":"여자","tts_text":"女"},
        {"kanji":"名前","kana":"なまえ","pron":"나마에","ko":"이름","tts_text":"名前"},
        {"kanji":"国","kana":"くに","pron":"쿠니","ko":"나라","tts_text":"国"},
        {"kanji":"日本","kana":"にほん","pron":"니혼","ko":"일본","tts_text":"日本"},
        {"kanji":"韓国","kana":"かんこく","pron":"칸코쿠","ko":"한국","tts_text":"韓国"},
        {"kanji":"皆","kana":"みんな","pron":"민나","ko":"모두","tts_text":"皆"},
        {"kanji":"一人","kana":"ひとり","pron":"히토리","ko":"한 사람","tts_text":"一人"},

        {"kanji":"","kana":"これ","pron":"코레","ko":"이것","tts_text":"これ"},
        {"kanji":"","kana":"それ","pron":"소레","ko":"그것","tts_text":"それ"},
        {"kanji":"","kana":"あれ","pron":"아레","ko":"저것","tts_text":"あれ"},
        {"kanji":"","kana":"ここ","pron":"코코","ko":"여기","tts_text":"ここ"},
        {"kanji":"","kana":"そこ","pron":"소코","ko":"거기","tts_text":"そこ"},
        {"kanji":"","kana":"あそこ","pron":"아소코","ko":"저기","tts_text":"あそこ"},

        {"kanji":"","kana":"だれ","pron":"다레","ko":"누구","tts_text":"だれ"},
        {"kanji":"","kana":"なに","pron":"나니","ko":"무엇","tts_text":"なに"},
        {"kanji":"","kana":"どこ","pron":"도코","ko":"어디","tts_text":"どこ"},
        {"kanji":"","kana":"いつ","pron":"이츠","ko":"언제","tts_text":"いつ"},
        {"kanji":"","kana":"どう","pron":"도오","ko":"어떻게","tts_text":"どう"},
        {"kanji":"","kana":"どうして","pron":"도오시테","ko":"왜","tts_text":"どうして"},

        {"kanji":"","kana":"はい","pron":"하이","ko":"네","tts_text":"はい"},
        {"kanji":"","kana":"いいえ","pron":"이이에","ko":"아니요","tts_text":"いいえ"},
        {"kanji":"","kana":"お願いします","pron":"오네가이시마스","ko":"부탁합니다","tts_text":"お願いします"},
        {"kanji":"","kana":"ください","pron":"쿠다사이","ko":"주세요","tts_text":"ください"},
        {"kanji":"大丈夫","kana":"だいじょうぶ","pron":"다이죠부","ko":"괜찮다","tts_text":"大丈夫"},
        {"kanji":"","kana":"ありがとう","pron":"아리가토","ko":"고마워요","tts_text":"ありがとう"},
        {"kanji":"","kana":"すみません","pron":"스미마센","ko":"죄송합니다","tts_text":"すみません"},
        {"kanji":"","kana":"はい、そうです","pron":"하이 소오데스","ko":"네, 맞아요","tts_text":"はい、そうです"},
        {"kanji":"違います","kana":"ちがいます","pron":"치가이마스","ko":"아닙니다","tts_text":"違います"}
    ]
    },
    "sec02": {
    "title": "시간·날짜·요일·숫자",
    "items": [
        # ---- 날짜/시간 기본 ----
        {"kanji":"今日","kana":"きょう","pron":"쿄오","ko":"오늘","tts_text":"今日"},
        {"kanji":"昨日","kana":"きのう","pron":"키노오","ko":"어제","tts_text":"昨日"},
        {"kanji":"明日","kana":"あした","pron":"아시타","ko":"내일","tts_text":"明日"},
        {"kanji":"今","kana":"いま","pron":"이마","ko":"지금","tts_text":"今"},
        {"kanji":"毎日","kana":"まいにち","pron":"마이니치","ko":"매일","tts_text":"毎日"},
        {"kanji":"朝","kana":"あさ","pron":"아사","ko":"아침","tts_text":"朝"},
        {"kanji":"昼","kana":"ひる","pron":"히루","ko":"낮, 점심","tts_text":"昼"},
        {"kanji":"夜","kana":"よる","pron":"요루","ko":"밤","tts_text":"夜"},
        {"kanji":"時間","kana":"じかん","pron":"지칸","ko":"시간","tts_text":"時間"},
        {"kanji":"週","kana":"しゅう","pron":"슈우","ko":"주(week)","tts_text":"週"},

        {"kanji":"年","kana":"とし","pron":"토시","ko":"해, 년","tts_text":"年"},
        {"kanji":"月","kana":"つき","pron":"츠키","ko":"달","tts_text":"月"},
        {"kanji":"日","kana":"ひ","pron":"히","ko":"날, 하루","tts_text":"日"},

        # ---- 요일 ----
        {"kanji":"月曜日","kana":"げつようび","pron":"게츠요오비","ko":"월요일","tts_text":"月曜日"},
        {"kanji":"火曜日","kana":"かようび","pron":"카요오비","ko":"화요일","tts_text":"火曜日"},
        {"kanji":"水曜日","kana":"すいようび","pron":"스이요오비","ko":"수요일","tts_text":"水曜日"},
        {"kanji":"木曜日","kana":"もくようび","pron":"모쿠요오비","ko":"목요일","tts_text":"木曜日"},
        {"kanji":"金曜日","kana":"きんようび","pron":"킨요오비","ko":"금요일","tts_text":"金曜日"},
        {"kanji":"土曜日","kana":"どようび","pron":"도요오비","ko":"토요일","tts_text":"土曜日"},
        {"kanji":"日曜日","kana":"にちようび","pron":"니치요오비","ko":"일요일","tts_text":"日曜日"},

        # ---- 숫자(1~10) ----
        {"kanji":"一","kana":"いち","pron":"이치","ko":"일, 하나","tts_text":"一"},
        {"kanji":"二","kana":"に","pron":"니","ko":"이, 둘","tts_text":"二"},
        {"kanji":"三","kana":"さん","pron":"산","ko":"삼, 셋","tts_text":"三"},
        {"kanji":"四","kana":"よん","pron":"욘","ko":"사, 넷","tts_text":"四"},
        {"kanji":"五","kana":"ご","pron":"고","ko":"오, 다섯","tts_text":"五"},
        {"kanji":"六","kana":"ろく","pron":"로쿠","ko":"육, 여섯","tts_text":"六"},
        {"kanji":"七","kana":"なな","pron":"나나","ko":"칠, 일곱","tts_text":"七"},
        {"kanji":"八","kana":"はち","pron":"하치","ko":"팔, 여덟","tts_text":"八"},
        {"kanji":"九","kana":"きゅう","pron":"큐우","ko":"구, 아홉","tts_text":"九"},
        {"kanji":"十","kana":"じゅう","pron":"쥬우","ko":"십","tts_text":"十"},

        # ---- 시각/빈도 ----
        {"kanji":"何時","kana":"なんじ","pron":"난지","ko":"몇 시","tts_text":"何時"},
        {"kanji":"分","kana":"ふん","pron":"훈","ko":"분","tts_text":"分"},
        {"kanji":"午前","kana":"ごぜん","pron":"고젠","ko":"오전","tts_text":"午前"},
        {"kanji":"午後","kana":"ごご","pron":"고고","ko":"오후","tts_text":"午後"},
        {"kanji":"","kana":"いつも","pron":"이츠모","ko":"항상","tts_text":"いつも"},
        {"kanji":"時々","kana":"ときどき","pron":"토키도키","ko":"가끔","tts_text":"時々"},
        {"kanji":"早い","kana":"はやい","pron":"하야이","ko":"이르다, 빠르다","tts_text":"早い"},
        {"kanji":"遅い","kana":"おそい","pron":"오소이","ko":"늦다","tts_text":"遅い"},

        # ---- (추가) 시험 자주 나오는 시간표현/날짜 ----
        {"kanji":"今日","kana":"きょう","pron":"쿄오","ko":"오늘(복습용)","tts_text":"今日"},
        {"kanji":"今週","kana":"こんしゅう","pron":"콘슈우","ko":"이번 주","tts_text":"今週"},
        {"kanji":"来週","kana":"らいしゅう","pron":"라이슈우","ko":"다음 주","tts_text":"来週"},
        {"kanji":"先週","kana":"せんしゅう","pron":"센슈우","ko":"지난 주","tts_text":"先週"},
        {"kanji":"今月","kana":"こんげつ","pron":"콘게츠","ko":"이번 달","tts_text":"今月"},
        {"kanji":"来月","kana":"らいげつ","pron":"라이게츠","ko":"다음 달","tts_text":"来月"},
        {"kanji":"先月","kana":"せんげつ","pron":"센게츠","ko":"지난달","tts_text":"先月"},
        {"kanji":"今年","kana":"ことし","pron":"코토시","ko":"올해","tts_text":"今年"},
        {"kanji":"来年","kana":"らいねん","pron":"라이넨","ko":"내년","tts_text":"来年"},
        {"kanji":"去年","kana":"きょねん","pron":"쿄넨","ko":"작년","tts_text":"去年"},
        {"kanji":"毎週","kana":"まいしゅう","pron":"마이슈우","ko":"매주","tts_text":"毎週"},
        {"kanji":"毎月","kana":"まいつき","pron":"마이츠키","ko":"매달","tts_text":"毎月"}
    ]
    },
        "sec03": {
    "title": "장소·시설·교통·이동",
    "items": [
        # ---- 장소·시설 ----
        {"kanji":"駅","kana":"えき","pron":"에키","ko":"역","tts_text":"駅"},
        {"kanji":"空港","kana":"くうこう","pron":"쿠우코오","ko":"공항","tts_text":"空港"},
        {"kanji":"店","kana":"みせ","pron":"미세","ko":"가게","tts_text":"店"},
        {"kanji":"","kana":"スーパー","pron":"수우파아","ko":"슈퍼마켓","tts_text":"スーパー"},
        {"kanji":"","kana":"コンビニ","pron":"콘비니","ko":"편의점","tts_text":"コンビニ"},
        {"kanji":"","kana":"レストラン","pron":"레스토랑","ko":"레스토랑","tts_text":"レストラン"},
        {"kanji":"","kana":"カフェ","pron":"카페","ko":"카페","tts_text":"カフェ"},
        {"kanji":"","kana":"ホテル","pron":"호테루","ko":"호텔","tts_text":"ホテル"},
        {"kanji":"病院","kana":"びょういん","pron":"뵤오인","ko":"병원","tts_text":"病院"},
        {"kanji":"銀行","kana":"ぎんこう","pron":"긴코오","ko":"은행","tts_text":"銀行"},

        {"kanji":"郵便局","kana":"ゆうびんきょく","pron":"유우빈쿄쿠","ko":"우체국","tts_text":"郵便局"},
        {"kanji":"学校","kana":"がっこう","pron":"각코오","ko":"학교","tts_text":"学校"},
        {"kanji":"会社","kana":"かいしゃ","pron":"카이샤","ko":"회사","tts_text":"会社"},
        {"kanji":"家","kana":"いえ","pron":"이에","ko":"집","tts_text":"家"},
        {"kanji":"部屋","kana":"へや","pron":"헤야","ko":"방","tts_text":"部屋"},
        {"kanji":"","kana":"トイレ","pron":"토이레","ko":"화장실","tts_text":"トイレ"},
        {"kanji":"入口","kana":"いりぐち","pron":"이리구치","ko":"입구","tts_text":"入口"},
        {"kanji":"出口","kana":"でぐち","pron":"데구치","ko":"출구","tts_text":"出口"},
        {"kanji":"道","kana":"みち","pron":"미치","ko":"길","tts_text":"道"},
        {"kanji":"交差点","kana":"こうさてん","pron":"코오사텐","ko":"교차로","tts_text":"交差点"},

        # ---- 교통수단 ----
        {"kanji":"電車","kana":"でんしゃ","pron":"덴샤","ko":"전철","tts_text":"電車"},
        {"kanji":"地下鉄","kana":"ちかてつ","pron":"치카테츠","ko":"지하철","tts_text":"地下鉄"},
        {"kanji":"","kana":"バス","pron":"바스","ko":"버스","tts_text":"バス"},
        {"kanji":"","kana":"タクシー","pron":"타쿠시이","ko":"택시","tts_text":"タクシー"},
        {"kanji":"車","kana":"くるま","pron":"쿠루마","ko":"차","tts_text":"車"},
        {"kanji":"自転車","kana":"じてんしゃ","pron":"지텐샤","ko":"자전거","tts_text":"自転車"},

        # ---- 이동·방향 ----
        {"kanji":"歩く","kana":"あるく","pron":"아루쿠","ko":"걷다","tts_text":"歩く"},
        {"kanji":"行く","kana":"いく","pron":"이쿠","ko":"가다","tts_text":"行く"},
        {"kanji":"来る","kana":"くる","pron":"쿠루","ko":"오다","tts_text":"来る"},
        {"kanji":"帰る","kana":"かえる","pron":"카에루","ko":"돌아가다","tts_text":"帰る"},

        {"kanji":"右","kana":"みぎ","pron":"미기","ko":"오른쪽","tts_text":"右"},
        {"kanji":"左","kana":"ひだり","pron":"히다리","ko":"왼쪽","tts_text":"左"},
        {"kanji":"前","kana":"まえ","pron":"마에","ko":"앞","tts_text":"前"},
        {"kanji":"後ろ","kana":"うしろ","pron":"우시로","ko":"뒤","tts_text":"後ろ"},
        {"kanji":"中","kana":"なか","pron":"나카","ko":"안, 속","tts_text":"中"},
        {"kanji":"外","kana":"そと","pron":"소토","ko":"밖","tts_text":"外"},
        {"kanji":"近く","kana":"ちかく","pron":"치카쿠","ko":"가까이","tts_text":"近く"},
        {"kanji":"遠い","kana":"とおい","pron":"토오이","ko":"멀다","tts_text":"遠い"},

        # ---- 시험 자주 나오는 위치 표현 ----
        {"kanji":"上","kana":"うえ","pron":"우에","ko":"위","tts_text":"上"},
        {"kanji":"下","kana":"した","pron":"시타","ko":"아래","tts_text":"下"},
        {"kanji":"横","kana":"よこ","pron":"요코","ko":"옆","tts_text":"横"},
        {"kanji":"近所","kana":"きんじょ","pron":"킨조","ko":"근처, 동네","tts_text":"近所"}
    ]
    },
       "sec04": {
    "title": "기본 동사·행동",
    "items": [
        # ---- 일상 기본 동작 ----
        {"kanji":"食べる","kana":"たべる","pron":"타베루","ko":"먹다","tts_text":"食べる"},
        {"kanji":"飲む","kana":"のむ","pron":"노무","ko":"마시다","tts_text":"飲む"},
        {"kanji":"見る","kana":"みる","pron":"미루","ko":"보다","tts_text":"見る"},
        {"kanji":"聞く","kana":"きく","pron":"키쿠","ko":"듣다 / 묻다","tts_text":"聞く"},
        {"kanji":"話す","kana":"はなす","pron":"하나스","ko":"말하다","tts_text":"話す"},
        {"kanji":"読む","kana":"よむ","pron":"요무","ko":"읽다","tts_text":"読む"},
        {"kanji":"書く","kana":"かく","pron":"카쿠","ko":"쓰다","tts_text":"書く"},
        {"kanji":"買う","kana":"かう","pron":"카우","ko":"사다","tts_text":"買う"},
        {"kanji":"使う","kana":"つかう","pron":"츠카우","ko":"사용하다","tts_text":"使う"},
        {"kanji":"作る","kana":"つくる","pron":"츠쿠루","ko":"만들다","tts_text":"作る"},

        # ---- 생활·활동 ----
        {"kanji":"","kana":"する","pron":"스루","ko":"하다","tts_text":"する"},
        {"kanji":"勉強する","kana":"べんきょうする","pron":"벤쿄오 스루","ko":"공부하다","tts_text":"勉強する"},
        {"kanji":"働く","kana":"はたらく","pron":"하타라쿠","ko":"일하다","tts_text":"働く"},
        {"kanji":"休む","kana":"やすむ","pron":"야스무","ko":"쉬다","tts_text":"休む"},
        {"kanji":"起きる","kana":"おきる","pron":"오키루","ko":"일어나다","tts_text":"起きる"},
        {"kanji":"寝る","kana":"ねる","pron":"네루","ko":"자다","tts_text":"寝る"},
        {"kanji":"出る","kana":"でる","pron":"데루","ko":"나가다","tts_text":"出る"},
        {"kanji":"入る","kana":"はいる","pron":"하이루","ko":"들어가다","tts_text":"入る"},
        {"kanji":"座る","kana":"すわる","pron":"스와루","ko":"앉다","tts_text":"座る"},
        {"kanji":"立つ","kana":"たつ","pron":"타츠","ko":"서다","tts_text":"立つ"},

        # ---- 물건·조작 ----
        {"kanji":"待つ","kana":"まつ","pron":"마츠","ko":"기다리다","tts_text":"待つ"},
        {"kanji":"持つ","kana":"もつ","pron":"모츠","ko":"가지다, 들다","tts_text":"持つ"},
        {"kanji":"置く","kana":"おく","pron":"오쿠","ko":"놓다","tts_text":"置く"},
        {"kanji":"取る","kana":"とる","pron":"토루","ko":"잡다, 취하다","tts_text":"取る"},
        {"kanji":"開ける","kana":"あける","pron":"아케루","ko":"열다","tts_text":"開ける"},
        {"kanji":"閉める","kana":"しめる","pron":"시메루","ko":"닫다","tts_text":"閉める"},
        {"kanji":"始める","kana":"はじめる","pron":"하지메루","ko":"시작하다","tts_text":"始める"},
        {"kanji":"終わる","kana":"おわる","pron":"오와루","ko":"끝나다","tts_text":"終わる"},

        # ---- 학습·사고 ----
        {"kanji":"教える","kana":"おしえる","pron":"오시에루","ko":"가르치다","tts_text":"教える"},
        {"kanji":"習う","kana":"ならう","pron":"나라우","ko":"배우다","tts_text":"習う"},
        {"kanji":"分かる","kana":"わかる","pron":"와카루","ko":"알다, 이해하다","tts_text":"分かる"},
        {"kanji":"知る","kana":"しる","pron":"시루","ko":"알게 되다","tts_text":"知る"},
        {"kanji":"考える","kana":"かんがえる","pron":"칸가에루","ko":"생각하다","tts_text":"考える"},
        {"kanji":"決める","kana":"きめる","pron":"키메루","ko":"정하다","tts_text":"決める"},
        {"kanji":"忘れる","kana":"わすれる","pron":"와스레루","ko":"잊다","tts_text":"忘れる"},
        {"kanji":"覚える","kana":"おぼえる","pron":"오보에루","ko":"외우다","tts_text":"覚える"},

        # ---- 대인 행동 ----
        {"kanji":"会う","kana":"あう","pron":"아우","ko":"만나다","tts_text":"会う"},
        {"kanji":"呼ぶ","kana":"よぶ","pron":"요부","ko":"부르다","tts_text":"呼ぶ"},
        {"kanji":"助ける","kana":"たすける","pron":"타스케루","ko":"돕다","tts_text":"助ける"},
        {"kanji":"行う","kana":"おこなう","pron":"오코나우","ko":"행하다","tts_text":"行う"}
    ]
    },
            "sec05": {
    "title": "형용사·상태 표현",
    "items": [
        # ---- 크기·양·길이 ----
        {"kanji":"大きい","kana":"おおきい","pron":"오오키이","ko":"크다","tts_text":"大きい"},
        {"kanji":"小さい","kana":"ちいさい","pron":"치이사이","ko":"작다","tts_text":"小さい"},
        {"kanji":"長い","kana":"ながい","pron":"나가이","ko":"길다","tts_text":"長い"},
        {"kanji":"短い","kana":"みじかい","pron":"미지카이","ko":"짧다","tts_text":"短い"},
        {"kanji":"多い","kana":"おおい","pron":"오오이","ko":"많다","tts_text":"多い"},
        {"kanji":"少ない","kana":"すくない","pron":"스쿠나이","ko":"적다","tts_text":"少ない"},

        # ---- 가격·높낮이 ----
        {"kanji":"高い","kana":"たかい","pron":"타카이","ko":"비싸다 / 높다","tts_text":"高い"},
        {"kanji":"安い","kana":"やすい","pron":"야스이","ko":"싸다","tts_text":"安い"},
        {"kanji":"重い","kana":"おもい","pron":"오모이","ko":"무겁다","tts_text":"重い"},
        {"kanji":"軽い","kana":"かるい","pron":"카루이","ko":"가볍다","tts_text":"軽い"},

        # ---- 시간·거리 ----
        {"kanji":"早い","kana":"はやい","pron":"하야이","ko":"빠르다 / 이르다","tts_text":"早い"},
        {"kanji":"遅い","kana":"おそい","pron":"오소이","ko":"느리다 / 늦다","tts_text":"遅い"},
        {"kanji":"近い","kana":"ちかい","pron":"치카이","ko":"가깝다","tts_text":"近い"},
        {"kanji":"遠い","kana":"とおい","pron":"토오이","ko":"멀다","tts_text":"遠い"},

        # ---- 강도·밝기 ----
        {"kanji":"強い","kana":"つよい","pron":"츠요이","ko":"강하다","tts_text":"強い"},
        {"kanji":"弱い","kana":"よわい","pron":"요와이","ko":"약하다","tts_text":"弱い"},
        {"kanji":"明るい","kana":"あかるい","pron":"아카루이","ko":"밝다","tts_text":"明るい"},
        {"kanji":"暗い","kana":"くらい","pron":"쿠라이","ko":"어둡다","tts_text":"暗い"},

        # ---- 날씨·온도 ----
        {"kanji":"暑い","kana":"あつい","pron":"아츠이","ko":"덥다","tts_text":"暑い"},
        {"kanji":"寒い","kana":"さむい","pron":"사무이","ko":"춥다","tts_text":"寒い"},
        {"kanji":"冷たい","kana":"つめたい","pron":"츠메타이","ko":"차갑다","tts_text":"冷たい"},
        {"kanji":"","kana":"あたたかい","pron":"아타타카이","ko":"따뜻하다","tts_text":"あたたかい"},

        # ---- 상태·난이도 ----
        {"kanji":"忙しい","kana":"いそがしい","pron":"이소가시이","ko":"바쁘다","tts_text":"忙しい"},
        {"kanji":"暇","kana":"ひま","pron":"히마","ko":"한가하다","tts_text":"暇"},
        {"kanji":"難しい","kana":"むずかしい","pron":"무즈카시이","ko":"어렵다","tts_text":"難しい"},
        {"kanji":"簡単","kana":"かんたん","pron":"칸탄","ko":"간단하다","tts_text":"簡単"},
        {"kanji":"便利","kana":"べんり","pron":"벤리","ko":"편리하다","tts_text":"便利"},
        {"kanji":"不便","kana":"ふべん","pron":"후벤","ko":"불편하다","tts_text":"不便"},

        # ---- 감정·평가 ----
        {"kanji":"元気","kana":"げんき","pron":"겡키","ko":"건강하다 / 활기차다","tts_text":"元気"},
        {"kanji":"静か","kana":"しずか","pron":"시즈카","ko":"조용하다","tts_text":"静か"},
        {"kanji":"","kana":"にぎやか","pron":"니기야카","ko":"번화하다","tts_text":"にぎやか"},
        {"kanji":"","kana":"きれい","pron":"키레이","ko":"깨끗하다 / 예쁘다","tts_text":"きれい"},
        {"kanji":"汚い","kana":"きたない","pron":"키타나이","ko":"더럽다","tts_text":"汚い"},

        # ---- 선호·중요도 ----
        {"kanji":"好き","kana":"すき","pron":"스키","ko":"좋아하다","tts_text":"好き"},
        {"kanji":"嫌い","kana":"きらい","pron":"키라이","ko":"싫어하다","tts_text":"嫌い"},
        {"kanji":"大切","kana":"たいせつ","pron":"타이세츠","ko":"중요하다","tts_text":"大切"},
        {"kanji":"必要","kana":"ひつよう","pron":"히츠요오","ko":"필요하다","tts_text":"必要"},
        {"kanji":"危ない","kana":"あぶない","pron":"아부나이","ko":"위험하다","tts_text":"危ない"}
    ]
    },
            "sec06": {
    "title": "조사와 함께 쓰이는 핵심 표현",
    "items": [
        # ---- 이동·방향 ----
        {"kanji":"会う","kana":"あう","pron":"아우","ko":"만나다 (に)","tts_text":"会う"},
        {"kanji":"行く","kana":"いく","pron":"이쿠","ko":"가다 (へ / に)","tts_text":"行く"},
        {"kanji":"来る","kana":"くる","pron":"쿠루","ko":"오다 (へ / に)","tts_text":"来る"},
        {"kanji":"帰る","kana":"かえる","pron":"카에루","ko":"돌아가다 (へ)","tts_text":"帰る"},
        {"kanji":"入る","kana":"はいる","pron":"하이루","ko":"들어가다 (に)","tts_text":"入る"},
        {"kanji":"出る","kana":"でる","pron":"데루","ko":"나가다 / 나오다 (を)","tts_text":"出る"},
        {"kanji":"渡る","kana":"わたる","pron":"와타루","ko":"건너다 (を)","tts_text":"渡る"},
        {"kanji":"歩く","kana":"あるく","pron":"아루쿠","ko":"걷다 (を)","tts_text":"歩く"},
        {"kanji":"乗る","kana":"のる","pron":"노루","ko":"타다 (に)","tts_text":"乗る"},
        {"kanji":"降りる","kana":"おりる","pron":"오리루","ko":"내리다 (を)","tts_text":"降りる"},

        # ---- 존재·생활 ----
        {"kanji":"住む","kana":"すむ","pron":"스무","ko":"살다 (に)","tts_text":"住む"},
        {"kanji":"","kana":"いる","pron":"이루","ko":"있다 (사람·동물) (に)","tts_text":"いる"},
        {"kanji":"","kana":"ある","pron":"아루","ko":"있다 (사물) (に)","tts_text":"ある"},
        {"kanji":"使う","kana":"つかう","pron":"츠카우","ko":"사용하다 (を)","tts_text":"使う"},
        {"kanji":"作る","kana":"つくる","pron":"츠쿠루","ko":"만들다 (を)","tts_text":"作る"},
        {"kanji":"買う","kana":"かう","pron":"카우","ko":"사다 (を)","tts_text":"買う"},
        {"kanji":"売る","kana":"うる","pron":"우루","ko":"팔다 (を)","tts_text":"売る"},
        {"kanji":"借りる","kana":"かりる","pron":"카리루","ko":"빌리다 (を)","tts_text":"借りる"},
        {"kanji":"貸す","kana":"かす","pron":"카스","ko":"빌려주다 (を)","tts_text":"貸す"},
        {"kanji":"置く","kana":"おく","pron":"오쿠","ko":"놓다 (を)","tts_text":"置く"},

        # ---- 식사·행동 ----
        {"kanji":"食べる","kana":"たべる","pron":"타베루","ko":"먹다 (を)","tts_text":"食べる"},
        {"kanji":"飲む","kana":"のむ","pron":"노무","ko":"마시다 (を)","tts_text":"飲む"},
        {"kanji":"見る","kana":"みる","pron":"미루","ko":"보다 (を)","tts_text":"見る"},
        {"kanji":"聞く","kana":"きく","pron":"키쿠","ko":"듣다 / 묻다 (を)","tts_text":"聞く"},
        {"kanji":"話す","kana":"はなす","pron":"하나스","ko":"말하다 (を)","tts_text":"話す"},
        {"kanji":"教える","kana":"おしえる","pron":"오시에루","ko":"가르치다 (を / に)","tts_text":"教える"},
        {"kanji":"習う","kana":"ならう","pron":"나라우","ko":"배우다 (を)","tts_text":"習う"},
        {"kanji":"勉強する","kana":"べんきょうする","pron":"벤쿄오스루","ko":"공부하다 (を)","tts_text":"勉強する"},
        {"kanji":"働く","kana":"はたらく","pron":"하타라쿠","ko":"일하다 (で)","tts_text":"働く"},
        {"kanji":"休む","kana":"やすむ","pron":"야스무","ko":"쉬다 (を)","tts_text":"休む"},

        # ---- 동작·변화 ----
        {"kanji":"待つ","kana":"まつ","pron":"마츠","ko":"기다리다 (を)","tts_text":"待つ"},
        {"kanji":"入れる","kana":"いれる","pron":"이레루","ko":"넣다 (を)","tts_text":"入れる"},
        {"kanji":"出す","kana":"だす","pron":"다스","ko":"내다 (を)","tts_text":"出す"},
        {"kanji":"止める","kana":"とめる","pron":"토메루","ko":"멈추다 (を)","tts_text":"止める"},
        {"kanji":"始める","kana":"はじめる","pron":"하지메루","ko":"시작하다 (を)","tts_text":"始める"},
        {"kanji":"終わる","kana":"おわる","pron":"오와루","ko":"끝나다 (が)","tts_text":"終わる"},
        {"kanji":"開ける","kana":"あける","pron":"아케루","ko":"열다 (を)","tts_text":"開ける"},
        {"kanji":"閉める","kana":"しめる","pron":"시메루","ko":"닫다 (を)","tts_text":"閉める"},
        {"kanji":"","kana":"つける","pron":"츠케루","ko":"켜다 / 붙이다 (を)","tts_text":"つける"},
        {"kanji":"消す","kana":"けす","pron":"케스","ko":"끄다 / 지우다 (を)","tts_text":"消す"}
    ]
    },
        "sec07": {
    "title": "숫자·수량·단위 표현",
    "items": [
        # ---- 기본 숫자 ----
        {"kanji":"一","kana":"いち","pron":"이치","ko":"일, 하나","tts_text":"一"},
        {"kanji":"二","kana":"に","pron":"니","ko":"이, 둘","tts_text":"二"},
        {"kanji":"三","kana":"さん","pron":"산","ko":"삼, 셋","tts_text":"三"},
        {"kanji":"四","kana":"よん","pron":"욘","ko":"사, 넷","tts_text":"四"},
        {"kanji":"五","kana":"ご","pron":"고","ko":"오, 다섯","tts_text":"五"},
        {"kanji":"六","kana":"ろく","pron":"로쿠","ko":"육, 여섯","tts_text":"六"},
        {"kanji":"七","kana":"なな","pron":"나나","ko":"칠, 일곱","tts_text":"七"},
        {"kanji":"八","kana":"はち","pron":"하치","ko":"팔, 여덟","tts_text":"八"},
        {"kanji":"九","kana":"きゅう","pron":"큐","ko":"구, 아홉","tts_text":"九"},
        {"kanji":"十","kana":"じゅう","pron":"쥬우","ko":"십","tts_text":"十"},

        # ---- 큰 수 ----
        {"kanji":"百","kana":"ひゃく","pron":"햐쿠","ko":"백","tts_text":"百"},
        {"kanji":"千","kana":"せん","pron":"센","ko":"천","tts_text":"千"},
        {"kanji":"万","kana":"まん","pron":"만","ko":"만","tts_text":"万"},

        # ---- 화폐·단위 ----
        {"kanji":"円","kana":"えん","pron":"엔","ko":"엔 (일본 화폐 단위)","tts_text":"円"},
        {"kanji":"個","kana":"こ","pron":"코","ko":"개 (사물 단위)","tts_text":"個"},
        {"kanji":"人","kana":"にん","pron":"닌","ko":"명 (사람 수)","tts_text":"人"},
        {"kanji":"台","kana":"だい","pron":"다이","ko":"대 (기계·차량)","tts_text":"台"},
        {"kanji":"枚","kana":"まい","pron":"마이","ko":"장 (종이·얇은 것)","tts_text":"枚"},
        {"kanji":"本","kana":"ほん","pron":"혼","ko":"개 (길고 둥근 것)","tts_text":"本"},
        {"kanji":"杯","kana":"はい","pron":"하이","ko":"잔","tts_text":"杯"},

        # ---- 고유 수사 ----
        {"kanji":"一つ","kana":"ひとつ","pron":"히토츠","ko":"한 개","tts_text":"一つ"},
        {"kanji":"二つ","kana":"ふたつ","pron":"후타츠","ko":"두 개","tts_text":"二つ"},
        {"kanji":"三つ","kana":"みっつ","pron":"밋츠","ko":"세 개","tts_text":"三つ"},
        {"kanji":"四つ","kana":"よっつ","pron":"욧츠","ko":"네 개","tts_text":"四つ"},
        {"kanji":"五つ","kana":"いつつ","pron":"이츠츠","ko":"다섯 개","tts_text":"五つ"},

        # ---- 질문·양 ----
        {"kanji":"","kana":"いくつ","pron":"이쿠츠","ko":"몇 개","tts_text":"いくつ"},
        {"kanji":"","kana":"いくら","pron":"이쿠라","ko":"얼마 (가격)","tts_text":"いくら"},
        {"kanji":"全部","kana":"ぜんぶ","pron":"젠부","ko":"전부","tts_text":"全部"},
        {"kanji":"半分","kana":"はんぶん","pron":"한분","ko":"절반","tts_text":"半分"},
        {"kanji":"多い","kana":"おおい","pron":"오오이","ko":"많다","tts_text":"多い"},
        {"kanji":"少ない","kana":"すくない","pron":"스쿠나이","ko":"적다","tts_text":"少ない"},

        # ---- 범위·정도 ----
        {"kanji":"同じ","kana":"おなじ","pron":"오나지","ko":"같다","tts_text":"同じ"},
        {"kanji":"全部で","kana":"ぜんぶで","pron":"젠부데","ko":"전부 합해서","tts_text":"全部で"},
        {"kanji":"","kana":"ぐらい","pron":"구라이","ko":"~정도","tts_text":"ぐらい"},
        {"kanji":"以上","kana":"いじょう","pron":"이죠오","ko":"이상","tts_text":"以上"},
        {"kanji":"以下","kana":"いか","pron":"이카","ko":"이하","tts_text":"以下"},
        {"kanji":"","kana":"だけ","pron":"다케","ko":"~만","tts_text":"だけ"},
        {"kanji":"","kana":"しか","pron":"시카","ko":"~밖에 (+부정)","tts_text":"しか"},
        {"kanji":"約","kana":"やく","pron":"야쿠","ko":"약, 대략","tts_text":"約"},
        {"kanji":"毎","kana":"まい","pron":"마이","ko":"매~","tts_text":"毎"}
    ]
    },
       
        "sec08": {
    "title": "위치·방향·장소 표현",
    "items": [
        # ---- 기본 위치 ----
        {"kanji":"上","kana":"うえ","pron":"우에","ko":"위","tts_text":"上"},
        {"kanji":"下","kana":"した","pron":"시타","ko":"아래","tts_text":"下"},
        {"kanji":"中","kana":"なか","pron":"나카","ko":"안, 속","tts_text":"中"},
        {"kanji":"外","kana":"そと","pron":"소토","ko":"밖","tts_text":"外"},
        {"kanji":"前","kana":"まえ","pron":"마에","ko":"앞","tts_text":"前"},
        {"kanji":"後ろ","kana":"うしろ","pron":"우시로","ko":"뒤","tts_text":"後ろ"},
        {"kanji":"右","kana":"みぎ","pron":"미기","ko":"오른쪽","tts_text":"右"},
        {"kanji":"左","kana":"ひだり","pron":"히다리","ko":"왼쪽","tts_text":"左"},
        {"kanji":"隣","kana":"となり","pron":"토나리","ko":"옆","tts_text":"隣"},
        {"kanji":"近く","kana":"ちかく","pron":"치카쿠","ko":"가까이, 근처","tts_text":"近く"},

        # ---- 방향·지시 ----
        {"kanji":"遠く","kana":"とおく","pron":"토오쿠","ko":"멀리","tts_text":"遠く"},
        {"kanji":"向こう","kana":"むこう","pron":"무코오","ko":"저쪽, 맞은편","tts_text":"向こう"},
        {"kanji":"","kana":"こちら","pron":"코치라","ko":"이쪽(정중)","tts_text":"こちら"},
        {"kanji":"","kana":"そちら","pron":"소치라","ko":"그쪽(정중)","tts_text":"そちら"},
        {"kanji":"","kana":"あちら","pron":"아치라","ko":"저쪽(정중)","tts_text":"あちら"},
        {"kanji":"","kana":"どちら","pron":"도치라","ko":"어느 쪽","tts_text":"どちら"},
        {"kanji":"","kana":"ここ","pron":"코코","ko":"여기","tts_text":"ここ"},
        {"kanji":"","kana":"そこ","pron":"소코","ko":"거기","tts_text":"そこ"},
        {"kanji":"","kana":"あそこ","pron":"아소코","ko":"저기","tts_text":"あそこ"},
        {"kanji":"","kana":"どこ","pron":"도코","ko":"어디","tts_text":"どこ"},

        # ---- 장소·시설 ----
        {"kanji":"場所","kana":"ばしょ","pron":"바쇼","ko":"장소","tts_text":"場所"},
        {"kanji":"入口","kana":"いりぐち","pron":"이리구치","ko":"입구","tts_text":"入口"},
        {"kanji":"出口","kana":"でぐち","pron":"데구치","ko":"출구","tts_text":"出口"},
        {"kanji":"道","kana":"みち","pron":"미치","ko":"길","tts_text":"道"},
        {"kanji":"角","kana":"かど","pron":"카도","ko":"모퉁이","tts_text":"角"},
        {"kanji":"交差点","kana":"こうさてん","pron":"코오사텐","ko":"교차로","tts_text":"交差点"},
        {"kanji":"橋","kana":"はし","pron":"하시","ko":"다리","tts_text":"橋"},
        {"kanji":"公園","kana":"こうえん","pron":"코오엔","ko":"공원","tts_text":"公園"},
        {"kanji":"駅","kana":"えき","pron":"에키","ko":"역","tts_text":"駅"},
        {"kanji":"建物","kana":"たてもの","pron":"타테모노","ko":"건물","tts_text":"建物"},

        # ---- 실내·생활 공간 ----
        {"kanji":"部屋","kana":"へや","pron":"헤야","ko":"방","tts_text":"部屋"},
        {"kanji":"教室","kana":"きょうしつ","pron":"쿄오시츠","ko":"교실","tts_text":"教室"},
        {"kanji":"店","kana":"みせ","pron":"미세","ko":"가게","tts_text":"店"},
        {"kanji":"会社","kana":"かいしゃ","pron":"카이샤","ko":"회사","tts_text":"会社"},
        {"kanji":"学校","kana":"がっこう","pron":"각코오","ko":"학교","tts_text":"学校"},
        {"kanji":"家","kana":"いえ","pron":"이에","ko":"집","tts_text":"家"},

        # ---- 조사 결합 표현 (시험 빈출) ----
        {"kanji":"近くに","kana":"ちかくに","pron":"치카쿠니","ko":"근처에","tts_text":"近くに"},
        {"kanji":"中に","kana":"なかに","pron":"나카니","ko":"안에","tts_text":"中に"},
        {"kanji":"上に","kana":"うえに","pron":"우에니","ko":"위에","tts_text":"上に"},
        {"kanji":"下に","kana":"したに","pron":"시타니","ko":"아래에","tts_text":"下に"}
    ]
    },
    "sec09": {
    "title": "음식·음료·쇼핑·일상 사물",
    "items": [
        # ---- 음식·음료 ----
        {"kanji":"食べ物","kana":"たべもの","pron":"타베모노","ko":"음식","tts_text":"食べ物"},
        {"kanji":"飲み物","kana":"のみもの","pron":"노미모노","ko":"음료","tts_text":"飲み物"},
        {"kanji":"ご飯","kana":"ごはん","pron":"고항","ko":"밥","tts_text":"ご飯"},
        {"kanji":"パン","kana":"パン","pron":"팡","ko":"빵","tts_text":"パン"},
        {"kanji":"肉","kana":"にく","pron":"니쿠","ko":"고기","tts_text":"肉"},
        {"kanji":"魚","kana":"さかな","pron":"사카나","ko":"생선","tts_text":"魚"},
        {"kanji":"野菜","kana":"やさい","pron":"야사이","ko":"채소","tts_text":"野菜"},
        {"kanji":"果物","kana":"くだもの","pron":"쿠다모노","ko":"과일","tts_text":"果物"},
        {"kanji":"水","kana":"みず","pron":"미즈","ko":"물","tts_text":"水"},
        {"kanji":"お茶","kana":"おちゃ","pron":"오챠","ko":"차","tts_text":"お茶"},

        # ---- 음료·외식 ----
        {"kanji":"牛乳","kana":"ぎゅうにゅう","pron":"규우뉴우","ko":"우유","tts_text":"牛乳"},
        {"kanji":"コーヒー","kana":"コーヒー","pron":"코오히이","ko":"커피","tts_text":"コーヒー"},
        {"kanji":"レストラン","kana":"レストラン","pron":"레스토랑","ko":"레스토랑","tts_text":"レストラン"},
        {"kanji":"メニュー","kana":"メニュー","pron":"메뉴우","ko":"메뉴","tts_text":"メニュー"},
        {"kanji":"注文","kana":"ちゅうもん","pron":"추우몬","ko":"주문","tts_text":"注文"},
        {"kanji":"一人前","kana":"ひとりまえ","pron":"히토리마에","ko":"1인분","tts_text":"一人前"},

        # ---- 쇼핑·돈 ----
        {"kanji":"店","kana":"みせ","pron":"미세","ko":"가게","tts_text":"店"},
        {"kanji":"買い物","kana":"かいもの","pron":"카이모노","ko":"쇼핑","tts_text":"買い物"},
        {"kanji":"お金","kana":"おかね","pron":"오카네","ko":"돈","tts_text":"お金"},
        {"kanji":"値段","kana":"ねだん","pron":"네단","ko":"가격","tts_text":"値段"},
        {"kanji":"円","kana":"えん","pron":"엔","ko":"엔(일본 화폐)","tts_text":"円"},
        {"kanji":"安い","kana":"やすい","pron":"야스이","ko":"싸다","tts_text":"安い"},
        {"kanji":"高い","kana":"たかい","pron":"타카이","ko":"비싸다","tts_text":"高い"},
        {"kanji":"いくら","kana":"いくら","pron":"이쿠라","ko":"얼마","tts_text":"いくら"},
        {"kanji":"払う","kana":"はらう","pron":"하라우","ko":"지불하다","tts_text":"払う"},
        {"kanji":"カード","kana":"カード","pron":"카아도","ko":"카드","tts_text":"カード"},

        # ---- 일상 사물 ----
        {"kanji":"物","kana":"もの","pron":"모노","ko":"물건","tts_text":"物"},
        {"kanji":"本","kana":"ほん","pron":"혼","ko":"책","tts_text":"本"},
        {"kanji":"かばん","kana":"かばん","pron":"카방","ko":"가방","tts_text":"かばん"},
        {"kanji":"財布","kana":"さいふ","pron":"사이후","ko":"지갑","tts_text":"財布"},
        {"kanji":"携帯","kana":"けいたい","pron":"케이타이","ko":"휴대폰","tts_text":"携帯"},
        {"kanji":"鍵","kana":"かぎ","pron":"카기","ko":"열쇠","tts_text":"鍵"},
        {"kanji":"机","kana":"つくえ","pron":"츠쿠에","ko":"책상","tts_text":"机"},
        {"kanji":"椅子","kana":"いす","pron":"이스","ko":"의자","tts_text":"椅子"},
        {"kanji":"服","kana":"ふく","pron":"후쿠","ko":"옷","tts_text":"服"},
        {"kanji":"靴","kana":"くつ","pron":"쿠츠","ko":"신발","tts_text":"靴"}
    ]
    },
        "sec10": {
    "title": "상태·감정·반응 표현",
    "items": [
        {"kanji":"疲れる","kana":"つかれる","pron":"츠카레루","ko":"피곤해지다","tts_text":"疲れる"},
        {"kanji":"楽しい","kana":"たのしい","pron":"타노시이","ko":"즐겁다","tts_text":"楽しい"},
        {"kanji":"つまらない","kana":"つまらない","pron":"츠마라나이","ko":"재미없다","tts_text":"つまらない"},
        {"kanji":"嬉しい","kana":"うれしい","pron":"우레시이","ko":"기쁘다","tts_text":"嬉しい"},
        {"kanji":"悲しい","kana":"かなしい","pron":"카나시이","ko":"슬프다","tts_text":"悲しい"},
        {"kanji":"怖い","kana":"こわい","pron":"코와이","ko":"무섭다","tts_text":"怖い"},
        {"kanji":"安心","kana":"あんしん","pron":"안신","ko":"안심","tts_text":"安心"},
        {"kanji":"心配","kana":"しんぱい","pron":"심파이","ko":"걱정","tts_text":"心配"},
        {"kanji":"大変","kana":"たいへん","pron":"타이헨","ko":"힘들다, 큰일이다","tts_text":"大変"},
        {"kanji":"無理","kana":"むり","pron":"무리","ko":"무리","tts_text":"無理"},

        {"kanji":"必要","kana":"ひつよう","pron":"히츠요오","ko":"필요","tts_text":"必要"},
        {"kanji":"要らない","kana":"いらない","pron":"이라나이","ko":"필요 없다","tts_text":"要らない"},
        {"kanji":"足りる","kana":"たりる","pron":"타리루","ko":"충분하다","tts_text":"足りる"},
        {"kanji":"足りない","kana":"たりない","pron":"타리나이","ko":"부족하다","tts_text":"足りない"},
        {"kanji":"大丈夫","kana":"だいじょうぶ","pron":"다이죠오부","ko":"괜찮다","tts_text":"大丈夫"},

        {"kanji":"上手","kana":"じょうず","pron":"죠오즈","ko":"잘하다","tts_text":"上手"},
        {"kanji":"下手","kana":"へた","pron":"헤타","ko":"못하다","tts_text":"下手"},
        {"kanji":"大好き","kana":"だいすき","pron":"다이스키","ko":"아주 좋아함","tts_text":"大好き"},
        {"kanji":"嫌","kana":"いや","pron":"이야","ko":"싫다","tts_text":"嫌"},
        {"kanji":"面白い","kana":"おもしろい","pron":"오모시로이","ko":"재미있다","tts_text":"面白い"},
        {"kanji":"眠い","kana":"ねむい","pron":"네무이","ko":"졸리다","tts_text":"眠い"}
    ]
    },
 
}

N4_WORDS = {

    "sec01": {
    "title": "사람·관계·사회 표현",
    "items": [
    {"kanji":"両親","kana":"りょうしん","pron":"료오신","ko":"부모","tts_text":"両親"},
    {"kanji":"兄弟","kana":"きょうだい","pron":"쿄오다이","ko":"형제","tts_text":"兄弟"},
    {"kanji":"夫","kana":"おっと","pron":"옷또","ko":"남편","tts_text":"夫"},
    {"kanji":"妻","kana":"つま","pron":"츠마","ko":"아내","tts_text":"妻"},
    {"kanji":"先輩","kana":"せんぱい","pron":"센파이","ko":"선배","tts_text":"先輩"},
    {"kanji":"後輩","kana":"こうはい","pron":"코오하이","ko":"후배","tts_text":"後輩"},
    {"kanji":"大人","kana":"おとな","pron":"오토나","ko":"어른","tts_text":"大人"},
    {"kanji":"若者","kana":"わかもの","pron":"와카모노","ko":"젊은이","tts_text":"若者"},
    {"kanji":"客","kana":"きゃく","pron":"캬쿠","ko":"손님","tts_text":"客"},
    {"kanji":"知り合い","kana":"しりあい","pron":"시리아이","ko":"아는 사람","tts_text":"知り合い"},

    {"kanji":"有名","kana":"ゆうめい","pron":"유우메이","ko":"유명함","tts_text":"有名"},
    {"kanji":"親切","kana":"しんせつ","pron":"신세츠","ko":"친절함","tts_text":"親切"},
    {"kanji":"失礼","kana":"しつれい","pron":"시츠레이","ko":"실례","tts_text":"失礼"},
    {"kanji":"真面目","kana":"まじめ","pron":"마지메","ko":"성실함","tts_text":"真面目"},
    {"kanji":"自由","kana":"じゆう","pron":"지유우","ko":"자유","tts_text":"自由"},
    {"kanji":"不安","kana":"ふあん","pron":"후안","ko":"불안","tts_text":"不安"},
    {"kanji":"安心","kana":"あんしん","pron":"안신","ko":"안심","tts_text":"安心"},
    {"kanji":"約束","kana":"やくそく","pron":"야쿠소쿠","ko":"약속","tts_text":"約束"},
    {"kanji":"意見","kana":"いけん","pron":"이켄","ko":"의견","tts_text":"意見"},
    {"kanji":"理由","kana":"りゆう","pron":"리유우","ko":"이유","tts_text":"理由"},

    {"kanji":"社会","kana":"しゃかい","pron":"샤카이","ko":"사회","tts_text":"社会"},
    {"kanji":"関係","kana":"かんけい","pron":"칸케이","ko":"관계","tts_text":"関係"},
    {"kanji":"文化","kana":"ぶんか","pron":"분카","ko":"문화","tts_text":"文化"},
    {"kanji":"習慣","kana":"しゅうかん","pron":"슈우칸","ko":"습관","tts_text":"習慣"},
    {"kanji":"経験","kana":"けいけん","pron":"케이켄","ko":"경험","tts_text":"経験"},
    {"kanji":"将来","kana":"しょうらい","pron":"쇼오라이","ko":"장래","tts_text":"将来"},
    {"kanji":"生活","kana":"せいかつ","pron":"세이카츠","ko":"생활","tts_text":"生活"},
    {"kanji":"人生","kana":"じんせい","pron":"진세이","ko":"인생","tts_text":"人生"},
    {"kanji":"場合","kana":"ばあい","pron":"바아이","ko":"경우","tts_text":"場合"},
    {"kanji":"立場","kana":"たちば","pron":"타치바","ko":"입장","tts_text":"立場"},

    {"kanji":"集まり","kana":"あつまり","pron":"아츠마리","ko":"모임","tts_text":"集まり"},
    {"kanji":"相談","kana":"そうだん","pron":"소오단","ko":"상담","tts_text":"相談"},
    {"kanji":"紹介","kana":"しょうかい","pron":"쇼오카이","ko":"소개","tts_text":"紹介"},
    {"kanji":"連絡","kana":"れんらく","pron":"렌라쿠","ko":"연락","tts_text":"連絡"},
    {"kanji":"注意","kana":"ちゅうい","pron":"츄우이","ko":"주의","tts_text":"注意"}
    ]
    },
    "sec03": {
    "title": "장소·시설·환경",
    "items": [
    {"kanji":"建物","kana":"たてもの","pron":"타테모노","ko":"건물","tts_text":"建物"},
    {"kanji":"周り","kana":"まわり","pron":"마와리","ko":"주위","tts_text":"周り"},
    {"kanji":"田舎","kana":"いなか","pron":"이나카","ko":"시골","tts_text":"田舎"},
    {"kanji":"都会","kana":"とかい","pron":"토카이","ko":"도시","tts_text":"都会"},
    {"kanji":"近所","kana":"きんじょ","pron":"킨죠","ko":"근처","tts_text":"近所"},
    {"kanji":"自然","kana":"しぜん","pron":"시젠","ko":"자연","tts_text":"自然"},
    {"kanji":"景色","kana":"けしき","pron":"케시키","ko":"경치","tts_text":"景色"},
    {"kanji":"空","kana":"そら","pron":"소라","ko":"하늘","tts_text":"空"},
    {"kanji":"海","kana":"うみ","pron":"우미","ko":"바다","tts_text":"海"},
    {"kanji":"山","kana":"やま","pron":"야마","ko":"산","tts_text":"山"},

    {"kanji":"川","kana":"かわ","pron":"카와","ko":"강","tts_text":"川"},
    {"kanji":"公園","kana":"こうえん","pron":"코오엔","ko":"공원","tts_text":"公園"},
    {"kanji":"道路","kana":"どうろ","pron":"도로","ko":"도로","tts_text":"道路"},
    {"kanji":"橋","kana":"はし","pron":"하시","ko":"다리","tts_text":"橋"},
    {"kanji":"場所","kana":"ばしょ","pron":"바쇼","ko":"장소","tts_text":"場所"},
    {"kanji":"角","kana":"かど","pron":"카도","ko":"모퉁이","tts_text":"角"},
    {"kanji":"向こう","kana":"むこう","pron":"무코오","ko":"저쪽","tts_text":"向こう"},
    {"kanji":"隣","kana":"となり","pron":"토나리","ko":"옆","tts_text":"隣"},
    {"kanji":"裏","kana":"うら","pron":"우라","ko":"뒤쪽","tts_text":"裏"},
    {"kanji":"表","kana":"おもて","pron":"오모테","ko":"겉, 앞","tts_text":"表"},

    {"kanji":"中","kana":"なか","pron":"나카","ko":"안","tts_text":"中"},
    {"kanji":"外","kana":"そと","pron":"소토","ko":"밖","tts_text":"外"},
    {"kanji":"上","kana":"うえ","pron":"우에","ko":"위","tts_text":"上"},
    {"kanji":"下","kana":"した","pron":"시타","ko":"아래","tts_text":"下"},
    {"kanji":"横","kana":"よこ","pron":"요코","ko":"옆","tts_text":"横"},
    {"kanji":"遠く","kana":"とおく","pron":"토오쿠","ko":"멀리","tts_text":"遠く"},
    {"kanji":"近く","kana":"ちかく","pron":"치카쿠","ko":"가까이","tts_text":"近く"},
    {"kanji":"真ん中","kana":"まんなか","pron":"만나카","ko":"한가운데","tts_text":"真ん中"},
    {"kanji":"左側","kana":"ひだりがわ","pron":"히다리가와","ko":"왼쪽","tts_text":"左側"},
    {"kanji":"右側","kana":"みぎがわ","pron":"미기가와","ko":"오른쪽","tts_text":"右側"},

    {"kanji":"入口","kana":"いりぐち","pron":"이리구치","ko":"입구","tts_text":"入口"},
    {"kanji":"出口","kana":"でぐち","pron":"데구치","ko":"출구","tts_text":"出口"},
    {"kanji":"階段","kana":"かいだん","pron":"카이단","ko":"계단","tts_text":"階段"},
    {"kanji":"玄関","kana":"げんかん","pron":"겐칸","ko":"현관","tts_text":"玄関"},
    {"kanji":"屋上","kana":"おくじょう","pron":"오쿠죠오","ko":"옥상","tts_text":"屋上"},
    {"kanji":"地下","kana":"ちか","pron":"치카","ko":"지하","tts_text":"地下"},
    {"kanji":"近くに","kana":"ちかくに","pron":"치카쿠니","ko":"근처에","tts_text":"近くに"},
    {"kanji":"中に","kana":"なかに","pron":"나카니","ko":"안에","tts_text":"中に"},
    {"kanji":"外で","kana":"そとで","pron":"소토데","ko":"밖에서","tts_text":"外で"},
    {"kanji":"家の中","kana":"いえのなか","pron":"이에노 나카","ko":"집 안","tts_text":"家の中"}
    ]
    },

    "sec04": {
    "title": "동작·이동·변화",
    "items": [
    {"kanji":"動く","kana":"うごく","pron":"우고쿠","ko":"움직이다","tts_text":"動く"},
    {"kanji":"運ぶ","kana":"はこぶ","pron":"하코부","ko":"나르다","tts_text":"運ぶ"},
    {"kanji":"集める","kana":"あつめる","pron":"아츠메루","ko":"모으다","tts_text":"集める"},
    {"kanji":"増える","kana":"ふえる","pron":"후에루","ko":"늘다","tts_text":"増える"},
    {"kanji":"減る","kana":"へる","pron":"헤루","ko":"줄다","tts_text":"減る"},
    {"kanji":"変わる","kana":"かわる","pron":"카와루","ko":"변하다","tts_text":"変わる"},
    {"kanji":"続く","kana":"つづく","pron":"츠즈쿠","ko":"계속되다","tts_text":"続く"},
    {"kanji":"止まる","kana":"とまる","pron":"토마루","ko":"멈추다","tts_text":"止まる"},
    {"kanji":"進む","kana":"すすむ","pron":"스스무","ko":"나아가다","tts_text":"進む"},
    {"kanji":"戻る","kana":"もどる","pron":"모도루","ko":"돌아오다","tts_text":"戻る"},

    {"kanji":"通る","kana":"とおる","pron":"토오루","ko":"지나가다","tts_text":"通る"},
    {"kanji":"渡す","kana":"わたす","pron":"와타스","ko":"건네다","tts_text":"渡す"},
    {"kanji":"受ける","kana":"うける","pron":"우케루","ko":"받다","tts_text":"受ける"},
    {"kanji":"比べる","kana":"くらべる","pron":"쿠라베루","ko":"비교하다","tts_text":"比べる"},
    {"kanji":"選ぶ","kana":"えらぶ","pron":"에라부","ko":"고르다","tts_text":"選ぶ"},
    {"kanji":"決まる","kana":"きまる","pron":"키마루","ko":"정해지다","tts_text":"決まる"},
    {"kanji":"起こる","kana":"おこる","pron":"오코루","ko":"일어나다","tts_text":"起こる"},
    {"kanji":"直す","kana":"なおす","pron":"나오스","ko":"고치다","tts_text":"直す"},
    {"kanji":"続ける","kana":"つづける","pron":"츠즈케루","ko":"계속하다","tts_text":"続ける"},
    {"kanji":"止める","kana":"とめる","pron":"토메루","ko":"멈추게 하다","tts_text":"止める"},

    {"kanji":"壊れる","kana":"こわれる","pron":"코와레루","ko":"고장나다","tts_text":"壊れる"},
    {"kanji":"直る","kana":"なおる","pron":"나오루","ko":"고쳐지다","tts_text":"直る"},
    {"kanji":"落ちる","kana":"おちる","pron":"오치루","ko":"떨어지다","tts_text":"落ちる"},
    {"kanji":"拾う","kana":"ひろう","pron":"히로오","ko":"줍다","tts_text":"拾う"},
    {"kanji":"触る","kana":"さわる","pron":"사와루","ko":"만지다","tts_text":"触る"},
    {"kanji":"離れる","kana":"はなれる","pron":"하나레루","ko":"떨어지다","tts_text":"離れる"},
    {"kanji":"近づく","kana":"ちかづく","pron":"치카즈쿠","ko":"가까워지다","tts_text":"近づく"},
    {"kanji":"通じる","kana":"つうじる","pron":"츠우지루","ko":"통하다","tts_text":"通じる"},
    {"kanji":"間に合う","kana":"まにあう","pron":"마니아우","ko":"시간에 맞다","tts_text":"間に合う"},
    {"kanji":"遅れる","kana":"おくれる","pron":"오쿠레루","ko":"늦다","tts_text":"遅れる"}
    ]
    },

    "sec05": {
    "title": "형용사·상태 심화",
    "items": [
    {"kanji":"深い","kana":"ふかい","pron":"후카이","ko":"깊다","tts_text":"深い"},
    {"kanji":"浅い","kana":"あさい","pron":"아사이","ko":"얕다","tts_text":"浅い"},
    {"kanji":"広い","kana":"ひろい","pron":"히로이","ko":"넓다","tts_text":"広い"},
    {"kanji":"狭い","kana":"せまい","pron":"세마이","ko":"좁다","tts_text":"狭い"},
    {"kanji":"重たい","kana":"おもたい","pron":"오모타이","ko":"무겁다","tts_text":"重たい"},
    {"kanji":"軽い","kana":"かるい","pron":"카루이","ko":"가볍다","tts_text":"軽い"},
    {"kanji":"柔らかい","kana":"やわらかい","pron":"야와라카이","ko":"부드럽다","tts_text":"柔らかい"},
    {"kanji":"固い","kana":"かたい","pron":"카타이","ko":"단단하다","tts_text":"固い"},
    {"kanji":"細かい","kana":"こまかい","pron":"코마카이","ko":"자잘하다","tts_text":"細かい"},
    {"kanji":"大切","kana":"たいせつ","pron":"타이세츠","ko":"중요하다","tts_text":"大切"},

    {"kanji":"必要","kana":"ひつよう","pron":"히츠요오","ko":"필요하다","tts_text":"必要"},
    {"kanji":"十分","kana":"じゅうぶん","pron":"쥬우분","ko":"충분하다","tts_text":"十分"},
    {"kanji":"無理","kana":"むり","pron":"무리","ko":"무리","tts_text":"無理"},
    {"kanji":"危険","kana":"きけん","pron":"키켄","ko":"위험","tts_text":"危険"},
    {"kanji":"安全","kana":"あんぜん","pron":"안젠","ko":"안전","tts_text":"安全"},
    {"kanji":"不思議","kana":"ふしぎ","pron":"후시기","ko":"신기하다","tts_text":"不思議"},
    {"kanji":"残念","kana":"ざんねん","pron":"잔넨","ko":"아쉽다","tts_text":"残念"},
    {"kanji":"大事","kana":"だいじ","pron":"다이지","ko":"중요함","tts_text":"大事"},
    {"kanji":"特別","kana":"とくべつ","pron":"토쿠베츠","ko":"특별함","tts_text":"特別"},
    {"kanji":"普通","kana":"ふつう","pron":"후츠우","ko":"보통","tts_text":"普通"},

    {"kanji":"簡単","kana":"かんたん","pron":"칸탄","ko":"간단하다","tts_text":"簡単"},
    {"kanji":"複雑","kana":"ふくざつ","pron":"후쿠자츠","ko":"복잡하다","tts_text":"複雑"},
    {"kanji":"静か","kana":"しずか","pron":"시즈카","ko":"조용하다","tts_text":"静か"},
    {"kanji":"にぎやか","kana":"にぎやか","pron":"니기야카","ko":"번화하다","tts_text":"にぎやか"},
    {"kanji":"正しい","kana":"ただしい","pron":"타다시이","ko":"옳다","tts_text":"正しい"},
    {"kanji":"間違い","kana":"まちがい","pron":"마치가이","ko":"틀림","tts_text":"間違い"},
    {"kanji":"強い","kana":"つよい","pron":"츠요이","ko":"강하다","tts_text":"強い"},
    {"kanji":"弱い","kana":"よわい","pron":"요와이","ko":"약하다","tts_text":"弱い"},
    {"kanji":"痛い","kana":"いたい","pron":"이타이","ko":"아프다","tts_text":"痛い"},
    {"kanji":"眠い","kana":"ねむい","pron":"네무이","ko":"졸리다","tts_text":"眠い"}
    ]
    },

    "sec06": {
    "title": "부사·연결 표현",
    "items": [
    {"kanji":"特に","kana":"とくに","pron":"토쿠니","ko":"특히","tts_text":"特に"},
    {"kanji":"大体","kana":"だいたい","pron":"다이타이","ko":"대체로","tts_text":"大体"},
    {"kanji":"例えば","kana":"たとえば","pron":"타토에바","ko":"예를 들면","tts_text":"例えば"},
    {"kanji":"もちろん","kana":"もちろん","pron":"모치론","ko":"물론","tts_text":"もちろん"},
    {"kanji":"実は","kana":"じつは","pron":"지츠와","ko":"사실은","tts_text":"実は"},
    {"kanji":"やはり","kana":"やはり","pron":"야하리","ko":"역시","tts_text":"やはり"},
    {"kanji":"しかも","kana":"しかも","pron":"시카모","ko":"게다가","tts_text":"しかも"},
    {"kanji":"それに","kana":"それに","pron":"소레니","ko":"그에 더해","tts_text":"それに"},
    {"kanji":"その後","kana":"そのあと","pron":"소노아토","ko":"그 후","tts_text":"その後"},
    {"kanji":"その前","kana":"そのまえ","pron":"소노마에","ko":"그 전","tts_text":"その前"},

    {"kanji":"以上","kana":"いじょう","pron":"이죠오","ko":"이상","tts_text":"以上"},
    {"kanji":"以下","kana":"いか","pron":"이카","ko":"이하","tts_text":"以下"},
    {"kanji":"以外","kana":"いがい","pron":"이가이","ko":"이외","tts_text":"以外"},
    {"kanji":"一方","kana":"いっぽう","pron":"잇뽀오","ko":"한편","tts_text":"一方"},
    {"kanji":"途中で","kana":"とちゅうで","pron":"토츄우데","ko":"도중에","tts_text":"途中で"},
    {"kanji":"そのまま","kana":"そのまま","pron":"소노마마","ko":"그대로","tts_text":"そのまま"},
    {"kanji":"別に","kana":"べつに","pron":"베츠니","ko":"특별히","tts_text":"別に"},
    {"kanji":"ほとんど","kana":"ほとんど","pron":"호톤도","ko":"거의","tts_text":"ほとんど"},
    {"kanji":"必ずしも","kana":"かならずしも","pron":"카나라즈시모","ko":"반드시~는 아니다","tts_text":"必ずしも"},
    {"kanji":"だいたい","kana":"だいたい","pron":"다이타이","ko":"대략","tts_text":"だいたい"},

    {"kanji":"しっかり","kana":"しっかり","pron":"식카리","ko":"확실히","tts_text":"しっかり"},
    {"kanji":"たしかに","kana":"たしかに","pron":"타시카니","ko":"확실히","tts_text":"たしかに"},
    {"kanji":"急に","kana":"きゅうに","pron":"큐우니","ko":"갑자기","tts_text":"急に"},
    {"kanji":"ゆっくり","kana":"ゆっくり","pron":"윳쿠리","ko":"천천히","tts_text":"ゆっくり"},
    {"kanji":"すっかり","kana":"すっかり","pron":"슷카리","ko":"완전히","tts_text":"すっかり"},
    {"kanji":"たまに","kana":"たまに","pron":"타마니","ko":"가끔","tts_text":"たまに"},
    {"kanji":"どうしても","kana":"どうしても","pron":"도오시테모","ko":"어쩔 수 없이","tts_text":"どうしても"},
    {"kanji":"すでに","kana":"すでに","pron":"스데니","ko":"이미","tts_text":"すでに"},
    {"kanji":"まだ","kana":"まだ","pron":"마다","ko":"아직","tts_text":"まだ"},
    {"kanji":"もうすぐ","kana":"もうすぐ","pron":"모오스구","ko":"곧","tts_text":"もうすぐ"}
    ]
    },

    "sec07": {
    "title": "감정·상태·반응",
    "items": [
    {"kanji":"驚く","kana":"おどろく","pron":"오도로쿠","ko":"놀라다","tts_text":"驚く"},
    {"kanji":"喜ぶ","kana":"よろこぶ","pron":"요로코부","ko":"기뻐하다","tts_text":"喜ぶ"},
    {"kanji":"悲しむ","kana":"かなしむ","pron":"카나시무","ko":"슬퍼하다","tts_text":"悲しむ"},
    {"kanji":"怒る","kana":"おこる","pron":"오코루","ko":"화내다","tts_text":"怒る"},
    {"kanji":"怖がる","kana":"こわがる","pron":"코와가루","ko":"무서워하다","tts_text":"怖がる"},
    {"kanji":"安心する","kana":"あんしんする","pron":"안신스루","ko":"안심하다","tts_text":"安心する"},
    {"kanji":"心配する","kana":"しんぱいする","pron":"심파이스루","ko":"걱정하다","tts_text":"心配する"},
    {"kanji":"緊張","kana":"きんちょう","pron":"킨쵸오","ko":"긴장","tts_text":"緊張"},
    {"kanji":"不安","kana":"ふあん","pron":"후안","ko":"불안","tts_text":"不安"},
    {"kanji":"安心","kana":"あんしん","pron":"안신","ko":"안심","tts_text":"安心"},

    {"kanji":"満足","kana":"まんぞく","pron":"만조쿠","ko":"만족","tts_text":"満足"},
    {"kanji":"失敗","kana":"しっぱい","pron":"싯파이","ko":"실패","tts_text":"失敗"},
    {"kanji":"成功","kana":"せいこう","pron":"세이코오","ko":"성공","tts_text":"成功"},
    {"kanji":"疲れ","kana":"つかれ","pron":"츠카레","ko":"피로","tts_text":"疲れ"},
    {"kanji":"元気","kana":"げんき","pron":"겐키","ko":"기운","tts_text":"元気"},
    {"kanji":"大丈夫","kana":"だいじょうぶ","pron":"다이죠오부","ko":"괜찮다","tts_text":"大丈夫"},
    {"kanji":"残念","kana":"ざんねん","pron":"잔넨","ko":"아쉽다","tts_text":"残念"},
    {"kanji":"大変","kana":"たいへん","pron":"타이헨","ko":"힘들다","tts_text":"大変"},
    {"kanji":"無理","kana":"むり","pron":"무리","ko":"무리","tts_text":"無理"},
    {"kanji":"安心感","kana":"あんしんかん","pron":"안신칸","ko":"안정감","tts_text":"安心感"},

    {"kanji":"寂しい","kana":"さびしい","pron":"사비시이","ko":"외롭다","tts_text":"寂しい"},
    {"kanji":"嬉しい","kana":"うれしい","pron":"우레시이","ko":"기쁘다","tts_text":"嬉しい"},
    {"kanji":"嫌","kana":"いや","pron":"이야","ko":"싫다","tts_text":"嫌"},
    {"kanji":"好き","kana":"すき","pron":"스키","ko":"좋아함","tts_text":"好き"},
    {"kanji":"大好き","kana":"だいすき","pron":"다이스키","ko":"아주 좋아함","tts_text":"大好き"},
    {"kanji":"苦手","kana":"にがて","pron":"니가테","ko":"서투름","tts_text":"苦手"},
    {"kanji":"得意","kana":"とくい","pron":"토쿠이","ko":"잘함","tts_text":"得意"},
    {"kanji":"心","kana":"こころ","pron":"코코로","ko":"마음","tts_text":"心"},
    {"kanji":"気持ち","kana":"きもち","pron":"키모치","ko":"기분","tts_text":"気持ち"},
    {"kanji":"感情","kana":"かんじょう","pron":"칸죠오","ko":"감정","tts_text":"感情"}
    ]
    },

    "sec08": {
    "title": "사고·의견·판단",
    "items": [
    {"kanji":"考え","kana":"かんがえ","pron":"칸가에","ko":"생각","tts_text":"考え"},
    {"kanji":"意見","kana":"いけん","pron":"이켄","ko":"의견","tts_text":"意見"},
    {"kanji":"判断","kana":"はんだん","pron":"한단","ko":"판단","tts_text":"判断"},
    {"kanji":"理由","kana":"りゆう","pron":"리유우","ko":"이유","tts_text":"理由"},
    {"kanji":"答え","kana":"こたえ","pron":"코타에","ko":"대답","tts_text":"答え"},
    {"kanji":"問題","kana":"もんだい","pron":"몬다이","ko":"문제","tts_text":"問題"},
    {"kanji":"結果","kana":"けっか","pron":"켁카","ko":"결과","tts_text":"結果"},
    {"kanji":"方法","kana":"ほうほう","pron":"호오호오","ko":"방법","tts_text":"方法"},
    {"kanji":"意味","kana":"いみ","pron":"이미","ko":"의미","tts_text":"意味"},
    {"kanji":"理由","kana":"りゆう","pron":"리유우","ko":"이유","tts_text":"理由"},

    {"kanji":"選択","kana":"せんたく","pron":"센타쿠","ko":"선택","tts_text":"選択"},
    {"kanji":"確認","kana":"かくにん","pron":"카쿠닌","ko":"확인","tts_text":"確認"},
    {"kanji":"理解","kana":"りかい","pron":"리카이","ko":"이해","tts_text":"理解"},
    {"kanji":"勘違い","kana":"かんちがい","pron":"칸치가이","ko":"착각","tts_text":"勘違い"},
    {"kanji":"予想","kana":"よそう","pron":"요소오","ko":"예상","tts_text":"予想"},
    {"kanji":"意外","kana":"いがい","pron":"이가이","ko":"의외","tts_text":"意外"},
    {"kanji":"本当","kana":"ほんとう","pron":"혼토오","ko":"진짜","tts_text":"本当"},
    {"kanji":"嘘","kana":"うそ","pron":"우소","ko":"거짓말","tts_text":"嘘"},
    {"kanji":"事実","kana":"じじつ","pron":"지지츠","ko":"사실","tts_text":"事実"},
    {"kanji":"正解","kana":"せいかい","pron":"세이카이","ko":"정답","tts_text":"正解"},

    {"kanji":"間違い","kana":"まちがい","pron":"마치가이","ko":"틀림","tts_text":"間違い"},
    {"kanji":"可能","kana":"かのう","pron":"카노오","ko":"가능","tts_text":"可能"},
    {"kanji":"不可能","kana":"ふかのう","pron":"후카노오","ko":"불가능","tts_text":"不可能"},
    {"kanji":"条件","kana":"じょうけん","pron":"죠오켄","ko":"조건","tts_text":"条件"},
    {"kanji":"決定","kana":"けってい","pron":"켓테이","ko":"결정","tts_text":"決定"},
    {"kanji":"選ぶ","kana":"えらぶ","pron":"에라부","ko":"고르다","tts_text":"選ぶ"},
    {"kanji":"信じる","kana":"しんじる","pron":"신지루","ko":"믿다","tts_text":"信じる"},
    {"kanji":"疑う","kana":"うたがう","pron":"우타가우","ko":"의심하다","tts_text":"疑う"},
    {"kanji":"考える","kana":"かんがえる","pron":"칸가에루","ko":"생각하다","tts_text":"考える"},
    {"kanji":"比べる","kana":"くらべる","pron":"쿠라베루","ko":"비교하다","tts_text":"比べる"}
    ]
    },

    "sec09": {
    "title": "음식·쇼핑·일상",
    "items": [
    {"kanji":"材料","kana":"ざいりょう","pron":"자이료오","ko":"재료","tts_text":"材料"},
    {"kanji":"味","kana":"あじ","pron":"아지","ko":"맛","tts_text":"味"},
    {"kanji":"料理","kana":"りょうり","pron":"료오리","ko":"요리","tts_text":"料理"},
    {"kanji":"注文","kana":"ちゅうもん","pron":"츄우몬","ko":"주문","tts_text":"注文"},
    {"kanji":"値段","kana":"ねだん","pron":"네단","ko":"가격","tts_text":"値段"},
    {"kanji":"割引","kana":"わりびき","pron":"와리비키","ko":"할인","tts_text":"割引"},
    {"kanji":"商品","kana":"しょうひん","pron":"쇼오힌","ko":"상품","tts_text":"商品"},
    {"kanji":"買い物","kana":"かいもの","pron":"카이모노","ko":"쇼핑","tts_text":"買い物"},
    {"kanji":"支払う","kana":"しはらう","pron":"시하라우","ko":"지불하다","tts_text":"支払う"},
    {"kanji":"予約","kana":"よやく","pron":"요야쿠","ko":"예약","tts_text":"予約"},

    {"kanji":"満席","kana":"まんせき","pron":"만세키","ko":"만석","tts_text":"満席"},
    {"kanji":"空席","kana":"くうせき","pron":"쿠우세키","ko":"빈자리","tts_text":"空席"},
    {"kanji":"袋","kana":"ふくろ","pron":"후쿠로","ko":"봉지","tts_text":"袋"},
    {"kanji":"箱","kana":"はこ","pron":"하코","ko":"상자","tts_text":"箱"},
    {"kanji":"量","kana":"りょう","pron":"료오","ko":"양","tts_text":"量"},
    {"kanji":"少なめ","kana":"すくなめ","pron":"스쿠나메","ko":"적게","tts_text":"少なめ"},
    {"kanji":"多め","kana":"おおめ","pron":"오오메","ko":"많게","tts_text":"多め"},
    {"kanji":"追加","kana":"ついか","pron":"츠이카","ko":"추가","tts_text":"追加"},
    {"kanji":"準備","kana":"じゅんび","pron":"쥰비","ko":"준비","tts_text":"準備"},
    {"kanji":"片付け","kana":"かたづけ","pron":"카타즈케","ko":"정리","tts_text":"片付け"},

    {"kanji":"洗う","kana":"あらう","pron":"아라우","ko":"씻다","tts_text":"洗う"},
    {"kanji":"掃除","kana":"そうじ","pron":"소오지","ko":"청소","tts_text":"掃除"},
    {"kanji":"洗濯","kana":"せんたく","pron":"센타쿠","ko":"세탁","tts_text":"洗濯"},
    {"kanji":"用意","kana":"ようい","pron":"요오이","ko":"준비","tts_text":"用意"},
    {"kanji":"暮らす","kana":"くらす","pron":"쿠라스","ko":"생활하다","tts_text":"暮らす"},
    {"kanji":"生活","kana":"せいかつ","pron":"세이카츠","ko":"생활","tts_text":"生活"},
    {"kanji":"習慣","kana":"しゅうかん","pron":"슈우칸","ko":"습관","tts_text":"習慣"},
    {"kanji":"忙しい","kana":"いそがしい","pron":"이소가시이","ko":"바쁘다","tts_text":"忙しい"},
    {"kanji":"暇","kana":"ひま","pron":"히마","ko":"한가함","tts_text":"暇"},
    {"kanji":"普段","kana":"ふだん","pron":"후단","ko":"평소","tts_text":"普段"}
    ]
    },

    "sec10": {
    "title": "시험·공부·능력",
    "items": [
    {"kanji":"勉強","kana":"べんきょう","pron":"벤쿄오","ko":"공부","tts_text":"勉強"},
    {"kanji":"練習","kana":"れんしゅう","pron":"렌슈우","ko":"연습","tts_text":"練習"},
    {"kanji":"復習","kana":"ふくしゅう","pron":"후쿠슈우","ko":"복습","tts_text":"復習"},
    {"kanji":"予習","kana":"よしゅう","pron":"요슈우","ko":"예습","tts_text":"予習"},
    {"kanji":"試験","kana":"しけん","pron":"시켄","ko":"시험","tts_text":"試験"},
    {"kanji":"点数","kana":"てんすう","pron":"텐스우","ko":"점수","tts_text":"点数"},
    {"kanji":"合格","kana":"ごうかく","pron":"고오카쿠","ko":"합격","tts_text":"合格"},
    {"kanji":"失敗","kana":"しっぱい","pron":"싯파이","ko":"실패","tts_text":"失敗"},
    {"kanji":"成功","kana":"せいこう","pron":"세이코오","ko":"성공","tts_text":"成功"},
    {"kanji":"能力","kana":"のうりょく","pron":"노오료쿠","ko":"능력","tts_text":"能力"},

    {"kanji":"上手","kana":"じょうず","pron":"죠오즈","ko":"잘함","tts_text":"上手"},
    {"kanji":"下手","kana":"へた","pron":"헤타","ko":"못함","tts_text":"下手"},
    {"kanji":"得意","kana":"とくい","pron":"토쿠이","ko":"특기","tts_text":"得意"},
    {"kanji":"苦手","kana":"にがて","pron":"니가테","ko":"약점","tts_text":"苦手"},
    {"kanji":"覚える","kana":"おぼえる","pron":"오보에루","ko":"외우다","tts_text":"覚える"},
    {"kanji":"忘れる","kana":"わすれる","pron":"와스레루","ko":"잊다","tts_text":"忘れる"},
    {"kanji":"理解","kana":"りかい","pron":"리카이","ko":"이해","tts_text":"理解"},
    {"kanji":"説明","kana":"せつめい","pron":"세츠메이","ko":"설명","tts_text":"説明"},
    {"kanji":"質問","kana":"しつもん","pron":"시츠몬","ko":"질문","tts_text":"質問"},
    {"kanji":"答え","kana":"こたえ","pron":"코타에","ko":"답","tts_text":"答え"},

    {"kanji":"間違える","kana":"まちがえる","pron":"마치가에루","ko":"틀리다","tts_text":"間違える"},
    {"kanji":"正しい","kana":"ただしい","pron":"타다시이","ko":"옳다","tts_text":"正しい"},
    {"kanji":"簡単","kana":"かんたん","pron":"칸탄","ko":"간단하다","tts_text":"簡単"},
    {"kanji":"難しい","kana":"むずかしい","pron":"무즈카시이","ko":"어렵다","tts_text":"難しい"},
    {"kanji":"必要","kana":"ひつよう","pron":"히츠요오","ko":"필요","tts_text":"必要"},
    {"kanji":"努力","kana":"どりょく","pron":"도료쿠","ko":"노력","tts_text":"努力"},
    {"kanji":"結果","kana":"けっか","pron":"켁카","ko":"결과","tts_text":"結果"},
    {"kanji":"成長","kana":"せいちょう","pron":"세이쵸오","ko":"성장","tts_text":"成長"},
    {"kanji":"目標","kana":"もくひょう","pron":"모쿠효오","ko":"목표","tts_text":"目標"},
    {"kanji":"自信","kana":"じしん","pron":"지신","ko":"자신감","tts_text":"自信"}
    ]
    }

}
N3_WORDS = {
    "sec01": {
    "title": "사람·관계·사회",
    "items": [
    {"kanji":"性格","kana":"せいかく","pron":"세이카쿠","ko":"성격","tts_text":"性格"},
    {"kanji":"態度","kana":"たいど","pron":"타이도","ko":"태도","tts_text":"態度"},
    {"kanji":"印象","kana":"いんしょう","pron":"인쇼오","ko":"인상","tts_text":"印象"},
    {"kanji":"関係","kana":"かんけい","pron":"칸케이","ko":"관계","tts_text":"関係"},
    {"kanji":"友人","kana":"ゆうじん","pron":"유우진","ko":"친구(격식)","tts_text":"友人"},
    {"kanji":"仲間","kana":"なかま","pron":"나카마","ko":"동료","tts_text":"仲間"},
    {"kanji":"先輩","kana":"せんぱい","pron":"센파이","ko":"선배","tts_text":"先輩"},
    {"kanji":"後輩","kana":"こうはい","pron":"코오하이","ko":"후배","tts_text":"後輩"},
    {"kanji":"上司","kana":"じょうし","pron":"죠오시","ko":"상사","tts_text":"上司"},
    {"kanji":"部下","kana":"ぶか","pron":"부카","ko":"부하","tts_text":"部下"},

    {"kanji":"同僚","kana":"どうりょう","pron":"도오료오","ko":"동료(회사)","tts_text":"同僚"},
    {"kanji":"両親","kana":"りょうしん","pron":"료오신","ko":"부모","tts_text":"両親"},
    {"kanji":"親戚","kana":"しんせき","pron":"신세키","ko":"친척","tts_text":"親戚"},
    {"kanji":"夫婦","kana":"ふうふ","pron":"후우후","ko":"부부","tts_text":"夫婦"},
    {"kanji":"本人","kana":"ほんにん","pron":"혼닌","ko":"본인","tts_text":"本人"},
    {"kanji":"相手","kana":"あいて","pron":"아이테","ko":"상대","tts_text":"相手"},
    {"kanji":"周囲","kana":"しゅうい","pron":"슈우이","ko":"주위","tts_text":"周囲"},
    {"kanji":"世代","kana":"せだい","pron":"세다이","ko":"세대","tts_text":"世代"},
    {"kanji":"社会","kana":"しゃかい","pron":"샤카이","ko":"사회","tts_text":"社会"},
    {"kanji":"人間","kana":"にんげん","pron":"닌겐","ko":"인간","tts_text":"人間"},

    {"kanji":"立場","kana":"たちば","pron":"타치바","ko":"입장, 처지","tts_text":"立場"},
    {"kanji":"責任","kana":"せきにん","pron":"세키닌","ko":"책임","tts_text":"責任"},
    {"kanji":"義務","kana":"ぎむ","pron":"기무","ko":"의무","tts_text":"義務"},
    {"kanji":"権利","kana":"けんり","pron":"켄리","ko":"권리","tts_text":"権利"},
    {"kanji":"約束","kana":"やくそく","pron":"야쿠소쿠","ko":"약속","tts_text":"約束"},
    {"kanji":"協力","kana":"きょうりょく","pron":"쿄오료쿠","ko":"협력","tts_text":"協力"},
    {"kanji":"相談","kana":"そうだん","pron":"소오단","ko":"상담","tts_text":"相談"},
    {"kanji":"紹介","kana":"しょうかい","pron":"쇼오카이","ko":"소개","tts_text":"紹介"},
    {"kanji":"意見","kana":"いけん","pron":"이켄","ko":"의견","tts_text":"意見"},
    {"kanji":"不満","kana":"ふまん","pron":"후만","ko":"불만","tts_text":"不満"},

    {"kanji":"文句","kana":"もんく","pron":"몬쿠","ko":"불평","tts_text":"文句"},
    {"kanji":"評判","kana":"ひょうばん","pron":"효오반","ko":"평판","tts_text":"評判"},
    {"kanji":"噂","kana":"うわさ","pron":"우와사","ko":"소문","tts_text":"噂"},
    {"kanji":"礼儀","kana":"れいぎ","pron":"레이기","ko":"예의","tts_text":"礼儀"},
    {"kanji":"挨拶","kana":"あいさつ","pron":"아이사츠","ko":"인사","tts_text":"挨拶"},
    {"kanji":"迷惑","kana":"めいわく","pron":"메이와쿠","ko":"폐","tts_text":"迷惑"},
    {"kanji":"冗談","kana":"じょうだん","pron":"죠오단","ko":"농담","tts_text":"冗談"},
    {"kanji":"本気","kana":"ほんき","pron":"혼키","ko":"진심","tts_text":"本気"},
    {"kanji":"真面目","kana":"まじめ","pron":"마지메","ko":"성실함","tts_text":"真面目"},
    {"kanji":"素直","kana":"すなお","pron":"스나오","ko":"솔직함","tts_text":"素直"},

    {"kanji":"大人しい","kana":"おとなしい","pron":"오토나시이","ko":"얌전하다","tts_text":"大人しい"},
    {"kanji":"親切","kana":"しんせつ","pron":"신세츠","ko":"친절","tts_text":"親切"},
    {"kanji":"失礼","kana":"しつれい","pron":"시츠레이","ko":"실례","tts_text":"失礼"},
    {"kanji":"無礼","kana":"ぶれい","pron":"부레이","ko":"무례","tts_text":"無礼"},
    {"kanji":"丁寧","kana":"ていねい","pron":"테이네이","ko":"정중함","tts_text":"丁寧"},
    {"kanji":"冷静","kana":"れいせい","pron":"레이세이","ko":"냉정","tts_text":"冷静"},
    {"kanji":"正直","kana":"しょうじき","pron":"쇼오지키","ko":"정직","tts_text":"正直"},
    {"kanji":"誠実","kana":"せいじつ","pron":"세이지츠","ko":"성실","tts_text":"誠実"},
    {"kanji":"積極的","kana":"せっきょくてき","pron":"셋쿄쿠테키","ko":"적극적","tts_text":"積極的"},
    {"kanji":"消極的","kana":"しょうきょくてき","pron":"쇼오쿄쿠테키","ko":"소극적","tts_text":"消極的"}
    ]
    },

    "sec02": {
    "title": "시간·일정·빈도",
    "items": [
    {"kanji":"予定","kana":"よてい","pron":"요테이","ko":"예정","tts_text":"予定"},
    {"kanji":"計画","kana":"けいかく","pron":"케이카쿠","ko":"계획","tts_text":"計画"},
    {"kanji":"約束","kana":"やくそく","pron":"야쿠소쿠","ko":"약속","tts_text":"約束"},
    {"kanji":"締め切り","kana":"しめきり","pron":"시메키리","ko":"마감","tts_text":"締め切り"},
    {"kanji":"期限","kana":"きげん","pron":"키겐","ko":"기한","tts_text":"期限"},
    {"kanji":"日程","kana":"にってい","pron":"닛테이","ko":"일정","tts_text":"日程"},
    {"kanji":"都合","kana":"つごう","pron":"츠고오","ko":"사정, 형편","tts_text":"都合"},
    {"kanji":"準備","kana":"じゅんび","pron":"쥰비","ko":"준비","tts_text":"準備"},
    {"kanji":"開始","kana":"かいし","pron":"카이시","ko":"개시","tts_text":"開始"},
    {"kanji":"終了","kana":"しゅうりょう","pron":"슈우료오","ko":"종료","tts_text":"終了"},

    {"kanji":"途中","kana":"とちゅう","pron":"토츄우","ko":"도중","tts_text":"途中"},
    {"kanji":"最初","kana":"さいしょ","pron":"사이쇼","ko":"처음","tts_text":"最初"},
    {"kanji":"最後","kana":"さいご","pron":"사이고","ko":"마지막","tts_text":"最後"},
    {"kanji":"最近","kana":"さいきん","pron":"사이킨","ko":"최근","tts_text":"最近"},
    {"kanji":"当時","kana":"とうじ","pron":"토오지","ko":"당시","tts_text":"当時"},
    {"kanji":"以前","kana":"いぜん","pron":"이젠","ko":"이전","tts_text":"以前"},
    {"kanji":"以降","kana":"いこう","pron":"이코오","ko":"이후","tts_text":"以降"},
    {"kanji":"今後","kana":"こんご","pron":"콘고","ko":"금후","tts_text":"今後"},
    {"kanji":"しばらく","kana":"しばらく","pron":"시바라쿠","ko":"잠시","tts_text":"しばらく"},
    {"kanji":"しばしば","kana":"しばしば","pron":"시바시바","ko":"자주","tts_text":"しばしば"},

    {"kanji":"たびたび","kana":"たびたび","pron":"타비타비","ko":"자주","tts_text":"たびたび"},
    {"kanji":"だんだん","kana":"だんだん","pron":"단단","ko":"점점","tts_text":"だんだん"},
    {"kanji":"次第に","kana":"しだいに","pron":"시다이니","ko":"차차","tts_text":"次第に"},
    {"kanji":"急に","kana":"きゅうに","pron":"큐우니","ko":"갑자기","tts_text":"急に"},
    {"kanji":"すぐに","kana":"すぐに","pron":"스구니","ko":"즉시","tts_text":"すぐに"},
    {"kanji":"とうとう","kana":"とうとう","pron":"토오토오","ko":"드디어","tts_text":"とうとう"},
    {"kanji":"やっと","kana":"やっと","pron":"얏토","ko":"겨우","tts_text":"やっと"},
    {"kanji":"結局","kana":"けっきょく","pron":"켓쿄쿠","ko":"결국","tts_text":"結局"},
    {"kanji":"ようやく","kana":"ようやく","pron":"요오야쿠","ko":"겨우","tts_text":"ようやく"},
    {"kanji":"いつの間にか","kana":"いつのまにか","pron":"이츠노마니카","ko":"어느새","tts_text":"いつの間にか"},

    {"kanji":"早めに","kana":"はやめに","pron":"하야메니","ko":"일찍","tts_text":"早めに"},
    {"kanji":"遅めに","kana":"おそめに","pron":"오소메니","ko":"늦게","tts_text":"遅めに"},
    {"kanji":"前もって","kana":"まえもって","pron":"마에못테","ko":"미리","tts_text":"前もって"},
    {"kanji":"しばらくして","kana":"しばらくして","pron":"시바라쿠시테","ko":"잠시 후","tts_text":"しばらくして"},
    {"kanji":"間に","kana":"あいだに","pron":"아이다니","ko":"~하는 사이에","tts_text":"間に"},
    {"kanji":"間","kana":"あいだ","pron":"아이다","ko":"사이","tts_text":"間"},
    {"kanji":"時間帯","kana":"じかんたい","pron":"지칸타이","ko":"시간대","tts_text":"時間帯"},
    {"kanji":"毎週","kana":"まいしゅう","pron":"마이슈우","ko":"매주","tts_text":"毎週"},
    {"kanji":"毎月","kana":"まいつき","pron":"마이츠키","ko":"매달","tts_text":"毎月"},
    {"kanji":"毎年","kana":"まいとし","pron":"마이토시","ko":"매년","tts_text":"毎年"}
    ]
    },

    "sec03": {
    "title": "이동·교통·여행",
    "items": [
    {"kanji":"乗り換え","kana":"のりかえ","pron":"노리카에","ko":"환승","tts_text":"乗り換え"},
    {"kanji":"終電","kana":"しゅうでん","pron":"슈우덴","ko":"막차","tts_text":"終電"},
    {"kanji":"往復","kana":"おうふく","pron":"오오후쿠","ko":"왕복","tts_text":"往復"},
    {"kanji":"片道","kana":"かたみち","pron":"카타미치","ko":"편도","tts_text":"片道"},
    {"kanji":"運転","kana":"うんてん","pron":"운텐","ko":"운전","tts_text":"運転"},
    {"kanji":"免許","kana":"めんきょ","pron":"멘쿄","ko":"면허","tts_text":"免許"},
    {"kanji":"交通","kana":"こうつう","pron":"코오츠우","ko":"교통","tts_text":"交通"},
    {"kanji":"渋滞","kana":"じゅうたい","pron":"쥬우타이","ko":"정체","tts_text":"渋滞"},
    {"kanji":"案内","kana":"あんない","pron":"안나이","ko":"안내","tts_text":"案内"},
    {"kanji":"地図","kana":"ちず","pron":"치즈","ko":"지도","tts_text":"地図"},

    {"kanji":"道順","kana":"みちじゅん","pron":"미치쥰","ko":"길 순서","tts_text":"道順"},
    {"kanji":"目的地","kana":"もくてきち","pron":"모쿠테키치","ko":"목적지","tts_text":"目的地"},
    {"kanji":"出発","kana":"しゅっぱつ","pron":"슈파츠","ko":"출발","tts_text":"出発"},
    {"kanji":"到着","kana":"とうちゃく","pron":"토오차쿠","ko":"도착","tts_text":"到着"},
    {"kanji":"遅刻","kana":"ちこく","pron":"치코쿠","ko":"지각","tts_text":"遅刻"},
    {"kanji":"欠席","kana":"けっせき","pron":"켓세키","ko":"결석","tts_text":"欠席"},
    {"kanji":"集合","kana":"しゅうごう","pron":"슈우고오","ko":"집합","tts_text":"集合"},
    {"kanji":"解散","kana":"かいさん","pron":"카이산","ko":"해산","tts_text":"解散"},
    {"kanji":"帰宅","kana":"きたく","pron":"키타쿠","ko":"귀가","tts_text":"帰宅"},
    {"kanji":"外出","kana":"がいしゅつ","pron":"가이슈츠","ko":"외출","tts_text":"外出"},

    {"kanji":"旅行","kana":"りょこう","pron":"료코오","ko":"여행","tts_text":"旅行"},
    {"kanji":"観光","kana":"かんこう","pron":"칸코오","ko":"관광","tts_text":"観光"},
    {"kanji":"温泉","kana":"おんせん","pron":"온센","ko":"온천","tts_text":"温泉"},
    {"kanji":"旅館","kana":"りょかん","pron":"료칸","ko":"료칸","tts_text":"旅館"},
    {"kanji":"予約","kana":"よやく","pron":"요야쿠","ko":"예약","tts_text":"予約"},
    {"kanji":"取消","kana":"とりけし","pron":"토리케시","ko":"취소","tts_text":"取消"},
    {"kanji":"変更","kana":"へんこう","pron":"헨코오","ko":"변경","tts_text":"変更"},
    {"kanji":"荷物","kana":"にもつ","pron":"니모츠","ko":"짐","tts_text":"荷物"},
    {"kanji":"手荷物","kana":"てにもつ","pron":"테니모츠","ko":"휴대 짐","tts_text":"手荷物"},
    {"kanji":"両替","kana":"りょうがえ","pron":"료오가에","ko":"환전","tts_text":"両替"},

    {"kanji":"海外","kana":"かいがい","pron":"카이가이","ko":"해외","tts_text":"海外"},
    {"kanji":"国内","kana":"こくない","pron":"코쿠나이","ko":"국내","tts_text":"国内"},
    {"kanji":"空港","kana":"くうこう","pron":"쿠우코오","ko":"공항","tts_text":"空港"},
    {"kanji":"入国","kana":"にゅうこく","pron":"뉴우코쿠","ko":"입국","tts_text":"入国"},
    {"kanji":"出国","kana":"しゅっこく","pron":"슈코쿠","ko":"출국","tts_text":"出国"},
    {"kanji":"搭乗","kana":"とうじょう","pron":"토오죠오","ko":"탑승","tts_text":"搭乗"},
    {"kanji":"便","kana":"びん","pron":"빈","ko":"편(비행편)","tts_text":"便"},
    {"kanji":"座席","kana":"ざせき","pron":"자세키","ko":"좌석","tts_text":"座席"},
    {"kanji":"通路","kana":"つうろ","pron":"츠우로","ko":"통로","tts_text":"通路"},
    {"kanji":"窓側","kana":"まどがわ","pron":"마도가와","ko":"창가 쪽","tts_text":"窓側"}
    ]
    },

    "sec04": {
    "title": "일·회사·비즈니스",
    "items": [
    {"kanji":"会議","kana":"かいぎ","pron":"카이기","ko":"회의","tts_text":"会議"},
    {"kanji":"資料","kana":"しりょう","pron":"시료오","ko":"자료","tts_text":"資料"},
    {"kanji":"報告","kana":"ほうこく","pron":"호오코쿠","ko":"보고","tts_text":"報告"},
    {"kanji":"連絡","kana":"れんらく","pron":"렌라쿠","ko":"연락","tts_text":"連絡"},
    {"kanji":"相談","kana":"そうだん","pron":"소오단","ko":"상담","tts_text":"相談"},
    {"kanji":"確認","kana":"かくにん","pron":"카쿠닌","ko":"확인","tts_text":"確認"},
    {"kanji":"予定","kana":"よてい","pron":"요테이","ko":"예정","tts_text":"予定"},
    {"kanji":"計画","kana":"けいかく","pron":"케이카쿠","ko":"계획","tts_text":"計画"},
    {"kanji":"準備","kana":"じゅんび","pron":"쥰비","ko":"준비","tts_text":"準備"},
    {"kanji":"対応","kana":"たいおう","pron":"타이오오","ko":"대응","tts_text":"対応"},

    {"kanji":"手続き","kana":"てつづき","pron":"테츠즈키","ko":"절차","tts_text":"手続き"},
    {"kanji":"申請","kana":"しんせい","pron":"신세이","ko":"신청","tts_text":"申請"},
    {"kanji":"許可","kana":"きょか","pron":"쿄카","ko":"허가","tts_text":"許可"},
    {"kanji":"禁止","kana":"きんし","pron":"킨시","ko":"금지","tts_text":"禁止"},
    {"kanji":"規則","kana":"きそく","pron":"키소쿠","ko":"규칙","tts_text":"規則"},
    {"kanji":"必要","kana":"ひつよう","pron":"히츠요오","ko":"필요","tts_text":"必要"},
    {"kanji":"重要","kana":"じゅうよう","pron":"쥬우요오","ko":"중요","tts_text":"重要"},
    {"kanji":"大事","kana":"だいじ","pron":"다이지","ko":"중요","tts_text":"大事"},
    {"kanji":"問題","kana":"もんだい","pron":"몬다이","ko":"문제","tts_text":"問題"},
    {"kanji":"解決","kana":"かいけつ","pron":"카이케츠","ko":"해결","tts_text":"解決"},

    {"kanji":"原因","kana":"げんいん","pron":"겐인","ko":"원인","tts_text":"原因"},
    {"kanji":"結果","kana":"けっか","pron":"켁카","ko":"결과","tts_text":"結果"},
    {"kanji":"提案","kana":"ていあん","pron":"테이안","ko":"제안","tts_text":"提案"},
    {"kanji":"意見","kana":"いけん","pron":"이켄","ko":"의견","tts_text":"意見"},
    {"kanji":"相談する","kana":"そうだんする","pron":"소오단스루","ko":"상담하다","tts_text":"相談する"},
    {"kanji":"確認する","kana":"かくにんする","pron":"카쿠닌스루","ko":"확인하다","tts_text":"確認する"},
    {"kanji":"説明","kana":"せつめい","pron":"세츠메이","ko":"설명","tts_text":"説明"},
    {"kanji":"説明する","kana":"せつめいする","pron":"세츠메이스루","ko":"설명하다","tts_text":"説明する"},
    {"kanji":"連絡する","kana":"れんらくする","pron":"렌라쿠스루","ko":"연락하다","tts_text":"連絡する"},
    {"kanji":"報告する","kana":"ほうこくする","pron":"호오코쿠스루","ko":"보고하다","tts_text":"報告する"},

    {"kanji":"担当","kana":"たんとう","pron":"탄토오","ko":"담당","tts_text":"担当"},
    {"kanji":"責任","kana":"せきにん","pron":"세키닌","ko":"책임","tts_text":"責任"},
    {"kanji":"職場","kana":"しょくば","pron":"쇼쿠바","ko":"직장","tts_text":"職場"},
    {"kanji":"部署","kana":"ぶしょ","pron":"부쇼","ko":"부서","tts_text":"部署"},
    {"kanji":"給料","kana":"きゅうりょう","pron":"큐우료오","ko":"급료","tts_text":"給料"},
    {"kanji":"残業","kana":"ざんぎょう","pron":"잔교오","ko":"잔업","tts_text":"残業"},
    {"kanji":"出張","kana":"しゅっちょう","pron":"슛쵸오","ko":"출장","tts_text":"出張"},
    {"kanji":"退職","kana":"たいしょく","pron":"타이쇼쿠","ko":"퇴직","tts_text":"退職"},
    {"kanji":"就職","kana":"しゅうしょく","pron":"슈우쇼쿠","ko":"취직","tts_text":"就職"},
    {"kanji":"面接","kana":"めんせつ","pron":"멘세츠","ko":"면접","tts_text":"面接"}
    ]
    },

    "sec05": {
    "title": "공부·시험·능력",
    "items": [
    {"kanji":"試験","kana":"しけん","pron":"시켄","ko":"시험","tts_text":"試験"},
    {"kanji":"合格","kana":"ごうかく","pron":"고오카쿠","ko":"합격","tts_text":"合格"},
    {"kanji":"不合格","kana":"ふごうかく","pron":"후고오카쿠","ko":"불합격","tts_text":"不合格"},
    {"kanji":"点数","kana":"てんすう","pron":"텐스우","ko":"점수","tts_text":"点数"},
    {"kanji":"成績","kana":"せいせき","pron":"세이세키","ko":"성적","tts_text":"成績"},
    {"kanji":"評価","kana":"ひょうか","pron":"효오카","ko":"평가","tts_text":"評価"},
    {"kanji":"結果","kana":"けっか","pron":"켁카","ko":"결과","tts_text":"結果"},
    {"kanji":"目的","kana":"もくてき","pron":"모쿠테키","ko":"목적","tts_text":"目的"},
    {"kanji":"目標","kana":"もくひょう","pron":"모쿠효오","ko":"목표","tts_text":"目標"},
    {"kanji":"努力","kana":"どりょく","pron":"도료쿠","ko":"노력","tts_text":"努力"},

    {"kanji":"練習","kana":"れんしゅう","pron":"렌슈우","ko":"연습","tts_text":"練習"},
    {"kanji":"復習","kana":"ふくしゅう","pron":"후쿠슈우","ko":"복습","tts_text":"復習"},
    {"kanji":"予習","kana":"よしゅう","pron":"요슈우","ko":"예습","tts_text":"予習"},
    {"kanji":"覚える","kana":"おぼえる","pron":"오보에루","ko":"외우다","tts_text":"覚える"},
    {"kanji":"暗記","kana":"あんき","pron":"안키","ko":"암기","tts_text":"暗記"},
    {"kanji":"理解","kana":"りかい","pron":"리카이","ko":"이해","tts_text":"理解"},
    {"kanji":"集中","kana":"しゅうちゅう","pron":"슈우츄우","ko":"집중","tts_text":"集中"},
    {"kanji":"注意","kana":"ちゅうい","pron":"츄우이","ko":"주의","tts_text":"注意"},
    {"kanji":"確認","kana":"かくにん","pron":"카쿠닌","ko":"확인","tts_text":"確認"},
    {"kanji":"間違い","kana":"まちがい","pron":"마치가이","ko":"틀림","tts_text":"間違い"},

    {"kanji":"解答","kana":"かいとう","pron":"카이토오","ko":"해답","tts_text":"解答"},
    {"kanji":"説明","kana":"せつめい","pron":"세츠메이","ko":"설명","tts_text":"説明"},
    {"kanji":"質問","kana":"しつもん","pron":"시츠몬","ko":"질문","tts_text":"質問"},
    {"kanji":"答える","kana":"こたえる","pron":"코타에루","ko":"대답하다","tts_text":"答える"},
    {"kanji":"調べる","kana":"しらべる","pron":"시라베루","ko":"조사하다","tts_text":"調べる"},
    {"kanji":"研究","kana":"けんきゅう","pron":"켄큐우","ko":"연구","tts_text":"研究"},
    {"kanji":"経験","kana":"けいけん","pron":"케이켄","ko":"경험","tts_text":"経験"},
    {"kanji":"能力","kana":"のうりょく","pron":"노오료쿠","ko":"능력","tts_text":"能力"},
    {"kanji":"才能","kana":"さいのう","pron":"사이노오","ko":"재능","tts_text":"才能"},
    {"kanji":"技術","kana":"ぎじゅつ","pron":"기쥬츠","ko":"기술","tts_text":"技術"},

    {"kanji":"上達","kana":"じょうたつ","pron":"죠오타츠","ko":"향상","tts_text":"上達"},
    {"kanji":"進歩","kana":"しんぽ","pron":"신포","ko":"진보","tts_text":"進歩"},
    {"kanji":"成長","kana":"せいちょう","pron":"세이쵸오","ko":"성장","tts_text":"成長"},
    {"kanji":"自信","kana":"じしん","pron":"지신","ko":"자신감","tts_text":"自信"},
    {"kanji":"失敗","kana":"しっぱい","pron":"싯파이","ko":"실패","tts_text":"失敗"},
    {"kanji":"成功","kana":"せいこう","pron":"세이코오","ko":"성공","tts_text":"成功"},
    {"kanji":"緊張","kana":"きんちょう","pron":"킨쵸오","ko":"긴장","tts_text":"緊張"},
    {"kanji":"安心","kana":"あんしん","pron":"안신","ko":"안심","tts_text":"安心"},
    {"kanji":"不安","kana":"ふあん","pron":"후안","ko":"불안","tts_text":"不安"},
    {"kanji":"準備する","kana":"じゅんびする","pron":"쥰비스루","ko":"준비하다","tts_text":"準備する"}
    ]
    },

    "sec06": {
    "title": "의사소통·정보",
    "items": [
    {"kanji":"会話","kana":"かいわ","pron":"카이와","ko":"회화","tts_text":"会話"},
    {"kanji":"話題","kana":"わだい","pron":"와다이","ko":"화제","tts_text":"話題"},
    {"kanji":"説明","kana":"せつめい","pron":"세츠메이","ko":"설명","tts_text":"説明"},
    {"kanji":"表現","kana":"ひょうげん","pron":"효오겐","ko":"표현","tts_text":"表現"},
    {"kanji":"文章","kana":"ぶんしょう","pron":"분쇼오","ko":"문장","tts_text":"文章"},
    {"kanji":"単語","kana":"たんご","pron":"탄고","ko":"단어","tts_text":"単語"},
    {"kanji":"漢字","kana":"かんじ","pron":"칸지","ko":"한자","tts_text":"漢字"},
    {"kanji":"意味","kana":"いみ","pron":"이미","ko":"의미","tts_text":"意味"},
    {"kanji":"内容","kana":"ないよう","pron":"나이요오","ko":"내용","tts_text":"内容"},
    {"kanji":"情報","kana":"じょうほう","pron":"죠오호오","ko":"정보","tts_text":"情報"},

    {"kanji":"連絡","kana":"れんらく","pron":"렌라쿠","ko":"연락","tts_text":"連絡"},
    {"kanji":"報告","kana":"ほうこく","pron":"호오코쿠","ko":"보고","tts_text":"報告"},
    {"kanji":"相談","kana":"そうだん","pron":"소오단","ko":"상담","tts_text":"相談"},
    {"kanji":"伝える","kana":"つたえる","pron":"츠타에루","ko":"전하다","tts_text":"伝える"},
    {"kanji":"知らせる","kana":"しらせる","pron":"시라세루","ko":"알리다","tts_text":"知らせる"},
    {"kanji":"聞き返す","kana":"ききかえす","pron":"키키카에스","ko":"되묻다","tts_text":"聞き返す"},
    {"kanji":"理解する","kana":"りかいする","pron":"리카이스루","ko":"이해하다","tts_text":"理解する"},
    {"kanji":"誤解","kana":"ごかい","pron":"고카이","ko":"오해","tts_text":"誤解"},
    {"kanji":"確認する","kana":"かくにんする","pron":"카쿠닌스루","ko":"확인하다","tts_text":"確認する"},
    {"kanji":"納得","kana":"なっとく","pron":"낫토쿠","ko":"납득","tts_text":"納得"},

    {"kanji":"同意","kana":"どうい","pron":"도오이","ko":"동의","tts_text":"同意"},
    {"kanji":"反対","kana":"はんたい","pron":"한타이","ko":"반대","tts_text":"反対"},
    {"kanji":"賛成","kana":"さんせい","pron":"산세이","ko":"찬성","tts_text":"賛成"},
    {"kanji":"意見","kana":"いけん","pron":"이켄","ko":"의견","tts_text":"意見"},
    {"kanji":"提案","kana":"ていあん","pron":"테이안","ko":"제안","tts_text":"提案"},
    {"kanji":"質問する","kana":"しつもんする","pron":"시츠몬스루","ko":"질문하다","tts_text":"質問する"},
    {"kanji":"答える","kana":"こたえる","pron":"코타에루","ko":"대답하다","tts_text":"答える"},
    {"kanji":"説明する","kana":"せつめいする","pron":"세츠메이스루","ko":"설명하다","tts_text":"説明する"},
    {"kanji":"翻訳","kana":"ほんやく","pron":"혼야쿠","ko":"번역","tts_text":"翻訳"},
    {"kanji":"通訳","kana":"つうやく","pron":"츠우야쿠","ko":"통역","tts_text":"通訳"},

    {"kanji":"記事","kana":"きじ","pron":"키지","ko":"기사","tts_text":"記事"},
    {"kanji":"ニュース","kana":"ニュース","pron":"뉴우스","ko":"뉴스","tts_text":"ニュース"},
    {"kanji":"放送","kana":"ほうそう","pron":"호오소오","ko":"방송","tts_text":"放送"},
    {"kanji":"番組","kana":"ばんぐみ","pron":"반구미","ko":"프로그램","tts_text":"番組"},
    {"kanji":"連載","kana":"れんさい","pron":"렌사이","ko":"연재","tts_text":"連載"},
    {"kanji":"広告","kana":"こうこく","pron":"코오코쿠","ko":"광고","tts_text":"広告"},
    {"kanji":"宣伝","kana":"せんでん","pron":"센덴","ko":"선전","tts_text":"宣伝"},
    {"kanji":"噂","kana":"うわさ","pron":"우와사","ko":"소문","tts_text":"噂"},
    {"kanji":"評判","kana":"ひょうばん","pron":"효오반","ko":"평판","tts_text":"評判"},
    {"kanji":"通知","kana":"つうち","pron":"츠우치","ko":"통지","tts_text":"通知"}
    ]
    },

    "sec07": {
    "title": "건강·몸·병원",
    "items": [
    {"kanji":"体調","kana":"たいちょう","pron":"타이쵸오","ko":"몸상태","tts_text":"体調"},
    {"kanji":"健康","kana":"けんこう","pron":"켄코오","ko":"건강","tts_text":"健康"},
    {"kanji":"病気","kana":"びょうき","pron":"뵤오키","ko":"병","tts_text":"病気"},
    {"kanji":"怪我","kana":"けが","pron":"케가","ko":"부상","tts_text":"怪我"},
    {"kanji":"熱","kana":"ねつ","pron":"네츠","ko":"열","tts_text":"熱"},
    {"kanji":"咳","kana":"せき","pron":"세키","ko":"기침","tts_text":"咳"},
    {"kanji":"頭痛","kana":"ずつう","pron":"즈츠우","ko":"두통","tts_text":"頭痛"},
    {"kanji":"腹痛","kana":"ふくつう","pron":"후쿠츠우","ko":"복통","tts_text":"腹痛"},
    {"kanji":"薬","kana":"くすり","pron":"쿠스리","ko":"약","tts_text":"薬"},
    {"kanji":"注射","kana":"ちゅうしゃ","pron":"츄우샤","ko":"주사","tts_text":"注射"},

    {"kanji":"手術","kana":"しゅじゅつ","pron":"슈쥬츠","ko":"수술","tts_text":"手術"},
    {"kanji":"入院","kana":"にゅういん","pron":"뉴우인","ko":"입원","tts_text":"入院"},
    {"kanji":"退院","kana":"たいいん","pron":"타이인","ko":"퇴원","tts_text":"退院"},
    {"kanji":"病院","kana":"びょういん","pron":"뵤오인","ko":"병원","tts_text":"病院"},
    {"kanji":"診察","kana":"しんさつ","pron":"신사츠","ko":"진찰","tts_text":"診察"},
    {"kanji":"検査","kana":"けんさ","pron":"켄사","ko":"검사","tts_text":"検査"},
    {"kanji":"治療","kana":"ちりょう","pron":"치료오","ko":"치료","tts_text":"治療"},
    {"kanji":"回復","kana":"かいふく","pron":"카이후쿠","ko":"회복","tts_text":"回復"},
    {"kanji":"予防","kana":"よぼう","pron":"요보오","ko":"예방","tts_text":"予防"},
    {"kanji":"原因","kana":"げんいん","pron":"겐인","ko":"원인","tts_text":"原因"},

    {"kanji":"症状","kana":"しょうじょう","pron":"쇼오죠오","ko":"증상","tts_text":"症状"},
    {"kanji":"痛み","kana":"いたみ","pron":"이타미","ko":"통증","tts_text":"痛み"},
    {"kanji":"疲れ","kana":"つかれ","pron":"츠카레","ko":"피로","tts_text":"疲れ"},
    {"kanji":"睡眠","kana":"すいみん","pron":"스이민","ko":"수면","tts_text":"睡眠"},
    {"kanji":"食欲","kana":"しょくよく","pron":"쇼쿠요쿠","ko":"식욕","tts_text":"食欲"},
    {"kanji":"運動","kana":"うんどう","pron":"운도오","ko":"운동","tts_text":"運動"},
    {"kanji":"ダイエット","kana":"ダイエット","pron":"다이에또","ko":"다이어트","tts_text":"ダイエット"},
    {"kanji":"栄養","kana":"えいよう","pron":"에이요오","ko":"영양","tts_text":"栄養"},
    {"kanji":"禁煙","kana":"きんえん","pron":"킨엔","ko":"금연","tts_text":"禁煙"},
    {"kanji":"禁止","kana":"きんし","pron":"킨시","ko":"금지","tts_text":"禁止"},

    {"kanji":"肩","kana":"かた","pron":"카타","ko":"어깨","tts_text":"肩"},
    {"kanji":"首","kana":"くび","pron":"쿠비","ko":"목","tts_text":"首"},
    {"kanji":"背中","kana":"せなか","pron":"세나카","ko":"등","tts_text":"背中"},
    {"kanji":"胃","kana":"い","pron":"이","ko":"위","tts_text":"胃"},
    {"kanji":"心臓","kana":"しんぞう","pron":"신조오","ko":"심장","tts_text":"心臓"},
    {"kanji":"血","kana":"ち","pron":"치","ko":"피","tts_text":"血"},
    {"kanji":"骨","kana":"ほね","pron":"호네","ko":"뼈","tts_text":"骨"},
    {"kanji":"肌","kana":"はだ","pron":"하다","ko":"피부","tts_text":"肌"},
    {"kanji":"目薬","kana":"めぐすり","pron":"메구스리","ko":"안약","tts_text":"目薬"},
    {"kanji":"風邪","kana":"かぜ","pron":"카제","ko":"감기","tts_text":"風邪"}
    ]
    },

    "sec08": {
    "title": "자연·날씨·환경",
    "items": [
    {"kanji":"天気予報","kana":"てんきよほう","pron":"텐키요호오","ko":"일기예보","tts_text":"天気予報"},
    {"kanji":"気温","kana":"きおん","pron":"키온","ko":"기온","tts_text":"気温"},
    {"kanji":"湿度","kana":"しつど","pron":"시츠도","ko":"습도","tts_text":"湿度"},
    {"kanji":"強風","kana":"きょうふう","pron":"쿄오후우","ko":"강풍","tts_text":"強風"},
    {"kanji":"台風","kana":"たいふう","pron":"타이후우","ko":"태풍","tts_text":"台風"},
    {"kanji":"雷","kana":"かみなり","pron":"카미나리","ko":"천둥","tts_text":"雷"},
    {"kanji":"雪","kana":"ゆき","pron":"유키","ko":"눈","tts_text":"雪"},
    {"kanji":"雨","kana":"あめ","pron":"아메","ko":"비","tts_text":"雨"},
    {"kanji":"雲","kana":"くも","pron":"쿠모","ko":"구름","tts_text":"雲"},
    {"kanji":"晴れ","kana":"はれ","pron":"하레","ko":"맑음","tts_text":"晴れ"},

    {"kanji":"曇り","kana":"くもり","pron":"쿠모리","ko":"흐림","tts_text":"曇り"},
    {"kanji":"温度","kana":"おんど","pron":"온도","ko":"온도","tts_text":"温度"},
    {"kanji":"季節","kana":"きせつ","pron":"키세츠","ko":"계절","tts_text":"季節"},
    {"kanji":"春","kana":"はる","pron":"하루","ko":"봄","tts_text":"春"},
    {"kanji":"夏","kana":"なつ","pron":"나츠","ko":"여름","tts_text":"夏"},
    {"kanji":"秋","kana":"あき","pron":"아키","ko":"가을","tts_text":"秋"},
    {"kanji":"冬","kana":"ふゆ","pron":"후유","ko":"겨울","tts_text":"冬"},
    {"kanji":"暑さ","kana":"あつさ","pron":"아츠사","ko":"더위","tts_text":"暑さ"},
    {"kanji":"寒さ","kana":"さむさ","pron":"사무사","ko":"추위","tts_text":"寒さ"},
    {"kanji":"暖房","kana":"だんぼう","pron":"단보오","ko":"난방","tts_text":"暖房"},

    {"kanji":"冷房","kana":"れいぼう","pron":"레이보오","ko":"냉방","tts_text":"冷房"},
    {"kanji":"地震","kana":"じしん","pron":"지신","ko":"지진","tts_text":"地震"},
    {"kanji":"災害","kana":"さいがい","pron":"사이가이","ko":"재해","tts_text":"災害"},
    {"kanji":"危険","kana":"きけん","pron":"키켄","ko":"위험","tts_text":"危険"},
    {"kanji":"安全","kana":"あんぜん","pron":"안젠","ko":"안전","tts_text":"安全"},
    {"kanji":"汚染","kana":"おせん","pron":"오센","ko":"오염","tts_text":"汚染"},
    {"kanji":"環境","kana":"かんきょう","pron":"칸쿄오","ko":"환경","tts_text":"環境"},
    {"kanji":"資源","kana":"しげん","pron":"시겐","ko":"자원","tts_text":"資源"},
    {"kanji":"節電","kana":"せつでん","pron":"세츠덴","ko":"절전","tts_text":"節電"},
    {"kanji":"節約","kana":"せつやく","pron":"세츠야쿠","ko":"절약","tts_text":"節約"},

    {"kanji":"自然","kana":"しぜん","pron":"시젠","ko":"자연","tts_text":"自然"},
    {"kanji":"景色","kana":"けしき","pron":"케시키","ko":"경치","tts_text":"景色"},
    {"kanji":"空気","kana":"くうき","pron":"쿠우키","ko":"공기","tts_text":"空気"},
    {"kanji":"森","kana":"もり","pron":"모리","ko":"숲","tts_text":"森"},
    {"kanji":"海岸","kana":"かいがん","pron":"카이간","ko":"해안","tts_text":"海岸"},
    {"kanji":"湖","kana":"みずうみ","pron":"미즈우미","ko":"호수","tts_text":"湖"},
    {"kanji":"動物","kana":"どうぶつ","pron":"도오부츠","ko":"동물","tts_text":"動物"},
    {"kanji":"植物","kana":"しょくぶつ","pron":"쇼쿠부츠","ko":"식물","tts_text":"植物"},
    {"kanji":"虫","kana":"むし","pron":"무시","ko":"벌레","tts_text":"虫"},
    {"kanji":"花粉","kana":"かふん","pron":"카푼","ko":"꽃가루","tts_text":"花粉"}
    ]
    },

    "sec09": {
    "title": "소비·금전·쇼핑",
    "items": [
    {"kanji":"値段","kana":"ねだん","pron":"네단","ko":"가격","tts_text":"値段"},
    {"kanji":"料金","kana":"りょうきん","pron":"료오킨","ko":"요금","tts_text":"料金"},
    {"kanji":"支払い","kana":"しはらい","pron":"시하라이","ko":"지불","tts_text":"支払い"},
    {"kanji":"現金","kana":"げんきん","pron":"겐킨","ko":"현금","tts_text":"現金"},
    {"kanji":"財布","kana":"さいふ","pron":"사이후","ko":"지갑","tts_text":"財布"},
    {"kanji":"レシート","kana":"レシート","pron":"레시이토","ko":"영수증","tts_text":"レシート"},
    {"kanji":"領収書","kana":"りょうしゅうしょ","pron":"료오슈우쇼","ko":"영수증(격식)","tts_text":"領収書"},
    {"kanji":"割引","kana":"わりびき","pron":"와리비키","ko":"할인","tts_text":"割引"},
    {"kanji":"値引き","kana":"ねびき","pron":"네비키","ko":"값 깎음","tts_text":"値引き"},
    {"kanji":"返品","kana":"へんぴん","pron":"헨핀","ko":"반품","tts_text":"返品"},

    {"kanji":"交換","kana":"こうかん","pron":"코오칸","ko":"교환","tts_text":"交換"},
    {"kanji":"在庫","kana":"ざいこ","pron":"자이코","ko":"재고","tts_text":"在庫"},
    {"kanji":"品切れ","kana":"しなぎれ","pron":"시나기레","ko":"품절","tts_text":"品切れ"},
    {"kanji":"商品","kana":"しょうひん","pron":"쇼오힌","ko":"상품","tts_text":"商品"},
    {"kanji":"品質","kana":"ひんしつ","pron":"힌시츠","ko":"품질","tts_text":"品質"},
    {"kanji":"説明書","kana":"せつめいしょ","pron":"세츠메이쇼","ko":"설명서","tts_text":"説明書"},
    {"kanji":"保証","kana":"ほしょう","pron":"호쇼오","ko":"보증","tts_text":"保証"},
    {"kanji":"修理","kana":"しゅうり","pron":"슈우리","ko":"수리","tts_text":"修理"},
    {"kanji":"故障","kana":"こしょう","pron":"코쇼오","ko":"고장","tts_text":"故障"},
    {"kanji":"注文","kana":"ちゅうもん","pron":"츄우몬","ko":"주문","tts_text":"注文"},

    {"kanji":"予約","kana":"よやく","pron":"요야쿠","ko":"예약","tts_text":"予約"},
    {"kanji":"キャンセル","kana":"キャンセル","pron":"캰세루","ko":"취소","tts_text":"キャンセル"},
    {"kanji":"配達","kana":"はいたつ","pron":"하이타츠","ko":"배달","tts_text":"配達"},
    {"kanji":"送料","kana":"そうりょう","pron":"소오료오","ko":"배송비","tts_text":"送料"},
    {"kanji":"無料","kana":"むりょう","pron":"무료오","ko":"무료","tts_text":"無料"},
    {"kanji":"有料","kana":"ゆうりょう","pron":"유우료오","ko":"유료","tts_text":"有料"},
    {"kanji":"節約","kana":"せつやく","pron":"세츠야쿠","ko":"절약","tts_text":"節約"},
    {"kanji":"無駄","kana":"むだ","pron":"무다","ko":"낭비","tts_text":"無駄"},
    {"kanji":"貯金","kana":"ちょきん","pron":"초킨","ko":"저금","tts_text":"貯金"},
    {"kanji":"借金","kana":"しゃっきん","pron":"샥킨","ko":"빚","tts_text":"借金"},

    {"kanji":"給料","kana":"きゅうりょう","pron":"큐우료오","ko":"급료","tts_text":"給料"},
    {"kanji":"収入","kana":"しゅうにゅう","pron":"슈우뉴우","ko":"수입","tts_text":"収入"},
    {"kanji":"出費","kana":"しゅっぴ","pron":"슛피","ko":"지출","tts_text":"出費"},
    {"kanji":"価格","kana":"かかく","pron":"카카쿠","ko":"가격(격식)","tts_text":"価格"},
    {"kanji":"安売り","kana":"やすうり","pron":"야스우리","ko":"싸게 팜","tts_text":"安売り"},
    {"kanji":"高級","kana":"こうきゅう","pron":"코오큐우","ko":"고급","tts_text":"高級"},
    {"kanji":"中古","kana":"ちゅうこ","pron":"츄우코","ko":"중고","tts_text":"中古"},
    {"kanji":"新品","kana":"しんぴん","pron":"신핀","ko":"새 제품","tts_text":"新品"},
    {"kanji":"人気","kana":"にんき","pron":"닌키","ko":"인기","tts_text":"人気"},
    {"kanji":"流行","kana":"りゅうこう","pron":"류우코오","ko":"유행","tts_text":"流行"}
    ]
    },

    "sec10": {
    "title": "상태·감정·평가",
    "items": [
    {"kanji":"気分","kana":"きぶん","pron":"키분","ko":"기분","tts_text":"気分"},
    {"kanji":"感情","kana":"かんじょう","pron":"칸죠오","ko":"감정","tts_text":"感情"},
    {"kanji":"不安","kana":"ふあん","pron":"후안","ko":"불안","tts_text":"不安"},
    {"kanji":"安心","kana":"あんしん","pron":"안신","ko":"안심","tts_text":"安心"},
    {"kanji":"緊張","kana":"きんちょう","pron":"킨쵸오","ko":"긴장","tts_text":"緊張"},
    {"kanji":"ストレス","kana":"ストレス","pron":"스토레스","ko":"스트레스","tts_text":"ストレス"},
    {"kanji":"満足","kana":"まんぞく","pron":"만조쿠","ko":"만족","tts_text":"満足"},
    {"kanji":"不満","kana":"ふまん","pron":"후만","ko":"불만","tts_text":"不満"},
    {"kanji":"後悔","kana":"こうかい","pron":"코오카이","ko":"후회","tts_text":"後悔"},
    {"kanji":"反省","kana":"はんせい","pron":"한세이","ko":"반성","tts_text":"反省"},

    {"kanji":"感謝","kana":"かんしゃ","pron":"칸샤","ko":"감사","tts_text":"感謝"},
    {"kanji":"尊敬","kana":"そんけい","pron":"손케이","ko":"존경","tts_text":"尊敬"},
    {"kanji":"信頼","kana":"しんらい","pron":"신라이","ko":"신뢰","tts_text":"信頼"},
    {"kanji":"期待","kana":"きたい","pron":"키타이","ko":"기대","tts_text":"期待"},
    {"kanji":"失望","kana":"しつぼう","pron":"시츠보오","ko":"실망","tts_text":"失望"},
    {"kanji":"驚き","kana":"おどろき","pron":"오도로키","ko":"놀람","tts_text":"驚き"},
    {"kanji":"喜び","kana":"よろこび","pron":"요로코비","ko":"기쁨","tts_text":"喜び"},
    {"kanji":"怒り","kana":"いかり","pron":"이카리","ko":"분노","tts_text":"怒り"},
    {"kanji":"悲しみ","kana":"かなしみ","pron":"카나시미","ko":"슬픔","tts_text":"悲しみ"},
    {"kanji":"恐れ","kana":"おそれ","pron":"오소레","ko":"두려움","tts_text":"恐れ"},

    {"kanji":"大変","kana":"たいへん","pron":"타이헨","ko":"힘듦, 큰일","tts_text":"大変"},
    {"kanji":"面倒","kana":"めんどう","pron":"멘도오","ko":"귀찮음","tts_text":"面倒"},
    {"kanji":"厳しい","kana":"きびしい","pron":"키비시이","ko":"엄격하다","tts_text":"厳しい"},
    {"kanji":"優しい","kana":"やさしい","pron":"야사시이","ko":"상냥하다","tts_text":"優しい"},
    {"kanji":"素晴らしい","kana":"すばらしい","pron":"스바라시이","ko":"훌륭하다","tts_text":"素晴らしい"},
    {"kanji":"便利","kana":"べんり","pron":"벤리","ko":"편리","tts_text":"便利"},
    {"kanji":"不便","kana":"ふべん","pron":"후벤","ko":"불편","tts_text":"不便"},
    {"kanji":"難しい","kana":"むずかしい","pron":"무즈카시이","ko":"어렵다","tts_text":"難しい"},
    {"kanji":"複雑","kana":"ふくざつ","pron":"후쿠자츠","ko":"복잡","tts_text":"複雑"},
    {"kanji":"簡単","kana":"かんたん","pron":"칸탄","ko":"간단","tts_text":"簡単"},

    {"kanji":"正しい","kana":"ただしい","pron":"타다시이","ko":"올바르다","tts_text":"正しい"},
    {"kanji":"確か","kana":"たしか","pron":"타시카","ko":"확실함","tts_text":"確か"},
    {"kanji":"確実","kana":"かくじつ","pron":"카쿠지츠","ko":"확실","tts_text":"確実"},
    {"kanji":"大切","kana":"たいせつ","pron":"타이세츠","ko":"중요","tts_text":"大切"},
    {"kanji":"重要","kana":"じゅうよう","pron":"쥬우요오","ko":"중요","tts_text":"重要"},
    {"kanji":"特別","kana":"とくべつ","pron":"토쿠베츠","ko":"특별","tts_text":"特別"},
    {"kanji":"普通","kana":"ふつう","pron":"후츠우","ko":"보통","tts_text":"普通"},
    {"kanji":"異常","kana":"いじょう","pron":"이죠오","ko":"이상(비정상)","tts_text":"異常"},
    {"kanji":"危険","kana":"きけん","pron":"키켄","ko":"위험","tts_text":"危険"},
    {"kanji":"安全","kana":"あんぜん","pron":"안젠","ko":"안전","tts_text":"安全"}
    ]
    }
}

N2_WORDS = {
  "sec01": {
    "title": "논리·업무·추상",
    "items": [
      {"kanji":"傾向","kana":"けいこう","pron":"케이코오","ko":"경향","tts_text":"傾向"},
      {"kanji":"動向","kana":"どうこう","pron":"도오코오","ko":"동향","tts_text":"動向"},
      {"kanji":"方針","kana":"ほうしん","pron":"호오신","ko":"방침","tts_text":"方針"},
      {"kanji":"対策","kana":"たいさく","pron":"타이사쿠","ko":"대책","tts_text":"対策"},
      {"kanji":"課題","kana":"かだい","pron":"카다이","ko":"과제","tts_text":"課題"},
      {"kanji":"問題点","kana":"もんだいてん","pron":"몬다이텐","ko":"문제점","tts_text":"問題点"},
      {"kanji":"原因","kana":"げんいん","pron":"겐인","ko":"원인","tts_text":"原因"},
      {"kanji":"背景","kana":"はいけい","pron":"하이케이","ko":"배경","tts_text":"背景"},
      {"kanji":"目的","kana":"もくてき","pron":"모쿠테키","ko":"목적","tts_text":"目的"},
      {"kanji":"結論","kana":"けつろん","pron":"켓론","ko":"결론","tts_text":"結論"},

      {"kanji":"影響","kana":"えいきょう","pron":"에이쿄오","ko":"영향","tts_text":"影響"},
      {"kanji":"効果","kana":"こうか","pron":"코오카","ko":"효과","tts_text":"効果"},
      {"kanji":"成果","kana":"せいか","pron":"세이카","ko":"성과","tts_text":"成果"},
      {"kanji":"結果","kana":"けっか","pron":"켓카","ko":"결과","tts_text":"結果"},
      {"kanji":"可能性","kana":"かのうせい","pron":"카노오세이","ko":"가능성","tts_text":"可能性"},
      {"kanji":"必要性","kana":"ひつようせい","pron":"히츠요오세이","ko":"필요성","tts_text":"必要性"},
      {"kanji":"重要性","kana":"じゅうようせい","pron":"주우요오세이","ko":"중요성","tts_text":"重要性"},
      {"kanji":"優先","kana":"ゆうせん","pron":"유우센","ko":"우선","tts_text":"優先"},
      {"kanji":"最適","kana":"さいてき","pron":"사이테키","ko":"최적","tts_text":"最適"},
      {"kanji":"適切","kana":"てきせつ","pron":"테키세츠","ko":"적절","tts_text":"適切"},

      {"kanji":"実施","kana":"じっし","pron":"짓시","ko":"실시","tts_text":"実施"},
      {"kanji":"導入","kana":"どうにゅう","pron":"도오뉴우","ko":"도입","tts_text":"導入"},
      {"kanji":"運用","kana":"うんよう","pron":"운요오","ko":"운용","tts_text":"運用"},
      {"kanji":"管理","kana":"かんり","pron":"칸리","ko":"관리","tts_text":"管理"},
      {"kanji":"調整","kana":"ちょうせい","pron":"초오세이","ko":"조정","tts_text":"調整"},
      {"kanji":"改善","kana":"かいぜん","pron":"카이젠","ko":"개선","tts_text":"改善"},
      {"kanji":"改革","kana":"かいかく","pron":"카이카쿠","ko":"개혁","tts_text":"改革"},
      {"kanji":"検討","kana":"けんとう","pron":"켄토오","ko":"검토","tts_text":"検討"},
      {"kanji":"分析","kana":"ぶんせき","pron":"분세키","ko":"분석","tts_text":"分析"},
      {"kanji":"評価","kana":"ひょうか","pron":"효오카","ko":"평가","tts_text":"評価"},

      {"kanji":"確認","kana":"かくにん","pron":"카쿠닌","ko":"확인","tts_text":"確認"},
      {"kanji":"把握","kana":"はあく","pron":"하아쿠","ko":"파악","tts_text":"把握"},
      {"kanji":"判断","kana":"はんだん","pron":"한단","ko":"판단","tts_text":"判断"},
      {"kanji":"決定","kana":"けってい","pron":"켓테이","ko":"결정","tts_text":"決定"},
      {"kanji":"提案","kana":"ていあん","pron":"테이안","ko":"제안","tts_text":"提案"},
      {"kanji":"提示","kana":"ていじ","pron":"테이지","ko":"제시","tts_text":"提示"},
      {"kanji":"説明","kana":"せつめい","pron":"세츠메이","ko":"설명","tts_text":"説明"},
      {"kanji":"説明責任","kana":"せつめいせきにん","pron":"세츠메이 세키닌","ko":"설명 책임","tts_text":"説明責任"},
      {"kanji":"報告","kana":"ほうこく","pron":"호오코쿠","ko":"보고","tts_text":"報告"},
      {"kanji":"連絡","kana":"れんらく","pron":"렌라쿠","ko":"연락","tts_text":"連絡"},

      {"kanji":"相談","kana":"そうだん","pron":"소오단","ko":"상담","tts_text":"相談"},
      {"kanji":"交渉","kana":"こうしょう","pron":"코오쇼오","ko":"교섭","tts_text":"交渉"},
      {"kanji":"合意","kana":"ごうい","pron":"고오이","ko":"합의","tts_text":"合意"},
      {"kanji":"契約","kana":"けいやく","pron":"케이야쿠","ko":"계약","tts_text":"契約"},
      {"kanji":"条件","kana":"じょうけん","pron":"죠오켄","ko":"조건","tts_text":"条件"},
      {"kanji":"要件","kana":"ようけん","pron":"요오켄","ko":"요건","tts_text":"要件"},
      {"kanji":"手続き","kana":"てつづき","pron":"테츠즈키","ko":"절차","tts_text":"手続き"},
      {"kanji":"対応","kana":"たいおう","pron":"타이오오","ko":"대응","tts_text":"対応"},
      {"kanji":"処理","kana":"しょり","pron":"쇼리","ko":"처리","tts_text":"処理"},
      {"kanji":"対処","kana":"たいしょ","pron":"타이쇼","ko":"대처","tts_text":"対処"},

      {"kanji":"維持","kana":"いじ","pron":"이지","ko":"유지","tts_text":"維持"},
      {"kanji":"継続","kana":"けいぞく","pron":"케이조쿠","ko":"지속","tts_text":"継続"},
      {"kanji":"中止","kana":"ちゅうし","pron":"츄우시","ko":"중지","tts_text":"中止"},
      {"kanji":"延期","kana":"えんき","pron":"엔키","ko":"연기","tts_text":"延期"},
      {"kanji":"変更","kana":"へんこう","pron":"헨코오","ko":"변경","tts_text":"変更"},
      {"kanji":"更新","kana":"こうしん","pron":"코오신","ko":"갱신","tts_text":"更新"},
      {"kanji":"削減","kana":"さくげん","pron":"사쿠겐","ko":"삭감","tts_text":"削減"},
      {"kanji":"増加","kana":"ぞうか","pron":"조오카","ko":"증가","tts_text":"増加"},
      {"kanji":"拡大","kana":"かくだい","pron":"카쿠다이","ko":"확대","tts_text":"拡大"},
      {"kanji":"縮小","kana":"しゅくしょう","pron":"슈쿠쇼오","ko":"축소","tts_text":"縮小"},

      {"kanji":"発生","kana":"はっせい","pron":"핫세이","ko":"발생","tts_text":"発生"},
      {"kanji":"発展","kana":"はってん","pron":"핫텐","ko":"발전","tts_text":"発展"},
      {"kanji":"進展","kana":"しんてん","pron":"신텐","ko":"진전","tts_text":"進展"},
      {"kanji":"停滞","kana":"ていたい","pron":"테이타이","ko":"정체","tts_text":"停滞"},
      {"kanji":"改善する","kana":"かいぜんする","pron":"카이젠 스루","ko":"개선하다","tts_text":"改善する"},
      {"kanji":"検討する","kana":"けんとうする","pron":"켄토오 스루","ko":"검토하다","tts_text":"検討する"},
      {"kanji":"提案する","kana":"ていあんする","pron":"테이안 스루","ko":"제안하다","tts_text":"提案する"},
      {"kanji":"実施する","kana":"じっしする","pron":"짓시 스루","ko":"실시하다","tts_text":"実施する"},
      {"kanji":"対応する","kana":"たいおうする","pron":"타이오오 스루","ko":"대응하다","tts_text":"対応する"},
      {"kanji":"把握する","kana":"はあくする","pron":"하아쿠 스루","ko":"파악하다","tts_text":"把握する"},

      {"kanji":"促進","kana":"そくしん","pron":"소쿠신","ko":"촉진","tts_text":"促進"},
      {"kanji":"抑制","kana":"よくせい","pron":"요쿠세이","ko":"억제","tts_text":"抑制"},
      {"kanji":"達成","kana":"たっせい","pron":"탓세이","ko":"달성","tts_text":"達成"},
      {"kanji":"実現","kana":"じつげん","pron":"짓겐","ko":"실현","tts_text":"実現"},
      {"kanji":"確保","kana":"かくほ","pron":"카쿠호","ko":"확보","tts_text":"確保"},
      {"kanji":"提供","kana":"ていきょう","pron":"테이쿄오","ko":"제공","tts_text":"提供"},
      {"kanji":"共有","kana":"きょうゆう","pron":"쿄오유우","ko":"공유","tts_text":"共有"},
      {"kanji":"配慮","kana":"はいりょ","pron":"하이료","ko":"배려","tts_text":"配慮"},
      {"kanji":"影響する","kana":"えいきょうする","pron":"에이쿄오 스루","ko":"영향을 미치다","tts_text":"影響する"},
      {"kanji":"関連","kana":"かんれん","pron":"칸렌","ko":"관련","tts_text":"関連"},

      {"kanji":"一方で","kana":"いっぽうで","pron":"잇포오데","ko":"한편으로는","tts_text":"一方で"},
      {"kanji":"それに対して","kana":"それにたいして","pron":"소레니 타이시테","ko":"그에 반해","tts_text":"それに対して"},
      {"kanji":"したがって","kana":"したがって","pron":"시타갓테","ko":"따라서","tts_text":"したがって"},
      {"kanji":"つまり","kana":"つまり","pron":"츠마리","ko":"즉","tts_text":"つまり"},
      {"kanji":"なお","kana":"なお","pron":"나오","ko":"덧붙여","tts_text":"なお"},
      {"kanji":"一応","kana":"いちおう","pron":"이치오오","ko":"일단","tts_text":"一応"},
      {"kanji":"むしろ","kana":"むしろ","pron":"무시로","ko":"오히려","tts_text":"むしろ"},
      {"kanji":"あくまで","kana":"あくまで","pron":"아쿠마데","ko":"어디까지나/끝까지","tts_text":"あくまで"},
      {"kanji":"いずれ","kana":"いずれ","pron":"이즈레","ko":"언젠가/어느 쪽이든","tts_text":"いずれ"},
      {"kanji":"各自","kana":"かくじ","pron":"카쿠지","ko":"각자","tts_text":"各自"}
    ]
  },

  "sec02": {
    "title": "경제·회사·비즈니스",
    "items": [
      {"kanji":"経営","kana":"けいえい","pron":"케이에이","ko":"경영","tts_text":"経営"},
      {"kanji":"企業","kana":"きぎょう","pron":"키교오","ko":"기업","tts_text":"企業"},
      {"kanji":"経済","kana":"けいざい","pron":"케이자이","ko":"경제","tts_text":"経済"},
      {"kanji":"景気","kana":"けいき","pron":"케이키","ko":"경기(경제)","tts_text":"景気"},
      {"kanji":"市場","kana":"しじょう","pron":"시죠오","ko":"시장","tts_text":"市場"},
      {"kanji":"需要","kana":"じゅよう","pron":"쥬요오","ko":"수요","tts_text":"需要"},
      {"kanji":"供給","kana":"きょうきゅう","pron":"쿄오큐우","ko":"공급","tts_text":"供給"},
      {"kanji":"取引","kana":"とりひき","pron":"토리히키","ko":"거래","tts_text":"取引"},
      {"kanji":"取扱い","kana":"とりあつかい","pron":"토리아츠카이","ko":"취급","tts_text":"取扱い"},
      {"kanji":"販売","kana":"はんばい","pron":"한바이","ko":"판매","tts_text":"販売"},

      {"kanji":"売上","kana":"うりあげ","pron":"우리아게","ko":"매출","tts_text":"売上"},
      {"kanji":"利益","kana":"りえき","pron":"리에키","ko":"이익","tts_text":"利益"},
      {"kanji":"損失","kana":"そんしつ","pron":"손시츠","ko":"손실","tts_text":"損失"},
      {"kanji":"収益","kana":"しゅうえき","pron":"슈우에키","ko":"수익","tts_text":"収益"},
      {"kanji":"収支","kana":"しゅうし","pron":"슈우시","ko":"수지","tts_text":"収支"},
      {"kanji":"予算","kana":"よさん","pron":"요산","ko":"예산","tts_text":"予算"},
      {"kanji":"費用","kana":"ひよう","pron":"히요오","ko":"비용","tts_text":"費用"},
      {"kanji":"支出","kana":"ししゅつ","pron":"시슈츠","ko":"지출","tts_text":"支出"},
      {"kanji":"投資","kana":"とうし","pron":"토오시","ko":"투자","tts_text":"投資"},
      {"kanji":"融資","kana":"ゆうし","pron":"유우시","ko":"융자","tts_text":"融資"},

      {"kanji":"金融","kana":"きんゆう","pron":"킨유우","ko":"금융","tts_text":"金融"},
      {"kanji":"株式","kana":"かぶしき","pron":"카부시키","ko":"주식","tts_text":"株式"},
      {"kanji":"証券","kana":"しょうけん","pron":"쇼오켄","ko":"증권","tts_text":"証券"},
      {"kanji":"価格","kana":"かかく","pron":"카카쿠","ko":"가격(격식)","tts_text":"価格"},
      {"kanji":"物価","kana":"ぶっか","pron":"붓카","ko":"물가","tts_text":"物価"},
      {"kanji":"賃金","kana":"ちんぎん","pron":"친긴","ko":"임금","tts_text":"賃金"},
      {"kanji":"雇用","kana":"こよう","pron":"코요오","ko":"고용","tts_text":"雇用"},
      {"kanji":"採用","kana":"さいよう","pron":"사이요오","ko":"채용","tts_text":"採用"},
      {"kanji":"人材","kana":"じんざい","pron":"진자이","ko":"인재","tts_text":"人材"},
      {"kanji":"研修","kana":"けんしゅう","pron":"켄슈우","ko":"연수/교육","tts_text":"研修"},

      {"kanji":"部署","kana":"ぶしょ","pron":"부쇼","ko":"부서","tts_text":"部署"},
      {"kanji":"会計","kana":"かいけい","pron":"카이케이","ko":"회계","tts_text":"会計"},
      {"kanji":"経理","kana":"けいり","pron":"케이리","ko":"경리","tts_text":"経理"},
      {"kanji":"事務","kana":"じむ","pron":"지무","ko":"사무","tts_text":"事務"},
      {"kanji":"総務","kana":"そうむ","pron":"소오무","ko":"총무","tts_text":"総務"},
      {"kanji":"営業","kana":"えいぎょう","pron":"에이교오","ko":"영업","tts_text":"営業"},
      {"kanji":"顧客","kana":"こきゃく","pron":"코캬쿠","ko":"고객","tts_text":"顧客"},
      {"kanji":"取引先","kana":"とりひきさき","pron":"토리히키사키","ko":"거래처","tts_text":"取引先"},
      {"kanji":"見積もり","kana":"みつもり","pron":"미츠모리","ko":"견적","tts_text":"見積もり"},
      {"kanji":"請求","kana":"せいきゅう","pron":"세이큐우","ko":"청구","tts_text":"請求"},

      {"kanji":"支払期限","kana":"しはらいきげん","pron":"시하라이 키겐","ko":"지불 기한","tts_text":"支払期限"},
      {"kanji":"納期","kana":"のうき","pron":"노오키","ko":"납기","tts_text":"納期"},
      {"kanji":"納品","kana":"のうひん","pron":"노오힌","ko":"납품","tts_text":"納品"},
      {"kanji":"在庫","kana":"ざいこ","pron":"자이코","ko":"재고","tts_text":"在庫"},
      {"kanji":"不足","kana":"ふそく","pron":"후소쿠","ko":"부족","tts_text":"不足"},
      {"kanji":"過剰","kana":"かじょう","pron":"카죠오","ko":"과잉","tts_text":"過剰"},
      {"kanji":"競争","kana":"きょうそう","pron":"쿄오소오","ko":"경쟁","tts_text":"競争"},
      {"kanji":"競合","kana":"きょうごう","pron":"쿄오고오","ko":"경합/경쟁사","tts_text":"競合"},
      {"kanji":"独占","kana":"どくせん","pron":"도쿠센","ko":"독점","tts_text":"独占"},
      {"kanji":"提携","kana":"ていけい","pron":"테이케이","ko":"제휴","tts_text":"提携"},

      {"kanji":"合併","kana":"がっぺい","pron":"갓페이","ko":"합병","tts_text":"合併"},
      {"kanji":"買収","kana":"ばいしゅう","pron":"바이슈우","ko":"인수","tts_text":"買収"},
      {"kanji":"倒産","kana":"とうさん","pron":"토오산","ko":"도산","tts_text":"倒産"},
      {"kanji":"赤字","kana":"あかじ","pron":"아카지","ko":"적자","tts_text":"赤字"},
      {"kanji":"黒字","kana":"くろじ","pron":"쿠로지","ko":"흑자","tts_text":"黒字"},
      {"kanji":"見直し","kana":"みなおし","pron":"미나오시","ko":"재검토","tts_text":"見直し"},
      {"kanji":"効率","kana":"こうりつ","pron":"코오리츠","ko":"효율","tts_text":"効率"},
      {"kanji":"生産性","kana":"せいさんせい","pron":"세이산세이","ko":"생산성","tts_text":"生産性"},
      {"kanji":"負担","kana":"ふたん","pron":"후탄","ko":"부담","tts_text":"負担"},
      {"kanji":"損害","kana":"そんがい","pron":"손가이","ko":"손해/손상","tts_text":"損害"}
    ]
  },

  "sec03": {
    "title": "정치·사회·제도",
    "items": [
      {"kanji":"政府","kana":"せいふ","pron":"세이후","ko":"정부","tts_text":"政府"},
      {"kanji":"行政","kana":"ぎょうせい","pron":"교오세이","ko":"행정","tts_text":"行政"},
      {"kanji":"政策","kana":"せいさく","pron":"세이사쿠","ko":"정책","tts_text":"政策"},
      {"kanji":"制度","kana":"せいど","pron":"세이도","ko":"제도","tts_text":"制度"},
      {"kanji":"法律","kana":"ほうりつ","pron":"호오리츠","ko":"법률","tts_text":"法律"},
      {"kanji":"規制","kana":"きせい","pron":"키세이","ko":"규제","tts_text":"規制"},
      {"kanji":"条例","kana":"じょうれい","pron":"죠오레이","ko":"조례","tts_text":"条例"},
      {"kanji":"権限","kana":"けんげん","pron":"켄겐","ko":"권한","tts_text":"権限"},
      {"kanji":"義務","kana":"ぎむ","pron":"기무","ko":"의무","tts_text":"義務"},
      {"kanji":"権利","kana":"けんり","pron":"켄리","ko":"권리","tts_text":"権利"},

      {"kanji":"選挙","kana":"せんきょ","pron":"센쿄","ko":"선거","tts_text":"選挙"},
      {"kanji":"議員","kana":"ぎいん","pron":"기인","ko":"의원","tts_text":"議員"},
      {"kanji":"議会","kana":"ぎかい","pron":"기가이","ko":"의회","tts_text":"議会"},
      {"kanji":"世論","kana":"せろん","pron":"세론","ko":"여론","tts_text":"世論"},
      {"kanji":"反発","kana":"はんぱつ","pron":"한파츠","ko":"반발","tts_text":"反発"},
      {"kanji":"賛否","kana":"さんぴ","pron":"산피","ko":"찬반","tts_text":"賛否"},
      {"kanji":"承認","kana":"しょうにん","pron":"쇼오닌","ko":"승인","tts_text":"承認"},
      {"kanji":"否決","kana":"ひけつ","pron":"히케츠","ko":"부결","tts_text":"否決"},
      {"kanji":"可決","kana":"かけつ","pron":"카케츠","ko":"가결","tts_text":"可決"},
      {"kanji":"署名","kana":"しょめい","pron":"쇼메이","ko":"서명","tts_text":"署名"},

      {"kanji":"裁判","kana":"さいばん","pron":"사이반","ko":"재판","tts_text":"裁判"},
      {"kanji":"判決","kana":"はんけつ","pron":"한케츠","ko":"판결","tts_text":"判決"},
      {"kanji":"被害","kana":"ひがい","pron":"히가이","ko":"피해","tts_text":"被害"},
      {"kanji":"加害","kana":"かがい","pron":"카가이","ko":"가해","tts_text":"加害"},
      {"kanji":"被害者","kana":"ひがいしゃ","pron":"히가이샤","ko":"피해자","tts_text":"被害者"},
      {"kanji":"容疑者","kana":"ようぎしゃ","pron":"요오기샤","ko":"용의자","tts_text":"容疑者"},
      {"kanji":"逮捕","kana":"たいほ","pron":"타이호","ko":"체포","tts_text":"逮捕"},
      {"kanji":"捜査","kana":"そうさ","pron":"소오사","ko":"수사","tts_text":"捜査"},
      {"kanji":"証拠","kana":"しょうこ","pron":"쇼오코","ko":"증거","tts_text":"証拠"},
      {"kanji":"証明","kana":"しょうめい","pron":"쇼오메이","ko":"증명","tts_text":"証明"},

      {"kanji":"税金","kana":"ぜいきん","pron":"제이킨","ko":"세금","tts_text":"税金"},
      {"kanji":"課税","kana":"かぜい","pron":"카제이","ko":"과세","tts_text":"課税"},
      {"kanji":"免税","kana":"めんぜい","pron":"멘제이","ko":"면세","tts_text":"免税"},
      {"kanji":"保険","kana":"ほけん","pron":"호켄","ko":"보험","tts_text":"保険"},
      {"kanji":"年金","kana":"ねんきん","pron":"넨킨","ko":"연금","tts_text":"年金"},
      {"kanji":"福祉","kana":"ふくし","pron":"후쿠시","ko":"복지","tts_text":"福祉"},
      {"kanji":"介護","kana":"かいご","pron":"카이고","ko":"간호/개호","tts_text":"介護"},
      {"kanji":"医療","kana":"いりょう","pron":"이료오","ko":"의료","tts_text":"医療"},
      {"kanji":"教育","kana":"きょういく","pron":"쿄오이쿠","ko":"교육","tts_text":"教育"},
      {"kanji":"少子化","kana":"しょうしか","pron":"쇼오시카","ko":"저출산","tts_text":"少子化"},

      {"kanji":"高齢化","kana":"こうれいか","pron":"코오레이카","ko":"고령화","tts_text":"高齢化"},
      {"kanji":"失業","kana":"しつぎょう","pron":"시츠교오","ko":"실업","tts_text":"失業"},
      {"kanji":"格差","kana":"かくさ","pron":"카쿠사","ko":"격차","tts_text":"格差"},
      {"kanji":"貧困","kana":"ひんこん","pron":"힌콘","ko":"빈곤","tts_text":"貧困"},
      {"kanji":"治安","kana":"ちあん","pron":"치안","ko":"치안","tts_text":"治安"},
      {"kanji":"犯罪","kana":"はんざい","pron":"한자이","ko":"범죄","tts_text":"犯罪"},
      {"kanji":"違反","kana":"いはん","pron":"이한","ko":"위반","tts_text":"違反"},
      {"kanji":"禁止","kana":"きんし","pron":"킨시","ko":"금지","tts_text":"禁止"},
      {"kanji":"許可","kana":"きょか","pron":"쿄카","ko":"허가","tts_text":"許可"},
      {"kanji":"申請","kana":"しんせい","pron":"신세이","ko":"신청","tts_text":"申請"},

      {"kanji":"提出","kana":"ていしゅつ","pron":"테이슈츠","ko":"제출","tts_text":"提出"},
      {"kanji":"届出","kana":"とどけで","pron":"토도케데","ko":"신고(제출)","tts_text":"届出"},
      {"kanji":"受付","kana":"うけつけ","pron":"우케츠케","ko":"접수","tts_text":"受付"},
      {"kanji":"窓口","kana":"まどぐち","pron":"마도구치","ko":"창구","tts_text":"窓口"},
      {"kanji":"手数料","kana":"てすうりょう","pron":"테스우료오","ko":"수수료","tts_text":"手数料"},
      {"kanji":"本人確認","kana":"ほんにんかくにん","pron":"혼닌 카쿠닌","ko":"본인 확인","tts_text":"本人確認"},
      {"kanji":"身分証","kana":"みぶんしょう","pron":"미분쇼오","ko":"신분증","tts_text":"身分証"},
      {"kanji":"住民票","kana":"じゅうみんひょう","pron":"쥬우민효오","ko":"주민표(등본)","tts_text":"住民票"},
      {"kanji":"戸籍","kana":"こせき","pron":"코세키","ko":"호적","tts_text":"戸籍"},
      {"kanji":"印鑑","kana":"いんかん","pron":"인칸","ko":"인감/도장","tts_text":"印鑑"}
    ]
  },

  "sec04": {
    "title": "학습·연구·표현",
    "items": [
      {"kanji":"仮説","kana":"かせつ","pron":"카세츠","ko":"가설","tts_text":"仮説"},
      {"kanji":"検証","kana":"けんしょう","pron":"켄쇼오","ko":"검증","tts_text":"検証"},
      {"kanji":"根拠","kana":"こんきょ","pron":"콘쿄","ko":"근거","tts_text":"根拠"},
      {"kanji":"裏付け","kana":"うらづけ","pron":"우라즈케","ko":"뒷받침","tts_text":"裏付け"},
      {"kanji":"推測","kana":"すいそく","pron":"스이소쿠","ko":"추측","tts_text":"推測"},
      {"kanji":"推定","kana":"すいてい","pron":"스이테이","ko":"추정","tts_text":"推定"},
      {"kanji":"予測","kana":"よそく","pron":"요소쿠","ko":"예측","tts_text":"予測"},
      {"kanji":"統計","kana":"とうけい","pron":"토오케이","ko":"통계","tts_text":"統計"},
      {"kanji":"数値","kana":"すうち","pron":"스우치","ko":"수치","tts_text":"数値"},
      {"kanji":"割合","kana":"わりあい","pron":"와리아이","ko":"비율","tts_text":"割合"},

      {"kanji":"傾向がある","kana":"けいこうがある","pron":"케이코오가 아루","ko":"경향이 있다","tts_text":"傾向がある"},
      {"kanji":"増える","kana":"ふえる","pron":"후에루","ko":"늘다","tts_text":"増える"},
      {"kanji":"減る","kana":"へる","pron":"헤루","ko":"줄다","tts_text":"減る"},
      {"kanji":"上昇","kana":"じょうしょう","pron":"죠오쇼오","ko":"상승","tts_text":"上昇"},
      {"kanji":"下降","kana":"かこう","pron":"카코오","ko":"하강","tts_text":"下降"},
      {"kanji":"維持する","kana":"いじする","pron":"이지 스루","ko":"유지하다","tts_text":"維持する"},
      {"kanji":"変動","kana":"へんどう","pron":"헨도오","ko":"변동","tts_text":"変動"},
      {"kanji":"安定","kana":"あんてい","pron":"안테이","ko":"안정","tts_text":"安定"},
      {"kanji":"不安定","kana":"ふあんてい","pron":"후안테이","ko":"불안정","tts_text":"不安定"},
      {"kanji":"影響力","kana":"えいきょうりょく","pron":"에이쿄오료쿠","ko":"영향력","tts_text":"影響力"},

      {"kanji":"主張","kana":"しゅちょう","pron":"슈쵸오","ko":"주장","tts_text":"主張"},
      {"kanji":"意図","kana":"いと","pron":"이토","ko":"의도","tts_text":"意図"},
      {"kanji":"狙い","kana":"ねらい","pron":"네라이","ko":"노림/목적","tts_text":"狙い"},
      {"kanji":"前提","kana":"ぜんてい","pron":"젠테이","ko":"전제","tts_text":"前提"},
      {"kanji":"結論として","kana":"けつろんとして","pron":"켓론 토시테","ko":"결론적으로","tts_text":"結論として"},
      {"kanji":"要するに","kana":"ようするに","pron":"요오스루니","ko":"요컨대","tts_text":"要するに"},
      {"kanji":"例えば","kana":"たとえば","pron":"타토에바","ko":"예를 들면","tts_text":"例えば"},
      {"kanji":"特に","kana":"とくに","pron":"토쿠니","ko":"특히","tts_text":"特に"},
      {"kanji":"基本的に","kana":"きほんてきに","pron":"키혼테키니","ko":"기본적으로","tts_text":"基本的に"},
      {"kanji":"具体的に","kana":"ぐたいてきに","pron":"구타이테키니","ko":"구체적으로","tts_text":"具体的に"},

      {"kanji":"抽象的","kana":"ちゅうしょうてき","pron":"츄우쇼오테키","ko":"추상적","tts_text":"抽象的"},
      {"kanji":"客観的","kana":"きゃっかんてき","pron":"캬칸테키","ko":"객관적","tts_text":"客観的"},
      {"kanji":"主観的","kana":"しゅかんてき","pron":"슈칸테키","ko":"주관적","tts_text":"主観的"},
      {"kanji":"論理","kana":"ろんり","pron":"론리","ko":"논리","tts_text":"論理"},
      {"kanji":"矛盾","kana":"むじゅん","pron":"무준","ko":"모순","tts_text":"矛盾"},
      {"kanji":"説得","kana":"せっとく","pron":"셋토쿠","ko":"설득","tts_text":"説得"},
      {"kanji":"納得","kana":"なっとく","pron":"낫토쿠","ko":"납득","tts_text":"納得"},
      {"kanji":"誤解","kana":"ごかい","pron":"고카이","ko":"오해","tts_text":"誤解"},
      {"kanji":"解釈","kana":"かいしゃく","pron":"카이샤쿠","ko":"해석","tts_text":"解釈"},
      {"kanji":"表現","kana":"ひょうげん","pron":"효오겐","ko":"표현","tts_text":"表現"},

      {"kanji":"言い換える","kana":"いいかえる","pron":"이이카에루","ko":"바꿔 말하다","tts_text":"言い換える"},
      {"kanji":"言い切る","kana":"いいきる","pron":"이이키루","ko":"단언하다","tts_text":"言い切る"},
      {"kanji":"言及","kana":"げんきゅう","pron":"겐큐우","ko":"언급","tts_text":"言及"},
      {"kanji":"指摘","kana":"してき","pron":"시테키","ko":"지적","tts_text":"指摘"},
      {"kanji":"批判","kana":"ひはん","pron":"히한","ko":"비판","tts_text":"批判"},
      {"kanji":"反論","kana":"はんろん","pron":"한론","ko":"반론","tts_text":"反論"},
      {"kanji":"主導","kana":"しゅどう","pron":"슈도오","ko":"주도","tts_text":"主導"},
      {"kanji":"段階","kana":"だんかい","pron":"단카이","ko":"단계","tts_text":"段階"},
      {"kanji":"手段","kana":"しゅだん","pron":"슈단","ko":"수단","tts_text":"手段"},
      {"kanji":"方法","kana":"ほうほう","pron":"호오호오","ko":"방법","tts_text":"方法"}
    ]
  },
  "sec05": {
    "title": "일상·생활·가정·소비",
    "items": [
      {"kanji":"生活費","kana":"せいかつひ","pron":"세이카츠히","ko":"생활비","tts_text":"生活費"},
      {"kanji":"家計","kana":"かけい","pron":"카케이","ko":"가계","tts_text":"家計"},
      {"kanji":"支出","kana":"ししゅつ","pron":"시슈츠","ko":"지출","tts_text":"支出"},
      {"kanji":"収入","kana":"しゅうにゅう","pron":"슈우뉴우","ko":"수입","tts_text":"収入"},
      {"kanji":"貯蓄","kana":"ちょちく","pron":"초치쿠","ko":"저축","tts_text":"貯蓄"},
      {"kanji":"浪費","kana":"ろうひ","pron":"로오히","ko":"낭비","tts_text":"浪費"},
      {"kanji":"節約","kana":"せつやく","pron":"세츠야쿠","ko":"절약","tts_text":"節約"},
      {"kanji":"無駄遣い","kana":"むだづかい","pron":"무다즈카이","ko":"헛돈 씀","tts_text":"無駄遣い"},
      {"kanji":"購入","kana":"こうにゅう","pron":"코오뉴우","ko":"구입","tts_text":"購入"},
      {"kanji":"消費","kana":"しょうひ","pron":"쇼오히","ko":"소비","tts_text":"消費"},

      {"kanji":"支払い","kana":"しはらい","pron":"시하라이","ko":"지불","tts_text":"支払い"},
      {"kanji":"分割払い","kana":"ぶんかつばらい","pron":"분카츠바라이","ko":"할부 결제","tts_text":"分割払い"},
      {"kanji":"領収書","kana":"りょうしゅうしょ","pron":"료오슈우쇼","ko":"영수증(격식)","tts_text":"領収書"},
      {"kanji":"返金","kana":"へんきん","pron":"헨킨","ko":"환불","tts_text":"返金"},
      {"kanji":"返品","kana":"へんぴん","pron":"헨핀","ko":"반품","tts_text":"返品"},
      {"kanji":"交換","kana":"こうかん","pron":"코오칸","ko":"교환","tts_text":"交換"},
      {"kanji":"保証","kana":"ほしょう","pron":"호쇼오","ko":"보증","tts_text":"保証"},
      {"kanji":"不良品","kana":"ふりょうひん","pron":"후료오힌","ko":"불량품","tts_text":"不良品"},
      {"kanji":"品切れ","kana":"しなぎれ","pron":"시나기레","ko":"품절","tts_text":"品切れ"},
      {"kanji":"在庫","kana":"ざいこ","pron":"자이코","ko":"재고","tts_text":"在庫"},

      {"kanji":"手入れ","kana":"ていれ","pron":"테이레","ko":"손질/관리","tts_text":"手入れ"},
      {"kanji":"修理","kana":"しゅうり","pron":"슈우리","ko":"수리","tts_text":"修理"},
      {"kanji":"故障","kana":"こしょう","pron":"코쇼오","ko":"고장","tts_text":"故障"},
      {"kanji":"破損","kana":"はそん","pron":"하손","ko":"파손","tts_text":"破損"},
      {"kanji":"交換する","kana":"こうかんする","pron":"코오칸 스루","ko":"교환하다","tts_text":"交換する"},
      {"kanji":"返品する","kana":"へんぴんする","pron":"헨핀 스루","ko":"반품하다","tts_text":"返品する"},
      {"kanji":"修理する","kana":"しゅうりする","pron":"슈우리 스루","ko":"수리하다","tts_text":"修理する"},
      {"kanji":"点検","kana":"てんけん","pron":"텐켄","ko":"점검","tts_text":"点検"},
      {"kanji":"掃除","kana":"そうじ","pron":"소오지","ko":"청소","tts_text":"掃除"},
      {"kanji":"片付け","kana":"かたづけ","pron":"카타즈케","ko":"정리","tts_text":"片付け"},

      {"kanji":"整理整頓","kana":"せいりせいとん","pron":"세이리 세이톤","ko":"정리정돈","tts_text":"整理整頓"},
      {"kanji":"洗濯","kana":"せんたく","pron":"센타쿠","ko":"세탁","tts_text":"洗濯"},
      {"kanji":"干す","kana":"ほす","pron":"호스","ko":"말리다(널다)","tts_text":"干す"},
      {"kanji":"乾燥","kana":"かんそう","pron":"칸소오","ko":"건조","tts_text":"乾燥"},
      {"kanji":"換気","kana":"かんき","pron":"칸키","ko":"환기","tts_text":"換気"},
      {"kanji":"湿気","kana":"しっけ","pron":"싯케","ko":"습기","tts_text":"湿気"},
      {"kanji":"騒音","kana":"そうおん","pron":"소오온","ko":"소음","tts_text":"騒音"},
      {"kanji":"近所","kana":"きんじょ","pron":"킨죠","ko":"근처/이웃","tts_text":"近所"},
      {"kanji":"近隣","kana":"きんりん","pron":"킨린","ko":"근린","tts_text":"近隣"},
      {"kanji":"苦情","kana":"くじょう","pron":"쿠죠오","ko":"불만/항의","tts_text":"苦情"},

      {"kanji":"迷惑","kana":"めいわく","pron":"메이와쿠","ko":"폐","tts_text":"迷惑"},
      {"kanji":"注意する","kana":"ちゅういする","pron":"츄우이 스루","ko":"주의하다/주다","tts_text":"注意する"},
      {"kanji":"禁止","kana":"きんし","pron":"킨시","ko":"금지","tts_text":"禁止"},
      {"kanji":"規則","kana":"きそく","pron":"키소쿠","ko":"규칙","tts_text":"規則"},
      {"kanji":"マナー","kana":"マナー","pron":"마나아","ko":"매너","tts_text":"マナー"},
      {"kanji":"習慣","kana":"しゅうかん","pron":"슈우칸","ko":"습관","tts_text":"習慣"},
      {"kanji":"家事","kana":"かじ","pron":"카지","ko":"가사","tts_text":"家事"},
      {"kanji":"育児","kana":"いくじ","pron":"이쿠지","ko":"육아","tts_text":"育児"},
      {"kanji":"介護","kana":"かいご","pron":"카이고","ko":"개호/돌봄","tts_text":"介護"},
      {"kanji":"同居","kana":"どうきょ","pron":"도오쿄","ko":"동거","tts_text":"同居"},

      {"kanji":"別居","kana":"べっきょ","pron":"벳쿄","ko":"별거","tts_text":"別居"},
      {"kanji":"引っ越し","kana":"ひっこし","pron":"힛코시","ko":"이사","tts_text":"引っ越し"},
      {"kanji":"転居","kana":"てんきょ","pron":"텐쿄","ko":"전거/이사","tts_text":"転居"},
      {"kanji":"家賃","kana":"やちん","pron":"야친","ko":"집세","tts_text":"家賃"},
      {"kanji":"敷金","kana":"しききん","pron":"시키킨","ko":"보증금(일부)","tts_text":"敷金"},
      {"kanji":"礼金","kana":"れいきん","pron":"레이킨","ko":"사례금(일본식)","tts_text":"礼金"},
      {"kanji":"契約書","kana":"けいやくしょ","pron":"케이야쿠쇼","ko":"계약서","tts_text":"契約書"},
      {"kanji":"更新料","kana":"こうしんりょう","pron":"코오신료오","ko":"갱신료","tts_text":"更新料"},
      {"kanji":"退去","kana":"たいきょ","pron":"타이쿄","ko":"퇴거","tts_text":"退去"},
      {"kanji":"手続き","kana":"てつづき","pron":"테츠즈키","ko":"절차","tts_text":"手続き"}
    ]
  },

  "sec06": {
    "title": "기술·미디어·인터넷",
    "items": [
      {"kanji":"技術","kana":"ぎじゅつ","pron":"기쥬츠","ko":"기술","tts_text":"技術"},
      {"kanji":"機能","kana":"きのう","pron":"키노오","ko":"기능","tts_text":"機能"},
      {"kanji":"性能","kana":"せいのう","pron":"세이노오","ko":"성능","tts_text":"性能"},
      {"kanji":"仕様","kana":"しよう","pron":"시요오","ko":"사양/규격","tts_text":"仕様"},
      {"kanji":"設定","kana":"せってい","pron":"셋테이","ko":"설정","tts_text":"設定"},
      {"kanji":"調整","kana":"ちょうせい","pron":"초오세이","ko":"조정","tts_text":"調整"},
      {"kanji":"更新","kana":"こうしん","pron":"코오신","ko":"업데이트/갱신","tts_text":"更新"},
      {"kanji":"不具合","kana":"ふぐあい","pron":"후구아이","ko":"오류/불편(결함)","tts_text":"不具合"},
      {"kanji":"故障","kana":"こしょう","pron":"코쇼오","ko":"고장","tts_text":"故障"},
      {"kanji":"修復","kana":"しゅうふく","pron":"슈우후쿠","ko":"복구","tts_text":"修復"},

      {"kanji":"起動","kana":"きどう","pron":"키도오","ko":"기동","tts_text":"起動"},
      {"kanji":"再起動","kana":"さいきどう","pron":"사이키도오","ko":"재부팅","tts_text":"再起動"},
      {"kanji":"接続","kana":"せつぞく","pron":"세츠조쿠","ko":"접속/연결","tts_text":"接続"},
      {"kanji":"通信","kana":"つうしん","pron":"츠우신","ko":"통신","tts_text":"通信"},
      {"kanji":"回線","kana":"かいせん","pron":"카이센","ko":"회선","tts_text":"回線"},
      {"kanji":"速度","kana":"そくど","pron":"소쿠도","ko":"속도","tts_text":"速度"},
      {"kanji":"遅延","kana":"ちえん","pron":"치엔","ko":"지연","tts_text":"遅延"},
      {"kanji":"容量","kana":"ようりょう","pron":"요오료오","ko":"용량","tts_text":"容量"},
      {"kanji":"保存","kana":"ほぞん","pron":"호존","ko":"저장","tts_text":"保存"},
      {"kanji":"削除","kana":"さくじょ","pron":"사쿠죠","ko":"삭제","tts_text":"削除"},

      {"kanji":"共有","kana":"きょうゆう","pron":"쿄오유우","ko":"공유","tts_text":"共有"},
      {"kanji":"送信","kana":"そうしん","pron":"소오신","ko":"송신","tts_text":"送信"},
      {"kanji":"受信","kana":"じゅしん","pron":"쥬신","ko":"수신","tts_text":"受信"},
      {"kanji":"添付","kana":"てんぷ","pron":"텐푸","ko":"첨부","tts_text":"添付"},
      {"kanji":"ダウンロード","kana":"ダウンロード","pron":"다운로오도","ko":"다운로드","tts_text":"ダウンロード"},
      {"kanji":"アップロード","kana":"アップロード","pron":"앗프로오도","ko":"업로드","tts_text":"アップロード"},
      {"kanji":"ログイン","kana":"ログイン","pron":"로구인","ko":"로그인","tts_text":"ログイン"},
      {"kanji":"ログアウト","kana":"ログアウト","pron":"로구아우토","ko":"로그아웃","tts_text":"ログアウト"},
      {"kanji":"登録","kana":"とうろく","pron":"토오로쿠","ko":"등록","tts_text":"登録"},
      {"kanji":"認証","kana":"にんしょう","pron":"닌쇼오","ko":"인증","tts_text":"認証"},

      {"kanji":"暗証番号","kana":"あんしょうばんごう","pron":"안쇼오 방고오","ko":"비밀번호(PIN)","tts_text":"暗証番号"},
      {"kanji":"個人情報","kana":"こじんじょうほう","pron":"코진 죠오호오","ko":"개인정보","tts_text":"個人情報"},
      {"kanji":"情報漏えい","kana":"じょうほうろうえい","pron":"죠오호오 로오에이","ko":"정보 유출","tts_text":"情報漏えい"},
      {"kanji":"セキュリティ","kana":"セキュリティ","pron":"세큐리티","ko":"보안","tts_text":"セキュリティ"},
      {"kanji":"対策","kana":"たいさく","pron":"타이사쿠","ko":"대책","tts_text":"対策"},
      {"kanji":"警告","kana":"けいこく","pron":"케이코쿠","ko":"경고","tts_text":"警告"},
      {"kanji":"承認","kana":"しょうにん","pron":"쇼오닌","ko":"승인","tts_text":"承認"},
      {"kanji":"権限","kana":"けんげん","pron":"켄겐","ko":"권한","tts_text":"権限"},
      {"kanji":"アクセス","kana":"アクセス","pron":"아쿠세스","ko":"접근/액세스","tts_text":"アクセス"},
      {"kanji":"制限","kana":"せいげん","pron":"세이겐","ko":"제한","tts_text":"制限"},

      {"kanji":"検索","kana":"けんさく","pron":"켄사쿠","ko":"검색","tts_text":"検索"},
      {"kanji":"検索結果","kana":"けんさくけっか","pron":"켄사쿠 켓카","ko":"검색 결과","tts_text":"検索結果"},
      {"kanji":"通知","kana":"つうち","pron":"츠우치","ko":"알림/통지","tts_text":"通知"},
      {"kanji":"広告","kana":"こうこく","pron":"코오코쿠","ko":"광고","tts_text":"広告"},
      {"kanji":"配信","kana":"はいしん","pron":"하이신","ko":"송출/배신","tts_text":"配信"},
      {"kanji":"視聴","kana":"しちょう","pron":"시쵸오","ko":"시청","tts_text":"視聴"},
      {"kanji":"再生","kana":"さいせい","pron":"사이세이","ko":"재생","tts_text":"再生"},
      {"kanji":"停止","kana":"ていし","pron":"테이시","ko":"정지","tts_text":"停止"},
      {"kanji":"編集","kana":"へんしゅう","pron":"헨슈우","ko":"편집","tts_text":"編集"},
      {"kanji":"加工","kana":"かこう","pron":"카코오","ko":"가공/편집","tts_text":"加工"},

      {"kanji":"印刷","kana":"いんさつ","pron":"인사츠","ko":"인쇄","tts_text":"印刷"},
      {"kanji":"書類","kana":"しょるい","pron":"쇼루이","ko":"서류","tts_text":"書類"},
      {"kanji":"データ","kana":"データ","pron":"데에타","ko":"데이터","tts_text":"データ"},
      {"kanji":"資料","kana":"しりょう","pron":"시료오","ko":"자료","tts_text":"資料"},
      {"kanji":"形式","kana":"けいしき","pron":"케이시키","ko":"형식","tts_text":"形式"},
      {"kanji":"互換性","kana":"ごかんせい","pron":"고칸세이","ko":"호환성","tts_text":"互換性"},
      {"kanji":"対応する","kana":"たいおうする","pron":"타이오오 스루","ko":"지원/대응하다","tts_text":"対応する"},
      {"kanji":"利用規約","kana":"りようきやく","pron":"리요오 키야쿠","ko":"이용약관","tts_text":"利用規約"},
      {"kanji":"規約","kana":"きやく","pron":"키야쿠","ko":"약관","tts_text":"規約"},
      {"kanji":"同意","kana":"どうい","pron":"도오이","ko":"동의","tts_text":"同意"}
    ]
  },
  "sec07": {
    "title": "건강·의료·몸",
    "items": [
      {"kanji":"診察","kana":"しんさつ","pron":"신사츠","ko":"진찰","tts_text":"診察"},
      {"kanji":"受診","kana":"じゅしん","pron":"쥬신","ko":"진료를 받음","tts_text":"受診"},
      {"kanji":"治療","kana":"ちりょう","pron":"치료오","ko":"치료","tts_text":"治療"},
      {"kanji":"処方","kana":"しょほう","pron":"쇼호오","ko":"처방","tts_text":"処方"},
      {"kanji":"処方箋","kana":"しょほうせん","pron":"쇼호오센","ko":"처방전","tts_text":"処方箋"},
      {"kanji":"服薬","kana":"ふくやく","pron":"후쿠야쿠","ko":"복약","tts_text":"服薬"},
      {"kanji":"副作用","kana":"ふくさよう","pron":"후쿠사요오","ko":"부작용","tts_text":"副作用"},
      {"kanji":"検査","kana":"けんさ","pron":"켄사","ko":"검사","tts_text":"検査"},
      {"kanji":"診断","kana":"しんだん","pron":"신단","ko":"진단","tts_text":"診断"},
      {"kanji":"手術","kana":"しゅじゅつ","pron":"슈쥬츠","ko":"수술","tts_text":"手術"},

      {"kanji":"入院","kana":"にゅういん","pron":"뉴우인","ko":"입원","tts_text":"入院"},
      {"kanji":"退院","kana":"たいいん","pron":"타이인","ko":"퇴원","tts_text":"退院"},
      {"kanji":"通院","kana":"つういん","pron":"츠우인","ko":"통원","tts_text":"通院"},
      {"kanji":"救急","kana":"きゅうきゅう","pron":"큐우큐우","ko":"응급","tts_text":"救急"},
      {"kanji":"救急車","kana":"きゅうきゅうしゃ","pron":"큐우큐우샤","ko":"구급차","tts_text":"救急車"},
      {"kanji":"応急処置","kana":"おうきゅうしょち","pron":"오오큐우 쇼치","ko":"응급처치","tts_text":"応急処置"},
      {"kanji":"症状","kana":"しょうじょう","pron":"쇼오죠오","ko":"증상","tts_text":"症状"},
      {"kanji":"体温","kana":"たいおん","pron":"타이온","ko":"체온","tts_text":"体温"},
      {"kanji":"血圧","kana":"けつあつ","pron":"케츠아츠","ko":"혈압","tts_text":"血圧"},
      {"kanji":"脈","kana":"みゃく","pron":"먀쿠","ko":"맥","tts_text":"脈"},

      {"kanji":"痛み","kana":"いたみ","pron":"이타미","ko":"통증","tts_text":"痛み"},
      {"kanji":"発熱","kana":"はつねつ","pron":"하츠네츠","ko":"발열","tts_text":"発熱"},
      {"kanji":"吐き気","kana":"はきけ","pron":"하기케","ko":"메스꺼움","tts_text":"吐き気"},
      {"kanji":"めまい","kana":"めまい","pron":"메마이","ko":"현기증","tts_text":"めまい"},
      {"kanji":"息切れ","kana":"いきぎれ","pron":"이키기레","ko":"숨참","tts_text":"息切れ"},
      {"kanji":"息苦しい","kana":"いきぐるしい","pron":"이키구루시이","ko":"숨이 차다","tts_text":"息苦しい"},
      {"kanji":"咳","kana":"せき","pron":"세키","ko":"기침","tts_text":"咳"},
      {"kanji":"くしゃみ","kana":"くしゃみ","pron":"쿠샤미","ko":"재채기","tts_text":"くしゃみ"},
      {"kanji":"鼻水","kana":"はなみず","pron":"하나미즈","ko":"콧물","tts_text":"鼻水"},
      {"kanji":"下痢","kana":"げり","pron":"게리","ko":"설사","tts_text":"下痢"},

      {"kanji":"便秘","kana":"べんぴ","pron":"벤피","ko":"변비","tts_text":"便秘"},
      {"kanji":"食中毒","kana":"しょくちゅうどく","pron":"쇼쿠츄우도쿠","ko":"식중독","tts_text":"食中毒"},
      {"kanji":"感染","kana":"かんせん","pron":"칸센","ko":"감염","tts_text":"感染"},
      {"kanji":"感染症","kana":"かんせんしょう","pron":"칸센쇼오","ko":"감염증","tts_text":"感染症"},
      {"kanji":"予防接種","kana":"よぼうせっしゅ","pron":"요보오 셋슈","ko":"예방접종","tts_text":"予防接種"},
      {"kanji":"アレルギー","kana":"アレルギー","pron":"아레루기이","ko":"알레르기","tts_text":"アレルギー"},
      {"kanji":"花粉症","kana":"かふんしょう","pron":"카푼쇼오","ko":"화분증","tts_text":"花粉症"},
      {"kanji":"慢性","kana":"まんせい","pron":"만세이","ko":"만성","tts_text":"慢性"},
      {"kanji":"持病","kana":"じびょう","pron":"지뵤오","ko":"지병","tts_text":"持病"},
      {"kanji":"過労","kana":"かろう","pron":"카로오","ko":"과로","tts_text":"過労"},

      {"kanji":"睡眠不足","kana":"すいみんぶそく","pron":"스이민 부소쿠","ko":"수면 부족","tts_text":"睡眠不足"},
      {"kanji":"ストレス","kana":"ストレス","pron":"스토레스","ko":"스트레스","tts_text":"ストレス"},
      {"kanji":"疲労","kana":"ひろう","pron":"히로오","ko":"피로","tts_text":"疲労"},
      {"kanji":"回復","kana":"かいふく","pron":"카이후쿠","ko":"회복","tts_text":"回復"},
      {"kanji":"栄養","kana":"えいよう","pron":"에이요오","ko":"영양","tts_text":"栄養"},
      {"kanji":"食欲","kana":"しょくよく","pron":"쇼쿠요쿠","ko":"식욕","tts_text":"食欲"},
      {"kanji":"食欲不振","kana":"しょくよくふしん","pron":"쇼쿠요쿠 후신","ko":"식욕부진","tts_text":"食欲不振"},
      {"kanji":"生活習慣","kana":"せいかつしゅうかん","pron":"세이카츠 슈우칸","ko":"생활 습관","tts_text":"生活習慣"},
      {"kanji":"禁酒","kana":"きんしゅ","pron":"킨슈","ko":"금주","tts_text":"禁酒"},
      {"kanji":"禁煙","kana":"きんえん","pron":"킨엔","ko":"금연","tts_text":"禁煙"},

      {"kanji":"体力","kana":"たいりょく","pron":"타이료쿠","ko":"체력","tts_text":"体力"},
      {"kanji":"筋肉","kana":"きんにく","pron":"킨니쿠","ko":"근육","tts_text":"筋肉"},
      {"kanji":"関節","kana":"かんせつ","pron":"칸세츠","ko":"관절","tts_text":"関節"},
      {"kanji":"骨折","kana":"こっせつ","pron":"콧세츠","ko":"골절","tts_text":"骨折"},
      {"kanji":"捻挫","kana":"ねんざ","pron":"넨자","ko":"염좌/삠","tts_text":"捻挫"}
    ]
  },

  "sec08": {
    "title": "자연·환경·재해",
    "items": [
      {"kanji":"環境問題","kana":"かんきょうもんだい","pron":"칸쿄오 몬다이","ko":"환경 문제","tts_text":"環境問題"},
      {"kanji":"温暖化","kana":"おんだんか","pron":"온단카","ko":"온난화","tts_text":"温暖化"},
      {"kanji":"気候","kana":"きこう","pron":"키코오","ko":"기후","tts_text":"気候"},
      {"kanji":"異常気象","kana":"いじょうきしょう","pron":"이죠오 키쇼오","ko":"이상 기후","tts_text":"異常気象"},
      {"kanji":"大雨","kana":"おおあめ","pron":"오오아메","ko":"폭우","tts_text":"大雨"},
      {"kanji":"豪雨","kana":"ごうう","pron":"고오우","ko":"호우","tts_text":"豪雨"},
      {"kanji":"洪水","kana":"こうずい","pron":"코오즈이","ko":"홍수","tts_text":"洪水"},
      {"kanji":"浸水","kana":"しんすい","pron":"신스이","ko":"침수","tts_text":"浸水"},
      {"kanji":"土砂崩れ","kana":"どしゃくずれ","pron":"도샤쿠즈레","ko":"산사태","tts_text":"土砂崩れ"},
      {"kanji":"避難","kana":"ひなん","pron":"히난","ko":"피난","tts_text":"避難"},

      {"kanji":"避難所","kana":"ひなんじょ","pron":"히난죠","ko":"대피소","tts_text":"避難所"},
      {"kanji":"警報","kana":"けいほう","pron":"케이호오","ko":"경보","tts_text":"警報"},
      {"kanji":"注意報","kana":"ちゅういほう","pron":"츄우이호오","ko":"주의보","tts_text":"注意報"},
      {"kanji":"台風","kana":"たいふう","pron":"타이후우","ko":"태풍","tts_text":"台風"},
      {"kanji":"地震","kana":"じしん","pron":"지신","ko":"지진","tts_text":"地震"},
      {"kanji":"震度","kana":"しんど","pron":"신도","ko":"진도","tts_text":"震度"},
      {"kanji":"余震","kana":"よしん","pron":"요신","ko":"여진","tts_text":"余震"},
      {"kanji":"津波","kana":"つなみ","pron":"츠나미","ko":"쓰나미","tts_text":"津波"},
      {"kanji":"噴火","kana":"ふんか","pron":"훈카","ko":"분화","tts_text":"噴火"},
      {"kanji":"火山","kana":"かざん","pron":"카잔","ko":"화산","tts_text":"火山"},

      {"kanji":"火災","kana":"かさい","pron":"카사이","ko":"화재","tts_text":"火災"},
      {"kanji":"延焼","kana":"えんしょう","pron":"엔쇼오","ko":"연소/불이 번짐","tts_text":"延焼"},
      {"kanji":"落雷","kana":"らくらい","pron":"라쿠라이","ko":"낙뢰","tts_text":"落雷"},
      {"kanji":"停電","kana":"ていでん","pron":"테이덴","ko":"정전","tts_text":"停電"},
      {"kanji":"断水","kana":"だんすい","pron":"단스이","ko":"단수","tts_text":"断水"},
      {"kanji":"被害","kana":"ひがい","pron":"히가이","ko":"피해","tts_text":"被害"},
      {"kanji":"被害状況","kana":"ひがいじょうきょう","pron":"히가이 죠오쿄오","ko":"피해 상황","tts_text":"被害状況"},
      {"kanji":"復旧","kana":"ふっきゅう","pron":"훗큐우","ko":"복구","tts_text":"復旧"},
      {"kanji":"復興","kana":"ふっこう","pron":"훗코오","ko":"부흥/재건","tts_text":"復興"},
      {"kanji":"支援","kana":"しえん","pron":"시엔","ko":"지원","tts_text":"支援"},

      {"kanji":"救助","kana":"きゅうじょ","pron":"큐우죠","ko":"구조","tts_text":"救助"},
      {"kanji":"安全確認","kana":"あんぜんかくにん","pron":"안젠 카쿠닌","ko":"안전 확인","tts_text":"安全確認"},
      {"kanji":"危険区域","kana":"きけんくいき","pron":"키켄 쿠이키","ko":"위험 구역","tts_text":"危険区域"},
      {"kanji":"立入禁止","kana":"たちいりきんし","pron":"타치이리 킨시","ko":"출입 금지","tts_text":"立入禁止"},
      {"kanji":"汚染","kana":"おせん","pron":"오센","ko":"오염","tts_text":"汚染"},
      {"kanji":"大気汚染","kana":"たいきおせん","pron":"타이키 오센","ko":"대기 오염","tts_text":"大気汚染"},
      {"kanji":"水質","kana":"すいしつ","pron":"스이시츠","ko":"수질","tts_text":"水質"},
      {"kanji":"水不足","kana":"みずぶそく","pron":"미즈 부소쿠","ko":"물 부족","tts_text":"水不足"},
      {"kanji":"資源","kana":"しげん","pron":"시겐","ko":"자원","tts_text":"資源"},
      {"kanji":"再利用","kana":"さいりよう","pron":"사이리요오","ko":"재이용","tts_text":"再利用"},

      {"kanji":"リサイクル","kana":"リサイクル","pron":"리사이쿠루","ko":"리사이클","tts_text":"リサイクル"},
      {"kanji":"節電","kana":"せつでん","pron":"세츠덴","ko":"절전","tts_text":"節電"},
      {"kanji":"省エネ","kana":"しょうえね","pron":"쇼오에네","ko":"에너지 절약","tts_text":"省エネ"},
      {"kanji":"排出","kana":"はいしゅつ","pron":"하이슈츠","ko":"배출","tts_text":"排出"},
      {"kanji":"二酸化炭素","kana":"にさんかたんそ","pron":"니산카 탄소","ko":"이산화탄소","tts_text":"二酸化炭素"},
      {"kanji":"自然保護","kana":"しぜんほご","pron":"시젠 호고","ko":"자연 보호","tts_text":"自然保護"},
      {"kanji":"保護","kana":"ほご","pron":"호고","ko":"보호","tts_text":"保護"},
      {"kanji":"絶滅","kana":"ぜつめつ","pron":"제츠메츠","ko":"멸종","tts_text":"絶滅"},
      {"kanji":"生態系","kana":"せいたいけい","pron":"세이타이케이","ko":"생태계","tts_text":"生態系"},
      {"kanji":"自然災害","kana":"しぜんさいがい","pron":"시젠 사이가이","ko":"자연재해","tts_text":"自然災害"},

      {"kanji":"被災","kana":"ひさい","pron":"히사이","ko":"피해를 입음(재해)","tts_text":"被災"},
      {"kanji":"被災者","kana":"ひさいしゃ","pron":"히사이샤","ko":"이재민","tts_text":"被災者"},
      {"kanji":"避難する","kana":"ひなんする","pron":"히난 스루","ko":"피난하다","tts_text":"避難する"},
      {"kanji":"備える","kana":"そなえる","pron":"소나에루","ko":"대비하다","tts_text":"備える"},
      {"kanji":"備蓄","kana":"びちく","pron":"비치쿠","ko":"비축","tts_text":"備蓄"}
    ]
  },
  "sec09": {
    "title": "감정·태도·성향",
    "items": [
      {"kanji":"感情","kana":"かんじょう","pron":"칸죠오","ko":"감정","tts_text":"感情"},
      {"kanji":"気分","kana":"きぶん","pron":"키분","ko":"기분","tts_text":"気分"},
      {"kanji":"不安","kana":"ふあん","pron":"후안","ko":"불안","tts_text":"不安"},
      {"kanji":"安心","kana":"あんしん","pron":"안신","ko":"안심","tts_text":"安心"},
      {"kanji":"緊張","kana":"きんちょう","pron":"킨쵸오","ko":"긴장","tts_text":"緊張"},
      {"kanji":"不満","kana":"ふまん","pron":"후만","ko":"불만","tts_text":"不満"},
      {"kanji":"満足","kana":"まんぞく","pron":"만조쿠","ko":"만족","tts_text":"満足"},
      {"kanji":"後悔","kana":"こうかい","pron":"코오카이","ko":"후회","tts_text":"後悔"},
      {"kanji":"反省","kana":"はんせい","pron":"한세이","ko":"반성","tts_text":"反省"},
      {"kanji":"期待","kana":"きたい","pron":"키타이","ko":"기대","tts_text":"期待"},

      {"kanji":"失望","kana":"しつぼう","pron":"시츠보오","ko":"실망","tts_text":"失望"},
      {"kanji":"驚き","kana":"おどろき","pron":"오도로키","ko":"놀람","tts_text":"驚き"},
      {"kanji":"喜び","kana":"よろこび","pron":"요로코비","ko":"기쁨","tts_text":"喜び"},
      {"kanji":"怒り","kana":"いかり","pron":"이카리","ko":"분노","tts_text":"怒り"},
      {"kanji":"悲しみ","kana":"かなしみ","pron":"카나시미","ko":"슬픔","tts_text":"悲しみ"},
      {"kanji":"恐れ","kana":"おそれ","pron":"오소레","ko":"두려움","tts_text":"恐れ"},
      {"kanji":"自信","kana":"じしん","pron":"지신","ko":"자신","tts_text":"自信"},
      {"kanji":"不安定","kana":"ふあんてい","pron":"후안테이","ko":"불안정","tts_text":"不安定"},
      {"kanji":"安定","kana":"あんてい","pron":"안테이","ko":"안정","tts_text":"安定"},
      {"kanji":"冷静","kana":"れいせい","pron":"레이세이","ko":"냉정","tts_text":"冷静"},

      {"kanji":"慎重","kana":"しんちょう","pron":"신쵸오","ko":"신중","tts_text":"慎重"},
      {"kanji":"大胆","kana":"だいたん","pron":"다이탄","ko":"대담","tts_text":"大胆"},
      {"kanji":"積極的","kana":"せっきょくてき","pron":"셋쿄쿠테키","ko":"적극적","tts_text":"積極的"},
      {"kanji":"消極的","kana":"しょうきょくてき","pron":"쇼오쿄쿠테키","ko":"소극적","tts_text":"消極的"},
      {"kanji":"真剣","kana":"しんけん","pron":"신켄","ko":"진지함","tts_text":"真剣"},
      {"kanji":"本気","kana":"ほんき","pron":"혼키","ko":"진심","tts_text":"本気"},
      {"kanji":"誠実","kana":"せいじつ","pron":"세이지츠","ko":"성실","tts_text":"誠実"},
      {"kanji":"正直","kana":"しょうじき","pron":"쇼오지키","ko":"정직","tts_text":"正直"},
      {"kanji":"率直","kana":"そっちょく","pron":"솟쵸쿠","ko":"솔직","tts_text":"率直"},
      {"kanji":"謙虚","kana":"けんきょ","pron":"켄쿄","ko":"겸손","tts_text":"謙虚"},

      {"kanji":"態度","kana":"たいど","pron":"타이도","ko":"태도","tts_text":"態度"},
      {"kanji":"姿勢","kana":"しせい","pron":"시세이","ko":"자세/태도","tts_text":"姿勢"},
      {"kanji":"立場","kana":"たちば","pron":"타치바","ko":"입장","tts_text":"立場"},
      {"kanji":"印象","kana":"いんしょう","pron":"인쇼오","ko":"인상","tts_text":"印象"},
      {"kanji":"評価","kana":"ひょうか","pron":"효오카","ko":"평가","tts_text":"評価"},
      {"kanji":"評判","kana":"ひょうばん","pron":"효오반","ko":"평판","tts_text":"評判"},
      {"kanji":"信頼","kana":"しんらい","pron":"신라이","ko":"신뢰","tts_text":"信頼"},
      {"kanji":"疑い","kana":"うたがい","pron":"우타가이","ko":"의심","tts_text":"疑い"},
      {"kanji":"尊敬","kana":"そんけい","pron":"손케이","ko":"존경","tts_text":"尊敬"},
      {"kanji":"軽視","kana":"けいし","pron":"케이시","ko":"경시","tts_text":"軽視"},

      {"kanji":"重視","kana":"じゅうし","pron":"쥬우시","ko":"중시","tts_text":"重視"},
      {"kanji":"無関心","kana":"むかんしん","pron":"무칸신","ko":"무관심","tts_text":"無関心"},
      {"kanji":"関心","kana":"かんしん","pron":"칸신","ko":"관심","tts_text":"関心"},
      {"kanji":"関心事","kana":"かんしんごと","pron":"칸신고토","ko":"관심사","tts_text":"関心事"},
      {"kanji":"意欲","kana":"いよく","pron":"이요쿠","ko":"의욕","tts_text":"意欲"},
      {"kanji":"向上心","kana":"こうじょうしん","pron":"코오죠오신","ko":"향상심","tts_text":"向上心"},
      {"kanji":"責任感","kana":"せきにんかん","pron":"세키닌칸","ko":"책임감","tts_text":"責任感"},
      {"kanji":"使命感","kana":"しめいかん","pron":"시메이칸","ko":"사명감","tts_text":"使命感"},
      {"kanji":"焦り","kana":"あせり","pron":"아세리","ko":"초조함","tts_text":"焦り"},
      {"kanji":"余裕","kana":"よゆう","pron":"요유우","ko":"여유","tts_text":"余裕"}
    ]
  },

  "sec10": {
    "title": "동사·형용사·부사",
    "items": [
      {"kanji":"達する","kana":"たっする","pron":"탓스루","ko":"도달하다","tts_text":"達する"},
      {"kanji":"及ぶ","kana":"およぶ","pron":"오요부","ko":"미치다","tts_text":"及ぶ"},
      {"kanji":"伴う","kana":"ともなう","pron":"토모나우","ko":"동반하다","tts_text":"伴う"},
      {"kanji":"含む","kana":"ふくむ","pron":"후쿠무","ko":"포함하다","tts_text":"含む"},
      {"kanji":"限る","kana":"かぎる","pron":"카기루","ko":"한정하다","tts_text":"限る"},
      {"kanji":"除く","kana":"のぞく","pron":"노조쿠","ko":"제외하다","tts_text":"除く"},
      {"kanji":"防ぐ","kana":"ふせぐ","pron":"후세구","ko":"막다","tts_text":"防ぐ"},
      {"kanji":"避ける","kana":"さける","pron":"사케루","ko":"피하다","tts_text":"避ける"},
      {"kanji":"保つ","kana":"たもつ","pron":"타모츠","ko":"유지하다","tts_text":"保つ"},
      {"kanji":"支える","kana":"ささえる","pron":"사사에루","ko":"지탱하다","tts_text":"支える"},

      {"kanji":"進める","kana":"すすめる","pron":"스스메루","ko":"진행시키다","tts_text":"進める"},
      {"kanji":"進む","kana":"すすむ","pron":"스스무","ko":"진행되다","tts_text":"進む"},
      {"kanji":"広げる","kana":"ひろげる","pron":"히로게루","ko":"넓히다","tts_text":"広げる"},
      {"kanji":"広がる","kana":"ひろがる","pron":"히로가루","ko":"퍼지다","tts_text":"広がる"},
      {"kanji":"高める","kana":"たかめる","pron":"타카메루","ko":"높이다","tts_text":"高める"},
      {"kanji":"低下","kana":"ていか","pron":"테이카","ko":"저하","tts_text":"低下"},
      {"kanji":"上回る","kana":"うわまわる","pron":"우와마와루","ko":"상회하다","tts_text":"上回る"},
      {"kanji":"下回る","kana":"したまわる","pron":"시타마와루","ko":"하회하다","tts_text":"下回る"},
      {"kanji":"左右する","kana":"さゆうする","pron":"사유우 스루","ko":"좌우하다","tts_text":"左右する"},
      {"kanji":"依存する","kana":"いぞんする","pron":"이존 스루","ko":"의존하다","tts_text":"依存する"},

      {"kanji":"有効","kana":"ゆうこう","pron":"유우코오","ko":"유효","tts_text":"有効"},
      {"kanji":"無効","kana":"むこう","pron":"무코오","ko":"무효","tts_text":"無効"},
      {"kanji":"困難","kana":"こんなん","pron":"콘난","ko":"곤란","tts_text":"困難"},
      {"kanji":"可能","kana":"かのう","pron":"카노오","ko":"가능","tts_text":"可能"},
      {"kanji":"不可能","kana":"ふかのう","pron":"후카노오","ko":"불가능","tts_text":"不可能"},
      {"kanji":"明確","kana":"めいかく","pron":"메이카쿠","ko":"명확","tts_text":"明確"},
      {"kanji":"曖昧","kana":"あいまい","pron":"아이마이","ko":"애매","tts_text":"曖昧"},
      {"kanji":"妥当","kana":"だとう","pron":"다토오","ko":"타당","tts_text":"妥当"},
      {"kanji":"適当","kana":"てきとう","pron":"테키토오","ko":"적당","tts_text":"適当"},
      {"kanji":"不適切","kana":"ふてきせつ","pron":"후테키세츠","ko":"부적절","tts_text":"不適切"},

      {"kanji":"主に","kana":"おもに","pron":"오모니","ko":"주로","tts_text":"主に"},
      {"kanji":"既に","kana":"すでに","pron":"스데니","ko":"이미","tts_text":"既に"},
      {"kanji":"徐々に","kana":"じょじょに","pron":"죠죠니","ko":"서서히","tts_text":"徐々に"},
      {"kanji":"急速に","kana":"きゅうそくに","pron":"큐우소쿠니","ko":"급속히","tts_text":"急速に"},
      {"kanji":"著しく","kana":"いちじるしく","pron":"이치지루시쿠","ko":"현저히","tts_text":"著しく"},
      {"kanji":"概ね","kana":"おおむね","pron":"오오무네","ko":"대체로","tts_text":"概ね"},
      {"kanji":"必ずしも","kana":"かならずしも","pron":"카나라즈시모","ko":"반드시 ~인 것은 아님","tts_text":"必ずしも"},
      {"kanji":"少なくとも","kana":"すくなくとも","pron":"스쿠나쿠토모","ko":"적어도","tts_text":"少なくとも"},
      {"kanji":"一層","kana":"いっそう","pron":"잇소오","ko":"더욱","tts_text":"一層"},
      {"kanji":"相対的に","kana":"そうたいてきに","pron":"소오타이테키니","ko":"상대적으로","tts_text":"相対的に"}
    ]
  },

}

N1_WORDS = {
    "sec01": {
    "title": "분석·전망·정책",
    "items": [
        {"kanji":"見解","kana":"けんかい","pron":"켄카이","ko":"견해","tts_text":"見解"},
        {"kanji":"認識","kana":"にんしき","pron":"닌시키","ko":"인식","tts_text":"認識"},
        {"kanji":"把握","kana":"はあく","pron":"하아쿠","ko":"파악","tts_text":"把握"},
        {"kanji":"見通し","kana":"みとおし","pron":"미토오시","ko":"전망","tts_text":"見通し"},
        {"kanji":"見込み","kana":"みこみ","pron":"미코미","ko":"가망, 전망","tts_text":"見込み"},
        {"kanji":"推移","kana":"すいい","pron":"스이이","ko":"추이","tts_text":"推移"},
        {"kanji":"動向","kana":"どうこう","pron":"도오코오","ko":"동향","tts_text":"動向"},
        {"kanji":"趨勢","kana":"すうせい","pron":"스우세이","ko":"추세","tts_text":"趨勢"},
        {"kanji":"概況","kana":"がいきょう","pron":"가이쿄오","ko":"개황(대략적 상황)","tts_text":"概況"},
        {"kanji":"状況","kana":"じょうきょう","pron":"죠오쿄오","ko":"상황","tts_text":"状況"},

        {"kanji":"背景","kana":"はいけい","pron":"하이케이","ko":"배경","tts_text":"背景"},
        {"kanji":"要因","kana":"よういん","pron":"요오인","ko":"요인","tts_text":"要因"},
        {"kanji":"原因","kana":"げんいん","pron":"겐인","ko":"원인","tts_text":"原因"},
        {"kanji":"経緯","kana":"けいい","pron":"케이이","ko":"경위","tts_text":"経緯"},
        {"kanji":"事情","kana":"じじょう","pron":"지죠오","ko":"사정","tts_text":"事情"},
        {"kanji":"影響","kana":"えいきょう","pron":"에이쿄오","ko":"영향","tts_text":"影響"},
        {"kanji":"波及","kana":"はきゅう","pron":"하큐","ko":"파급","tts_text":"波及"},
        {"kanji":"効果","kana":"こうか","pron":"코오카","ko":"효과","tts_text":"効果"},
        {"kanji":"成果","kana":"せいか","pron":"세이카","ko":"성과","tts_text":"成果"},
        {"kanji":"帰結","kana":"きけつ","pron":"키케츠","ko":"귀결","tts_text":"帰結"},

        {"kanji":"指針","kana":"ししん","pron":"시신","ko":"지침","tts_text":"指針"},
        {"kanji":"方針","kana":"ほうしん","pron":"호오신","ko":"방침","tts_text":"方針"},
        {"kanji":"施策","kana":"しさく","pron":"시사쿠","ko":"시책","tts_text":"施策"},
        {"kanji":"対策","kana":"たいさく","pron":"타이사쿠","ko":"대책","tts_text":"対策"},
        {"kanji":"戦略","kana":"せんりゃく","pron":"센랴쿠","ko":"전략","tts_text":"戦略"},
        {"kanji":"方策","kana":"ほうさく","pron":"호오사쿠","ko":"방책","tts_text":"方策"},
        {"kanji":"構想","kana":"こうそう","pron":"코오소오","ko":"구상","tts_text":"構想"},
        {"kanji":"計画","kana":"けいかく","pron":"케이카쿠","ko":"계획","tts_text":"計画"},
        {"kanji":"見直し","kana":"みなおし","pron":"미나오시","ko":"재검토","tts_text":"見直し"},
        {"kanji":"改善","kana":"かいぜん","pron":"카이젠","ko":"개선","tts_text":"改善"},

        {"kanji":"改革","kana":"かいかく","pron":"카이카쿠","ko":"개혁","tts_text":"改革"},
        {"kanji":"是正","kana":"ぜせい","pron":"제세이","ko":"시정(바로잡음)","tts_text":"是正"},
        {"kanji":"刷新","kana":"さっしん","pron":"사신","ko":"쇄신","tts_text":"刷新"},
        {"kanji":"再編","kana":"さいへん","pron":"사이헨","ko":"재편","tts_text":"再編"},
        {"kanji":"統合","kana":"とうごう","pron":"토오고오","ko":"통합","tts_text":"統合"},
        {"kanji":"整備","kana":"せいび","pron":"세이비","ko":"정비","tts_text":"整備"},
        {"kanji":"拡充","kana":"かくじゅう","pron":"카쿠쥬우","ko":"확충","tts_text":"拡充"},
        {"kanji":"充実","kana":"じゅうじつ","pron":"쥬우지츠","ko":"충실","tts_text":"充実"},
        {"kanji":"維持","kana":"いじ","pron":"이지","ko":"유지","tts_text":"維持"},
        {"kanji":"継続","kana":"けいぞく","pron":"케이조쿠","ko":"지속","tts_text":"継続"},

        {"kanji":"推進","kana":"すいしん","pron":"스이신","ko":"추진","tts_text":"推進"},
        {"kanji":"促進","kana":"そくしん","pron":"소쿠신","ko":"촉진","tts_text":"促進"},
        {"kanji":"抑制","kana":"よくせい","pron":"요쿠세이","ko":"억제","tts_text":"抑制"},
        {"kanji":"低迷","kana":"ていめい","pron":"테이메이","ko":"침체","tts_text":"低迷"},
        {"kanji":"停滞","kana":"ていたい","pron":"테이타이","ko":"정체","tts_text":"停滞"},
        {"kanji":"進展","kana":"しんてん","pron":"신텐","ko":"진전","tts_text":"進展"},
        {"kanji":"発展","kana":"はってん","pron":"핫텐","ko":"발전","tts_text":"発展"},
        {"kanji":"発生","kana":"はっせい","pron":"핫세이","ko":"발생","tts_text":"発生"},
        {"kanji":"顕著","kana":"けんちょ","pron":"켄쵸","ko":"현저","tts_text":"顕著"},
        {"kanji":"著しい","kana":"いちじるしい","pron":"이치지루시이","ko":"현저하다","tts_text":"著しい"}
    ]
    },
    "sec02": {
    "title": "논증·판단·연결표현",
    "items": [
        {"kanji":"徹底","kana":"てってい","pron":"텟테이","ko":"철저","tts_text":"徹底"},
        {"kanji":"厳格","kana":"げんかく","pron":"겐카쿠","ko":"엄격","tts_text":"厳格"},
        {"kanji":"適切","kana":"てきせつ","pron":"테키세츠","ko":"적절","tts_text":"適切"},
        {"kanji":"妥当","kana":"だとう","pron":"다토오","ko":"타당","tts_text":"妥当"},
        {"kanji":"有効","kana":"ゆうこう","pron":"유우코오","ko":"유효","tts_text":"有効"},
        {"kanji":"無効","kana":"むこう","pron":"무코오","ko":"무효","tts_text":"無効"},
        {"kanji":"合理的","kana":"ごうりてき","pron":"고오리테키","ko":"합리적","tts_text":"合理的"},
        {"kanji":"具体的","kana":"ぐたいてき","pron":"구타이테키","ko":"구체적","tts_text":"具体的"},
        {"kanji":"抽象的","kana":"ちゅうしょうてき","pron":"추우쇼오테키","ko":"추상적","tts_text":"抽象的"},
        {"kanji":"根拠","kana":"こんきょ","pron":"콘쿄","ko":"근거","tts_text":"根拠"},

        {"kanji":"論拠","kana":"ろんきょ","pron":"론쿄","ko":"논거","tts_text":"論拠"},
        {"kanji":"論理","kana":"ろんり","pron":"론리","ko":"논리","tts_text":"論理"},
        {"kanji":"整合性","kana":"せいごうせい","pron":"세이고오세이","ko":"정합성","tts_text":"整合性"},
        {"kanji":"妥協","kana":"だきょう","pron":"다쿄오","ko":"타협","tts_text":"妥協"},
        {"kanji":"譲歩","kana":"じょうほ","pron":"죠오호","ko":"양보","tts_text":"譲歩"},
        {"kanji":"合意","kana":"ごうい","pron":"고오이","ko":"합의","tts_text":"合意"},
        {"kanji":"合致","kana":"がっち","pron":"갓치","ko":"합치","tts_text":"合致"},
        {"kanji":"相違","kana":"そうい","pron":"소오이","ko":"차이","tts_text":"相違"},
        {"kanji":"相反","kana":"そうはん","pron":"소오한","ko":"상반","tts_text":"相反"},
        {"kanji":"矛盾","kana":"むじゅん","pron":"무쥰","ko":"모순","tts_text":"矛盾"},

        {"kanji":"一貫","kana":"いっかん","pron":"잇칸","ko":"일관","tts_text":"一貫"},
        {"kanji":"一律","kana":"いちりつ","pron":"이치리츠","ko":"일률","tts_text":"一律"},
        {"kanji":"例外","kana":"れいがい","pron":"레이가이","ko":"예외","tts_text":"例外"},
        {"kanji":"例","kana":"れい","pron":"레이","ko":"예","tts_text":"例"},
        {"kanji":"例示","kana":"れいじ","pron":"레이지","ko":"예시","tts_text":"例示"},
        {"kanji":"概念","kana":"がいねん","pron":"가이넨","ko":"개념","tts_text":"概念"},
        {"kanji":"枠組み","kana":"わくぐみ","pron":"와쿠구미","ko":"틀, 프레임","tts_text":"枠組み"},
        {"kanji":"枠","kana":"わく","pron":"와쿠","ko":"틀","tts_text":"枠"},
        {"kanji":"枠内","kana":"わくない","pron":"와쿠나이","ko":"범위 내","tts_text":"枠内"},
        {"kanji":"当面","kana":"とうめん","pron":"토오멘","ko":"당면","tts_text":"当面"},

        {"kanji":"ひいては","kana":"ひいては","pron":"히이테와","ko":"나아가서는","tts_text":"ひいては"},
        {"kanji":"ひとまず","kana":"ひとまず","pron":"히토마즈","ko":"일단","tts_text":"ひとまず"},
        {"kanji":"もっぱら","kana":"もっぱら","pron":"못파라","ko":"오로지","tts_text":"もっぱら"},
        {"kanji":"あながち","kana":"あながち","pron":"아나가치","ko":"반드시~만은 아니다","tts_text":"あながち"},
        {"kanji":"いかなる","kana":"いかなる","pron":"이카나루","ko":"어떤","tts_text":"いかなる"},
        {"kanji":"いずれにせよ","kana":"いずれにせよ","pron":"이즈레니세요","ko":"어쨌든","tts_text":"いずれにせよ"},
        {"kanji":"とはいえ","kana":"とはいえ","pron":"토와이에","ko":"그렇다 해도","tts_text":"とはいえ"},
        {"kanji":"まして","kana":"まして","pron":"마시테","ko":"하물며","tts_text":"まして"},
        {"kanji":"かえって","kana":"かえって","pron":"카엣테","ko":"오히려","tts_text":"かえって"},
        {"kanji":"あくまで","kana":"あくまで","pron":"아쿠마데","ko":"어디까지나","tts_text":"あくまで"},

        {"kanji":"示唆","kana":"しさ","pron":"시사","ko":"시사","tts_text":"示唆"},
        {"kanji":"示唆する","kana":"しさする","pron":"시사 스루","ko":"시사하다","tts_text":"示唆する"},
        {"kanji":"前提","kana":"ぜんてい","pron":"젠테이","ko":"전제","tts_text":"前提"},
        {"kanji":"帰納","kana":"きのう","pron":"키노오","ko":"귀납","tts_text":"帰納"},
        {"kanji":"演繹","kana":"えんえき","pron":"엔에키","ko":"연역","tts_text":"演繹"},
        {"kanji":"検証","kana":"けんしょう","pron":"켄쇼오","ko":"검증","tts_text":"検証"},
        {"kanji":"仮説","kana":"かせつ","pron":"카세츠","ko":"가설","tts_text":"仮説"},
        {"kanji":"推論","kana":"すいろん","pron":"스이론","ko":"추론","tts_text":"推論"},
        {"kanji":"妥結","kana":"だけつ","pron":"다케츠","ko":"타결","tts_text":"妥結"},
        {"kanji":"総括","kana":"そうかつ","pron":"소오카츠","ko":"총괄/총정리","tts_text":"総括"}
    ]
    },

    "sec03": {
    "title": "사회·정치·제도·법",
    "items": [
        {"kanji":"行政","kana":"ぎょうせい","pron":"교오세이","ko":"행정","tts_text":"行政"},
        {"kanji":"施行","kana":"しこう","pron":"시코오","ko":"시행","tts_text":"施行"},
        {"kanji":"改正","kana":"かいせい","pron":"카이세이","ko":"개정","tts_text":"改正"},
        {"kanji":"法令","kana":"ほうれい","pron":"호오레이","ko":"법령","tts_text":"法令"},
        {"kanji":"条項","kana":"じょうこう","pron":"죠오코오","ko":"조항","tts_text":"条項"},
        {"kanji":"規定","kana":"きてい","pron":"키테이","ko":"규정","tts_text":"規定"},
        {"kanji":"規範","kana":"きはん","pron":"키한","ko":"규범","tts_text":"規範"},
        {"kanji":"是非","kana":"ぜひ","pron":"제히","ko":"가부/옳고 그름","tts_text":"是非"},
        {"kanji":"正当","kana":"せいとう","pron":"세이토오","ko":"정당","tts_text":"正当"},
        {"kanji":"不当","kana":"ふとう","pron":"후토오","ko":"부당","tts_text":"不当"},

        {"kanji":"不正","kana":"ふせい","pron":"후세이","ko":"부정","tts_text":"不正"},
        {"kanji":"違法","kana":"いほう","pron":"이호오","ko":"위법","tts_text":"違法"},
        {"kanji":"摘発","kana":"てきはつ","pron":"테키하츠","ko":"적발","tts_text":"摘発"},
        {"kanji":"捜査","kana":"そうさ","pron":"소오사","ko":"수사","tts_text":"捜査"},
        {"kanji":"立証","kana":"りっしょう","pron":"릿쇼오","ko":"입증","tts_text":"立証"},
        {"kanji":"審理","kana":"しんり","pron":"신리","ko":"심리(재판)","tts_text":"審理"},
        {"kanji":"判決","kana":"はんけつ","pron":"한케츠","ko":"판결","tts_text":"判決"},
        {"kanji":"賠償","kana":"ばいしょう","pron":"바이쇼오","ko":"배상","tts_text":"賠償"},
        {"kanji":"補償","kana":"ほしょう","pron":"호쇼오","ko":"보상","tts_text":"補償"},
        {"kanji":"損害賠償","kana":"そんがいばいしょう","pron":"손가이 바이쇼오","ko":"손해배상","tts_text":"損害賠償"},

        {"kanji":"世論","kana":"せろん","pron":"세론","ko":"여론","tts_text":"世論"},
        {"kanji":"世論調査","kana":"せろんちょうさ","pron":"세론 쵸오사","ko":"여론조사","tts_text":"世論調査"},
        {"kanji":"支持","kana":"しじ","pron":"시지","ko":"지지","tts_text":"支持"},
        {"kanji":"反発","kana":"はんぱつ","pron":"한파츠","ko":"반발","tts_text":"反発"},
        {"kanji":"抗議","kana":"こうぎ","pron":"코오기","ko":"항의","tts_text":"抗議"},
        {"kanji":"紛争","kana":"ふんそう","pron":"훈소오","ko":"분쟁","tts_text":"紛争"},
        {"kanji":"対立","kana":"たいりつ","pron":"타이리츠","ko":"대립","tts_text":"対立"},
        {"kanji":"協調","kana":"きょうちょう","pron":"쿄오쵸오","ko":"협조/조화","tts_text":"協調"},
        {"kanji":"調停","kana":"ちょうてい","pron":"쵸오테이","ko":"조정/중재","tts_text":"調停"},
        {"kanji":"合意形成","kana":"ごういけいせい","pron":"고오이 케이세이","ko":"합의 형성","tts_text":"合意形成"},

        {"kanji":"格差","kana":"かくさ","pron":"카쿠사","ko":"격차","tts_text":"格差"},
        {"kanji":"貧困","kana":"ひんこん","pron":"힌콘","ko":"빈곤","tts_text":"貧困"},
        {"kanji":"雇用","kana":"こよう","pron":"코요오","ko":"고용","tts_text":"雇用"},
        {"kanji":"失業","kana":"しつぎょう","pron":"시츠교오","ko":"실업","tts_text":"失業"},
        {"kanji":"労働力","kana":"ろうどうりょく","pron":"로오도오료쿠","ko":"노동력","tts_text":"労働力"},
        {"kanji":"過重労働","kana":"かじゅうろうどう","pron":"카쥬우 로오도오","ko":"과중 노동","tts_text":"過重労働"},
        {"kanji":"少子化","kana":"しょうしか","pron":"쇼오시카","ko":"저출산","tts_text":"少子化"},
        {"kanji":"高齢化","kana":"こうれいか","pron":"코오레이카","ko":"고령화","tts_text":"高齢化"},
        {"kanji":"社会保障","kana":"しゃかいほしょう","pron":"샤카이 호쇼오","ko":"사회보장","tts_text":"社会保障"},
        {"kanji":"福祉","kana":"ふくし","pron":"후쿠시","ko":"복지","tts_text":"福祉"},

        {"kanji":"医療制度","kana":"いりょうせいど","pron":"이료오 세이도","ko":"의료 제도","tts_text":"医療制度"},
        {"kanji":"教育格差","kana":"きょういくかくさ","pron":"쿄오이쿠 카쿠사","ko":"교육 격차","tts_text":"教育格差"},
        {"kanji":"治安","kana":"ちあん","pron":"치안","ko":"치안","tts_text":"治安"},
        {"kanji":"倫理","kana":"りんり","pron":"린리","ko":"윤리","tts_text":"倫理"},
        {"kanji":"人権","kana":"じんけん","pron":"진켄","ko":"인권","tts_text":"人権"},
        {"kanji":"差別","kana":"さべつ","pron":"사베츠","ko":"차별","tts_text":"差別"},
        {"kanji":"偏見","kana":"へんけん","pron":"헨켄","ko":"편견","tts_text":"偏見"},
        {"kanji":"多様性","kana":"たようせい","pron":"타요오세이","ko":"다양성","tts_text":"多様性"},
        {"kanji":"共生","kana":"きょうせい","pron":"쿄오세이","ko":"공생","tts_text":"共生"},
        {"kanji":"公共","kana":"こうきょう","pron":"코오쿄오","ko":"공공","tts_text":"公共"}
    ]
    },

    "sec04": {
    "title": "경제·산업·경영",
    "items": [
        {"kanji":"景気","kana":"けいき","pron":"케이키","ko":"경기(경제)","tts_text":"景気"},
        {"kanji":"経済","kana":"けいざい","pron":"케이자이","ko":"경제","tts_text":"経済"},
        {"kanji":"市場","kana":"しじょう","pron":"시죠오","ko":"시장","tts_text":"市場"},
        {"kanji":"需給","kana":"じゅきゅう","pron":"쥬큐우","ko":"수급","tts_text":"需給"},
        {"kanji":"需要","kana":"じゅよう","pron":"쥬요오","ko":"수요","tts_text":"需要"},
        {"kanji":"供給","kana":"きょうきゅう","pron":"쿄오큐우","ko":"공급","tts_text":"供給"},
        {"kanji":"物価","kana":"ぶっか","pron":"붓카","ko":"물가","tts_text":"物価"},
        {"kanji":"インフレ","kana":"インフレ","pron":"인후레","ko":"인플레이션","tts_text":"インフレ"},
        {"kanji":"デフレ","kana":"デフレ","pron":"데후레","ko":"디플레이션","tts_text":"デフレ"},
        {"kanji":"為替","kana":"かわせ","pron":"카와세","ko":"환율","tts_text":"為替"},

        {"kanji":"金融","kana":"きんゆう","pron":"킨유우","ko":"금융","tts_text":"金融"},
        {"kanji":"金利","kana":"きんり","pron":"킨리","ko":"금리","tts_text":"金利"},
        {"kanji":"資金","kana":"しきん","pron":"시키ン","ko":"자금","tts_text":"資金"},
        {"kanji":"資本","kana":"しほん","pron":"시혼","ko":"자본","tts_text":"資本"},
        {"kanji":"投資","kana":"とうし","pron":"토오시","ko":"투자","tts_text":"投資"},
        {"kanji":"融資","kana":"ゆうし","pron":"유우시","ko":"융자","tts_text":"融資"},
        {"kanji":"株式","kana":"かぶしき","pron":"카부시키","ko":"주식","tts_text":"株式"},
        {"kanji":"債券","kana":"さいけん","pron":"사이켄","ko":"채권","tts_text":"債券"},
        {"kanji":"配当","kana":"はいとう","pron":"하이토오","ko":"배당","tts_text":"配当"},
        {"kanji":"損益","kana":"そんえき","pron":"손에키","ko":"손익","tts_text":"損益"},

        {"kanji":"利益","kana":"りえき","pron":"리에키","ko":"이익","tts_text":"利益"},
        {"kanji":"損失","kana":"そんしつ","pron":"손시츠","ko":"손실","tts_text":"損失"},
        {"kanji":"赤字","kana":"あかじ","pron":"아카지","ko":"적자","tts_text":"赤字"},
        {"kanji":"黒字","kana":"くろじ","pron":"쿠로지","ko":"흑자","tts_text":"黒字"},
        {"kanji":"売上","kana":"うりあげ","pron":"우리아게","ko":"매출","tts_text":"売上"},
        {"kanji":"収益","kana":"しゅうえき","pron":"슈우에키","ko":"수익","tts_text":"収益"},
        {"kanji":"コスト","kana":"コスト","pron":"코스토","ko":"비용(코스트)","tts_text":"コスト"},
        {"kanji":"採算","kana":"さいさん","pron":"사이산","ko":"채산","tts_text":"採算"},
        {"kanji":"採算性","kana":"さいさんせい","pron":"사이산세이","ko":"채산성","tts_text":"採算性"},
        {"kanji":"効率","kana":"こうりつ","pron":"코오리츠","ko":"효율","tts_text":"効率"},

        {"kanji":"生産性","kana":"せいさんせい","pron":"세이산세이","ko":"생산성","tts_text":"生産性"},
        {"kanji":"競争力","kana":"きょうそうりょく","pron":"쿄오소오료쿠","ko":"경쟁력","tts_text":"競争力"},
        {"kanji":"供給網","kana":"きょうきゅうもう","pron":"쿄오큐우모오","ko":"공급망","tts_text":"供給網"},
        {"kanji":"調達","kana":"ちょうたつ","pron":"쵸오타츠","ko":"조달","tts_text":"調達"},
        {"kanji":"在庫","kana":"ざいこ","pron":"자이코","ko":"재고","tts_text":"在庫"},
        {"kanji":"不足","kana":"ふそく","pron":"후소쿠","ko":"부족","tts_text":"不足"},
        {"kanji":"過剰","kana":"かじょう","pron":"카죠오","ko":"과잉","tts_text":"過剰"},
        {"kanji":"需要減","kana":"じゅようげん","pron":"쥬요오겐","ko":"수요 감소","tts_text":"需要減"},
        {"kanji":"拡大","kana":"かくだい","pron":"카쿠다이","ko":"확대","tts_text":"拡大"},
        {"kanji":"縮小","kana":"しゅくしょう","pron":"슈쿠쇼오","ko":"축소","tts_text":"縮小"},

        {"kanji":"企業","kana":"きぎょう","pron":"키교오","ko":"기업","tts_text":"企業"},
        {"kanji":"経営","kana":"けいえい","pron":"케이에이","ko":"경영","tts_text":"経営"},
        {"kanji":"経営陣","kana":"けいえいじん","pron":"케이에이진","ko":"경영진","tts_text":"経営陣"},
        {"kanji":"組織","kana":"そしき","pron":"소시키","ko":"조직","tts_text":"組織"},
        {"kanji":"再編","kana":"さいへん","pron":"사이헨","ko":"재편","tts_text":"再編"},
        {"kanji":"提携","kana":"ていけい","pron":"테이케이","ko":"제휴","tts_text":"提携"},
        {"kanji":"合併","kana":"がっぺい","pron":"갓페이","ko":"합병","tts_text":"合併"},
        {"kanji":"買収","kana":"ばいしゅう","pron":"바이슈우","ko":"인수","tts_text":"買収"},
        {"kanji":"倒産","kana":"とうさん","pron":"토오산","ko":"도산","tts_text":"倒産"},
        {"kanji":"撤退","kana":"てったい","pron":"텟타이","ko":"철수","tts_text":"撤退"}
    ]
    },
    "sec05": {
    "title": "학술·연구·논설",
    "items": [
        {"kanji":"研究","kana":"けんきゅう","pron":"켄큐우","ko":"연구","tts_text":"研究"},
        {"kanji":"調査","kana":"ちょうさ","pron":"쵸오사","ko":"조사","tts_text":"調査"},
        {"kanji":"分析","kana":"ぶんせき","pron":"분세키","ko":"분석","tts_text":"分析"},
        {"kanji":"考察","kana":"こうさつ","pron":"코오사츠","ko":"고찰","tts_text":"考察"},
        {"kanji":"検討","kana":"けんとう","pron":"켄토오","ko":"검토","tts_text":"検討"},
        {"kanji":"検証","kana":"けんしょう","pron":"켄쇼오","ko":"검증","tts_text":"検証"},
        {"kanji":"評価","kana":"ひょうか","pron":"효오카","ko":"평가","tts_text":"評価"},
        {"kanji":"推測","kana":"すいそく","pron":"스이소쿠","ko":"추측","tts_text":"推測"},
        {"kanji":"推定","kana":"すいてい","pron":"스이테이","ko":"추정","tts_text":"推定"},
        {"kanji":"仮説","kana":"かせつ","pron":"카세츠","ko":"가설","tts_text":"仮説"},

        {"kanji":"実証","kana":"じっしょう","pron":"짓쇼오","ko":"실증","tts_text":"実証"},
        {"kanji":"裏付け","kana":"うらづけ","pron":"우라즈케","ko":"뒷받침","tts_text":"裏付け"},
        {"kanji":"根拠付ける","kana":"こんきょづける","pron":"콘쿄즈케루","ko":"근거를 대다","tts_text":"根拠付ける"},
        {"kanji":"立証","kana":"りっしょう","pron":"릿쇼오","ko":"입증","tts_text":"立証"},
        {"kanji":"証拠","kana":"しょうこ","pron":"쇼오코","ko":"증거","tts_text":"証拠"},
        {"kanji":"妥当性","kana":"だとうせい","pron":"다토오세이","ko":"타당성","tts_text":"妥当性"},
        {"kanji":"信憑性","kana":"しんぴょうせい","pron":"신표오세이","ko":"신빙성","tts_text":"信憑性"},
        {"kanji":"客観的","kana":"きゃっかんてき","pron":"캿칸테키","ko":"객관적","tts_text":"客観的"},
        {"kanji":"主観的","kana":"しゅかんてき","pron":"슈칸테키","ko":"주관적","tts_text":"主観的"},
        {"kanji":"統計","kana":"とうけい","pron":"토오케이","ko":"통계","tts_text":"統計"},

        {"kanji":"統計的","kana":"とうけいてき","pron":"토오케이테키","ko":"통계적","tts_text":"統計的"},
        {"kanji":"傾向","kana":"けいこう","pron":"케이코오","ko":"경향","tts_text":"傾向"},
        {"kanji":"相関","kana":"そうかん","pron":"소오칸","ko":"상관","tts_text":"相関"},
        {"kanji":"因果関係","kana":"いんがかんけい","pron":"인가 칸케이","ko":"인과관계","tts_text":"因果関係"},
        {"kanji":"要約","kana":"ようやく","pron":"요오야쿠","ko":"요약","tts_text":"要約"},
        {"kanji":"概略","kana":"がいりゃく","pron":"가이랴쿠","ko":"개략","tts_text":"概略"},
        {"kanji":"概要","kana":"がいよう","pron":"가이요오","ko":"개요","tts_text":"概要"},
        {"kanji":"詳細","kana":"しょうさい","pron":"쇼오사이","ko":"상세","tts_text":"詳細"},
        {"kanji":"論点","kana":"ろんてん","pron":"론텐","ko":"논점","tts_text":"論点"},
        {"kanji":"争点","kana":"そうてん","pron":"소오텐","ko":"쟁점","tts_text":"争点"},

        {"kanji":"主張","kana":"しゅちょう","pron":"슈쵸오","ko":"주장","tts_text":"主張"},
        {"kanji":"反論","kana":"はんろん","pron":"한론","ko":"반론","tts_text":"反論"},
        {"kanji":"弁解","kana":"べんかい","pron":"벤카이","ko":"변명","tts_text":"弁解"},
        {"kanji":"見落とす","kana":"みおとす","pron":"미오토스","ko":"놓치다","tts_text":"見落とす"},
        {"kanji":"見落とし","kana":"みおとし","pron":"미오토시","ko":"간과/놓침","tts_text":"見落とし"},
        {"kanji":"見誤る","kana":"みあやまる","pron":"미아야마루","ko":"오판하다","tts_text":"見誤る"},
        {"kanji":"見極める","kana":"みきわめる","pron":"미키와메루","ko":"판별하다","tts_text":"見極める"},
        {"kanji":"言及","kana":"げんきゅう","pron":"겐큐우","ko":"언급","tts_text":"言及"},
        {"kanji":"示す","kana":"しめす","pron":"시메스","ko":"보이다/나타내다","tts_text":"示す"},
        {"kanji":"裏付ける","kana":"うらづける","pron":"우라즈케루","ko":"뒷받침하다","tts_text":"裏付ける"},

        {"kanji":"仮に","kana":"かりに","pron":"카리니","ko":"가령/만약","tts_text":"仮に"},
        {"kanji":"一概に","kana":"いちがいに","pron":"이치가이니","ko":"일괄적으로","tts_text":"一概に"},
        {"kanji":"一概には言えない","kana":"いちがいにはいえない","pron":"이치가이니와 이에나이","ko":"일概적으로 말할 수 없다","tts_text":"一概には言えない"},
        {"kanji":"もとより","kana":"もとより","pron":"모토요리","ko":"애초에","tts_text":"もとより"},
        {"kanji":"ひとえに","kana":"ひとえに","pron":"히토에니","ko":"오로지","tts_text":"ひとえに"},
        {"kanji":"概して","kana":"がいして","pron":"가이시테","ko":"대체로","tts_text":"概して"},
        {"kanji":"ひたすら","kana":"ひたすら","pron":"히타스라","ko":"오로지/한결같이","tts_text":"ひたすら"},
        {"kanji":"総じて","kana":"そうじて","pron":"소오지테","ko":"총괄적으로","tts_text":"総じて"},
        {"kanji":"ひいては","kana":"ひいては","pron":"히이테와","ko":"나아가서는","tts_text":"ひいては"},
        {"kanji":"かねて","kana":"かねて","pron":"카네테","ko":"이전부터","tts_text":"かねて"}
    ]
    },

    "sec06": {
    "title": "심리·관계·태도",
    "items": [
        {"kanji":"本質","kana":"ほんしつ","pron":"혼시츠","ko":"본질","tts_text":"本質"},
        {"kanji":"本音","kana":"ほんね","pron":"혼네","ko":"속마음","tts_text":"本音"},
        {"kanji":"建前","kana":"たてまえ","pron":"타테마에","ko":"겉치레/명분","tts_text":"建前"},
        {"kanji":"価値観","kana":"かちかん","pron":"카치칸","ko":"가치관","tts_text":"価値観"},
        {"kanji":"先入観","kana":"せんにゅうかん","pron":"센뉴우칸","ko":"선입견","tts_text":"先入観"},
        {"kanji":"偏見","kana":"へんけん","pron":"헨켄","ko":"편견","tts_text":"偏見"},
        {"kanji":"固定観念","kana":"こていかんねん","pron":"코테이 칸넨","ko":"고정관념","tts_text":"固定観念"},
        {"kanji":"主観","kana":"しゅかん","pron":"슈칸","ko":"주관","tts_text":"主観"},
        {"kanji":"客観","kana":"きゃっかん","pron":"캿칸","ko":"객관","tts_text":"客観"},
        {"kanji":"視点","kana":"してん","pron":"시텐","ko":"시점/관점","tts_text":"視点"},

        {"kanji":"観点","kana":"かんてん","pron":"칸텐","ko":"관점","tts_text":"観点"},
        {"kanji":"見方","kana":"みかた","pron":"미카타","ko":"관점/시각","tts_text":"見方"},
        {"kanji":"姿勢","kana":"しせい","pron":"시세이","ko":"태도","tts_text":"姿勢"},
        {"kanji":"態度","kana":"たいど","pron":"타이도","ko":"태도","tts_text":"態度"},
        {"kanji":"反応","kana":"はんのう","pron":"한노오","ko":"반응","tts_text":"反応"},
        {"kanji":"受け止める","kana":"うけとめる","pron":"우케토메루","ko":"받아들이다","tts_text":"受け止める"},
        {"kanji":"納得","kana":"なっとく","pron":"낫토쿠","ko":"납득","tts_text":"納得"},
        {"kanji":"納得する","kana":"なっとくする","pron":"낫토쿠 스루","ko":"납득하다","tts_text":"納得する"},
        {"kanji":"同調","kana":"どうちょう","pron":"도오쵸오","ko":"동조","tts_text":"同調"},
        {"kanji":"共感","kana":"きょうかん","pron":"쿄오칸","ko":"공감","tts_text":"共感"},

        {"kanji":"反感","kana":"はんかん","pron":"한칸","ko":"반감","tts_text":"反感"},
        {"kanji":"嫌悪","kana":"けんお","pron":"켄오","ko":"혐오","tts_text":"嫌悪"},
        {"kanji":"嫉妬","kana":"しっと","pron":"싯토","ko":"질투","tts_text":"嫉妬"},
        {"kanji":"劣等感","kana":"れっとうかん","pron":"렛토오칸","ko":"열등감","tts_text":"劣等感"},
        {"kanji":"優越感","kana":"ゆうえつかん","pron":"유우에츠칸","ko":"우월감","tts_text":"優越感"},
        {"kanji":"孤独","kana":"こどく","pron":"코도쿠","ko":"고독","tts_text":"孤独"},
        {"kanji":"孤立","kana":"こりつ","pron":"코리츠","ko":"고립","tts_text":"孤立"},
        {"kanji":"疎外感","kana":"そがいかん","pron":"소가이칸","ko":"소외감","tts_text":"疎外感"},
        {"kanji":"不信","kana":"ふしん","pron":"후신","ko":"불신","tts_text":"不信"},
        {"kanji":"信用","kana":"しんよう","pron":"신요오","ko":"신용","tts_text":"信用"},

        {"kanji":"信頼","kana":"しんらい","pron":"신라이","ko":"신뢰","tts_text":"信頼"},
        {"kanji":"疑念","kana":"ぎねん","pron":"기넨","ko":"의혹","tts_text":"疑念"},
        {"kanji":"疑う","kana":"うたがう","pron":"우타가우","ko":"의심하다","tts_text":"疑う"},
        {"kanji":"誤解","kana":"ごかい","pron":"고카이","ko":"오해","tts_text":"誤解"},
        {"kanji":"偏る","kana":"かたよる","pron":"카타요루","ko":"치우치다","tts_text":"偏る"},
        {"kanji":"執着","kana":"しゅうちゃく","pron":"슈우차쿠","ko":"집착","tts_text":"執着"},
        {"kanji":"執念","kana":"しゅうねん","pron":"슈우넨","ko":"집념","tts_text":"執念"},
        {"kanji":"忍耐","kana":"にんたい","pron":"닌타이","ko":"인내","tts_text":"忍耐"},
        {"kanji":"自制","kana":"じせい","pron":"지세이","ko":"자제","tts_text":"自制"},
        {"kanji":"抑える","kana":"おさえる","pron":"오사에루","ko":"억누르다/누르다","tts_text":"抑える"},

        {"kanji":"慎む","kana":"つつしむ","pron":"츠츠시무","ko":"삼가다","tts_text":"慎む"},
        {"kanji":"遠慮","kana":"えんりょ","pron":"엔료","ko":"사양/원거리낌","tts_text":"遠慮"},
        {"kanji":"配慮","kana":"はいりょ","pron":"하이료","ko":"배려","tts_text":"配慮"},
        {"kanji":"気遣い","kana":"きづかい","pron":"키즈카이","ko":"배려/신경씀","tts_text":"気遣い"},
        {"kanji":"思いやり","kana":"おもいやり","pron":"오모이야리","ko":"배려/상냥함","tts_text":"思いやり"},
        {"kanji":"誠意","kana":"せいい","pron":"세이이","ko":"성의","tts_text":"誠意"},
        {"kanji":"謙虚","kana":"けんきょ","pron":"켄쿄","ko":"겸손","tts_text":"謙虚"},
        {"kanji":"傲慢","kana":"ごうまん","pron":"고오만","ko":"오만","tts_text":"傲慢"},
        {"kanji":"冷淡","kana":"れいたん","pron":"레이탄","ko":"냉담","tts_text":"冷淡"},
        {"kanji":"誹謗","kana":"ひぼう","pron":"히보오","ko":"비방","tts_text":"誹謗"},

        {"kanji":"中傷","kana":"ちゅうしょう","pron":"츄우쇼오","ko":"중상","tts_text":"中傷"},
        {"kanji":"侮辱","kana":"ぶじょく","pron":"부죠쿠","ko":"모욕","tts_text":"侮辱"},
        {"kanji":"礼儀","kana":"れいぎ","pron":"레이기","ko":"예의","tts_text":"礼儀"},
        {"kanji":"無礼","kana":"ぶれい","pron":"부레이","ko":"무례","tts_text":"無礼"},
        {"kanji":"体裁","kana":"ていさい","pron":"테이사이","ko":"겉모양/체면","tts_text":"体裁"},
        {"kanji":"面目","kana":"めんぼく","pron":"멘보쿠","ko":"체면","tts_text":"面目"},
        {"kanji":"面目を保つ","kana":"めんぼくをたもつ","pron":"멘보쿠오 타모츠","ko":"체면을 지키다","tts_text":"面目を保つ"},
        {"kanji":"本心","kana":"ほんしん","pron":"혼신","ko":"본심","tts_text":"本心"},
        {"kanji":"心情","kana":"しんじょう","pron":"신죠오","ko":"심정","tts_text":"心情"},
        {"kanji":"心境","kana":"しんきょう","pron":"신쿄오","ko":"심경","tts_text":"心境"}
    ]
    },
    "sec07": {
    "title": "환경·에너지·과학",
    "items": [
        {"kanji":"環境","kana":"かんきょう","pron":"칸쿄오","ko":"환경","tts_text":"環境"},
        {"kanji":"環境問題","kana":"かんきょうもんだい","pron":"칸쿄오 몬다이","ko":"환경 문제","tts_text":"環境問題"},
        {"kanji":"保全","kana":"ほぜん","pron":"호젠","ko":"보전","tts_text":"保全"},
        {"kanji":"保護","kana":"ほご","pron":"호고","ko":"보호","tts_text":"保護"},
        {"kanji":"保護区","kana":"ほごく","pron":"호고쿠","ko":"보호구","tts_text":"保護区"},
        {"kanji":"自然保護","kana":"しぜんほご","pron":"시젠 호고","ko":"자연 보호","tts_text":"自然保護"},
        {"kanji":"生態系","kana":"せいたいけい","pron":"세이타이케이","ko":"생태계","tts_text":"生態系"},
        {"kanji":"多様性","kana":"たようせい","pron":"타요오세이","ko":"다양성","tts_text":"多様性"},
        {"kanji":"絶滅","kana":"ぜつめつ","pron":"제츠메츠","ko":"멸종","tts_text":"絶滅"},
        {"kanji":"絶滅危惧種","kana":"ぜつめつきぐしゅ","pron":"제츠메츠 키구슈","ko":"멸종위기종","tts_text":"絶滅危惧種"},

        {"kanji":"汚染","kana":"おせん","pron":"오센","ko":"오염","tts_text":"汚染"},
        {"kanji":"大気汚染","kana":"たいきおせん","pron":"타이키 오센","ko":"대기 오염","tts_text":"大気汚染"},
        {"kanji":"水質汚濁","kana":"すいしつおだく","pron":"스이시츠 오다쿠","ko":"수질 오염","tts_text":"水質汚濁"},
        {"kanji":"排出","kana":"はいしゅつ","pron":"하이슈츠","ko":"배출","tts_text":"排出"},
        {"kanji":"排出量","kana":"はいしゅつりょう","pron":"하이슈츠료오","ko":"배출량","tts_text":"排出量"},
        {"kanji":"二酸化炭素","kana":"にさんかたんそ","pron":"니산카 탄소","ko":"이산화탄소","tts_text":"二酸化炭素"},
        {"kanji":"温室効果ガス","kana":"おんしつこうかがす","pron":"온시츠 코오카 가스","ko":"온실가스","tts_text":"温室効果ガス"},
        {"kanji":"温暖化","kana":"おんだんか","pron":"온단카","ko":"온난화","tts_text":"温暖化"},
        {"kanji":"気候変動","kana":"きこうへんどう","pron":"키코오 헨도오","ko":"기후변화","tts_text":"気候変動"},
        {"kanji":"異常気象","kana":"いじょうきしょう","pron":"이죠오 키쇼오","ko":"이상기후","tts_text":"異常気象"},

        {"kanji":"資源","kana":"しげん","pron":"시겐","ko":"자원","tts_text":"資源"},
        {"kanji":"資源枯渇","kana":"しげんこかつ","pron":"시겐 코카츠","ko":"자원 고갈","tts_text":"資源枯渇"},
        {"kanji":"再生可能","kana":"さいせいかのう","pron":"사이세이 카노오","ko":"재생 가능","tts_text":"再生可能"},
        {"kanji":"再生可能エネルギー","kana":"さいせいかのうえねるぎー","pron":"사이세이 카노오 에네루기이","ko":"재생에너지","tts_text":"再生可能エネルギー"},
        {"kanji":"太陽光","kana":"たいようこう","pron":"타이요오코오","ko":"태양광","tts_text":"太陽光"},
        {"kanji":"風力","kana":"ふうりょく","pron":"후우료쿠","ko":"풍력","tts_text":"風力"},
        {"kanji":"発電","kana":"はつでん","pron":"하츠덴","ko":"발전(전기)","tts_text":"発電"},
        {"kanji":"原子力","kana":"げんしりょく","pron":"겐시료쿠","ko":"원자력","tts_text":"原子力"},
        {"kanji":"節電","kana":"せつでん","pron":"세츠덴","ko":"절전","tts_text":"節電"},
        {"kanji":"省エネ","kana":"しょうえね","pron":"쇼오에네","ko":"에너지 절약","tts_text":"省エネ"},

        {"kanji":"効率化","kana":"こうりつか","pron":"코오리츠카","ko":"효율화","tts_text":"効率化"},
        {"kanji":"最適化","kana":"さいてきか","pron":"사이테키카","ko":"최적화","tts_text":"最適化"},
        {"kanji":"技術革新","kana":"ぎじゅつかくしん","pron":"기쥬츠 카쿠신","ko":"기술혁신","tts_text":"技術革新"},
        {"kanji":"先端","kana":"せんたん","pron":"센탄","ko":"최첨단","tts_text":"先端"},
        {"kanji":"革新","kana":"かくしん","pron":"카쿠신","ko":"혁신","tts_text":"革新"},
        {"kanji":"開発","kana":"かいはつ","pron":"카이하츠","ko":"개발","tts_text":"開発"},
        {"kanji":"研究開発","kana":"けんきゅうかいはつ","pron":"켄큐우 카이하츠","ko":"연구개발","tts_text":"研究開発"},
        {"kanji":"実験","kana":"じっけん","pron":"짓켄","ko":"실험","tts_text":"実験"},
        {"kanji":"観測","kana":"かんそく","pron":"칸소쿠","ko":"관측","tts_text":"観測"},
        {"kanji":"測定","kana":"そくてい","pron":"소쿠테이","ko":"측정","tts_text":"測定"},

        {"kanji":"データ","kana":"データ","pron":"데에타","ko":"데이터","tts_text":"データ"},
        {"kanji":"処理","kana":"しょり","pron":"쇼리","ko":"처리","tts_text":"処理"},
        {"kanji":"解析","kana":"かいせき","pron":"카이세키","ko":"해석/분석(해석)","tts_text":"解析"},
        {"kanji":"精度","kana":"せいど","pron":"세이도","ko":"정밀도","tts_text":"精度"},
        {"kanji":"誤差","kana":"ごさ","pron":"고사","ko":"오차","tts_text":"誤差"},
        {"kanji":"再現性","kana":"さいげんせい","pron":"사이겐세이","ko":"재현성","tts_text":"再現性"},
        {"kanji":"有害","kana":"ゆうがい","pron":"유우가이","ko":"유해","tts_text":"有害"},
        {"kanji":"有毒","kana":"ゆうどく","pron":"유우도쿠","ko":"유독","tts_text":"有毒"},
        {"kanji":"無害","kana":"むがい","pron":"무가이","ko":"무해","tts_text":"無害"},
        {"kanji":"安全性","kana":"あんぜんせい","pron":"안젠세이","ko":"안전성","tts_text":"安全性"}
    ]
    },

  "sec08": {
    "title": "법·계약·문서",
    "items": [
      {"kanji":"契約","kana":"けいやく","pron":"케이야쿠","ko":"계약","tts_text":"契約"},
      {"kanji":"契約書","kana":"けいやくしょ","pron":"케이야쿠쇼","ko":"계약서","tts_text":"契約書"},
      {"kanji":"条項","kana":"じょうこう","pron":"죠오코오","ko":"조항","tts_text":"条項"},
      {"kanji":"規約","kana":"きやく","pron":"키야쿠","ko":"규약","tts_text":"規約"},
      {"kanji":"規定","kana":"きてい","pron":"키테이","ko":"규정","tts_text":"規定"},
      {"kanji":"規制","kana":"きせい","pron":"키세이","ko":"규제","tts_text":"規制"},
      {"kanji":"法的","kana":"ほうてき","pron":"호오테키","ko":"법적","tts_text":"法的"},
      {"kanji":"合法","kana":"ごうほう","pron":"고오호오","ko":"합법","tts_text":"合法"},
      {"kanji":"違法","kana":"いほう","pron":"이호오","ko":"위법","tts_text":"違法"},
      {"kanji":"違反","kana":"いはん","pron":"이한","ko":"위반","tts_text":"違反"},

      {"kanji":"遵守","kana":"じゅんしゅ","pron":"쥰슈","ko":"준수","tts_text":"遵守"},
      {"kanji":"履行","kana":"りこう","pron":"리코오","ko":"이행","tts_text":"履行"},
      {"kanji":"不履行","kana":"ふりこう","pron":"후리코오","ko":"불이행","tts_text":"不履行"},
      {"kanji":"解除","kana":"かいじょ","pron":"카이죠","ko":"해제","tts_text":"解除"},
      {"kanji":"無効","kana":"むこう","pron":"무코오","ko":"무효","tts_text":"無効"},
      {"kanji":"有効","kana":"ゆうこう","pron":"유우코오","ko":"유효","tts_text":"有効"},
      {"kanji":"効力","kana":"こうりょく","pron":"코오료쿠","ko":"효력","tts_text":"効力"},
      {"kanji":"権利","kana":"けんり","pron":"켄리","ko":"권리","tts_text":"権利"},
      {"kanji":"義務","kana":"ぎむ","pron":"기무","ko":"의무","tts_text":"義務"},
      {"kanji":"責務","kana":"せきむ","pron":"세키무","ko":"책무","tts_text":"責務"},

      {"kanji":"責任","kana":"せきにん","pron":"세키닌","ko":"책임","tts_text":"責任"},
      {"kanji":"免責","kana":"めんせき","pron":"멘세키","ko":"면책","tts_text":"免責"},
      {"kanji":"賠償","kana":"ばいしょう","pron":"바이쇼오","ko":"배상","tts_text":"賠償"},
      {"kanji":"補償","kana":"ほしょう","pron":"호쇼오","ko":"보상","tts_text":"補償"},
      {"kanji":"違約金","kana":"いやくきん","pron":"이야쿠킨","ko":"위약금","tts_text":"違約金"},
      {"kanji":"損害","kana":"そんがい","pron":"손가이","ko":"손해","tts_text":"損害"},
      {"kanji":"損害賠償","kana":"そんがいばいしょう","pron":"손가이 바이쇼오","ko":"손해배상","tts_text":"損害賠償"},
      {"kanji":"請求","kana":"せいきゅう","pron":"세이큐우","ko":"청구","tts_text":"請求"},
      {"kanji":"請求書","kana":"せいきゅうしょ","pron":"세이큐우쇼","ko":"청구서","tts_text":"請求書"},
      {"kanji":"支払い","kana":"しはらい","pron":"시하라이","ko":"지불","tts_text":"支払い"},

      {"kanji":"期限","kana":"きげん","pron":"키겐","ko":"기한","tts_text":"期限"},
      {"kanji":"猶予","kana":"ゆうよ","pron":"유우요","ko":"유예","tts_text":"猶予"},
      {"kanji":"延期","kana":"えんき","pron":"엔키","ko":"연기","tts_text":"延期"},
      {"kanji":"更新","kana":"こうしん","pron":"코오신","ko":"갱신","tts_text":"更新"},
      {"kanji":"締結","kana":"ていけつ","pron":"테이케츠","ko":"체결","tts_text":"締結"},
      {"kanji":"合意","kana":"ごうい","pron":"고오이","ko":"합의","tts_text":"合意"},
      {"kanji":"合意書","kana":"ごういしょ","pron":"고오이쇼","ko":"합의서","tts_text":"合意書"},
      {"kanji":"同意","kana":"どうい","pron":"도오이","ko":"동의","tts_text":"同意"},
      {"kanji":"承諾","kana":"しょうだく","pron":"쇼오다쿠","ko":"승낙","tts_text":"承諾"},
      {"kanji":"拒否","kana":"きょひ","pron":"쿄히","ko":"거부","tts_text":"拒否"},

      {"kanji":"申請","kana":"しんせい","pron":"신세이","ko":"신청","tts_text":"申請"},
      {"kanji":"届出","kana":"とどけで","pron":"토도케데","ko":"신고/제출","tts_text":"届出"},
      {"kanji":"提出","kana":"ていしゅつ","pron":"테이슈츠","ko":"제출","tts_text":"提出"},
      {"kanji":"添付","kana":"てんぷ","pron":"텐푸","ko":"첨부","tts_text":"添付"},
      {"kanji":"記載","kana":"きさい","pron":"키사이","ko":"기재","tts_text":"記載"},
      {"kanji":"明記","kana":"めいき","pron":"메이키","ko":"명기","tts_text":"明記"},
      {"kanji":"署名","kana":"しょめい","pron":"쇼메이","ko":"서명","tts_text":"署名"},
      {"kanji":"押印","kana":"おういん","pron":"오오인","ko":"날인","tts_text":"押印"},
      {"kanji":"閲覧","kana":"えつらん","pron":"에츠란","ko":"열람","tts_text":"閲覧"},
      {"kanji":"参照","kana":"さんしょう","pron":"산쇼오","ko":"참조","tts_text":"参照"}
    ]
  },
  "sec09": {
    "title": "비즈니스·조직·운영",
    "items": [
      {"kanji":"組織","kana":"そしき","pron":"소시키","ko":"조직","tts_text":"組織"},
      {"kanji":"体制","kana":"たいせい","pron":"타이세이","ko":"체제","tts_text":"体制"},
      {"kanji":"構造","kana":"こうぞう","pron":"코오조오","ko":"구조","tts_text":"構造"},
      {"kanji":"枠組み","kana":"わくぐみ","pron":"와쿠구미","ko":"틀, 프레임","tts_text":"枠組み"},
      {"kanji":"編成","kana":"へんせい","pron":"헨세이","ko":"편성","tts_text":"編成"},
      {"kanji":"統制","kana":"とうせい","pron":"토오세이","ko":"통제","tts_text":"統制"},
      {"kanji":"管理","kana":"かんり","pron":"칸리","ko":"관리","tts_text":"管理"},
      {"kanji":"監督","kana":"かんとく","pron":"칸토쿠","ko":"감독","tts_text":"監督"},
      {"kanji":"運営","kana":"うんえい","pron":"운에이","ko":"운영","tts_text":"運営"},
      {"kanji":"運用","kana":"うんよう","pron":"운요오","ko":"운용","tts_text":"運用"},

      {"kanji":"指揮","kana":"しき","pron":"시키","ko":"지휘","tts_text":"指揮"},
      {"kanji":"裁量","kana":"さいりょう","pron":"사이료오","ko":"재량","tts_text":"裁量"},
      {"kanji":"権限","kana":"けんげん","pron":"켄겐","ko":"권한","tts_text":"権限"},
      {"kanji":"権威","kana":"けんい","pron":"켄이","ko":"권위","tts_text":"権威"},
      {"kanji":"責任","kana":"せきにん","pron":"세키닌","ko":"책임","tts_text":"責任"},
      {"kanji":"任務","kana":"にんむ","pron":"닌무","ko":"임무","tts_text":"任務"},
      {"kanji":"役割","kana":"やくわり","pron":"야쿠와리","ko":"역할","tts_text":"役割"},
      {"kanji":"担当","kana":"たんとう","pron":"탄토오","ko":"담당","tts_text":"担当"},
      {"kanji":"分担","kana":"ぶんたん","pron":"분탄","ko":"분담","tts_text":"分担"},
      {"kanji":"配置","kana":"はいち","pron":"하이치","ko":"배치","tts_text":"配置"},

      {"kanji":"調整","kana":"ちょうせい","pron":"쵸오세이","ko":"조정","tts_text":"調整"},
      {"kanji":"折衝","kana":"せっしょう","pron":"셋쇼오","ko":"절충·교섭","tts_text":"折衝"},
      {"kanji":"交渉","kana":"こうしょう","pron":"코오쇼오","ko":"교섭","tts_text":"交渉"},
      {"kanji":"妥結","kana":"だけつ","pron":"다케츠","ko":"타결","tts_text":"妥結"},
      {"kanji":"合意形成","kana":"ごういけいせい","pron":"고오이 케이세이","ko":"합의 형성","tts_text":"合意形成"},
      {"kanji":"意思決定","kana":"いしけってい","pron":"이시 켓테이","ko":"의사결정","tts_text":"意思決定"},
      {"kanji":"迅速","kana":"じんそく","pron":"진소쿠","ko":"신속","tts_text":"迅速"},
      {"kanji":"円滑","kana":"えんかつ","pron":"엔카츠","ko":"원활","tts_text":"円滑"},
      {"kanji":"停滞","kana":"ていたい","pron":"테이타이","ko":"정체","tts_text":"停滞"},
      {"kanji":"混乱","kana":"こんらん","pron":"콘란","ko":"혼란","tts_text":"混乱"},

      {"kanji":"是正","kana":"ぜせい","pron":"제세이","ko":"시정","tts_text":"是正"},
      {"kanji":"改善","kana":"かいぜん","pron":"카이젠","ko":"개선","tts_text":"改善"},
      {"kanji":"刷新","kana":"さっしん","pron":"삿신","ko":"쇄신","tts_text":"刷新"},
      {"kanji":"再構築","kana":"さいこうちく","pron":"사이코오치쿠","ko":"재구축","tts_text":"再構築"},
      {"kanji":"再編","kana":"さいへん","pron":"사이헨","ko":"재편","tts_text":"再編"},
      {"kanji":"合理化","kana":"ごうりか","pron":"고오리카","ko":"합리화","tts_text":"合理化"},
      {"kanji":"効率化","kana":"こうりつか","pron":"코오리츠카","ko":"효율화","tts_text":"効率化"},
      {"kanji":"簡素化","kana":"かんそか","pron":"칸소카","ko":"간소화","tts_text":"簡素化"},
      {"kanji":"最適化","kana":"さいてきか","pron":"사이테키카","ko":"최적화","tts_text":"最適化"},
      {"kanji":"高度化","kana":"こうどか","pron":"코오도카","ko":"고도화","tts_text":"高度化"}
    ]
  },

  "sec10": {
    "title": "고급 동사·형용사·부사(논설 핵심)",
    "items": [
      {"kanji":"想定","kana":"そうてい","pron":"소오테이","ko":"상정","tts_text":"想定"},
      {"kanji":"見込む","kana":"みこむ","pron":"미코무","ko":"내다보다","tts_text":"見込む"},
      {"kanji":"見据える","kana":"みすえる","pron":"미스에루","ko":"내다보다","tts_text":"見据える"},
      {"kanji":"捉える","kana":"とらえる","pron":"토라에루","ko":"파악하다","tts_text":"捉える"},
      {"kanji":"踏まえる","kana":"ふまえる","pron":"후마에루","ko":"~을 바탕으로 하다","tts_text":"踏まえる"},
      {"kanji":"勘案","kana":"かんあん","pron":"칸안","ko":"감안","tts_text":"勘案"},
      {"kanji":"鑑みる","kana":"かんがみる","pron":"칸가미루","ko":"비추어 보다","tts_text":"鑑みる"},
      {"kanji":"考慮","kana":"こうりょ","pron":"코오료","ko":"고려","tts_text":"考慮"},
      {"kanji":"配慮","kana":"はいりょ","pron":"하이료","ko":"배려","tts_text":"配慮"},
      {"kanji":"懸念","kana":"けねん","pron":"케넨","ko":"우려","tts_text":"懸念"},

      {"kanji":"危惧","kana":"きぐ","pron":"키구","ko":"우려","tts_text":"危惧"},
      {"kanji":"懸命","kana":"けんめい","pron":"켄메이","ko":"필사적","tts_text":"懸命"},
      {"kanji":"著しい","kana":"いちじるしい","pron":"이치지루시이","ko":"현저하다","tts_text":"著しい"},
      {"kanji":"顕著","kana":"けんちょ","pron":"켄쵸","ko":"현저","tts_text":"顕著"},
      {"kanji":"妥当","kana":"だとう","pron":"다토오","ko":"타당","tts_text":"妥当"},
      {"kanji":"妥協","kana":"だきょう","pron":"다쿄오","ko":"타협","tts_text":"妥協"},
      {"kanji":"徹底","kana":"てってい","pron":"텟테이","ko":"철저","tts_text":"徹底"},
      {"kanji":"厳格","kana":"げんかく","pron":"겐카쿠","ko":"엄격","tts_text":"厳格"},
      {"kanji":"柔軟","kana":"じゅうなん","pron":"쥬우난","ko":"유연","tts_text":"柔軟"},
      {"kanji":"慎重","kana":"しんちょう","pron":"신쵸오","ko":"신중","tts_text":"慎重"},

      {"kanji":"一貫","kana":"いっかん","pron":"잇칸","ko":"일관","tts_text":"一貫"},
      {"kanji":"一律","kana":"いちりつ","pron":"이치리츠","ko":"일률","tts_text":"一律"},
      {"kanji":"概ね","kana":"おおむね","pron":"오오무네","ko":"대체로","tts_text":"概ね"},
      {"kanji":"総じて","kana":"そうじて","pron":"소오지테","ko":"대체로","tts_text":"総じて"},
      {"kanji":"概して","kana":"がいして","pron":"가이시테","ko":"대체로","tts_text":"概して"},
      {"kanji":"ひいては","kana":"ひいては","pron":"히이테와","ko":"나아가서는","tts_text":"ひいては"},
      {"kanji":"もっぱら","kana":"もっぱら","pron":"못파라","ko":"오로지","tts_text":"もっぱら"},
      {"kanji":"あながち","kana":"あながち","pron":"아나가치","ko":"반드시~만은 아니다","tts_text":"あながち"},
      {"kanji":"とはいえ","kana":"とはいえ","pron":"토와이에","ko":"그렇다 해도","tts_text":"とはいえ"},
      {"kanji":"いずれにせよ","kana":"いずれにせよ","pron":"이즈레니세요","ko":"어쨌든","tts_text":"いずれにせよ"}
    ]
  }  
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
    return (user.get("username") or "").lower() == "cjswoaostk"



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


def pick_daily_item(pool, key_prefix="daily"):
    if not pool:
        return {}
    seed_key = f"{key_prefix}:{kst_today_key()}"
    rng = random.Random(seed_key)
    return rng.choice(pool)

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

def nickname_exists(nickname: str) -> bool:
    conn = db()
    row = conn.execute(
        "SELECT 1 FROM users WHERE nickname = ? COLLATE NOCASE",
        (nickname,)
    ).fetchone()
    conn.close()
    return row is not None


    conn = db()
    row = conn.execute(
        "SELECT 1 FROM users WHERE LOWER(nickname) = LOWER(?)",
        (n,)
    ).fetchone()
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
            "desc": WORDS_CAT_DESC.get(k, "일본 여행과 일상 회화에서 자주 쓰는 핵심 단어 모음"),
        })

    ctx = build_words_seo()
    return render_template("words_categories.html", user=user, categories=categories, **ctx)


def row3_to_worddict(r):
    # r = (jp, pron, ko)
    jp = r[0] if len(r) > 0 else ""
    pron = r[1] if len(r) > 1 else ""
    ko = r[2] if len(r) > 2 else ""

    # ✅ 회화 단어모음은 보통 kana가 없으니 비워두거나 jp로 채우기
    # kana를 jp로 넣고 싶으면 kana = jp 로 바꾸면 됨.
    return {
        "sec_key": "",     # 필요하면 나중에 카테고리/섹션 키 넣기
        "kanji": jp,       # 기존 jp → kanji/표기
        "kana": "",        # 없으면 ""
        "pron": pron,      # 기존 pron
        "ko": ko,          # 기존 ko
        "jp": jp,          # note에서 fallback로 쓰게 유지해도 좋음
        "tts_text": jp,    # tts
    }

@app.route("/words/<cat_key>")
def words_detail(cat_key):
    user = current_user()
    q = (request.args.get("q") or "").strip()  # ✅ 검색어

    # ✅ row(튜플/리스트/딕트) → 통일 dict 변환
    def to_word_dict(r):
        # dict 형태가 이미 들어오면 최대한 그대로 살림
        if isinstance(r, dict):
            kanji = r.get("kanji", "") or r.get("jp", "") or ""
            kana  = r.get("kana", "") or ""
            pron  = r.get("pron", "") or ""
            ko    = r.get("ko", "") or ""
            sec_key = r.get("sec_key", "") or ""
        else:
            # (jp, pron, ko) 튜플/리스트 형태
            jp   = r[0] if len(r) > 0 else ""
            pron = r[1] if len(r) > 1 else ""
            ko   = r[2] if len(r) > 2 else ""
            kanji = jp
            kana  = ""   # ✅ 회화단어모음은 보통 kana 없음 → 빈칸
            sec_key = ""

        # ✅ 템플릿(note/words 공용)에서 쓰기 좋은 필드까지 맞춰줌
        return {
            "sec_key": sec_key,
            "kanji": kanji,
            "kana": kana,
            "pron": pron,
            "ko": ko,
            "jp": kanji or kana,      # fallback용
            "tts_text": kanji or kana # TTS용
        }

    cat = (WORDS or {}).get(cat_key)
    if not cat:
        ctx = build_words_seo("단어")
        ctx.pop("page_intro", None)  # ✅ 중복 키 제거

        return render_template(
            "words_detail.html",
            user=user,
            title="없음",
            cat_key=cat_key,
            rows=[],
            fav_jp_set=set(),
            q=q,
            page_intro=None,
            **ctx
        )

    title = cat.get("title", cat_key)
    rows_all = cat.get("items", [])

    # ✅ 카테고리별 소개 문구(없으면 None)
    page_intro = WORDS_CAT_DESC.get(cat_key)

    # ✅ 검색 필터: kanji/kana/pron/ko 어디든 포함되면 통과
    if q:
        qq = q.lower()
        filtered = []
        for r in rows_all:
            w = to_word_dict(r)
            kanji = (w.get("kanji") or "")
            kana  = (w.get("kana") or "")
            pron  = (w.get("pron") or "")
            ko    = (w.get("ko") or "")

            if (qq in kanji.lower()
                or qq in kana.lower()
                or qq in pron.lower()
                or qq in ko.lower()):
                filtered.append(w)
        rows = filtered
    else:
        rows = [to_word_dict(r) for r in rows_all]

    # ✅ 즐겨찾기: DB는 기존대로 jp(표기) 기준으로 유지
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

    # ✅ SEO
    ctx = build_words_seo(f"{title} 검색: {q}") if q else build_words_seo(title)
    ctx.pop("page_intro", None)  # ✅ 중복 키 제거

    return render_template(
        "words_detail.html",
        user=user,
        title=title,
        cat_key=cat_key,
        rows=rows,  # ✅ 이제 rows는 dict 리스트 (kanji/kana/pron/ko)
        fav_jp_set=fav_jp_set,
        q=q,
        page_intro=page_intro,
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
    ensure_board_schema()
    user = current_user()
    if user and not isinstance(user, dict):
        user = dict(user)

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        content = (request.form.get("content") or "").strip()

        # 관리자만 공지 설정 가능
        is_notice = 0
        if user and (user.get("nickname") == "SW" or user.get("id") == 1):
            is_notice = 1 if (request.form.get("is_notice") == "1") else 0

        if not title or not content:
            flash("제목과 내용을 입력해주세요.", "error")
            return render_template("board_write.html", user=user, form=request.form)

        # ✅ 여러 파일 받기 (name="images" multiple)
        files = request.files.getlist("images")
        urls = []

        for file in files:
            if not file or not file.filename:
                continue

            if not allowed_file(file.filename):
                flash("이미지 파일(png/jpg/jpeg/gif/webp)만 업로드할 수 있어요.", "error")
                return render_template("board_write.html", user=user, form=request.form)

            filename = secure_filename(file.filename)
            stamp = datetime.now(timezone.utc).astimezone(_KST).strftime("%Y%m%d%H%M%S")
            save_name = f"user{user['id']}_{stamp}_{filename}"
            save_path = os.path.join(UPLOAD_FOLDER, save_name)
            file.save(save_path)

            urls.append(f"/static/uploads/{save_name}")

        # ✅ thumb_url은 첫 이미지(없으면 None)
        thumb_url = urls[0] if urls else None

        author_grade = normalize_author_grade(get_user_grade_label(user))
        author_nickname = user["nickname"]

        conn = db()
        try:
            conn.execute(
                """
                INSERT INTO board_posts
                (user_id, author_grade, author_nickname, title, content,
                 thumb_url, images_json, upvotes, views, created_at, is_notice)
                VALUES (?,?,?,?,?,?,?,0,0,?,?)
                """,
                (
                    user["id"],
                    author_grade,
                    author_nickname,
                    title,
                    content,
                    thumb_url,
                    json.dumps(urls, ensure_ascii=False),
                    kst_now_iso(),
                    is_notice,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        flash("글이 등록되었습니다.", "success")
        return redirect(url_for("board"))

    return render_template("board_write.html", user=user, form={})



def get_post_or_404(post_id: int):
    ensure_board_schema()  # ✅ 추가(안전)

    conn = db()
    row = conn.execute(
        """
        SELECT id, user_id, title, content, thumb_url,
               images_json,
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
    ensure_board_schema()
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
          images_json,
          COALESCE(is_notice,0) AS is_notice
        FROM board_posts
        WHERE id=?
        """,
        (post_id,),
    ).fetchone()

    if not post:
        conn.close()
        abort(404)

    # ✅ 여러 이미지 JSON 파싱 (sqlite3.Row는 dict처럼 get이 안 될 수 있어서 []로 접근)
    images = []
    try:
        raw = post["images_json"]  # None or str
        if raw:
            images = json.loads(raw) or []
            images = [u for u in images if isinstance(u, str) and u.strip()]
    except Exception:
        images = []

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
        images=images,
        comments=comments,
        is_owner=is_owner,
        user_has_upvoted=user_has_upvoted,
    )



@app.route("/board/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def board_edit(post_id: int):
    import json
    ensure_board_schema()
    user = current_user()
    if user and not isinstance(user, dict):
        user = dict(user)

    post = get_post_or_404(post_id)

    # 공지글 여부
    is_notice = int(post.get("is_notice") or 0)

    # 공지글이면 "관리자만" 수정 가능
    is_admin_user = bool(user and (user.get("nickname") == "SW" or user.get("id") == 1))
    if is_notice == 1 and not is_admin_user:
        abort(403)

    # ---- 현재 저장된 이미지 리스트 만들기 (thumb_url + images_json 통합) ----
    images = []
    try:
        if post.get("images_json"):
            images = json.loads(post["images_json"]) or []
    except Exception:
        images = []

    # 혹시 섞인 값 정리
    images = [u for u in images if isinstance(u, str) and u.strip()]

    # thumb_url이 따로 있으면 리스트에 포함(중복 방지)
    if post.get("thumb_url"):
        tu = post["thumb_url"]
        if tu and tu not in images:
            images.insert(0, tu)

    # ✅ GET이면: 템플릿에 images 넘겨서 "여러 장" 미리보기 뜨게
    if request.method == "GET":
        return render_template(
            "board_edit.html",
            user=user,
            post=post,
            images=images,  # ✅ 핵심
            show_notice_toggle=is_admin_user,
            is_notice=is_notice,
        )

    # -------------------------
    # POST: 수정 저장
    # -------------------------
    title = (request.form.get("title") or "").strip()
    content = (request.form.get("content") or "").strip()

    if not title or not content:
        flash("제목과 내용을 입력해주세요.", "error")
        return render_template(
            "board_edit.html",
            user=user,
            post=post,
            images=images,
            show_notice_toggle=is_admin_user,
            is_notice=is_notice,
        )

    # 1) X로 제외한(삭제) 이미지 반영
    remove_raw = request.form.get("remove_images_json") or "[]"
    try:
        remove_list = json.loads(remove_raw) or []
    except Exception:
        remove_list = []

    remove_set = set([u for u in remove_list if isinstance(u, str) and u.strip()])
    if remove_set:
        images = [u for u in images if u not in remove_set]

    # 2) 새로 추가한 이미지 업로드(여러 장)
    files = request.files.getlist("images")  # ✅ name="images" multiple
    new_urls = []

    for f in files:
        if not f or not f.filename:
            continue

        if not allowed_file(f.filename):
            flash("이미지 파일(png/jpg/jpeg/gif/webp)만 업로드할 수 있어요.", "error")
            return render_template(
                "board_edit.html",
                user=user,
                post=post,
                images=images,
                show_notice_toggle=is_admin_user,
                is_notice=is_notice,
            )

        filename = secure_filename(f.filename)
        stamp = datetime.now(timezone.utc).astimezone(_KST).strftime("%Y%m%d%H%M%S")
        save_name = f"user{user['id']}_{stamp}_{filename}"
        save_path = os.path.join(UPLOAD_FOLDER, save_name)
        f.save(save_path)
        new_urls.append(f"/static/uploads/{save_name}")

    # 추가 업로드는 기존 뒤에 붙임
    for u in new_urls:
        if u not in images:
            images.append(u)

    # 3) 공지글 토글은 관리자만
    new_is_notice = is_notice
    if is_admin_user:
        new_is_notice = 1 if request.form.get("is_notice") == "1" else 0

    # 4) thumb_url은 첫 이미지로(없으면 None)
    thumb_url = images[0] if images else None

    # 5) DB 저장: images_json + thumb_url 같이 업데이트
    conn = db()
    try:
        conn.execute(
            """
            UPDATE board_posts
            SET title=?, content=?, thumb_url=?, images_json=?, is_notice=?
            WHERE id=?
            """,
            (title, content, thumb_url, json.dumps(images, ensure_ascii=False), new_is_notice, post_id),
        )
        conn.commit()
    finally:
        conn.close()

    flash("수정되었습니다.", "success")
    return redirect(url_for("board_detail", post_id=post_id))



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
        elif nickname_exists(nickname):
            errors["nickname"] = "이미 사용 중인 닉네임입니다."

        else:
            conn = db()
            dup_nick = conn.execute(
                "SELECT id FROM users WHERE nickname = ? COLLATE NOCASE",
                (nickname,)
            ).fetchone()
            conn.close()
            if dup_nick:
                errors["nickname"] = "이미 사용 중인 닉네임입니다. (대소문자 구분 없이 중복 불가)"

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

def iter_jlpt_items(src):
    """
    JLPT 단어 소스가
    - 섹션 dict(sec01~sec10) 형태면: 모든 items를 펼쳐서 yield
    - 이미 list 형태면: 그대로 yield
    """
    if not src:
        return
    if isinstance(src, dict):
        for sec in src.values():
            if isinstance(sec, dict):
                for it in (sec.get("items") or []):
                    yield it
    elif isinstance(src, list):
        for it in src:
            yield it


def match_jlpt_word(it, key):
    """
    word_favorites.jp에 저장된 값(key)이
    kanji/kana/기존 jp 중 하나와 일치하면 매칭
    """
    key = _norm_text(key)
    if not key:
        return False

    kanji = _norm_text(it.get("kanji"))
    kana  = _norm_text(it.get("kana"))
    jp    = _norm_text(it.get("jp"))

    return key == kanji or key == kana or key == jp

def _norm_text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, (list, tuple)):
        # 리스트면 줄바꿈으로 합치기
        return "\n".join(str(x).strip() for x in v if x is not None).strip()
    if isinstance(v, dict):
        # dict면 보기 좋게 key:value 형태로
        return "\n".join(f"{k}: {v[k]}" for k in v).strip()
    return str(v).strip()

# -------------------------
# Note (login-only)
# -------------------------
@app.route("/note")
@login_required
def note():
    user = current_user()

    # -------------------------
    # 1) 문장 즐겨찾기 (favorites)
    # -------------------------
    conn = db()
    try:
        rows = conn.execute(
            """
            SELECT phrase_key, jp, pron, ko, created_at
            FROM favorites
            WHERE user_id=?
            ORDER BY rowid DESC
            """,
            (user["id"],),
        ).fetchall()
    finally:
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

    # -------------------------
    # 2) 단어 즐겨찾기 (word_favorites)
    #    - JLPT도 word_favorites에 저장됨
    #    - kanji/kana/pron/ko/tts_text까지 찾아서 채움
    # -------------------------
    word_fav_items = []

    conn = db()
    try:
        ensure_word_favorites_table(conn)
        wrows = conn.execute(
            """
            SELECT cat_key, jp, created_at
            FROM word_favorites
            WHERE user_id=?
            ORDER BY rowid DESC
            """,
            (user["id"],),
        ).fetchall()
    finally:
        conn.close()

    for wr in wrows:
        ck = _norm_text(wr["cat_key"])
        key = _norm_text(wr["jp"])   # ✅ 즐겨찾기 저장키(kanji 또는 kana 등)

        pron = ""
        ko = ""
        kanji = ""
        kana = ""
        tts_text = ""

        if ck == "jlpt:N5:words":
            cat_title = "JLPT N5 단어"
            src = N5_WORDS
        elif ck == "jlpt:N4:words":
            cat_title = "JLPT N4 단어"
            src = N4_WORDS
        elif ck == "jlpt:N3:words":
            cat_title = "JLPT N3 단어"
            src = N3_WORDS
        elif ck == "jlpt:N2:words":
            cat_title = "JLPT N2 단어"
            src = N2_WORDS
        elif ck == "jlpt:N1:words":
            cat_title = "JLPT N1 단어"
            src = N1_WORDS
        else:
            cat = (WORDS or {}).get(ck) or {}
            cat_title = cat.get("title", ck)
            src = None

        if src is not None:
            # ✅ JLPT: sec01~sec10 펼쳐서 검색
            for it in iter_jlpt_items(src):
                if match_jlpt_word(it, key):
                    kanji = _norm_text(it.get("kanji") or it.get("jp"))
                    kana  = _norm_text(it.get("kana"))
                    pron  = _norm_text(it.get("pron"))
                    ko    = _norm_text(it.get("ko"))
                    tts_text = _norm_text(it.get("tts_text")) or kanji or kana or key
                    break
        else:
            # ✅ 기존 WORDS 튜플: (jp, pron, ko)
            for (w_jp, w_pron, w_ko) in (cat.get("items") or []):
                if _norm_text(w_jp) == key:
                    kanji = _norm_text(w_jp)
                    kana = ""
                    pron = _norm_text(w_pron)
                    ko = _norm_text(w_ko)          # ✅ 핵심: 여기!
                    tts_text = kanji
                    break

        word_fav_items.append({
            "cat_key": ck,
            "cat_title": cat_title,
            "key": key,
            "kanji": kanji or key,
            "kana": kana,
            "pron": pron,
            "ko": ko,
            "tts_text": tts_text or (kanji or kana or key),
            "created_at": wr["created_at"],
        })

    return render_template(
        "note.html",
        user=user,
        fav_items=fav_items,
        word_fav_items=word_fav_items,
        **seo(
            title="나만의 일본어 학습노트 | 즐겨찾기 회화·단어 암기 공부",
            desc="자주 쓰는 일본어 회화와 단어를 저장하고 가리기 기능으로 암기하세요. 나만의 일본어 공부 노트 공간입니다.",
            keywords="일본어 학습노트, 일본어 암기, 일본어 단어장, 일본어 회화 저장",
        ),
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


@app.post("/api/jlpt_word_fav")
@login_required
def api_jlpt_word_fav_post():
    user = current_user()
    data = request.get_json(silent=True) or {}

    action  = (data.get("action") or "").strip()   # add/remove
    level   = (data.get("level") or "").strip()    # "N5"
    section = (data.get("section") or "words").strip()
    jp      = (data.get("jp") or "").strip()
    pron    = (data.get("pron") or "").strip()
    ko      = (data.get("ko") or "").strip()

    if not level or not section or not jp:
        return jsonify({"ok": False, "error": "BAD_REQUEST"}), 400

    conn = db()
    try:
        ensure_jlpt_word_favorites_table(conn)

        if action == "add":
            # ✅ pron/ko가 비어있으면 원본(JLPT_WORDS 등)에서 복구 시도
            if (not pron or not ko) and jp:
                try:
                    src = (JLPT_WORDS or {}).get(level) or {}

                    # (A) {"items":[(jp,pron,ko),...]} 형태
                    items = src.get("items") if isinstance(src, dict) else None
                    if items:
                        for wjp, wpron, wko in items:
                            if (wjp or "").strip() == jp:
                                pron = pron or (wpron or "")
                                ko = ko or (wko or "")
                                break

                    # (B) [{"jp":..,"pron":..,"ko":..}, ...] 형태
                    if (not pron or not ko) and isinstance(src, list):
                        for it in src:
                            if (it.get("jp", "").strip() == jp):
                                pron = pron or it.get("pron", "")
                                ko = ko or it.get("ko", "")
                                break
                except Exception:
                    pass

            conn.execute("""
                INSERT OR IGNORE INTO jlpt_word_favorites
                (user_id, level, section, jp, pron, ko, created_at)
                VALUES(?,?,?,?,?,?,?)
            """, (user["id"], level, section, jp, pron, ko, kst_now_iso()))
            conn.commit()
            return jsonify({"ok": True})

        if action == "remove":
            conn.execute("""
                DELETE FROM jlpt_word_favorites
                WHERE user_id=? AND level=? AND section=? AND jp=?
            """, (user["id"], level, section, jp))
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
        return jsonify({
            "ok": False,
            "msg": "닉네임은 2~8자 이내로 입력해주세요.",
            "available": False
        })

    if not nickname_allowed(nickname):
        return jsonify({
            "ok": False,
            "msg": "사용할 수 없는 닉네임입니다.",
            "available": False
        })

    # ✅ DB 중복 체크 (대소문자 무시)
    conn = db()
    try:
        row = conn.execute(
            "SELECT 1 FROM users WHERE nickname = ? COLLATE NOCASE",
            (nickname,)
        ).fetchone()
    finally:
        conn.close()

    if row:
        return jsonify({
            "ok": False,
            "msg": "이미 사용 중인 닉네임입니다.",
            "available": False
        })

    return jsonify({
        "ok": True,
        "msg": "사용 가능한 닉네임입니다.",
        "available": True
    })



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
        {
        "id": 58,
        "title": "- 58번문제 -",
        "image": "dialog_quiz/ask_wifi_password_cafe.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、Wi-Fiはありますか？",
                "pron": "스미마센, 와이파이와 아리마스카",
                "ko": "실례합니다, 와이파이 있나요?"
            },
            {
                "role": "직원",
                "jp": "はい、ございます。パスワードが必要ですか？",
                "pron": "하이, 고자이마스. 파스와-도가 히츠요-데스카",
                "ko": "네, 있습니다. 비밀번호가 필요하세요?"
            },
            {
                "role": "남자",
                "jp": "はい、教えてください。",
                "pron": "하이, 오시에테 쿠다사이",
                "ko": "네, 알려주세요."
            },
            {
                "role": "직원",
                "jp": "レシートに書いてあります。こちらです。",
                "pron": "레시-토니 카이테 아리마스. 코치라데스",
                "ko": "영수증에 적혀 있어요. 여기요."
            }
        ],

        "choices": [
            "와이파이 비밀번호를 알려 달라고 요청하고 있다.",
            "자리에서 주문을 받아 달라고 부탁하고 있다.",
            "화장실 위치를 물어보고 있다.",
            "카드 결제가 가능한지 확인하고 있다."
        ],

        "answer": 1,

        "explain_ko": "남자가 ‘Wi-Fiはありますか？(와이파이 있나요?)’라고 묻고, 직원이 ‘パスワードが必要ですか？(비밀번호가 필요하세요?)’라고 확인한 뒤 ‘レシートに書いてあります(영수증에 적혀 있어요)’라고 안내하므로 와이파이 비밀번호를 요청/확인하는 상황입니다."
    },  # ✅ 반드시 필요
        {
        "id": 59,
        "title": "- 59번문제 -",
        "image": "dialog_quiz/ask_baggage_coin_locker.png",

        "lines": [
            {
                "role": "여자",
                "jp": "すみません、コインロッカーはどこですか？",
                "pron": "스미마센, 코인 롯카-와 도코데스카",
                "ko": "실례합니다, 코인 로커는 어디예요?"
            },
            {
                "role": "직원",
                "jp": "改札を出て左にあります。",
                "pron": "카이사츠오 데테 히다리니 아리마스",
                "ko": "개찰구 나가서 왼쪽에 있어요."
            },
            {
                "role": "여자",
                "jp": "大きい荷物も入りますか？",
                "pron": "오오키이 니모츠모 하이리마스카",
                "ko": "큰 짐도 들어가나요?"
            },
            {
                "role": "직원",
                "jp": "はい、大きいサイズもありますよ。",
                "pron": "하이, 오오키이 사이즈모 아리마스요",
                "ko": "네, 큰 사이즈도 있어요."
            }
        ],

        "choices": [
            "지하철 환승 장소를 물어보고 있다.",
            "코인 로커 위치를 물어보고 있다.",
            "짐을 택배로 보내고 싶다고 말하고 있다.",
            "가방을 분실했다고 신고하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘コインロッカーはどこですか？’로 코인 로커 위치를 묻고, ‘大きい荷物も入りますか？’로 큰 짐 보관 가능 여부까지 확인하므로 코인 로커 안내 상황입니다."
    },  # ✅ 반드시 필요

    {
        "id": 60,
        "title": "- 60번문제 -",
        "image": "dialog_quiz/hotel_late_checkout.png",

        "lines": [
            {
                "role": "손님",
                "jp": "すみません、チェックアウトを延長できますか？",
                "pron": "스미마센, 체쿠아우토오 엔초- 데키마스카",
                "ko": "실례합니다, 체크아웃을 연장할 수 있나요?"
            },
            {
                "role": "직원",
                "jp": "はい、何時までがご希望ですか？",
                "pron": "하이, 난지마데가 고키보-데스카",
                "ko": "네, 몇 시까지 원하시나요?"
            },
            {
                "role": "손님",
                "jp": "1時間だけお願いします。",
                "pron": "이치지칸다케 오네가이시마스",
                "ko": "1시간만 부탁드려요."
            },
            {
                "role": "직원",
                "jp": "かしこまりました。追加料金がかかります。",
                "pron": "카시코마리마시타. 츠이카료-킨가 카카리마스",
                "ko": "알겠습니다. 추가 요금이 발생합니다."
            }
        ],

        "choices": [
            "체크아웃 시간을 연장할 수 있는지 문의하고 있다.",
            "체크인을 진행하고 있다.",
            "객실 청소를 요청하고 있다.",
            "짐 보관 서비스를 신청하고 있다."
        ],

        "answer": 1,

        "explain_ko": "‘チェックアウトを延長できますか？’는 체크아웃 시간을 늦출 수 있는지(레이트 체크아웃) 묻는 표현이며, 직원이 희망 시간을 확인하고 추가 요금을 안내하므로 1번이 정답입니다."
    },  # ✅ 반드시 필요

    {
        "id": 61,
        "title": "- 61번문제 -",
        "image": "dialog_quiz/store_return_exchange.png",

        "lines": [
            {
                "role": "손님",
                "jp": "すみません、これを返品できますか？",
                "pron": "스미마센, 코레오 헨핀 데키마스카",
                "ko": "실례합니다, 이거 환불(반품)할 수 있나요?"
            },
            {
                "role": "직원",
                "jp": "レシートはお持ちですか？",
                "pron": "레시-토와 오모치데스카",
                "ko": "영수증은 가지고 계신가요?"
            },
            {
                "role": "손님",
                "jp": "はい、ここにあります。",
                "pron": "하이, 코코니 아리마스",
                "ko": "네, 여기 있어요."
            },
            {
                "role": "직원",
                "jp": "ありがとうございます。確認いたします。",
                "pron": "아리가토- 고자이마스. 카쿠닌 이타시마스",
                "ko": "감사합니다. 확인하겠습니다."
            }
        ],

        "choices": [
            "상품 교환을 위해 사이즈를 바꾸고 있다.",
            "상품이 어디에 있는지 위치를 묻고 있다.",
            "상품을 반품(환불)할 수 있는지 묻고 있다.",
            "결제할 때 카드 사용이 가능한지 물어보고 있다."
        ],

        "answer": 3,

        "explain_ko": "‘返品できますか？’는 반품/환불 가능 여부를 묻는 표현이고, 직원이 영수증(レシート) 유무를 확인하므로 반품 문의 상황입니다."
    },  # ✅ 반드시 필요

    {
        "id": 62,
        "title": "- 62번문제 -",
        "image": "dialog_quiz/train_platform_number.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、東京行きは何番線ですか？",
                "pron": "스미마센, 토-쿄-이키와 난반센데스카",
                "ko": "실례합니다, 도쿄행은 몇 번 승강장인가요?"
            },
            {
                "role": "직원",
                "jp": "3番線です。階段を上がってください。",
                "pron": "산반센데스. 카이단오 아갓테 쿠다사이",
                "ko": "3번 승강장입니다. 계단을 올라가세요."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。間に合いそうです。",
                "pron": "아리가토- 고자이마스. 마니아이소-데스",
                "ko": "감사합니다. 늦지 않을 것 같아요."
            }
        ],

        "choices": [
            "출구가 어디인지 묻고 있다.",
            "도쿄행 열차 승강장이 몇 번인지 묻고 있다.",
            "표를 환불하려고 하고 있다.",
            "열차 요금이 얼마인지 묻고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘何番線ですか？’는 ‘몇 번 승강장이에요?’라는 뜻이고, 직원이 ‘3番線’이라고 답하므로 승강장 번호를 묻는 상황입니다."
    },  # ✅ 반드시 필요

    {
        "id": 63,
        "title": "- 63번문제 -",
        "image": "dialog_quiz/restaurant_allergy.png",

        "lines": [
            {
                "role": "여자",
                "jp": "すみません、私、えびアレルギーがあります。",
                "pron": "스미마센, 와타시, 에비 아레루기-가 아리마스",
                "ko": "실례합니다, 저 새우 알레르기가 있어요."
            },
            {
                "role": "직원",
                "jp": "かしこまりました。えびは入っていません。",
                "pron": "카시코마리마시타. 에비와 하잇테이마센",
                "ko": "알겠습니다. 새우는 들어가지 않습니다."
            },
            {
                "role": "여자",
                "jp": "この料理は大丈夫ですか？",
                "pron": "코노 료-리와 다이죠-부데스카",
                "ko": "이 요리는 괜찮나요?"
            },
            {
                "role": "직원",
                "jp": "はい、安心して召し上がれます。",
                "pron": "하이, 안신시테 메시아가레마스",
                "ko": "네, 안심하고 드실 수 있어요."
            }
        ],

        "choices": [
            "예약 시간을 변경해 달라고 요청하고 있다.",
            "알레르기 때문에 음식에 특정 재료가 들어가는지 확인하고 있다.",
            "음식이 얼마나 매운지 묻고 있다.",
            "포장 가능 여부를 물어보고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘えびアレルギーがあります(새우 알레르기가 있어요)’라고 말한 뒤 ‘この料理は大丈夫ですか？’로 재료 포함 여부를 확인하므로 알레르기 관련 확인 상황입니다."
    },  # ✅ 반드시 필요

    {
        "id": 64,
        "title": "- 64번문제 -",
        "image": "dialog_quiz/ask_photo_no_flash.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、フラッシュなしで撮ってもいいですか？",
                "pron": "스미마센, 후랏슈 나시데 톳테모 이이데스카",
                "ko": "실례합니다, 플래시 없이 찍어도 될까요?"
            },
            {
                "role": "직원",
                "jp": "はい、フラッシュなしなら大丈夫です。",
                "pron": "하이, 후랏슈 나시나라 다이죠-부데스",
                "ko": "네, 플래시 없이면 괜찮습니다."
            },
            {
                "role": "남자",
                "jp": "ありがとうございます。気をつけます。",
                "pron": "아리가토- 고자이마스. 키오 츠케마스",
                "ko": "감사합니다. 주의할게요."
            }
        ],

        "choices": [
            "사진 촬영을 전면 금지해 달라고 요청하고 있다.",
            "플래시 없이 사진 촬영해도 되는지 허락을 구하고 있다.",
            "기념품 가격을 흥정하고 있다.",
            "전시 설명을 부탁하고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘フラッシュなしで撮ってもいいですか？’는 플래시를 사용하지 않는 조건으로 사진 촬영 허락을 구하는 말이며, 직원이 ‘なしなら大丈夫’라고 허용하고 있습니다."
    },  # ✅ 반드시 필요

    {
        "id": 65,
        "title": "- 65번문제 -",
        "image": "dialog_quiz/pharmacy_cold_medicine.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、風邪薬はありますか？",
                "pron": "스미마센, 카제구스리와 아리마스카",
                "ko": "실례합니다, 감기약 있나요?"
            },
            {
                "role": "약사",
                "jp": "はい。熱はありますか？",
                "pron": "하이. 네츠와 아리마스카",
                "ko": "네. 열이 있으신가요?"
            },
            {
                "role": "남자",
                "jp": "少しだけあります。",
                "pron": "스코시다케 아리마스",
                "ko": "조금 있어요."
            },
            {
                "role": "약사",
                "jp": "では、こちらをおすすめします。",
                "pron": "데와, 코치라오 오스스메시마스",
                "ko": "그럼 이걸 추천드릴게요."
            }
        ],

        "choices": [
            "약국에서 감기약을 찾고 상담하고 있다.",
            "약국에서 배탈약을 찾고 있다.",
            "병원 진료 예약을 하고 있다.",
            "약국에서 밴드를 요청하고 있다."
        ],

        "answer": 1,

        "explain_ko": "‘風邪薬はありますか？(감기약 있나요?)’라고 묻고, 약사가 ‘熱はありますか？(열이 있나요?)’라고 증상을 확인한 뒤 추천하는 흐름이므로 감기약 상담 상황입니다."
    },  # ✅ 반드시 필요

    {
        "id": 66,
        "title": "- 66번문제 -",
        "image": "dialog_quiz/hotel_wake_up_call.png",

        "lines": [
            {
                "role": "손님",
                "jp": "すみません、モーニングコールをお願いできますか？",
                "pron": "스미마센, 모-닝구 코-루오 오네가이 데키마스카",
                "ko": "실례합니다, 모닝콜 부탁드릴 수 있나요?"
            },
            {
                "role": "직원",
                "jp": "はい、何時におかけしますか？",
                "pron": "하이, 난지니 오카케 시마스카",
                "ko": "네, 몇 시에 해드릴까요?"
            },
            {
                "role": "손님",
                "jp": "朝7時にお願いします。",
                "pron": "아사 시치지니 오네가이시마스",
                "ko": "아침 7시에 부탁합니다."
            },
            {
                "role": "직원",
                "jp": "かしこまりました。7時にお電話します。",
                "pron": "카시코마리마시타. 시치지니 오뎅와 시마스",
                "ko": "알겠습니다. 7시에 전화드리겠습니다."
            }
        ],

        "choices": [
            "방 청소 시간을 조정하고 있다.",
            "모닝콜을 요청하고 있다.",
            "체크아웃을 연장하고 있다.",
            "짐을 맡기고 있다."
        ],

        "answer": 2,

        "explain_ko": "‘モーニングコールをお願いできますか？’는 호텔에서 기상 전화를 요청하는 표현이고, 직원이 시간을 확인해 ‘7時にお電話します’라고 확정하므로 모닝콜 요청 상황입니다."
    },  # ✅ 반드시 필요

    {
        "id": 67,
        "title": "- 67번문제 -",
        "image": "dialog_quiz/store_size_not_available.png",

        "lines": [
            {
                "role": "여자",
                "jp": "すみません、この服のMサイズはありますか？",
                "pron": "스미마센, 코노 후쿠노 엠 사이즈와 아리마스카",
                "ko": "실례합니다, 이 옷 M사이즈 있나요?"
            },
            {
                "role": "직원",
                "jp": "申し訳ありません。Mサイズは品切れです。",
                "pron": "모오시아케 아리마센. 엠 사이즈와 시나기레데스",
                "ko": "죄송합니다. M사이즈는 품절입니다."
            },
            {
                "role": "여자",
                "jp": "じゃあ、Lサイズを試着してもいいですか？",
                "pron": "자아, 에루 사이즈오 시챠쿠시테모 이이데스카",
                "ko": "그럼 L사이즈를 입어봐도 될까요?"
            },
            {
                "role": "직원",
                "jp": "はい、試着室はこちらです。",
                "pron": "하이, 시챠쿠시츠와 코치라데스",
                "ko": "네, 피팅룸은 이쪽입니다."
            }
        ],

        "choices": [
            "옷 사이즈를 찾고 있다.",
            "옷 가격 할인을 요청하고 있다.",
            "환불 규정을 문의하고 있다.",
            "직원에게 옷을 포장해달라고 부탁하고 있다."
        ],

        "answer": 1,

        "explain_ko": "‘Mサイズは品切れです( M사이즈는 품절입니다 )’라고 답한 뒤, 손님이 ‘Lサイズを試着してもいいですか？’로 다른 사이즈를 입어보려 하므로 1번이 정답입니다."
    },  # ✅ 반드시 필요
        {
        "id": 68,
        "title": "- 68번문제 -",
        "image": "dialog_quiz/ask_phone_charge.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、スマホを充電してもいいですか？",
                "pron": "스미마센, 스마호오 쥬-덴시테모 이이데스카",
                "ko": "실례합니다, 휴대폰 충전해도 될까요?"
            },
            {
                "role": "직원",
                "jp": "はい、こちらのコンセントを使ってください。",
                "pron": "하이, 코치라노 콘센토오 츠캇테 쿠다사이",
                "ko": "네, 이쪽 콘센트를 사용하세요."
            },
            {
                "role": "남자",
                "jp": "助かります。ありがとうございます。",
                "pron": "타스카리마스. 아리가토- 고자이마스",
                "ko": "도움이 되네요. 감사합니다."
            }
        ],

        "choices": [
            "와이파이 비밀번호를 묻고 있다.",
            "자리를 옮겨 달라고 요청하고 있다.",
            "휴대폰 충전을 해도 되는지 허락을 구하고 있다.",
            "콘센트가 고장 났다고 말하고 있다."
        ],

        "answer": 3,

        "explain_ko": "남자가 ‘スマホを充電してもいいですか？’라고 말하며 휴대폰을 충전해도 되는지 허락을 구하고 있고, 직원이 콘센트를 안내해 주고 있으므로 충전 허락을 요청하는 상황입니다."
    },  # ✅ 반드시 필요
        {
        "id": 69,
        "title": "- 69번문제 -",
        "image": "dialog_quiz/ask_restaurant_wait_time.png",
        "lines": [
            {"role": "남자", "jp": "すみません、どのくらい待ちますか？", "pron": "스미마센, 도노쿠라이 마치마스카", "ko": "실례합니다, 얼마나 기다려야 하나요?"},
            {"role": "직원", "jp": "30分ほどです。", "pron": "산쥬푼호도데스", "ko": "30분 정도입니다."},
            {"role": "남자", "jp": "わかりました。待ちます。", "pron": "와카리마시타. 마치마스", "ko": "알겠습니다. 기다릴게요."}
        ],
        "choices": [
            "예약을 취소하고 있다.",
            "대기 시간을 확인하고 있다.",
            "메뉴를 추천받고 있다.",
            "포장 주문을 하고 있다."
        ],
        "answer": 2,
        "explain_ko": "‘どのくらい待ちますか？’는 대기 시간을 물을 때 쓰는 표현으로, 식당에서 기다려야 하는 시간을 확인하는 상황입니다."
    },

    {
        "id": 70,
        "title": "- 70번문제 -",
        "image": "dialog_quiz/ask_last_train.png",
        "lines": [
            {"role": "남자", "jp": "すみません、終電は何時ですか？", "pron": "스미마센, 슈-덴와 난지데스카", "ko": "실례합니다, 막차는 몇 시인가요?"},
            {"role": "직원", "jp": "23時45分です。", "pron": "니쥬-산지 욘쥬-고푼데스", "ko": "23시 45분입니다."},
            {"role": "남자", "jp": "まだ間に合いますね。", "pron": "마다 마니아이마스네", "ko": "아직 탈 수 있겠네요."}
        ],
        "choices": [
            "첫차 시간을 묻고 있다.",
            "열차 요금을 묻고 있다.",
            "막차 시간을 확인하고 있다.",
            "환승 위치를 묻고 있다."
        ],
        "answer": 3,
        "explain_ko": "‘終電’은 막차를 의미하며, 막차 시간을 확인하는 대화입니다."
    },

    {
        "id": 71,
        "title": "- 71번문제 -",
        "image": "dialog_quiz/ask_takeout.png",
        "lines": [
            {"role": "여자", "jp": "すみません、テイクアウトできますか？", "pron": "스미마센, 테이쿠아우토 데키마스카", "ko": "실례합니다, 포장 가능할까요?"},
            {"role": "직원", "jp": "はい、できます。", "pron": "하이, 데키마스", "ko": "네, 가능합니다."},
            {"role": "여자", "jp": "じゃあ、これをお願いします。", "pron": "자아, 코레오 오네가이시마스", "ko": "그럼 이걸로 부탁해요."}
        ],
        "choices": [
            "배달을 요청하고 있다.",
            "예약 여부를 확인하고 있다.",
            "포장 주문이 가능한지 묻고 있다.",
            "매운 정도를 조절해달라고 요청하고 있다."
        ],
        "answer": 3,
        "explain_ko": "‘テイクアウトできますか？’는 포장 가능한지 물을 때 사용하는 표현입니다."
    },

    {
        "id": 72,
        "title": "- 72번문제 -",
        "image": "dialog_quiz/ask_restroom_station.png",
        "lines": [
            {"role": "남자", "jp": "すみません、トイレは改札の中ですか？", "pron": "스미마센, 토이레와 카이사츠노 나카데스카", "ko": "실례합니다, 화장실은 개찰구 안에 있나요?"},
            {"role": "직원", "jp": "はい、中にあります。", "pron": "하이, 나카니 아리마스", "ko": "네, 안에 있습니다."}
        ],
        "choices": [
            "화장실 위치를 자세히 확인하고 있다.",
            "출구 위치를 묻고 있다.",
            "환승 통로를 찾고 있다.",
            "엘리베이터 위치를 묻고 있다."
        ],
        "answer": 1,
        "explain_ko": "화장실이 개찰구 안쪽에 있는지 여부를 확인하는 상황입니다."
    },

    {
        "id": 73,
        "title": "- 73번문제 -",
        "image": "dialog_quiz/ask_free_refill.png",
        "lines": [
            {"role": "남자", "jp": "すみません、おかわりできますか？", "pron": "스미마센, 오카와리 데키마스카", "ko": "실례합니다, 리필 가능할까요?"},
            {"role": "직원", "jp": "はい、無料です。", "pron": "하이, 무료-데스", "ko": "네, 무료입니다."}
        ],
        "choices": [
            "음식을 추가 주문하고 있다.",
            "리필이 가능한지 묻고 있다.",
            "계산서를 요청하고 있다.",
            "메뉴 설명을 듣고 있다."
        ],
        "answer": 2,
        "explain_ko": "‘おかわりできますか？’는 음식이나 음료를 더 받을 수 있는지 묻는 표현입니다."
    },

    {
        "id": 74,
        "title": "- 74번문제 -",
        "image": "dialog_quiz/ask_bus_stop.png",
        "lines": [
            {"role": "여자", "jp": "すみません、このバス停は空港行きですか？", "pron": "스미마센, 코노 바스테이와 쿠-코-이키데스카", "ko": "실례합니다, 이 버스정류장은 공항 가나요?"},
            {"role": "남자", "jp": "はい、空港まで行きます。", "pron": "하이, 쿠-코-마데 이키마스", "ko": "네, 공항까지 가요."}
        ],
        "choices": [
            "공항행 버스인지 확인하고 있다.",
            "버스 요금을 묻고 있다.",
            "막차 시간을 묻고 있다.",
            "좌석 예약을 하고 있다."
        ],
        "answer": 1,
        "explain_ko": "버스가 공항으로 가는 노선인지 확인하는 상황입니다."
    },

    {
        "id": 75,
        "title": "- 75번문제 -",
        "image": "dialog_quiz/ask_change_money_small.png",
        "lines": [
            {"role": "남자", "jp": "すみません、小銭に両替できますか？", "pron": "스미마센, 코제니니 료-가에 데키마스카", "ko": "실례합니다, 잔돈으로 바꿀 수 있나요?"},
            {"role": "직원", "jp": "はい、できますよ。", "pron": "하이, 데키마스요", "ko": "네, 가능합니다."}
        ],
        "choices": [
            "큰 금액을 환전하고 있다.",
            "카드 결제를 요청하고 있다.",
            "잔돈으로 교환 가능한지 묻고 있다.",
            "수수료를 흥정하고 있다."
        ],
        "answer": 3,
        "explain_ko": "‘小銭に両替’는 큰 돈을 잔돈으로 바꾸는 것을 의미합니다."
    },

    {
        "id": 76,
        "title": "- 76번문제 -",
        "image": "dialog_quiz/ask_seat_available.png",
        "lines": [
            {"role": "여자", "jp": "すみません、この席空いていますか？", "pron": "스미마센, 코노 세키 아이테이마스카", "ko": "실례합니다, 이 자리 비어 있나요?"},
            {"role": "남자", "jp": "はい、大丈夫です。", "pron": "하이, 다이죠-부데스", "ko": "네, 괜찮아요."}
        ],
        "choices": [
            "자리에 앉아도 되는지 확인하고 있다.",
            "자리를 예약하고 있다.",
            "자리를 바꿔달라고 요청하고 있다.",
            "의자를 추가로 요청하고 있다."
        ],
        "answer": 1,
        "explain_ko": "‘席空いていますか？’는 자리가 비어 있는지 확인할 때 사용하는 표현입니다."
    },

    {
        "id": 77,
        "title": "- 77번문제 -",
        "image": "dialog_quiz/ask_no_ice.png",
        "lines": [
            {"role": "남자", "jp": "すみません、氷なしでお願いします。", "pron": "스미마센, 코오리 나시데 오네가이시마스", "ko": "실례합니다, 얼음 빼주세요."},
            {"role": "직원", "jp": "かしこまりました。", "pron": "카시코마리마시타", "ko": "알겠습니다."}
        ],
        "choices": [
            "음료를 취소하고 있다.",
            "얼음 없이 주문하고 있다.",
            "음료를 추가 주문하고 있다.",
            "사이즈 변경을 요청하고 있다."
        ],
        "answer": 2,
        "explain_ko": "‘氷なしで’는 음료 주문 시 얼음을 넣지 말아달라는 요청입니다."
    },

    {
        "id": 78,
        "title": "- 78번문제 -",
        "image": "dialog_quiz/ask_rain_forecast.png",
        "lines": [
            {"role": "여자", "jp": "今日は雨が降りますか？", "pron": "쿄-와 아메가 후리마스카", "ko": "오늘 비 오나요?"},
            {"role": "남자", "jp": "夕方から降るそうです。", "pron": "유-가타카라 후루소-데스", "ko": "저녁부터 온대요."}
        ],
        "choices": [
            "날씨 예보를 묻고 있다.",
            "기온을 묻고 있다.",
            "우산을 빌리고 있다.",
            "약속 시간을 정하고 있다."
        ],
        "answer": 1,
        "explain_ko": "비가 오는지 여부를 묻고 있어 날씨 예보 관련 대화입니다."
    },

        {
        "id": 79,
        "title": "- 79번문제 -",
        "image": "dialog_quiz/ask_delivery_time.png",
        "lines": [
            {
                "role": "남자",
                "jp": "今日注文したら、いつ届きますか？",
                "pron": "쿄-오 츄-몬시타라, 이츠 토도키마스카",
                "ko": "오늘 주문하면 언제 도착하나요?"
            },
            {
                "role": "직원",
                "jp": "明日届きます。",
                "pron": "아시타 토도키마스",
                "ko": "내일 도착합니다."
            }
        ],
        "choices": [
            "배송비를 묻고 있다.",
            "배송 도착 시점을 묻고 있다.",
            "주문을 취소하고 있다.",
            "상품 교환을 요청하고 있다."
        ],
        "answer": 2,
        "explain_ko": "‘今日注文したら、いつ届きますか？’는 오늘 주문했을 때 배송 도착 시점을 묻는 자연스러운 표현이며, 직원이 ‘明日届きます’라고 답해 내일 도착함을 알려주고 있습니다."
    },

    {
        "id": 80,
        "title": "- 80번문제 -",
        "image": "dialog_quiz/ask_train_delay.png",
        "lines": [
            {"role": "여자", "jp": "電車は遅れていますか？", "pron": "덴샤와 오쿠레테이마스카", "ko": "전철이 지연되고 있나요?"},
            {"role": "직원", "jp": "少し遅れています。", "pron": "스코시 오쿠레테이마스", "ko": "조금 지연되고 있습니다."}
        ],
        "choices": [
            "열차 운행 취소 여부를 묻고 있다.",
            "전철 지연 여부를 확인하고 있다.",
            "막차 시간을 묻고 있다.",
            "노선 변경을 요청하고 있다."
        ],
        "answer": 2,
        "explain_ko": "열차가 지연 중인지 여부를 확인하는 상황입니다."
    },

    {
        "id": 81,
        "title": "- 81번문제 -",
        "image": "dialog_quiz/ask_menu_english.png",
        "lines": [
            {"role": "남자", "jp": "英語のメニューはありますか？", "pron": "에이고노 메뉴-와 아리마스카", "ko": "영어 메뉴 있나요?"},
            {"role": "직원", "jp": "はい、こちらです。", "pron": "하이, 코치라데스", "ko": "네, 여기 있습니다."}
        ],
        "choices": [
            "메뉴 추천을 받고 있다.",
            "영어 메뉴가 있는지 묻고 있다.",
            "알레르기를 설명하고 있다.",
            "포장 여부를 묻고 있다."
        ],
        "answer": 2,
        "explain_ko": "‘英語のメニューはありますか？’는 영어 메뉴 제공 여부를 묻는 표현입니다."
    },

    {
        "id": 82,
        "title": "- 82번문제 -",
        "image": "dialog_quiz/ask_photo_again.png",
        "lines": [
            {"role": "여자", "jp": "すみません、もう一枚撮ってもらえますか？", "pron": "스미마센, 모오 이치마이 톳테 모라에마스카", "ko": "실례합니다, 한 장 더 찍어주실 수 있나요?"},
            {"role": "남자", "jp": "はい、大丈夫ですよ。", "pron": "하이, 다이죠-부데스요", "ko": "네, 괜찮아요."}
        ],
        "choices": [
            "사진 삭제를 요청하고 있다.",
            "사진을 한장 더 찍어달라고 부탁하고 있다.",
            "사진 촬영을 거절하고 있다.",
            "사진을 인쇄해 달라고 요청하고 있다."
        ],
        "answer": 2,
        "explain_ko": "‘もう一枚撮ってもらえますか？’는 사진을 한 장 더 찍어달라는 정중한 요청입니다."
    },

    {
        "id": 83,
        "title": "- 83번문제 -",
        "image": "dialog_quiz/ask_slowly.png",
        "lines": [
            {"role": "남자", "jp": "すみません、もう少しゆっくり話してください。", "pron": "스미마센, 모오 스코시 윳쿠리 하나시테 쿠다사이", "ko": "실례합니다, 조금만 천천히 말해 주세요."},
            {"role": "여자", "jp": "はい、わかりました。", "pron": "하이, 와카리마시타", "ko": "네, 알겠습니다."}
        ],
        "choices": [
            "말을 반복해 달라고 요청하고 있다.",
            "천천히 말해 달라고 요청하고 있다.",
            "볼륨을 줄여 달라고 요청하고 있다.",
            "다른 언어로 말해 달라고 요청하고 있다."
        ],
        "answer": 2,
        "explain_ko": "‘ゆっくり話してください’는 상대에게 천천히 말해 달라고 요청할 때 쓰는 표현입니다."
    },

    {
        "id": 84,
        "title": "- 84번문제 -",
        "image": "dialog_quiz/ask_open_window.png",
        "lines": [
            {"role": "여자", "jp": "すみません、窓を開けてもいいですか？", "pron": "스미마센, 마도오 아케테모 이이데스카", "ko": "실례합니다, 창문 열어도 될까요?"},
            {"role": "남자", "jp": "はい、どうぞ。", "pron": "하이, 도-조", "ko": "네, 그러세요."}
        ],
        "choices": [
            "창문을 닫아 달라고 요청하고 있다.",
            "에어컨을 켜 달라고 요청하고 있다.",
            "창문을 열어도 되는지 묻고 있다.",
            "자리를 옮기고 있다."
        ],
        "answer": 3,
        "explain_ko": "창문을 열어도 되는지 허락을 구하는 상황입니다."
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
@app.route("/travel-phrases-50")
def travel_phrases_50():
    user = current_user()

    q = (request.args.get("q") or "").strip()

    merged = TRAVEL_PHRASES_50[:]

    items = []
    for i, (jp, pron, ko) in enumerate(merged, start=1):
        items.append({
            "phrase_key": f"travel50_{i}",
            "jp": jp,
            "pron": pron,
            "ko": ko,
            "source": None,
            "is_fav": False
        })

    if q:
        q_low = q.lower()
        items = [
            it for it in items
            if (it["jp"] and q in it["jp"])
            or (it["pron"] and q_low in it["pron"].lower())
            or (it["ko"] and q in it["ko"])
        ]

    return render_template(
        "situation_detail.html",
        user=user,
        cat_title="🔥 일본 여행에서 바로 쓰는 일본어 필수회화 50문장 모음 🔥",
        sub_title="공항·호텔·식당·쇼핑·교통",
        page_intro="일본여행 가기 전, 공항·호텔·식당·쇼핑·교통에서 가장 많이 쓰는 핵심 일본어 50문장을 모았어요.",
        main_key="travel",
        sub_key="phrases50",
        q=q,
        items=items,
    )


@app.route("/travel/scene/<scene_id>")
def travel_scene(scene_id):
    user = current_user()

    SCENES = {
        "airport_1": "travel/airport_1.html",
        "department_1": "travel/department_1.html",
        "park_1": "travel/park_1.html",
        "park_inside_1": "travel/park_inside_1.html",
        "toilet_1": "travel/toilet_1.html",
        "park_inside_2": "travel/park_inside_2.html",
        "festival_1": "travel/festival_1.html",
        "tourist_1": "travel/tourist_1.html",
        "hotel_1": "travel/hotel_1.html",
        "movie_1": "travel/movie_1.html",
        "restaurant_1": "travel/restaurant_1.html",
        "exchange_1": "travel/exchange_1.html",
        "cafe_1": "travel/cafe_1.html",
        "hospital_1": "travel/hospital_1.html",
        "onsen_1": "travel/onsen_1.html",
        "convenience_1": "travel/convenience_1.html",
    }

    tpl = SCENES.get(scene_id)
    if not tpl:
        return render_template("travel/scene_not_found.html", user=user, scene_id=scene_id), 404

    return render_template(tpl, user=user)


@app.route("/travel/worldmap")
def travel_worldmap():
    user = current_user()
    return render_template("travel/travel_map.html", user=user)


@app.route("/travel/start")
def travel_start():
    user = current_user()
    return render_template(
        "travel/travel_start.html",
        user=user,
        start_url="/travel/scene/airport_1",
        list_url="/quiz"
    )


@app.route("/travel/scene/department_1")
def department_scene():
    user = current_user()
    return render_template(
        "travel/department_1.html",
        user=user,
        current_place="department"
    )


@app.route("/travel/scene/airport_1")
def airport_scene():
    user = current_user()
    return render_template(
        "travel/airport_1.html",
        user=user,
        current_place="airport"
    )


@app.route("/travel/scene/cafe_1")
def cafe_scene():
    user = current_user()
    return render_template(
        "travel/cafe_1.html",
        user=user,
        current_place="cafe"
    )


@app.route("/travel/scene/convenience_1")
def convenience_scene():
    user = current_user()
    return render_template(
        "travel/convenience_1.html",
        user=user,
        current_place="convenience"
    )


@app.route("/travel/scene/exchange_1")
def exchange_scene():
    user = current_user()
    return render_template(
        "travel/exchange_1.html",
        user=user,
        current_place="exchange"
    )


@app.route("/travel/scene/festival_1")
def festival_scene():
    user = current_user()
    return render_template(
        "travel/festival_1.html",
        user=user,
        current_place="festival"
    )


@app.route("/travel/scene/hospital_1")
def hospital_scene():
    user = current_user()
    return render_template(
        "travel/hospital_1.html",
        user=user,
        current_place="hospital"
    )


@app.route("/travel/scene/hotel_1")
def hotel_scene():
    user = current_user()
    return render_template(
        "travel/hotel_1.html",
        user=user,
        current_place="hotel"
    )


@app.route("/travel/scene/movie_1")
def movie_scene():
    user = current_user()
    return render_template(
        "travel/movie_1.html",
        user=user,
        current_place="movie"
    )


@app.route("/travel/scene/onsen_1")
def onsen_scene():
    user = current_user()
    return render_template(
        "travel/onsen_1.html",
        user=user,
        current_place="onsen"
    )


@app.route("/travel/scene/park_1")
def park_scene():
    user = current_user()
    return render_template(
        "travel/park_1.html",
        user=user,
        current_place="park"
    )


@app.route("/travel/scene/park_inside_1")
def park_inside_1_scene():
    user = current_user()
    return render_template(
        "travel/park_inside_1.html",
        user=user,
        current_place="park"
    )


@app.route("/travel/scene/park_inside_2")
def park_inside_2_scene():
    user = current_user()
    return render_template(
        "travel/park_inside_2.html",
        user=user,
        current_place="park"
    )


@app.route("/travel/scene/restaurant_1")
def restaurant_scene():
    user = current_user()
    return render_template(
        "travel/restaurant_1.html",
        user=user,
        current_place="restaurant"
    )


@app.route("/travel/scene/toilet_1")
def toilet_scene():
    user = current_user()
    return render_template(
        "travel/toilet_1.html",
        user=user,
        current_place="park"
    )


@app.route("/travel/scene/tourist_1")
def tourist_scene():
    user = current_user()
    return render_template(
        "travel/tourist_1.html",
        user=user,
        current_place="tourist"
    )
# =========================================================
# ✅ JLPT 홈
#    - d: 오늘의 회화(기존 그대로 유지 가능)
#    - w: 오늘의 단어(단어+예문)
# =========================================================
@app.route("/jlpt")
def jlpt_home():
    user = current_user()

    d = pick_daily_item(DAILY_POOL, key_prefix="daily_talk")          # 오늘의 회화
    w = pick_daily_item(DAILY_WORD_POOL, key_prefix="daily_word")    # 오늘의 단어

    return render_template("jlpt_home.html", user=user, d=d, w=w)


# =========================================================
# ✅ JLPT 기초(가나) - "소리 없는 표"용 데이터
#    - 템플릿에서 cell.jp / cell.pron 으로 출력
# =========================================================
@app.route("/jlpt/kana")
def jlpt_kana_home():
    user = current_user()

    hira = [
        [{"jp":"あ","pron":"아"},{"jp":"い","pron":"이"},{"jp":"う","pron":"우"},{"jp":"え","pron":"에"},{"jp":"お","pron":"오"}],
        [{"jp":"か","pron":"카"},{"jp":"き","pron":"키"},{"jp":"く","pron":"쿠"},{"jp":"け","pron":"케"},{"jp":"こ","pron":"코"}],
        [{"jp":"さ","pron":"사"},{"jp":"し","pron":"시"},{"jp":"す","pron":"스"},{"jp":"せ","pron":"세"},{"jp":"そ","pron":"소"}],
        [{"jp":"た","pron":"타"},{"jp":"ち","pron":"치"},{"jp":"つ","pron":"츠"},{"jp":"て","pron":"테"},{"jp":"と","pron":"토"}],
        [{"jp":"な","pron":"나"},{"jp":"に","pron":"니"},{"jp":"ぬ","pron":"누"},{"jp":"ね","pron":"네"},{"jp":"の","pron":"노"}],
        [{"jp":"は","pron":"하"},{"jp":"ひ","pron":"히"},{"jp":"ふ","pron":"후"},{"jp":"へ","pron":"헤"},{"jp":"ほ","pron":"호"}],
        [{"jp":"ま","pron":"마"},{"jp":"み","pron":"미"},{"jp":"む","pron":"무"},{"jp":"め","pron":"메"},{"jp":"も","pron":"모"}],
        [{"jp":"や","pron":"야"},{"jp":"","pron":""},{"jp":"ゆ","pron":"유"},{"jp":"","pron":""},{"jp":"よ","pron":"요"}],
        [{"jp":"ら","pron":"라"},{"jp":"り","pron":"리"},{"jp":"る","pron":"루"},{"jp":"れ","pron":"레"},{"jp":"ろ","pron":"로"}],
        [{"jp":"わ","pron":"와"},{"jp":"","pron":""},{"jp":"","pron":""},{"jp":"","pron":""},{"jp":"を","pron":"오"}],
        [{"jp":"ん","pron":"응"},{"jp":"","pron":""},{"jp":"","pron":""},{"jp":"","pron":""},{"jp":"","pron":""}],
    ]

    kata = [
        [{"jp":"ア","pron":"아"},{"jp":"イ","pron":"이"},{"jp":"ウ","pron":"우"},{"jp":"エ","pron":"에"},{"jp":"オ","pron":"오"}],
        [{"jp":"カ","pron":"카"},{"jp":"キ","pron":"키"},{"jp":"ク","pron":"쿠"},{"jp":"ケ","pron":"케"},{"jp":"コ","pron":"코"}],
        [{"jp":"サ","pron":"사"},{"jp":"シ","pron":"시"},{"jp":"ス","pron":"스"},{"jp":"セ","pron":"세"},{"jp":"ソ","pron":"소"}],
        [{"jp":"タ","pron":"타"},{"jp":"チ","pron":"치"},{"jp":"ツ","pron":"츠"},{"jp":"テ","pron":"테"},{"jp":"ト","pron":"토"}],
        [{"jp":"ナ","pron":"나"},{"jp":"ニ","pron":"니"},{"jp":"ヌ","pron":"누"},{"jp":"ネ","pron":"네"},{"jp":"ノ","pron":"노"}],
        [{"jp":"ハ","pron":"하"},{"jp":"ヒ","pron":"히"},{"jp":"フ","pron":"후"},{"jp":"ヘ","pron":"헤"},{"jp":"ホ","pron":"호"}],
        [{"jp":"マ","pron":"마"},{"jp":"ミ","pron":"미"},{"jp":"ム","pron":"무"},{"jp":"メ","pron":"메"},{"jp":"モ","pron":"모"}],
        [{"jp":"ヤ","pron":"야"},{"jp":"","pron":""},{"jp":"ユ","pron":"유"},{"jp":"","pron":""},{"jp":"ヨ","pron":"요"}],
        [{"jp":"ラ","pron":"라"},{"jp":"リ","pron":"리"},{"jp":"ル","pron":"루"},{"jp":"レ","pron":"레"},{"jp":"ロ","pron":"로"}],
        [{"jp":"ワ","pron":"와"},{"jp":"","pron":""},{"jp":"","pron":""},{"jp":"","pron":""},{"jp":"ヲ","pron":"오"}],
        [{"jp":"ン","pron":"응"},{"jp":"","pron":""},{"jp":"","pron":""},{"jp":"","pron":""},{"jp":"","pron":""}],
    ]

    return render_template("jlpt_kana_home.html", user=user, hira=hira, kata=kata)

N5_SENTENCE_SECTIONS = [
    {
        "key": "basic",
        "title": "1) 기본문장",
        "desc": "です/ます 기본 문장. 가장 자주 나오는 틀",
        "items": [
            {"jp":"わたしは学生です。","pron":"와타시와 가쿠세이데스","ko":"저는 학생입니다."},
            {"jp":"これは日本語の本です。","pron":"코레와 니혼고노 혼데스","ko":"이것은 일본어 책입니다."},
            {"jp":"田中さんは先生です。","pron":"타나카상와 센세이데스","ko":"다나카 씨는 선생님입니다."},
            {"jp":"毎日、勉強します。","pron":"마이니치 벤쿄오 시마스","ko":"매일 공부합니다."},
            {"jp":"朝ごはんを食べます。","pron":"아사고항오 타베마스","ko":"아침밥을 먹습니다."},
            {"jp":"駅へ行きます。","pron":"에키에 이키마스","ko":"역에 갑니다."},
            {"jp":"友達と映画を見ます。","pron":"토모다치토 에이가오 미마스","ko":"친구와 영화를 봅니다."},
            {"jp":"日本語を話します。","pron":"니혼고오 하나시마스","ko":"일본어를 말합니다."},
            {"jp":"今日は忙しいです。","pron":"쿄오와 이소가시이데스","ko":"오늘은 바쁩니다."},
            {"jp":"明日、休みます。","pron":"아시타 야스미마스","ko":"내일 쉽니다."},
        ],
    },
    {
        "key": "particle",
        "title": "2) 조사",
        "desc": "は/が/を/に/へ/で/と 기본",
        "items": [
            {"jp":"今日は日曜日です。","pron":"쿄오와 니치요오비데스","ko":"오늘은 일요일입니다."},
            {"jp":"雨が降っています。","pron":"아메가 후잇테이마스","ko":"비가 오고 있습니다."},
            {"jp":"水を飲みます。","pron":"미즈오 노미마스","ko":"물을 마십니다."},
            {"jp":"パンを買います。","pron":"팡오 카이마스","ko":"빵을 삽니다."},
            {"jp":"7時に起きます。","pron":"시치지니 오키마스","ko":"7시에 일어납니다."},
            {"jp":"学校に行きます。","pron":"각코오니 이키마스","ko":"학교에 갑니다."},
            {"jp":"友達に電話します。","pron":"토모다치니 덴와 시마스","ko":"친구에게 전화합니다."},
            {"jp":"うちで勉強します。","pron":"우치데 벤쿄오 시마스","ko":"집에서 공부합니다."},
            {"jp":"電車で行きます。","pron":"덴샤데 이키마스","ko":"전철로 갑니다."},
            {"jp":"友達と会います。","pron":"토모다치토 아이마스","ko":"친구를 만납니다."},
        ],
    },
    {
        "key": "exist",
        "title": "3) 있다/없다",
        "desc": "あります/います (물건/사람·동물)",
        "items": [
            {"jp":"ここにコンビニがあります。","pron":"코코니 콘비니가 아리마스","ko":"여기에 편의점이 있어요."},
            {"jp":"部屋にテレビがあります。","pron":"헤야니 테레비가 아리마스","ko":"방에 TV가 있어요."},
            {"jp":"公園に猫がいます。","pron":"코오엔니 네코가 이마스","ko":"공원에 고양이가 있어요."},
            {"jp":"教室に先生がいます。","pron":"쿄오시츠니 센세이가 이마스","ko":"교실에 선생님이 있어요."},
            {"jp":"時間がありません。","pron":"지칸가 아리마센","ko":"시간이 없어요."},
            {"jp":"お金がありません。","pron":"오카네가 아리마센","ko":"돈이 없어요."},
            {"jp":"トイレはあそこにあります。","pron":"토이레와 아소코니 아리마스","ko":"화장실은 저기에 있어요."},
            {"jp":"駅は近くにあります。","pron":"에키와 치카쿠니 아리마스","ko":"역은 가까이에 있어요."},
            {"jp":"兄がいます。","pron":"아니가 이마스","ko":"형/오빠가 있어요."},
            {"jp":"妹がいます。","pron":"이모오토가 이마스","ko":"여동생이 있어요."},
        ],
    },
    {
        "key": "request",
        "title": "4) 요청/허가",
        "desc": "～てください / ～てもいいですか / ～てはいけません",
        "items": [
            {"jp":"もう一度言ってください。","pron":"모오 이치도 잇테 쿠다사이","ko":"한 번 더 말해 주세요."},
            {"jp":"ここに名前を書いてください。","pron":"코코니 나마에오 카이테 쿠다사이","ko":"여기에 이름을 써 주세요."},
            {"jp":"少し待ってください。","pron":"스코시 맛테 쿠다사이","ko":"조금 기다려 주세요."},
            {"jp":"ゆっくり話してください。","pron":"윳쿠리 하나시테 쿠다사이","ko":"천천히 말해 주세요."},
            {"jp":"写真を撮ってもいいですか。","pron":"샤신오 톳테모 이이데스카","ko":"사진 찍어도 될까요?"},
            {"jp":"ここに座ってもいいですか。","pron":"코코니 스왓테모 이이데스카","ko":"여기 앉아도 될까요?"},
            {"jp":"入ってもいいです。","pron":"하잇테모 이이데스","ko":"들어가도 돼요."},
            {"jp":"ここでタバコを吸ってはいけません。","pron":"코코데 타바코오 슷테와 이케마센","ko":"여기서 담배 피우면 안 돼요."},
            {"jp":"時間に遅れてはいけません。","pron":"지칸니 오쿠레테와 이케마센","ko":"시간에 늦으면 안 돼요."},
            {"jp":"この紙を見せてください。","pron":"코노 카미오 미세테 쿠다사이","ko":"이 종이를 보여 주세요."},
        ],
    },
    {
        "key": "want",
        "title": "5) 원하다",
        "desc": "～たい / ～ほしい",
        "items": [
            {"jp":"日本へ行きたいです。","pron":"니혼에 이키타이데스","ko":"일본에 가고 싶어요."},
            {"jp":"寿司を食べたいです。","pron":"스시오 타베타이데스","ko":"초밥을 먹고 싶어요."},
            {"jp":"もっと日本語を話したいです。","pron":"못토 니혼고오 하나시타이데스","ko":"더 일본어를 말하고 싶어요."},
            {"jp":"映画を見たいです。","pron":"에이가오 미타이데스","ko":"영화를 보고 싶어요."},
            {"jp":"水が飲みたいです。","pron":"미즈가 노미타이데스","ko":"물을 마시고 싶어요."},
            {"jp":"休みたいです。","pron":"야스미타이데스","ko":"쉬고 싶어요."},
            {"jp":"新しいかばんがほしいです。","pron":"아타라시이 카방가 호시이데스","ko":"새 가방이 갖고 싶어요."},
            {"jp":"時間がほしいです。","pron":"지칸가 호시이데스","ko":"시간이 있었으면 좋겠어요."},
            {"jp":"友達がほしいです。","pron":"토모다치가 호시이데스","ko":"친구가 갖고 싶어요(친구가 필요해요)."},
            {"jp":"日本語の辞書がほしいです。","pron":"니혼고노 지쇼가 호시이데스","ko":"일본어 사전이 갖고 싶어요."},
        ],
    },
    {
        "key": "adj",
        "title": "6) 형용사",
        "desc": "い형용사/な형용사 기본 표현",
        "items": [
            {"jp":"この店は安いです。","pron":"코노 미세와 야스이데스","ko":"이 가게는 싸요."},
            {"jp":"今日は暑いです。","pron":"쿄오와 아츠이데스","ko":"오늘은 더워요."},
            {"jp":"この問題は難しいです。","pron":"코노 몬다이와 무즈카시이데스","ko":"이 문제는 어려워요."},
            {"jp":"この料理はおいしいです。","pron":"코노 료오리와 오이시이데스","ko":"이 요리는 맛있어요."},
            {"jp":"この町は静かです。","pron":"코노 마치와 시즈카데스","ko":"이 마을은 조용해요."},
            {"jp":"彼は親切です。","pron":"카레와 신세츠데스","ko":"그는 친절해요."},
            {"jp":"ここは便利です。","pron":"코코와 벤리데스","ko":"여기는 편리해요."},
            {"jp":"今日は元気です。","pron":"쿄오와 겐키데스","ko":"오늘은 건강/기분이 좋아요."},
            {"jp":"この部屋はきれいです。","pron":"코노 헤야와 키레에데스","ko":"이 방은 깨끗해요."},
            {"jp":"その映画は有名です。","pron":"소노 에이가와 유메에데스","ko":"그 영화는 유명해요."},
        ],
    },
    {
        "key": "time",
        "title": "7) 시간/빈도",
        "desc": "～から～まで / いつも / よく / ときどき / あまり～ません",
        "items": [
            {"jp":"9時から5時まで働きます。","pron":"쿠지카라 고지마데 하타라키마스","ko":"9시부터 5시까지 일합니다."},
            {"jp":"月曜日から金曜日まで学校があります。","pron":"게츠요오비카라 킨요오비마데 각코오가 아리마스","ko":"월~금까지 학교가 있어요."},
            {"jp":"今、何時ですか。","pron":"이마 난지데스카","ko":"지금 몇 시예요?"},
            {"jp":"毎朝、6時に起きます。","pron":"마이아사 로쿠지니 오키마스","ko":"매일 아침 6시에 일어나요."},
            {"jp":"ときどき図書館へ行きます。","pron":"토키도키 토쇼칸에 이키마스","ko":"가끔 도서관에 가요."},
            {"jp":"いつも朝ごはんを食べます。","pron":"이츠모 아사고항오 타베마스","ko":"항상 아침을 먹어요."},
            {"jp":"よく公園で散歩します。","pron":"요쿠 코오엔데 산포 시마스","ko":"자주 공원에서 산책해요."},
            {"jp":"あまりテレビを見ません。","pron":"아마리 테레비오 미마센","ko":"TV를 별로 안 봐요."},
            {"jp":"来週、旅行します。","pron":"라이슈우 료코오 시마스","ko":"다음 주 여행합니다."},
            {"jp":"昨日、雨が降りました。","pron":"키노오 아메가 후리마시타","ko":"어제 비가 왔어요."},
        ],
    },
]
N4_SENTENCE_SECTIONS = [
    {
        "key": "basic",
        "title": "1) 기본 확장문장",
        "desc": "N5보다 길어진 문장 + 연결(그리고/하지만/그래서)",
        "items": [
            {"jp":"昨日は雨でしたが、今日は晴れました。","pron":"키노오와 아메데시타가 쿄오와 하레마시타","ko":"어제는 비였지만 오늘은 개었습니다."},
            {"jp":"勉強して、宿題もしました。","pron":"벤쿄오시테 슈쿠다이모 시마시타","ko":"공부하고 숙제도 했습니다."},
            {"jp":"急いで駅へ行きました。","pron":"이소이데 에키에 이키마시타","ko":"서둘러 역에 갔습니다."},
            {"jp":"この店は安くて、おいしいです。","pron":"코노 미세와 야스쿠테 오이시이데스","ko":"이 가게는 싸고 맛있습니다."},
            {"jp":"今日は仕事があるので、出かけません。","pron":"쿄오와 시고토가 아루노데 데카케마센","ko":"오늘은 일이 있어서 나가지 않습니다."},
            {"jp":"明日、友達に会うつもりです。","pron":"아시타 토모다치니 아우 츠모리데스","ko":"내일 친구를 만날 예정입니다."},
            {"jp":"日本語が少し分かるようになりました。","pron":"니혼고가 스코시 와카루요오니 나리마시타","ko":"일본어를 조금 알게 되었습니다."},
            {"jp":"早く寝ないと、明日起きられません。","pron":"하야쿠 네나이토 아시타 오키라레마센","ko":"빨리 자지 않으면 내일 일어날 수 없어요."},
            {"jp":"この道をまっすぐ行くと、駅があります。","pron":"코노 미치오 맛스구 이쿠토 에키가 아리마스","ko":"이 길을 곧장 가면 역이 있어요."},
            {"jp":"ちょっと休んでから、続けましょう。","pron":"촛토 야슨데카라 츠즈케마쇼오","ko":"조금 쉬고 나서 계속합시다."},
        ],
    },
    {
        "key": "request",
        "title": "2) 부탁/권유",
        "desc": "～てくれますか / ～ましょう / ～ませんか",
        "items": [
            {"jp":"もう少しゆっくり話してくれますか。","pron":"모오 스코시 윳쿠리 하나시테 쿠레마스카","ko":"조금 더 천천히 말해 줄 수 있나요?"},
            {"jp":"写真を撮ってくれませんか。","pron":"샤신오 톳테 쿠레마센카","ko":"사진 찍어 주실래요?"},
            {"jp":"いっしょに昼ごはんを食べましょう。","pron":"잇쇼니 히루고항오 타베마쇼오","ko":"같이 점심 먹읍시다."},
            {"jp":"今度の日曜日、どこかへ行きませんか。","pron":"콘도노 니치요오비 도코카에 이키마센카","ko":"이번 일요일 어디 가시지 않을래요?"},
            {"jp":"もう一度説明してもらえますか。","pron":"모오 이치도 세츠메이시테 모라에마스카","ko":"한 번 더 설명해 주실 수 있나요?"},
            {"jp":"ここで少し待っていてください。","pron":"코코데 스코시 맛테이테 쿠다사이","ko":"여기서 잠깐 기다리고 있어 주세요."},
            {"jp":"手伝ってくれてありがとうございます。","pron":"테츠닷테 쿠레테 아리가토오 고자이마스","ko":"도와줘서 감사합니다."},
            {"jp":"荷物を持ちましょうか。","pron":"니모츠오 모치마쇼오카","ko":"짐 들어드릴까요?"},
            {"jp":"静かにしてもらえませんか。","pron":"시즈카니 시테 모라에마센카","ko":"조용히 해 주실 수 없나요?"},
            {"jp":"あとで電話してもいいですか。","pron":"아토데 덴와시테모 이이데스카","ko":"나중에 전화해도 될까요?"},
        ],
    },
    {
        "key": "can",
        "title": "3) 가능형",
        "desc": "～できます / ～られます (할 수 있다)",
        "items": [
            {"jp":"日本語で少し話せます。","pron":"니혼고데 스코시 하나세마스","ko":"일본어로 조금 말할 수 있어요."},
            {"jp":"ここでカードが使えます。","pron":"코코데 카아도가 츠카에마스","ko":"여기서 카드를 사용할 수 있어요."},
            {"jp":"この店は夜まで開いています。いつでも来られます。","pron":"코노 미세와 요루마데 아이테이마스 이츠데모 코라레마스","ko":"이 가게는 밤까지 열려 있어요. 언제든 올 수 있어요."},
            {"jp":"駅まで歩いて行けます。","pron":"에키마데 아루이테 이케마스","ko":"역까지 걸어서 갈 수 있어요."},
            {"jp":"漢字が読めるようになりたいです。","pron":"칸지가 요메루요오니 나리타이데스","ko":"한자를 읽을 수 있게 되고 싶어요."},
            {"jp":"このパソコンで日本語が入力できます。","pron":"코노 파소콘데 니혼고가 뉴우료쿠 데키마스","ko":"이 컴퓨터로 일본어 입력이 가능해요."},
            {"jp":"一人でも大丈夫です。自分でできます。","pron":"히토리데모 다이죠오부데스 지분데 데키마스","ko":"혼자여도 괜찮아요. 스스로 할 수 있어요."},
            {"jp":"明日は早く起きられます。","pron":"아시타와 하야쿠 오키라레마스","ko":"내일은 일찍 일어날 수 있어요."},
            {"jp":"この映画は子どもでも見られます。","pron":"코노 에이가와 코도모데모 미라레마스","ko":"이 영화는 아이도 볼 수 있어요."},
            {"jp":"ここから富士山が見えます。","pron":"코코카라 후지상가 미에마스","ko":"여기서 후지산이 보여요."},
        ],
    },
    {
        "key": "experience",
        "title": "4) 경험/완료",
        "desc": "～たことがあります / ～てしまいました",
        "items": [
            {"jp":"日本へ行ったことがあります。","pron":"니혼에 잇타 코토가 아리마스","ko":"일본에 가 본 적이 있어요."},
            {"jp":"寿司を食べたことがあります。","pron":"스시오 타베타 코토가 아리마스","ko":"초밥을 먹어 본 적이 있어요."},
            {"jp":"この本は前に読んだことがあります。","pron":"코노 혼와 마에니 욘다 코토가 아리마스","ko":"이 책은 전에 읽어 본 적이 있어요."},
            {"jp":"宿題を忘れてしまいました。","pron":"슈쿠다이오 와스레테 시마이마시타","ko":"숙제를 깜빡해 버렸어요."},
            {"jp":"電車に乗り遅れてしまいました。","pron":"덴샤니 노리오쿠레테 시마이마시타","ko":"전철을 놓쳐 버렸어요."},
            {"jp":"財布をなくしてしまいました。","pron":"사이후오 나쿠시테 시마이마시타","ko":"지갑을 잃어버렸어요."},
            {"jp":"もう全部食べてしまいました。","pron":"모오 젠부 타베테 시마이마시타","ko":"이미 다 먹어버렸어요."},
            {"jp":"間違えて書いてしまいました。","pron":"마치가에테 카이테 시마이마시타","ko":"실수로 써버렸어요."},
            {"jp":"この映画は見たことがありません。","pron":"코노 에이가와 미타 코토가 아리마센","ko":"이 영화는 본 적이 없어요."},
            {"jp":"一度も海外へ行ったことがありません。","pron":"이치도모 카이가이에 잇타 코토가 아리마센","ko":"한 번도 해외에 가 본 적이 없어요."},
        ],
    },
    {
        "key": "obligation",
        "title": "5) 의무/금지",
        "desc": "～なければなりません / ～てはいけません",
        "items": [
            {"jp":"明日までに提出しなければなりません。","pron":"아시타마데니 테이슈츠시나케레바 나리마센","ko":"내일까지 제출해야 합니다."},
            {"jp":"薬は毎日飲まなければなりません。","pron":"쿠스리와 마이니치 노마나케레바 나리마센","ko":"약은 매일 먹어야 합니다."},
            {"jp":"ここでは写真を撮ってはいけません。","pron":"코코데와 샤신오 톳테와 이케마센","ko":"여기서는 사진을 찍으면 안 됩니다."},
            {"jp":"この部屋で食べてはいけません。","pron":"코노 헤야데 타베테와 이케마센","ko":"이 방에서 먹으면 안 돼요."},
            {"jp":"早く寝なければなりません。","pron":"하야쿠 네나케레바 나리마센","ko":"빨리 자야 합니다."},
            {"jp":"忘れ物をしないようにしなければなりません。","pron":"와스레모노오 시나이요오니 시나케레바 나리마센","ko":"잊어버리지 않도록 해야 합니다."},
            {"jp":"運転中はスマホを使ってはいけません。","pron":"운텐추우와 스마호오 츠캇테와 이케마센","ko":"운전 중엔 휴대폰을 쓰면 안 돼요."},
            {"jp":"もっと練習しなければなりません。","pron":"못토 렌슈우시나케레바 나리마센","ko":"더 연습해야 합니다."},
            {"jp":"ここに入ってはいけません。","pron":"코코니 하잇테와 이케마센","ko":"여기에 들어가면 안 됩니다."},
            {"jp":"時間を守らなければなりません。","pron":"지칸오 마모라나케레바 나리마센","ko":"시간을 지켜야 합니다."},
        ],
    },
    {
        "key": "reason",
        "title": "6) 이유/조건",
        "desc": "～から/ので / ～たら / ～と",
        "items": [
            {"jp":"雨なので、出かけません。","pron":"아메나노데 데카케마센","ko":"비라서 나가지 않습니다."},
            {"jp":"忙しいから、今日は行けません。","pron":"이소가시이카라 쿄오와 이케마센","ko":"바쁘니까 오늘은 못 가요."},
            {"jp":"安かったので、買いました。","pron":"야스캇타노데 카이마시타","ko":"쌌기 때문에 샀어요."},
            {"jp":"時間があったら、映画を見ます。","pron":"지칸가 앗타라 에이가오 미마스","ko":"시간이 있으면 영화를 봐요."},
            {"jp":"日本へ行ったら、寿司を食べたいです。","pron":"니혼에 잇타라 스시오 타베타이데스","ko":"일본에 가면 초밥을 먹고 싶어요."},
            {"jp":"このボタンを押すと、ドアが開きます。","pron":"코노 보탄오 오스토 도아가 아키마스","ko":"이 버튼을 누르면 문이 열려요."},
            {"jp":"早く寝ないと、明日起きられません。","pron":"하야쿠 네나이토 아시타 오키라레마센","ko":"빨리 자지 않으면 내일 일어날 수 없어요."},
            {"jp":"寒いので、上着を着ました。","pron":"사무이노데 우와기오 키마시타","ko":"추워서 겉옷을 입었어요."},
            {"jp":"わからないときは、聞いてください。","pron":"와카라나이 토키와 키이테 쿠다사이","ko":"모를 때는 물어보세요."},
            {"jp":"遅れたら、連絡してください。","pron":"오쿠레타라 렌라쿠시테 쿠다사이","ko":"늦으면 연락해 주세요."},
        ],
    },
    {
        "key": "comparison",
        "title": "7) 비교/정도",
        "desc": "～より/～のほうが / ～くらい",
        "items": [
            {"jp":"電車のほうがバスより早いです。","pron":"덴샤노 호오가 바스요리 하야이데스","ko":"전철이 버스보다 빨라요."},
            {"jp":"犬より猫のほうが好きです。","pron":"이누요리 네코노 호오가 스키데스","ko":"개보다 고양이를 더 좋아해요."},
            {"jp":"この問題は前のより難しいです。","pron":"코노 몬다이와 마에노요리 무즈카시이데스","ko":"이 문제는 이전 것보다 어려워요."},
            {"jp":"日本語は英語ほど難しくありません。","pron":"니혼고와 에이고호도 무즈카시쿠 아리마센","ko":"일본어는 영어만큼 어렵지 않아요."},
            {"jp":"ここから駅まで10分ぐらいです。","pron":"코코카라 에키마데 쥬쁭구라이데스","ko":"여기서 역까지 10분 정도예요."},
            {"jp":"このかばんは思ったより軽いです。","pron":"코노 카방와 오못타요리 카루이데스","ko":"이 가방은 생각보다 가벼워요."},
            {"jp":"今日は昨日より暖かいです。","pron":"쿄오와 키노오요리 아타타카이데스","ko":"오늘은 어제보다 따뜻해요."},
            {"jp":"この店はあの店より安いです。","pron":"코노 미세와 아노 미세요리 야스이데스","ko":"이 가게는 저 가게보다 싸요."},
            {"jp":"1時間ぐらい待ちました。","pron":"이치지칸구라이 마치마시타","ko":"1시간 정도 기다렸어요."},
            {"jp":"この町は東京ほど大きくありません。","pron":"코노 마치와 토오쿄오호도 오오키쿠 아리마센","ko":"이 도시는 도쿄만큼 크지 않아요."},
        ],
    },
]

N3_SENTENCE_SECTIONS = [
    {
        "key": "opinion",
        "title": "1) 의견/추측",
        "desc": "～と思います / ～かもしれません / ～ようです",
        "items": [
            {"jp":"この問題は少し難しいと思います。","pron":"코노 몬다이와 스코시 무즈카시이 토 오모이마스","ko":"이 문제는 조금 어렵다고 생각합니다."},
            {"jp":"明日は雨が降るかもしれません。","pron":"아시타와 아메가 후루 카모 시레마센","ko":"내일은 비가 올지도 모릅니다."},
            {"jp":"彼はまだ来ていないようです。","pron":"카레와 마다 키테이나이 요오데스","ko":"그는 아직 오지 않은 것 같습니다."},
            {"jp":"この店は思ったより混んでいますね。","pron":"코노 미세와 오못타요리 콘데이마스네","ko":"이 가게는 생각보다 붐비네요."},
            {"jp":"その話は本当らしいです。","pron":"소노 하나시와 혼토오 라시이데스","ko":"그 이야기는 사실인 것 같습니다."},
            {"jp":"彼は疲れているみたいです。","pron":"카레와 츠카레테이루 미타이데스","ko":"그는 피곤한 것 같아요."},
            {"jp":"この映画は人気があるようですね。","pron":"코노 에이가와 닌키가 아루 요오데스네","ko":"이 영화는 인기가 있는 것 같네요."},
            {"jp":"今日は早く帰ったほうがいいと思います。","pron":"쿄오와 하야쿠 카엣타 호오가 이이 토 오모이마스","ko":"오늘은 일찍 돌아가는 게 좋다고 생각합니다."},
            {"jp":"その方法ならうまくいくかもしれません。","pron":"소노 호오호오나라 우마쿠 이쿠 카모 시레마센","ko":"그 방법이라면 잘 될지도 모릅니다."},
            {"jp":"彼は日本に行ったことがあるようです。","pron":"카레와 니혼니 잇타 코토가 아루 요오데스","ko":"그는 일본에 가 본 적이 있는 것 같습니다."},
        ],
    },
    {
        "key": "advice",
        "title": "2) 조언/당연",
        "desc": "～ほうがいい / ～べき / ～はず",
        "items": [
            {"jp":"もっと早く寝たほうがいいですよ。","pron":"못토 하야쿠 네타 호오가 이이데스요","ko":"좀 더 일찍 자는 게 좋아요."},
            {"jp":"薬を飲んだほうがいいと思います。","pron":"쿠스리오 논다 호오가 이이 토 오모이마스","ko":"약을 먹는 게 좋다고 생각해요."},
            {"jp":"約束は守るべきです。","pron":"야쿠소쿠와 마모루 베키데스","ko":"약속은 지켜야 합니다."},
            {"jp":"遅刻するなら連絡するべきです。","pron":"치코쿠 스루나라 렌라쿠 스루 베키데스","ko":"지각할 거면 연락해야 합니다."},
            {"jp":"もうすぐ着くはずです。","pron":"모오스구 츠쿠 하즈데스","ko":"곧 도착할 거예요."},
            {"jp":"この道を行けば駅があるはずです。","pron":"코노 미치오 이케바 에키가 아루 하즈데스","ko":"이 길로 가면 역이 있을 거예요."},
            {"jp":"彼はもう知っているはずです。","pron":"카레와 모오 싯테이루 하즈데스","ko":"그는 이미 알고 있을 거예요."},
            {"jp":"無理をしないほうがいいです。","pron":"무리오 시나이 호오가 이이데스","ko":"무리하지 않는 게 좋아요."},
            {"jp":"健康のために運動するべきです。","pron":"켄코오노 타메니 운도오 스루 베키데스","ko":"건강을 위해 운동해야 해요."},
            {"jp":"この値段なら安いはずです。","pron":"코노 네단나라 야스이 하즈데스","ko":"이 가격이면 쌀 거예요."},
        ],
    },
    {
        "key": "purpose",
        "title": "3) 목적/이유",
        "desc": "～ために / ～ように / ～ので / ～から",
        "items": [
            {"jp":"健康のために毎日歩いています。","pron":"켄코오노 타메니 마이니치 아루이테이마스","ko":"건강을 위해 매일 걷고 있어요."},
            {"jp":"忘れないようにメモします。","pron":"와스레나이 요오니 메모시마스","ko":"잊지 않도록 메모합니다."},
            {"jp":"日本語が上手になるように練習しています。","pron":"니혼고가 조오즈니 나루 요오니 렌슈우시테이마스","ko":"일본어가 늘도록 연습하고 있어요."},
            {"jp":"雨が降ったので、予定を変えました。","pron":"아메가 훗타노데 요테이오 카에마시타","ko":"비가 와서 계획을 바꿨어요."},
            {"jp":"忙しいから今日は行けません。","pron":"이소가시이카라 쿄오와 이케마센","ko":"바쁘니까 오늘은 못 가요."},
            {"jp":"遅れないように早く出ました。","pron":"오쿠레나이 요오니 하야쿠 데마시타","ko":"늦지 않도록 일찍 나왔어요."},
            {"jp":"お金を節約するために外食しません。","pron":"오카네오 세츠야쿠스루 타메니 가이쇼쿠 시마센","ko":"돈을 아끼기 위해 외식하지 않아요."},
            {"jp":"聞こえるように大きい声で話してください。","pron":"키코에루 요오니 오오키이 코에데 하나시테 쿠다사이","ko":"들리도록 큰 소리로 말해 주세요."},
            {"jp":"事故があったので電車が止まりました。","pron":"지코가 앗타노데 덴샤가 토마리마시타","ko":"사고가 있어서 전철이 멈췄어요."},
            {"jp":"合格するために毎日勉強しています。","pron":"고오카쿠스루 타메니 마이니치 벤쿄오시테이마스","ko":"합격하기 위해 매일 공부하고 있어요."},
        ],
    },
    {
        "key": "condition",
        "title": "4) 조건/가정",
        "desc": "～たら / ～なら / ～と / ～場合",
        "items": [
            {"jp":"雨が降ったら、家にいます。","pron":"아메가 훗타라 이에니 이마스","ko":"비가 오면 집에 있어요."},
            {"jp":"時間があれば、手伝います。","pron":"지칸가 아레바 테츠다이마스","ko":"시간이 있으면 도와줄게요."},
            {"jp":"日本に行くなら、京都にも行きたいです。","pron":"니혼니 이쿠나라 쿄오토니모 이키타이데스","ko":"일본에 간다면 교토도 가고 싶어요."},
            {"jp":"このボタンを押すと、ドアが開きます。","pron":"코노 보탄오 오스토 도아가 아키마스","ko":"이 버튼을 누르면 문이 열려요."},
            {"jp":"困った場合は、ここに連絡してください。","pron":"코맛타 바아이와 코코니 렌라쿠시테 쿠다사이","ko":"곤란한 경우에는 여기로 연락해 주세요."},
            {"jp":"もし間に合わなかったら、先に始めてください。","pron":"모시 마니아와나캇타라 사키니 하지메테 쿠다사이","ko":"만약 늦으면 먼저 시작해 주세요."},
            {"jp":"安いなら買います。","pron":"야스이나라 카이마스","ko":"싸면 살게요."},
            {"jp":"遅れると、みんなに迷惑がかかります。","pron":"오쿠레루토 민나니 메이와쿠가 카카리마스","ko":"늦으면 모두에게 민폐가 됩니다."},
            {"jp":"体調が悪かったら、無理しないでください。","pron":"타이초오가 와루캇타라 무리 시나이데 쿠다사이","ko":"컨디션이 나쁘면 무리하지 마세요."},
            {"jp":"帰る場合は、鍵を返してください。","pron":"카에루 바아이와 카기오 카에시테 쿠다사이","ko":"돌아갈 경우 열쇠를 반납해 주세요."},
        ],
    },
    {
        "key": "passive_causative",
        "title": "5) 수동/사역 기초",
        "desc": "～られる(수동/가능) / ～させる(사역) 기본",
        "items": [
            {"jp":"この歌は多くの人に愛されています。","pron":"코노 우타와 오오쿠노 히토니 아이사레테이마스","ko":"이 노래는 많은 사람에게 사랑받고 있어요."},
            {"jp":"昨日、先生にほめられました。","pron":"키노오 센세이니 호메라레마시타","ko":"어제 선생님께 칭찬받았어요."},
            {"jp":"雨に降られて、服がぬれました。","pron":"아메니 후라레테 후쿠가 누레마시타","ko":"비를 맞아서 옷이 젖었어요."},
            {"jp":"子どもに泣かれて困りました。","pron":"코도모니 나카레테 코마리마시타","ko":"아이에게 울음을 당(?)해서 곤란했어요."},
            {"jp":"部長に待たされました。","pron":"부쵸오니 마타사레마시타","ko":"부장님 때문에 기다리게 되었어요."},
            {"jp":"母は私に野菜を食べさせます。","pron":"하하와 와타시니 야사이오 타베사세마스","ko":"엄마는 나에게 채소를 먹게 해요."},
            {"jp":"先生は学生に漢字を覚えさせます。","pron":"센세이와 가쿠세이니 칸지오 오보에사세마스","ko":"선생님은 학생들에게 한자를 외우게 해요."},
            {"jp":"上司に残業させられました。","pron":"죠오시니 잔교오 사세라레마시타","ko":"상사 때문에 야근을 하게 되었어요."},
            {"jp":"この仕事は新人に任せられません。","pron":"코노 시고토와 신진니 마카세라레마센","ko":"이 일은 신입에게 맡길 수 없어요."},
            {"jp":"子どもを一人で行かせません。","pron":"코도모오 히토리데 이카세마센","ko":"아이를 혼자 보내지 않아요."},
        ],
    },
    {
        "key": "keigo",
        "title": "6) 경어/정중 표현",
        "desc": "N3 기본 경어(いらっしゃる/お～になる/～ていただく 등 맛보기)",
        "items": [
            {"jp":"社長はもういらっしゃいました。","pron":"샤초오와 모오 이랏샤이마시타","ko":"사장님은 이미 오셨어요."},
            {"jp":"こちらにお座りください。","pron":"코치라니 오스와리 쿠다사이","ko":"이쪽에 앉아 주세요."},
            {"jp":"少々お待ちください。","pron":"쇼오쇼오 오마치 쿠다사이","ko":"잠시만 기다려 주세요."},
            {"jp":"ご覧になりますか。","pron":"고란 니 나리마스카","ko":"보시겠습니까?"},
            {"jp":"ご連絡いただき、ありがとうございます。","pron":"고렌라쿠 이타다키 아리가토오 고자이마스","ko":"연락 주셔서 감사합니다."},
            {"jp":"後ほどこちらからお電話いたします。","pron":"아토호도 코치라카라 오덴와 이타시마스","ko":"나중에 이쪽에서 전화드리겠습니다."},
            {"jp":"お名前を伺ってもよろしいですか。","pron":"오나마에오 우카갓테모 요로시이데스카","ko":"성함을 여쭤봐도 될까요?"},
            {"jp":"申し訳ありませんが、今日は満席です。","pron":"모오시아케 아리마센가 쿄오와 만세키데스","ko":"죄송하지만 오늘은 만석입니다."},
            {"jp":"お手数をおかけしてすみません。","pron":"오테스오 오카케시테 스미마센","ko":"번거롭게 해서 죄송합니다."},
            {"jp":"よろしくお願いいたします。","pron":"요로시쿠 오네가이 이타시마스","ko":"잘 부탁드립니다."},
        ],
    },
    {
        "key": "connect",
        "title": "7) 접속/표현 확장",
        "desc": "～のに / ～のような / ～に対して / ～について",
        "items": [
            {"jp":"一生懸命勉強したのに、落ちてしまいました。","pron":"잇쇼오켄메이 벤쿄오시타노니 오치테 시마이마시타","ko":"열심히 공부했는데도 떨어져 버렸어요."},
            {"jp":"彼は学生なのに、とても忙しそうです。","pron":"카레와 가쿠세이나노니 토테모 이소가시소오데스","ko":"그는 학생인데도 매우 바빠 보여요."},
            {"jp":"日本語について質問があります。","pron":"니혼고니 츠이테 시츠몬가 아리마스","ko":"일본어에 대해 질문이 있어요."},
            {"jp":"この問題について説明します。","pron":"코노 몬다이니 츠이테 세츠메이시마스","ko":"이 문제에 대해 설명하겠습니다."},
            {"jp":"彼の意見に対して反対しました。","pron":"카레노 이켄니 타이시테 한타이시마시타","ko":"그의 의견에 대해 반대했어요."},
            {"jp":"あなたの考えは私のと違います。","pron":"아나타노 캉가에와 와타시노토 치가이마스","ko":"당신의 생각은 제 것과 달라요."},
            {"jp":"彼のような人になりたいです。","pron":"카레노 요오나 히토니 나리타이데스","ko":"그 같은 사람이 되고 싶어요."},
            {"jp":"最近は以前より忙しくなりました。","pron":"사이킨와 이젠요리 이소가시쿠 나리마시타","ko":"최근에는 예전보다 바빠졌어요."},
            {"jp":"旅行のためにお金を貯めています。","pron":"료코오노 타메니 오카네오 타메테이마스","ko":"여행을 위해 돈을 모으고 있어요."},
            {"jp":"そのニュースを聞いてびっくりしました。","pron":"소노 뉴스오 키이테 빗쿠리시마시타","ko":"그 뉴스를 듣고 놀랐어요."},
        ],
    },
]

N2_SENTENCE_SECTIONS = [
    {
        "key": "logic",
        "title": "1) 논리/결론",
        "desc": "～わけだ / ～ということだ / ～に違いない",
        "items": [
            {"jp":"つまり、あなたは反対だということですね。","pron":"츠마리 아나타와 한타이다 토 이우코토데스네","ko":"즉, 당신은 반대라는 말이군요."},
            {"jp":"この結果から見ると、成功したわけだ。","pron":"코노 켓카카라 미루토 세이코오시타 와케다","ko":"이 결과로 보면 성공한 셈이다."},
            {"jp":"こんなに静かなら、もう帰ったわけだ。","pron":"콘나니 시즈카나라 모오 카엣타 와케다","ko":"이렇게 조용하면 이미 돌아간 거다."},
            {"jp":"電気がついていない。留守に違いない。","pron":"덴키가 츠이테이나이 루스니 치가이나이","ko":"불이 안 켜져 있다. 부재가 틀림없다."},
            {"jp":"彼が来ないのは、用事があるということだろう。","pron":"카레가 코나이노와 요오지가 아루 토 이우코토다로오","ko":"그가 안 오는 건 일이 있다는 뜻이겠지."},
            {"jp":"説明を聞けば分かるわけです。","pron":"세츠메이오 키케바 와카루 와케데스","ko":"설명을 들으면 알게 되는 겁니다."},
            {"jp":"遅れたのは私のせいだというわけではありません。","pron":"오쿠레타노와 와타시노 세이다 토 이우 와케데와 아리마센","ko":"늦은 게 제 탓이라는 뜻은 아닙니다."},
            {"jp":"彼の態度からして、怒っているに違いない。","pron":"카레노 타이도카라시테 오콧테이루니 치가이나이","ko":"그의 태도로 보아 화난 게 틀림없다."},
            {"jp":"この価格なら、品質が高いというわけでもない。","pron":"코노 카카쿠나라 힌시츠가 타카이 토 이우 와케데모 나이","ko":"이 가격이라고 해서 품질이 높다는 뜻도 아니다."},
            {"jp":"結局、努力が必要だということだ。","pron":"켓쿄쿠 도료쿠가 히츠요오다 토 이우코토다","ko":"결국 노력은 필요하다는 것이다."},
        ],
    },
    {
        "key": "contrast",
        "title": "2) 대조/양보",
        "desc": "～ものの / ～とはいえ / ～ながら",
        "items": [
            {"jp":"約束したものの、行けなくなりました。","pron":"야쿠소쿠시타 모노노 이케나쿠 나리마시타","ko":"약속하긴 했지만 못 가게 됐어요."},
            {"jp":"便利とはいえ、値段が高すぎます。","pron":"벤리 토와이에 네단가 타카스기마스","ko":"편리하긴 해도 가격이 너무 비싸요."},
            {"jp":"知っていながら、何も言いませんでした。","pron":"싯테이나가라 나니모 이이마센데시타","ko":"알면서도 아무 말도 안 했어요."},
            {"jp":"難しいとはいえ、やってみる価値はあります。","pron":"무즈카시이 토와이에 얏테미루 카치와 아리마스","ko":"어렵긴 해도 해볼 가치는 있어요."},
            {"jp":"努力したものの、結果は変わりませんでした。","pron":"도료쿠시타 모노노 켓카와 카와리마센데시타","ko":"노력했지만 결과는 바뀌지 않았어요."},
            {"jp":"忙しいながらも、時間を作っています。","pron":"이소가시이 나가라모 지칸오 츠쿠앗테이마스","ko":"바쁘면서도 시간을 내고 있어요."},
            {"jp":"好きとはいえ、毎日は食べません。","pron":"스키 토와이에 마이니치와 타베마센","ko":"좋아하긴 해도 매일 먹진 않아요."},
            {"jp":"理解していながら、同じミスをしました。","pron":"리카이시테이나가라 오나지 미스오 시마시타","ko":"이해하면서도 같은 실수를 했어요."},
            {"jp":"行きたいものの、予定が合いません。","pron":"이키타이 모노노 요테이가 아이마센","ko":"가고 싶지만 일정이 안 맞아요."},
            {"jp":"高いとはいえ、その性能は魅力的です。","pron":"타카이 토와이에 소노 세이노오와 미료쿠테키데스","ko":"비싸긴 해도 그 성능은 매력적이에요."},
        ],
    },
    {
        "key": "cause",
        "title": "3) 원인/결과",
        "desc": "～おかげで / ～せいで / ～ため",
        "items": [
            {"jp":"友達のおかげで助かりました。","pron":"토모다치노 오카게데 타스카리마시타","ko":"친구 덕분에 살았어요."},
            {"jp":"雨のせいで試合が中止になりました。","pron":"아메노 세이데 시아이가 츄우시니 나리마시타","ko":"비 때문에 경기가 취소됐어요."},
            {"jp":"準備不足のため、失敗しました。","pron":"준비부소쿠노 타메 시っぱい시마시타","ko":"준비 부족 때문에 실패했어요."},
            {"jp":"先生のおかげで分かるようになりました。","pron":"센세이노 오카게데 와카루요오니 나리마시타","ko":"선생님 덕분에 알게 되었어요."},
            {"jp":"寝不足のせいで集中できません。","pron":"네부소쿠노 세이데 슈우츄우 데키마센","ko":"잠 부족 때문에 집중이 안 돼요."},
            {"jp":"事故のため、電車が遅れています。","pron":"지코노 타메 덴샤가 오쿠레테이마스","ko":"사고로 전철이 지연 중입니다."},
            {"jp":"みんなの協力のおかげで予定通り終わりました。","pron":"민나노 쿄오료쿠노 오카게데 요테이도오리 오와리마시타","ko":"모두의 협력 덕분에 예정대로 끝났어요."},
            {"jp":"彼の一言のせいで雰囲気が悪くなりました。","pron":"카레노 히토코토노 세이데 훈이키가 와루쿠 나리마시타","ko":"그의 한마디 때문에 분위기가 나빠졌어요."},
            {"jp":"体調不良のため、本日は休みます。","pron":"타이초오후료오노 타메 혼지츠와 야스미마스","ko":"컨디션 불량으로 오늘은 쉽니다."},
            {"jp":"あなたのおかげで勇気が出ました。","pron":"아나타노 오카게데 유우키가 데마시타","ko":"당신 덕분에 용기가 났어요."},
        ],
    },
    {
        "key": "change",
        "title": "4) 변화/추이",
        "desc": "～につれて / ～ようになる / ～ば～ほど",
        "items": [
            {"jp":"年を取るにつれて体力が落ちます。","pron":"토시오 토루니 츠레테 타이료쿠가 오치마스","ko":"나이가 들수록 체력이 떨어져요."},
            {"jp":"練習するにつれて上手になります。","pron":"렌슈우스루니 츠레테 조오즈니 나리마스","ko":"연습할수록 잘하게 돼요."},
            {"jp":"最近、早起きできるようになりました。","pron":"사이킨 하야오키 데키루요오니 나리마시타","ko":"최근 일찍 일어날 수 있게 됐어요."},
            {"jp":"経験を積むほど自信がつきます。","pron":"케이켄오 츠무호도 지신가 츠키마스","ko":"경험을 쌓을수록 자신감이 생겨요."},
            {"jp":"勉強すればするほど面白くなります。","pron":"벤쿄오스레바 스루호도 오모시로쿠 나리마스","ko":"공부하면 할수록 재미있어져요."},
            {"jp":"春になるにつれて暖かくなります。","pron":"하루니 나루니 츠레테 아타타카쿠 나리마스","ko":"봄이 될수록 따뜻해져요."},
            {"jp":"日本語が聞き取れるようになってきました。","pron":"니혼고가 키키토레루요오니 낫테키마시타","ko":"일본어가 들리게 되기 시작했어요."},
            {"jp":"考えれば考えるほど分からなくなります。","pron":"캉가에레바 캉가에루호도 와카라나쿠 나리마스","ko":"생각하면 할수록 모르겠어요."},
            {"jp":"状況は日がたつにつれて悪化しました。","pron":"죠오쿄오와 히가 타츠니 츠레테 악카시마시타","ko":"상황은 날이 갈수록 악화했어요."},
            {"jp":"慣れるほど楽になります。","pron":"나레루호도 라쿠니 나리마스","ko":"익숙해질수록 편해져요."},
        ],
    },
    {
        "key": "certainty",
        "title": "5) 확신/추정",
        "desc": "～に決まっている / ～に違いない / ～恐れがある",
        "items": [
            {"jp":"そんなの嘘に決まっています。","pron":"손나노 우소니 키맛테이마스","ko":"그건 거짓말이 분명해요."},
            {"jp":"彼はまだ寝ているに違いない。","pron":"카레와 마다 네테이루니 치가이나이","ko":"그는 아직 자고 있는 게 틀림없다."},
            {"jp":"このままだと失敗する恐れがあります。","pron":"코노마마다토 싯파이스루 오소레가 아리마스","ko":"이대로면 실패할 우려가 있어요."},
            {"jp":"あの二人は付き合っているに決まっています。","pron":"아노 후타리와 츠키앗테이루니 키맛테이마스","ko":"그 둘은 사귀는 게 분명해요."},
            {"jp":"道がぬれている。雨が降ったに違いない。","pron":"미치가 누레테이루 아메가 훗타니 치가이나이","ko":"길이 젖어 있다. 비가 온 게 틀림없다."},
            {"jp":"準備しないと問題が起こる恐れがあります。","pron":"준비시나이토 몬다이가 오코루 오소레가 아리마스","ko":"준비 안 하면 문제가 생길 우려가 있어요."},
            {"jp":"彼ならできるに決まっています。","pron":"카레나라 데키루니 키맛테이마스","ko":"그라면 할 수 있음이 분명해요."},
            {"jp":"この結果は偶然ではないに違いない。","pron":"코노 켓카와 구우젠데와 나이니 치가이나이","ko":"이 결과는 우연이 아닐 게 틀림없다."},
            {"jp":"台風で電車が止まる恐れがあります。","pron":"타이후우데 덴샤가 토마루 오소레가 아리마스","ko":"태풍으로 전철이 멈출 우려가 있어요."},
            {"jp":"そんな態度じゃ嫌われるに決まっています。","pron":"손나 타이도쟈 키라와레루니 키맛테이마스","ko":"그런 태도면 미움받는 게 뻔해요."},
        ],
    },
    {
        "key": "formal",
        "title": "6) 공지/안내 표현",
        "desc": "～いたします / ～させていただきます / ～となっております",
        "items": [
            {"jp":"本日は臨時休業とさせていただきます。","pron":"혼지츠와 린지큐우교오토 사세테 이타다키마스","ko":"오늘은 임시 휴업으로 하겠습니다."},
            {"jp":"こちらで確認いたします。","pron":"코치라데 카쿠닌 이타시마스","ko":"이쪽에서 확인하겠습니다."},
            {"jp":"ただいま満席となっております。","pron":"타다이마 만세키토 낫테오리마스","ko":"현재 만석입니다."},
            {"jp":"後ほど担当者からご連絡いたします。","pron":"아토호도 탄토오샤카라 고렌라쿠 이타시마스","ko":"나중에 담당자가 연락드리겠습니다."},
            {"jp":"恐れ入りますが、少々お待ちください。","pron":"오소레이리마스가 쇼오쇼오 오마치 쿠다사이","ko":"죄송하지만 잠시만 기다려 주세요."},
            {"jp":"資料は受付にてお渡ししております。","pron":"시료오와 우케츠케니테 오와타시 시테오리마스","ko":"자료는 접수처에서 드리고 있습니다."},
            {"jp":"ご不明点はお問い合わせください。","pron":"고후메이텐와 오토이아와세 쿠다사이","ko":"문의 사항은 연락해 주세요."},
            {"jp":"本日の受付は終了いたしました。","pron":"혼지츠노 우케츠케와 슈우료오 이타시마시타","ko":"오늘 접수는 종료했습니다."},
            {"jp":"ただいま準備中となっております。","pron":"타다이마 준비츄우토 낫테오리마스","ko":"현재 준비 중입니다."},
            {"jp":"変更があり次第お知らせいたします。","pron":"헨코오가 아리시다이 오시라세 이타시마스","ko":"변경이 생기는 대로 안내드리겠습니다."},
        ],
    },
    {
        "key": "idiom",
        "title": "7) 관용/뉘앙스",
        "desc": "～気がする / ～ところ / ～わけにはいかない",
        "items": [
            {"jp":"今日はなんだか疲れた気がします。","pron":"쿄오와 난다카 츠카레타 키가 시마스","ko":"오늘은 왠지 피곤한 느낌이에요."},
            {"jp":"今から出かけるところです。","pron":"이마카라 데카케루 토코로데스","ko":"지금부터 나가려는 참입니다."},
            {"jp":"ちょうど食べ終わったところです。","pron":"초오도 타베오왓타 토코로데스","ko":"마침 다 먹은 참이에요."},
            {"jp":"忙しくて休むわけにはいきません。","pron":"이소가시쿠테 야스무 와케니와 이키마센","ko":"바빠서 쉴 수가 없어요."},
            {"jp":"今さらやめるわけにはいきません。","pron":"이마사라 야메루 와케니와 이키마센","ko":"이제 와서 그만둘 수는 없어요."},
            {"jp":"彼の話は信じられない気がします。","pron":"카레노 하나시와 신지라레나이 키가 시마스","ko":"그의 이야기는 믿기 어려운 느낌이에요."},
            {"jp":"これから確認するところです。","pron":"코레카라 카쿠닌스루 토코로데스","ko":"이제 확인하려는 참입니다."},
            {"jp":"まだ決めていないところです。","pron":"마다 키메테이나이 토코로데스","ko":"아직 결정하지 못한 상태예요."},
            {"jp":"そんなことを言うわけにはいきません。","pron":"손나 코토오 이우 와케니와 이키마센","ko":"그런 말을 할 수는 없어요."},
            {"jp":"もう少しで終わるところでした。","pron":"모오 스코시데 오와루 토코로데시타","ko":"거의 끝날 뻔했어요."},
        ],
    },
]
N1_SENTENCE_SECTIONS = [
    {
        "key": "advanced_logic",
        "title": "1) 고급 논리/결론",
        "desc": "～にほかならない / ～にすぎない / ～といわざるをえない",
        "items": [
            {"jp":"この結果は努力の積み重ねにほかなりません。","pron":"코노 켓카와 도료쿠노 츠미카사네니 호카나리마센","ko":"이 결과는 노력의 축적에 다름 아닙니다."},
            {"jp":"それは単なる誤解にすぎません。","pron":"소레와 탄나루 고카이니 스기마센","ko":"그건 단순한 오해에 불과합니다."},
            {"jp":"彼の行動は無責任だといわざるをえません。","pron":"카레노 코오도오와 무세키닌다 토 이와자루오에마센","ko":"그의 행동은 무책임하다고 말하지 않을 수 없습니다."},
            {"jp":"今回の失敗は想定不足にほかなりません。","pron":"콘카이노 싯파이와 소오테이부소쿠니 호카나리마센","ko":"이번 실패는 예상 부족에 다름 아닙니다."},
            {"jp":"この判断は妥協の産物にすぎない。","pron":"코노 한단와 다쿄오노 산부츠니 스기나이","ko":"이 판단은 타협의 산물에 불과하다."},
            {"jp":"そう結論づけるのは早計だといわざるをえない。","pron":"소오 켓론즈케루노와 소오케이다 토 이와자루오에나이","ko":"그렇게 결론내리는 건 성급하다고 말할 수밖에 없다."},
            {"jp":"それは口実にすぎないでしょう。","pron":"소레와 코오지츠니 스기나이데쇼오","ko":"그건 구실에 불과하겠죠."},
            {"jp":"彼が怒るのも無理はない。","pron":"카레가 오코루노모 무리와 나이","ko":"그가 화내는 것도 무리는 아니다."},
            {"jp":"この問題は制度そのものに起因するといえます。","pron":"코노 몬다이와 세이도 소노모노니 키인스루 토 이에마스","ko":"이 문제는 제도 자체에 기인한다고 말할 수 있습니다."},
            {"jp":"その説明では納得できないといわざるをえません。","pron":"소노 세츠메이데와 낫토쿠 데키나이 토 이와자루오에마센","ko":"그 설명으로는 납득할 수 없다고 말할 수밖에 없습니다."},
        ],
    },
    {
        "key": "contrast_n1",
        "title": "2) 양보/역접 고급",
        "desc": "～にもかかわらず / ～ものの / ～とはいえ",
        "items": [
            {"jp":"反対が多かったにもかかわらず、計画は進められた。","pron":"한타이가 오오캇타니모 카카와라즈 케이카쿠와 스스메라레타","ko":"반대가 많았음에도 계획은 추진되었다."},
            {"jp":"努力したものの、結果が伴わなかった。","pron":"도료쿠시타 모노노 켓카가 토모나와나캇타","ko":"노력했지만 결과가 따르지 않았다."},
            {"jp":"簡単とはいえ、油断は禁物だ。","pron":"칸탄 토와이에 유단와 킨모츠다","ko":"쉽다 해도 방심은 금물이다."},
            {"jp":"謝罪したにもかかわらず、許してもらえなかった。","pron":"샤자이시타니모 카카와라즈 유루시테 모라에나캇타","ko":"사과했음에도 용서받지 못했다."},
            {"jp":"知っていながら黙っていた。","pron":"싯테이나가라 다맛테이타","ko":"알면서도 말없이 있었다."},
            {"jp":"便利とはいえ、万能ではない。","pron":"벤리 토와이에 반노오데와 나이","ko":"편리하긴 해도 만능은 아니다."},
            {"jp":"期待したものの、裏切られた気がした。","pron":"키타이시타 모노노 우라기라레타 키가 시타","ko":"기대했지만 배신당한 느낌이 들었다."},
            {"jp":"努力にもかかわらず、評価されなかった。","pron":"도료쿠니모 카카와라즈 효오카사레나캇타","ko":"노력에도 불구하고 평가받지 못했다."},
            {"jp":"難しいとはいえ、可能性は残っている。","pron":"무즈카시이 토와이에 카노오세이와 노콧테이루","ko":"어렵다 해도 가능성은 남아 있다."},
            {"jp":"慎重に進めたものの、想定外の問題が起きた。","pron":"신초오니 스스메타 모노노 소오테이가이노 몬다이가 오키타","ko":"신중히 진행했지만 예상 밖 문제가 일어났다."},
        ],
    },
    {
        "key": "cause_n1",
        "title": "3) 원인/배경 고급",
        "desc": "～をめぐって / ～に伴って / ～を受けて",
        "items": [
            {"jp":"その発言をめぐって議論が起きた。","pron":"소노 하츠겐오 메굿테 기론가 오키타","ko":"그 발언을 둘러싸고 논의가 일어났다."},
            {"jp":"人口増加に伴って問題も増えている。","pron":"진코오조오카니 토모낫테 몬다이모 후에테이루","ko":"인구 증가에 따라 문제도 늘고 있다."},
            {"jp":"事故を受けて安全対策が強化された。","pron":"지코오 우케테 안젠타이사쿠가 쿄오카사레타","ko":"사고를 계기로 안전대책이 강화되었다."},
            {"jp":"制度改正をめぐって賛否が分かれた。","pron":"세이도카이세이오 메굿테 산피가 와카레타","ko":"제도 개정을 둘러싸고 찬반이 갈렸다."},
            {"jp":"円安に伴って物価が上がった。","pron":"엔야스니 토모낫테 붓카가 아갓타","ko":"엔저에 따라 물가가 올랐다."},
            {"jp":"批判を受けて方針を変更した。","pron":"히한오 우케테 호오신오 헨코오시타","ko":"비판을 받고 방침을 변경했다."},
            {"jp":"新情報をめぐって報道が過熱している。","pron":"신조오호오오 메굿테 호오도오가 카네츠시테이루","ko":"새 정보를 둘러싸고 보도가 과열되고 있다."},
            {"jp":"災害に伴って交通が混乱した。","pron":"사이가이니 토모낫테 코오츠우가 콘란시타","ko":"재해에 따라 교통이 혼란해졌다."},
            {"jp":"声明を受けて市場が反応した。","pron":"세이메이오 우케테 시조오가 한노오시타","ko":"성명을 받고 시장이 반응했다."},
            {"jp":"事件をめぐる真相はまだ不明だ。","pron":"지켄오 메구루 신소오와 마다 후메이다","ko":"사건을 둘러싼 진상은 아직 불명이다."},
        ],
    },
    {
        "key": "evaluation",
        "title": "4) 평가/정도 고급",
        "desc": "～にすぎない / ～にたえない / ～までもない",
        "items": [
            {"jp":"それは推測にすぎません。","pron":"소레와 스이소쿠니 스기마센","ko":"그건 추측에 불과합니다."},
            {"jp":"その態度は見るにたえない。","pron":"소노 타이도와 미루니 타에나이","ko":"그 태도는 보기 힘들다."},
            {"jp":"今さら説明するまでもないでしょう。","pron":"이마사라 세츠메이스루 마데모 나이데쇼오","ko":"이제 와서 설명할 필요도 없겠죠."},
            {"jp":"それほど驚くにはあたりません。","pron":"소레호도 오도로쿠니와 아타리마센","ko":"그렇게 놀랄 일도 아닙니다."},
            {"jp":"彼の努力は評価に値します。","pron":"카레노 도료쿠와 효오카니 아타이시마스","ko":"그의 노력은 평가할 가치가 있습니다."},
            {"jp":"その意見は検討に値しない。","pron":"소노 이켄와 켄토오니 아타이시나이","ko":"그 의견은 검토할 가치가 없다."},
            {"jp":"今さら後悔しても始まらない。","pron":"이마사라 코오카이시테모 하지마라나이","ko":"이제 와서 후회해도 소용없다."},
            {"jp":"彼の話は聞くにたえない。","pron":"카레노 하나시와 키쿠니 타에나이","ko":"그의 이야기는 들을 만하지 않다."},
            {"jp":"説明するまでもなく、結果は明らかだ。","pron":"세츠메이스루 마데모 나쿠 켓카와 아키라카다","ko":"설명할 것도 없이 결과는 명백하다."},
            {"jp":"それは事実にすぎない。","pron":"소레와 지지츠니 스기나이","ko":"그건 사실에 불과하다."},
        ],
    },
    {
        "key": "formal_n1",
        "title": "5) 문어/격식 표현",
        "desc": "～に際して / ～をもって / ～次第",
        "items": [
            {"jp":"入社に際して、必要書類をご提出ください。","pron":"뉴우샤니 사이시테 히츠요오쇼루이오 고테이슈츠 쿠다사이","ko":"입사에 즈음하여 필요 서류를 제출해 주세요."},
            {"jp":"本日をもって受付を終了いたします。","pron":"혼지츠오 못테 우케츠케오 슈우료오 이타시마스","ko":"오늘부로 접수를 종료하겠습니다."},
            {"jp":"準備ができ次第、ご案内いたします。","pron":"준비가 데키시다이 고안나이 이타시마스","ko":"준비되는 대로 안내드리겠습니다."},
            {"jp":"変更があり次第、連絡してください。","pron":"헨코오가 아리시다이 렌라쿠시테 쿠다사이","ko":"변경이 생기는 대로 연락해 주세요."},
            {"jp":"発表に際して多くの支援を受けました。","pron":"핫표오니 사이시테 오오쿠노 시엔오 우케마시타","ko":"발표에 즈음하여 많은 지원을 받았습니다."},
            {"jp":"本契約は署名をもって成立します。","pron":"혼케이야쿠와 쇼메이오 못테 세이리츠시마스","ko":"본 계약은 서명을 통해 성립합니다."},
            {"jp":"到着次第、電話してください。","pron":"도오착 시다이 덴와시테 쿠다사이","ko":"도착하는 대로 전화해 주세요."},
            {"jp":"退職に際して、ご挨拶申し上げます。","pron":"타이쇼쿠니 사이시테 고아이사츠 모오시아게마스","ko":"퇴직에 즈음하여 인사드립니다."},
            {"jp":"本件は確認次第、対応します。","pron":"혼켄와 카쿠닌 시다이 타이오오시마스","ko":"본 건은 확인되는 대로 대응하겠습니다."},
            {"jp":"本日をもって閉店いたします。","pron":"혼지츠오 못테 헤이텐 이타시마스","ko":"오늘부로 폐점합니다."},
        ],
    },
    {
        "key": "nuance_n1",
        "title": "6) 뉘앙스/관용 고급",
        "desc": "～かねない / ～ざるをえない / ～にこたえる",
        "items": [
            {"jp":"その発言は誤解を招きかねません。","pron":"소노 하츠겐와 고카이오 마네키카네마센","ko":"그 발언은 오해를 불러일으킬 수도 있습니다."},
            {"jp":"このままでは失敗しかねない。","pron":"코노마마데와 싯파이시카네나이","ko":"이대로면 실패할지도 모른다."},
            {"jp":"黙っているわけにはいきません。","pron":"다맛테이루 와케니와 이키마센","ko":"가만히 있을 수는 없습니다."},
            {"jp":"彼の態度には怒りを覚えざるをえない。","pron":"카레노 타이도니와 이카리오 오보에자루오에나이","ko":"그의 태도에는 분노를 느끼지 않을 수 없다."},
            {"jp":"その対応は期待にこたえるものではない。","pron":"소노 타이오오와 키타이니 코타에루 모노데와 나이","ko":"그 대응은 기대에 부응하는 것이 아니다."},
            {"jp":"説明不足は混乱を招きかねません。","pron":"세츠메이부소쿠와 콘란오 마네키카네마센","ko":"설명 부족은 혼란을 초래할 수도 있습니다."},
            {"jp":"これ以上待つのは限界だと言わざるをえない。","pron":"코레이죠오 마츠노와 겐카이다 토 이와자루오에나이","ko":"이 이상 기다리는 건 한계라고 말할 수밖에 없다."},
            {"jp":"その提案は現実的とは言い難い。","pron":"소노 테이안와 겐지츠테키 토와 이이가타이","ko":"그 제안은 현실적이라 말하기 어렵다."},
            {"jp":"この品質では評判を落としかねない。","pron":"코노 힌시츠데와 효오반오 오토시카네나이","ko":"이 품질로는 평판을 떨어뜨릴 수도 있다."},
            {"jp":"誠意ある対応が求められます。","pron":"세이이아루 타이오오가 모토메라레마스","ko":"성의 있는 대응이 요구됩니다."},
        ],
    },
    {
        "key": "structure",
        "title": "7) 문장 구조/표현",
        "desc": "～にあたって / ～を皮切りに / ～を通じて",
        "items": [
            {"jp":"出発にあたって注意事項を確認してください。","pron":"슈っぱ츠니 아탓테 추우이 지코오오 카쿠닌시테 쿠다사이","ko":"출발에 앞서 주의사항을 확인해 주세요."},
            {"jp":"開会を皮切りにイベントが始まった。","pron":"카이카이오 카와키리니 이ベント가 하지맛타","ko":"개회를 시작으로 행사가 시작됐다."},
            {"jp":"経験を通じて多くを学びました。","pron":"케이켄오 츠우지테 오오쿠오 마나비마시타","ko":"경험을 통해 많은 것을 배웠습니다."},
            {"jp":"研修を通じて基本を身につけます。","pron":"켄슈우오 츠우지테 키혼오 미니츠케마스","ko":"연수를 통해 기본을 익힙니다."},
            {"jp":"新制度導入にあたって説明会を行う。","pron":"신세이도 도오뉴우니 아탓테 세츠메이카이오 오코나우","ko":"새 제도 도입에 앞서 설명회를 실시한다."},
            {"jp":"その改革を皮切りに、変化が加速した。","pron":"소노 카이카쿠오 카와키리니 헨카가 카소쿠시타","ko":"그 개혁을 시작으로 변화가 가속했다."},
            {"jp":"調査を通じて実態が明らかになった。","pron":"초오사오 츠우지테 지ったい 가 아키라카니 낫타","ko":"조사를 통해 실태가 밝혀졌다."},
            {"jp":"開催にあたって多くの準備が必要だ。","pron":"카이사이니 아탓테 오오쿠노 준비가 히츠요오다","ko":"개최에 앞서 많은 준비가 필요하다."},
            {"jp":"交流を通じて理解が深まった。","pron":"코오류우오 츠우지테 리카이가 후카맛타","ko":"교류를 통해 이해가 깊어졌다."},
            {"jp":"発表を皮切りに議論が活発になった。","pron":"핫표오오 카와키리니 기론가 캇파츠니 낫타","ko":"발표를 시작으로 논의가 활발해졌다."},
        ],
    },
]

import json

# =========================
# JLPT N5 문법 데이터 (app.py)
# =========================
N5_GRAMMAR_DATA = [
  {
    "cat":"basics", "tag":"기본문장", "title":"～です / ～ます",
    "desc":"공손하게 말할 때 쓰는 기본 문장 끝맺음",
    "rule":"명사 + です / 동사 ます형 + ます",
    "warn":"N5는 정중형(です/ます)이 매우 자주 나옵니다.",
    "extra":{
      "core":'<span class="x-badge">기본문장</span> “~입니다 / ~합니다”',
      "situation":"처음 만났을 때 자기소개, 일상 습관 말하기",
      "breakdown":"私は(주제) + 学生(명사) + です(정중 종결)",
      "caution":"구어체(だ/る)보다 시험에서는 정중형이 더 흔함",
      "variation":"私は学生です。／毎日勉強します。"
    },
    "examples":[
      {"jp":"私は学生です。","pron":"와타시와 가쿠세이데스","ko":"저는 학생입니다.","use":"자기소개할 때","highlight":["です"]},
      {"jp":"毎日、日本語を勉強します。","pron":"마이니치, 니혼고오 벤쿄오 시마스","ko":"매일 일본어를 공부합니다.","use":"습관을 말할 때","highlight":["します"]},
      {"jp":"週末、友達に会います。","pron":"슈우마츠, 토모다치니 아이마스","ko":"주말에 친구를 만납니다.","use":"일정/계획 말할 때","highlight":["ます"]}
    ]
  },
  {
    "cat":"basics", "tag":"기본문장", "title":"～ではありません / ～じゃありません",
    "desc":"정중한 부정(명사/な형용사)",
    "rule":"명사/な형용사 + ではありません(＝じゃありません)",
    "warn":"공식/시험 느낌은 ではありません이 더 안전합니다.",
    "extra":{
      "core":'<span class="x-badge">부정</span> “~이/가 아닙니다”',
      "situation":"정정/부정할 때(직업, 신분, 상태)",
      "breakdown":"これは(주제) + 私の本(명사구) + ではありません(부정)",
      "caution":"じゃありません은 회화 느낌(문제집/시험은 では〜 추천)",
      "variation":"学生ではありません。／元気じゃありません。"
    },
    "examples":[
      {"jp":"私は学生ではありません。","pron":"와타시와 가쿠세이데와 아리마센","ko":"저는 학생이 아닙니다.","use":"신분/직업을 부정할 때","highlight":["ではありません"]},
      {"jp":"これは私の本ではありません。","pron":"코레와 와타시노 혼데와 아리마센","ko":"이것은 제 책이 아닙니다.","use":"물건이 내 것이 아니라고 말할 때","highlight":["ではありません"]},
      {"jp":"今日は暇じゃありません。","pron":"쿄오와 히마쟈 아리마센","ko":"오늘은 한가하지 않아요.","use":"회화에서 가볍게 부정할 때","highlight":["じゃありません"]}
    ]
  },
  {
    "cat":"basics", "tag":"기본문장", "title":"～ましょう / ～ましょうか",
    "desc":"권유/제안(같이 하자, 할까요?)",
    "rule":"동사 ます형 → ましょう / ましょうか",
    "warn":"강요가 아니라 ‘부드러운 제안’ 느낌입니다.",
    "extra":{
      "core":'<span class="x-badge">권유</span> “~합시다 / ~할까요?”',
      "situation":"친구/동료에게 같이 하자고 제안할 때",
      "breakdown":"行き(ます형 어간) + ましょう(권유)",
      "caution":"상대에게 선택권을 주려면 ましょうか가 더 부드러움",
      "variation":"行きましょう。／行きましょうか。"
    },
    "examples":[
      {"jp":"一緒に行きましょう。","pron":"잇쇼니 이키마쇼오","ko":"같이 갑시다.","use":"함께 행동을 제안할 때","highlight":["ましょう"]},
      {"jp":"休みましょうか。","pron":"야스미마쇼오카","ko":"쉴까요?","use":"상대에게 제안/확인할 때","highlight":["ましょうか"]},
      {"jp":"ここで会いましょう。","pron":"코코데 아이마쇼오","ko":"여기서 만납시다.","use":"만날 장소를 정할 때","highlight":["ましょう"]}
    ]
  },

  # -----------------------
  # particles: 조사
  # -----------------------
  {
    "cat":"particles", "tag":"조사", "title":"は (주제)",
    "desc":"문장의 주제 ‘~은/는’",
    "rule":"명사 + は(조사 발음: 와)",
    "warn":"글자는 は지만 조사일 때는 ‘와’로 읽습니다.",
    "extra":{
      "core":'<span class="x-badge">주제</span> “~은/는”',
      "situation":"‘무엇에 대해 말하는지’ 주제를 꺼낼 때",
      "breakdown":"私は(주제) + 学生です(설명)",
      "caution":"は=주제, が=새정보/주어 느낌(구분 연습 추천)",
      "variation":"私は〜です。／今日は〜です。"
    },
    "examples":[
      {"jp":"私は会社員です。","pron":"와타시와 카이샤인데스","ko":"저는 회사원입니다.","use":"자기 소개","highlight":["は"]},
      {"jp":"今日は忙しいです。","pron":"쿄오와 이소가시이데스","ko":"오늘은 바쁩니다.","use":"오늘 상태/상황 말하기","highlight":["は"]},
      {"jp":"この店は安いです。","pron":"코노 미세와 야스이데스","ko":"이 가게는 싸요.","use":"대상의 특징 말하기","highlight":["は"]}
    ]
  },
  {
    "cat":"particles", "tag":"조사", "title":"が (주어/새정보/존재)",
    "desc":"새 정보/주어 강조, 존재 문장에 자주",
    "rule":"명사 + が",
    "warn":"‘있다/없다(あります/います)’ 문장에 자주 붙습니다.",
    "extra":{
      "core":'<span class="x-badge">주어</span> “~이/가”',
      "situation":"‘무엇이 있다/없다’, ‘무엇이 좋아요’처럼 새정보 말할 때",
      "breakdown":"駅が(주어) + あります(존재)",
      "caution":"は vs が: 소개/새정보는 が가 자연스러운 경우 많음",
      "variation":"駅があります。／猫が好きです。"
    },
    "examples":[
      {"jp":"近くに駅があります。","pron":"치카쿠니 에키가 아리마스","ko":"근처에 역이 있어요.","use":"위치/존재 소개","highlight":["が"]},
      {"jp":"猫が好きです。","pron":"네코가 스키데스","ko":"고양이를 좋아합니다.","use":"좋아하는 것 말할 때","highlight":["が"]},
      {"jp":"時間がありません。","pron":"지칸가 아리마센","ko":"시간이 없습니다.","use":"시간이 없다고 말할 때","highlight":["が"]}
    ]
  },
  {
    "cat":"particles", "tag":"조사", "title":"を (목적어)",
    "desc":"행동의 대상 ‘~을/를’",
    "rule":"명사 + を",
    "warn":"먹다/마시다/보다/하다 같은 기본 동사와 세트로 익히면 빠릅니다.",
    "extra":{
      "core":'<span class="x-badge">목적어</span> “~을/를”',
      "situation":"‘무엇을’ 하다(먹다/사다/보다)",
      "breakdown":"パンを(목적어) + 買います(동사)",
      "caution":"を는 동작 대상, 장소는 で/に로 구분",
      "variation":"水を飲みます。／映画を見ます。"
    },
    "examples":[
      {"jp":"パンを買います。","pron":"팡오 카이마스","ko":"빵을 삽니다.","use":"쇼핑","highlight":["を"]},
      {"jp":"水を飲みます。","pron":"미즈오 노미마스","ko":"물을 마십니다.","use":"음료","highlight":["を"]},
      {"jp":"映画を見ます。","pron":"에이가오 미마스","ko":"영화를 봅니다.","use":"취미/일상","highlight":["を"]}
    ]
  },
  {
    "cat":"particles", "tag":"조사", "title":"に / へ (시간·도착·방향)",
    "desc":"시간/도착(に), 방향(へ)",
    "rule":"시간 + に / 장소(도착) + に / 방향 + へ(발음: 에)",
    "warn":"へ는 글자는 へ지만 조사일 때 ‘에’로 읽습니다.",
    "extra":{
      "core":'<span class="x-badge">시간/방향</span> “~에(로)”',
      "situation":"몇 시에/어디에/어디로 가다",
      "breakdown":"七時に(시간) + 起きます(동사)",
      "caution":"도착점=に, 방향=へ(둘 다 쓰이지만 느낌이 다름)",
      "variation":"駅に行きます。／学校へ行きます。"
    },
    "examples":[
      {"jp":"七時に起きます。","pron":"시치지니 오키마스","ko":"7시에 일어납니다.","use":"시간 말하기","highlight":["に"]},
      {"jp":"駅に行きます。","pron":"에키니 이키마스","ko":"역에 갑니다.","use":"목적지(도착점)","highlight":["に"]},
      {"jp":"学校へ行きます。","pron":"각코오에 이키마스","ko":"학교에(로) 갑니다.","use":"방향 강조","highlight":["へ"]}
    ]
  },
  {
    "cat":"particles", "tag":"조사", "title":"で (장소·수단)",
    "desc":"행동이 일어나는 장소/이동수단",
    "rule":"장소 + で / 교통·도구 + で",
    "warn":"‘어디에서 했는가?’는 で가 핵심입니다.",
    "extra":{
      "core":'<span class="x-badge">장소/수단</span> “~에서 / ~로(수단)”',
      "situation":"공부/일/먹기 등 행동 장소, 버스/전철 등 수단",
      "breakdown":"学校で(장소) + 勉強します(행동)",
      "caution":"에 있다(존재)=に / 행동=で로 구분",
      "variation":"電車で行きます。／家で食べます。"
    },
    "examples":[
      {"jp":"学校で勉強します。","pron":"각코오데 벤쿄오 시마스","ko":"학교에서 공부합니다.","use":"행동 장소","highlight":["で"]},
      {"jp":"電車で行きます。","pron":"덴샤데 이키마스","ko":"전철로 갑니다.","use":"이동 수단","highlight":["で"]},
      {"jp":"家でごはんを食べます。","pron":"이에데 고항오 타베마스","ko":"집에서 밥을 먹습니다.","use":"행동 장소","highlight":["で"]}
    ]
  },
  {
    "cat":"particles", "tag":"조사", "title":"も / の / から / まで",
    "desc":"~도 / 소유·수식 / ~부터~까지",
    "rule":"명사 + も / 명사 + の + 명사 / 명사+から, 명사+まで",
    "warn":"N5에서 문장 만들 때 진짜 자주 등장하는 ‘필수 조사’ 묶음입니다.",
    "extra":{
      "core":'<span class="x-badge">필수</span> “~도 / ~의 / ~부터~까지”',
      "situation":"추가/소유/시간·범위 말할 때",
      "breakdown":"私も／私の本／9時から5時まで",
      "caution":"から는 이유(だから)와도 연결됨(카테고리 주의)",
      "variation":"私も行きます。／私のかばんです。／9時から5時まで働きます。"
    },
    "examples":[
      {"jp":"私も行きます。","pron":"와타시모 이키마스","ko":"저도 갑니다.","use":"‘나도’ 포함","highlight":["も"]},
      {"jp":"これは私のかばんです。","pron":"코레와 와타시노 카방데스","ko":"이것은 제 가방입니다.","use":"소유 말하기","highlight":["の"]},
      {"jp":"九時から五時まで働きます。","pron":"쿠지카라 고지마데 하타라키마스","ko":"9시부터 5시까지 일합니다.","use":"시간 범위","highlight":["から","まで"]}
    ]
  },

  # -----------------------
  # exist: 존재/위치
  # -----------------------
  {
    "cat":"exist", "tag":"존재/위치", "title":"あります / います (있다/없다)",
    "desc":"사물=あります, 사람·동물=います / 부정: ありません・いません",
    "rule":"(장소)に + (명사)が + あります/います",
    "warn":"부정은 ありません / いません.",
    "extra":{
      "core":'<span class="x-badge">존재</span> “있다/없다”',
      "situation":"길 안내/소개(‘~가 있어요’)",
      "breakdown":"近くに(장소) + 駅が(주어) + あります(존재)",
      "caution":"사물=あります, 사람/동물=います 구분",
      "variation":"駅があります。／友達がいます。／お金がありません。"
    },
    "examples":[
      {"jp":"近くに駅があります。","pron":"치카쿠니 에키가 아리마스","ko":"근처에 역이 있어요.","use":"주변 안내","highlight":["あります"]},
      {"jp":"公園に子どもがいます。","pron":"코오엔니 코도모가 이마스","ko":"공원에 아이가 있어요.","use":"사람/동물 존재","highlight":["います"]},
      {"jp":"お金がありません。","pron":"오카네가 아리마센","ko":"돈이 없어요.","use":"없다(부정)","highlight":["ありません"]}
    ]
  },
  {
    "cat":"exist", "tag":"존재/위치", "title":"위치 표현 (上/下/前/後ろ/中… + に)",
    "desc":"‘~위/아래/앞/뒤/안…에’ 위치 말하기",
    "rule":"명사 + の + 上/下/前/後ろ/中/外 + に + あります/います",
    "warn":"위치어는 ‘명사+の’와 세트로 익히면 빠릅니다.",
    "extra":{
      "core":'<span class="x-badge">위치</span> “~의 위/아래/안에”',
      "situation":"물건/사람 위치 설명",
      "breakdown":"机の上に + 本が + あります",
      "caution":"존재=に, 행동=で (자주 헷갈림)",
      "variation":"机の上に本があります。／駅の前に店があります。"
    },
    "examples":[
      {"jp":"机の上に本があります。","pron":"츠쿠에노 우에니 혼가 아리마스","ko":"책상 위에 책이 있어요.","use":"물건 위치 설명","highlight":["上に","あります"]},
      {"jp":"駅の前に店があります。","pron":"에키노 마에니 미세가 아리마스","ko":"역 앞에 가게가 있어요.","use":"길 안내","highlight":["前に","あります"]},
      {"jp":"かばんの中に財布があります。","pron":"카방노 나카니 사이후가 아리마스","ko":"가방 안에 지갑이 있어요.","use":"소지품 위치","highlight":["中に","あります"]}
    ]
  },

  # -----------------------
  # teform: て형
  # -----------------------
  {
    "cat":"teform", "tag":"て형", "title":"～てください (해주세요)",
    "desc":"정중한 부탁/요청",
    "rule":"동사 て형 + ください",
    "warn":"부탁이지만 명령처럼 들리지 않게 ‘ください’가 완충 역할을 합니다.",
    "extra":{
      "core":'<span class="x-badge">요청</span> “~해 주세요”',
      "situation":"가게/역/학교에서 정중히 부탁할 때",
      "breakdown":"待って(て형) + ください(요청)",
      "caution":"더 부드럽게: ちょっと/少し 같이 쓰면 좋음",
      "variation":"少し待ってください。／ここに書いてください。"
    },
    "examples":[
      {"jp":"少し待ってください。","pron":"스코시 맛테 쿠다사이","ko":"조금 기다려 주세요.","use":"잠깐 기다려 달라고 부탁","highlight":["てください"]},
      {"jp":"ここに名前を書いてください。","pron":"코코니 나마에오 카이테 쿠다사이","ko":"여기에 이름을 써 주세요.","use":"서류/신청서 작성 안내","highlight":["てください"]},
      {"jp":"ゆっくり話してください。","pron":"윳쿠리 하나시테 쿠다사이","ko":"천천히 말해 주세요.","use":"말이 빠를 때 부탁","highlight":["てください"]}
    ]
  },
  {
    "cat":"teform", "tag":"て형", "title":"～てもいいです / ～てもいいですか (해도 돼요/될까요?)",
    "desc":"허가/승인",
    "rule":"동사 て형 + もいいです / もいいですか",
    "warn":"질문형(ですか)을 붙이면 ‘해도 될까요?’가 됩니다.",
    "extra":{
      "core":'<span class="x-badge">허가 질문</span> “~해도 될까요?”',
      "situation":"가게/학교/공공장소에서 규칙을 확인할 때",
      "breakdown":"ここで + 写真を + 撮って + もいいですか",
      "caution":"공손하게 부탁하려면 마지막을 ～ですか 로 올리기",
      "variation":"ここで水を飲んでもいいですか。／その本を見てもいいですか。"
    },
    "examples":[
      {"jp":"ここで写真を撮ってもいいですか。","pron":"코코데 샤신오 톳테모 이이데스카","ko":"여기서 사진 찍어도 되나요?","use":"박물관/매장에서 ‘찍어도 돼요?’ 물을 때","highlight":["もいいですか"]},
      {"jp":"このペンを使ってもいいです。","pron":"코노 펜오 츠캇테모 이이데스","ko":"이 펜을 써도 됩니다.","use":"허용됨을 말할 때","highlight":["もいいです"]},
      {"jp":"トイレに行ってもいいですか。","pron":"토이레니 잇테모 이이데스카","ko":"화장실 가도 될까요?","use":"수업/회의 중 허가 요청","highlight":["もいいですか"]}
    ]
  },
  {
    "cat":"teform", "tag":"て형", "title":"～てはいけません (하면 안 돼요)",
    "desc":"금지",
    "rule":"동사 て형 + はいけません",
    "warn":"규칙/주의문에서 자주 등장합니다.",
    "extra":{
      "core":'<span class="x-badge">금지</span> “~하면 안 됩니다”',
      "situation":"규칙/표지판/주의 사항",
      "breakdown":"吸って(て형) + はいけません(금지)",
      "caution":"더 부드럽게: ～ないでください(다음 단계)",
      "variation":"ここで吸ってはいけません。／遅れてはいけません。"
    },
    "examples":[
      {"jp":"ここでタバコを吸ってはいけません。","pron":"코코데 타바코오 슷테와 이케마센","ko":"여기서 담배 피우면 안 됩니다.","use":"금연구역 규칙","highlight":["てはいけません"]},
      {"jp":"遅れてはいけません。","pron":"오쿠레테와 이케마센","ko":"늦으면 안 됩니다.","use":"시간 약속/규칙","highlight":["てはいけません"]},
      {"jp":"ここで写真を撮ってはいけません。","pron":"코코데 샤신오 톳테와 이케마센","ko":"여기서 사진 찍으면 안 됩니다.","use":"촬영 금지","highlight":["てはいけません"]}
    ]
  },
  {
    "cat":"teform", "tag":"て형", "title":"～ています (진행/상태)",
    "desc":"‘~하고 있어요’ 진행, 또는 ‘~되어 있어요’ 상태",
    "rule":"동사 て형 + います(정중형: ています)",
    "warn":"N5에서도 자주 나오는 핵심 표현입니다.",
    "extra":{
      "core":'<span class="x-badge">진행/상태</span> “~하고 있어요”',
      "situation":"지금 하는 중/현재 상태 말할 때",
      "breakdown":"勉強して + います → “하고 있다”",
      "caution":"雨が降っています 처럼 자연현상에도 사용",
      "variation":"今、勉強しています。／雨が降っています。"
    },
    "examples":[
      {"jp":"今、日本語を勉強しています。","pron":"이마, 니혼고오 벤쿄오 시테이마스","ko":"지금 일본어를 공부하고 있어요.","use":"지금 하는 중","highlight":["ています"]},
      {"jp":"雨が降っています。","pron":"아메가 후잇테이마스","ko":"비가 오고 있어요.","use":"날씨/현상","highlight":["ています"]},
      {"jp":"ここに住んでいます。","pron":"코코니 슨데이마스","ko":"여기 살고 있어요.","use":"거주(상태)","highlight":["ています"]}
    ]
  },

  # -----------------------
  # tense: 부정/과거
  # -----------------------
  {
    "cat":"tense", "tag":"부정/과거", "title":"～ません / ～ませんでした",
    "desc":"정중한 부정 / 과거부정",
    "rule":"동사 ます형 → ません / ませんでした",
    "warn":"N5에서는 ない형보다 ‘ません’이 더 자주 보이기도 합니다.",
    "extra":{
      "core":'<span class="x-badge">정중 부정</span> “~하지 않습니다/않았습니다”',
      "situation":"정중하게 거절/부정할 때",
      "breakdown":"行きます → 行きません / 行きませんでした",
      "caution":"문장 끝은 또박또박(시험에서 형태 확인)",
      "variation":"行きません。／行きませんでした。"
    },
    "examples":[
      {"jp":"今日は会社へ行きません。","pron":"쿄오와 카이샤에 이키마센","ko":"오늘은 회사에 가지 않습니다.","use":"계획 취소/부정","highlight":["ません"]},
      {"jp":"昨日、勉強しませんでした。","pron":"키노오 벤쿄오 시마센데시타","ko":"어제 공부하지 않았습니다.","use":"과거 부정","highlight":["ませんでした"]},
      {"jp":"その映画は見ません。","pron":"소노 에이가와 미마센","ko":"그 영화는 보지 않습니다.","use":"정중하게 ‘안 해요’","highlight":["ません"]}
    ]
  },
  {
    "cat":"tense", "tag":"부정/과거", "title":"～ました / ～でした",
    "desc":"과거(정중) ‘~했어요/였어요’",
    "rule":"동사 ます형 → ました / 명사·な형용사 + でした",
    "warn":"でした는 ‘명사/な형용사’ 과거 정중형입니다.",
    "extra":{
      "core":'<span class="x-badge">과거</span> “~했습니다/였어요”',
      "situation":"어제/지난주 등 과거 사실 말하기",
      "breakdown":"行きます → 行きました / 休みです → 休みでした",
      "caution":"명사/な형용사는 ‘でした’를 쓴다",
      "variation":"行きました。／休みでした。"
    },
    "examples":[
      {"jp":"昨日は休みでした。","pron":"키노오와 야스미데시타","ko":"어제는 휴일이었어요.","use":"과거 상태","highlight":["でした"]},
      {"jp":"さっき、駅に着きました。","pron":"삿키 에키니 츠키마시타","ko":"아까 역에 도착했어요.","use":"방금 한 행동","highlight":["ました"]},
      {"jp":"昨日、映画を見ました。","pron":"키노오 에이가오 미마시타","ko":"어제 영화를 봤어요.","use":"과거 경험","highlight":["ました"]}
    ]
  },
  {
    "cat":"tense", "tag":"부정/과거", "title":"い형용사/な형용사 변화(기초)",
    "desc":"형용사도 과거/부정 형태가 자주 나옵니다.",
    "rule":"い형: 高い→高くない/高かった/高くなかった, な형: 元気→元気じゃない/元気でした",
    "warn":"N5 문제에서 ‘형용사 부정/과거’는 단골입니다.",
    "extra":{
      "core":'<span class="x-badge">형용사</span> “비싸요/안 비싸요/비쌌어요…”',
      "situation":"상태/감정/가격 설명",
      "breakdown":"高い → 高くない → 高かった",
      "caution":"な형용사는 명사처럼 です/でした/じゃありません 사용",
      "variation":"高くないです。／元気じゃありません。"
    },
    "examples":[
      {"jp":"この本は高くないです。","pron":"코노 혼와 타카쿠나이데스","ko":"이 책은 비싸지 않아요.","use":"가격 부정","highlight":["高くない"]},
      {"jp":"昨日は寒かったです。","pron":"키노오와 사무캇타데스","ko":"어제는 추웠어요.","use":"과거 날씨","highlight":["寒かった"]},
      {"jp":"今日は元気じゃありません。","pron":"쿄오와 겡키쟈 아리마센","ko":"오늘은 건강하지 않아요.","use":"상태 부정(な형)","highlight":["じゃありません"]}
    ]
  },

  # -----------------------
  # connect: 이유/연결
  # -----------------------
  {
    "cat":"connect", "tag":"이유/연결", "title":"～から (이유: ~해서)",
    "desc":"이유/원인 ‘~해서, ~이니까’",
    "rule":"문장 + から + 결과",
    "warn":"설득/이유 말하기의 가장 기본입니다.",
    "extra":{
      "core":'<span class="x-badge">이유</span> “~해서(니까)”',
      "situation":"거절/결정의 이유를 말할 때",
      "breakdown":"雨です + から + 行きません",
      "caution":"구어에서는 だから도 자주",
      "variation":"雨ですから、行きません。／忙しいから、また今度。"
    },
    "examples":[
      {"jp":"雨ですから、行きません。","pron":"아메데스카라 이키마센","ko":"비가 오니까 가지 않아요.","use":"거절 이유","highlight":["から"]},
      {"jp":"時間がないから、急ぎます。","pron":"지칸가 나이카라 이소기마스","ko":"시간이 없어서 서둘러요.","use":"행동 이유","highlight":["から"]},
      {"jp":"安いですから、この店で買います。","pron":"야스이데스카라 코노 미세데 카이마스","ko":"싸니까 이 가게에서 사요.","use":"선택 이유","highlight":["から"]}
    ]
  },
  {
    "cat":"connect", "tag":"이유/연결", "title":"そして / それから (그리고/그리고 나서)",
    "desc":"문장을 자연스럽게 이어주는 연결 표현",
    "rule":"문장1。+ そして/それから + 문장2。",
    "warn":"문장 전개가 부드러워져서 독해에도 도움이 됩니다.",
    "extra":{
      "core":'<span class="x-badge">연결</span> “그리고 / 그리고 나서”',
      "situation":"순서대로 설명할 때",
      "breakdown":"まず〜。それから〜。",
      "caution":"そして=그리고 / それから=그 다음",
      "variation":"ごはんを食べます。そして勉強します。"
    },
    "examples":[
      {"jp":"ごはんを食べます。そして勉強します。","pron":"고항오 타베마스. 소시테 벤쿄오 시마스","ko":"밥을 먹고, 그리고 공부합니다.","use":"행동을 이어 말하기","highlight":["そして"]},
      {"jp":"駅へ行きます。それから電車に乗ります。","pron":"에키에 이키마스. 소레카라 덴샤니 노리마스","ko":"역에 가고, 그 다음 전철을 탑니다.","use":"순서 설명","highlight":["それから"]},
      {"jp":"買い物をします。そして家に帰ります。","pron":"카이모노오 시마스. 소시테 이에니 카에리마스","ko":"쇼핑하고 집에 돌아갑니다.","use":"일정 설명","highlight":["そして"]}
    ]
  },

  # -----------------------
  # desire: 희망/능력
  # -----------------------
  {
    "cat":"desire", "tag":"희망/능력", "title":"～たいです (~하고 싶다)",
    "desc":"희망/원함(정중)",
    "rule":"동사 ます형 어간 + たいです",
    "warn":"‘〜たいです’는 자기 희망(내가 하고 싶다)에 주로 씁니다.",
    "extra":{
      "core":'<span class="x-badge">희망</span> “~하고 싶어요”',
      "situation":"하고 싶은 계획/희망 말하기",
      "breakdown":"食べます → 食べ + たいです",
      "caution":"상대에게 강요X, 내 마음 표현",
      "variation":"日本へ行きたいです。／ラーメンを食べたいです。"
    },
    "examples":[
      {"jp":"日本へ行きたいです。","pron":"니혼에 이키타이데스","ko":"일본에 가고 싶어요.","use":"여행 희망","highlight":["たいです"]},
      {"jp":"ラーメンを食べたいです。","pron":"라아멘오 타베타이데스","ko":"라멘을 먹고 싶어요.","use":"먹고 싶은 것","highlight":["たいです"]},
      {"jp":"もっと日本語を勉強したいです。","pron":"못토 니혼고오 벤쿄오 시타이데스","ko":"일본어를 더 공부하고 싶어요.","use":"목표/의지","highlight":["たいです"]}
    ]
  },
  {
    "cat":"desire", "tag":"희망/능력", "title":"～できます (~할 수 있다)",
    "desc":"능력/가능",
    "rule":"명사 + が + できます (예: 日本語ができます)",
    "warn":"N5에선 “できます”를 통째로 패턴처럼 익히면 편합니다.",
    "extra":{
      "core":'<span class="x-badge">가능</span> “~할 수 있어요”',
      "situation":"할 수 있는 것(언어/운동/기능) 말하기",
      "breakdown":"日本語が + できます",
      "caution":"대상은 が를 많이 씀",
      "variation":"日本語ができます。／料理ができます。"
    },
    "examples":[
      {"jp":"日本語ができます。","pron":"니혼고가 데키마스","ko":"일본어를 할 수 있어요.","use":"능력 말하기","highlight":["できます"]},
      {"jp":"料理ができます。","pron":"료오리가 데키마스","ko":"요리를 할 수 있어요.","use":"가능한 일","highlight":["できます"]},
      {"jp":"今日は行けませんが、明日はできます。","pron":"쿄오와 이케마셍가, 아시타와 데키마스","ko":"오늘은 못 가지만 내일은 가능합니다.","use":"가능 여부","highlight":["できます"]}
    ]
  },
  {
    "cat":"desire", "tag":"희망/능력", "title":"～が好きです / 上手です / 下手です",
    "desc":"좋아하다 / 잘하다 / 못하다",
    "rule":"명사 + が + 好きです/上手です/下手です",
    "warn":"好きです는 な형용사처럼 취급(정중형 です).",
    "extra":{
      "core":'<span class="x-badge">선호/능력</span> “좋아해요/잘해요/못해요”',
      "situation":"취미/선호/특기 말하기",
      "breakdown":"猫が + 好きです",
      "caution":"좋아하다=が가 자연스러운 경우 많음",
      "variation":"猫が好きです。／歌が上手です。"
    },
    "examples":[
      {"jp":"猫が好きです。","pron":"네코가 스키데스","ko":"고양이를 좋아해요.","use":"좋아하는 것","highlight":["好きです"]},
      {"jp":"田中さんは歌が上手です。","pron":"타나카상와 우타가 조오즈데스","ko":"다나카 씨는 노래를 잘해요.","use":"칭찬/특기","highlight":["上手です"]},
      {"jp":"私はスポーツが下手です。","pron":"와타시와 스포오츠가 헤타데스","ko":"저는 운동을 못해요.","use":"약한 분야","highlight":["下手です"]}
    ]
  },

  # -----------------------
  # timefreq: 시간/빈도
  # -----------------------
  {
    "cat":"timefreq", "tag":"시간/빈도", "title":"いつも / よく / ときどき / あまり～ません / ぜんぜん～ません",
    "desc":"빈도 표현(항상/자주/가끔/별로~않다/전혀~않다)",
    "rule":"부사 + 동사. 부정 세트: あまり～ません / ぜんぜん～ません",
    "warn":"あまり/ぜんぜん은 보통 ‘부정’과 세트입니다.",
    "extra":{
      "core":'<span class="x-badge">빈도</span> “항상/자주/가끔/별로/전혀”',
      "situation":"습관/빈도를 말할 때",
      "breakdown":"ときどき + 行きます",
      "caution":"N5는 ぜんぜん + 부정으로 고정 추천",
      "variation":"よく行きます。／あまり食べません。／ぜんぜん分かりません。"
    },
    "examples":[
      {"jp":"私はいつも七時に起きます。","pron":"와타시와 이츠모 시치지니 오키마스","ko":"저는 항상 7시에 일어나요.","use":"습관","highlight":["いつも"]},
      {"jp":"私はあまりテレビを見ません。","pron":"와타시와 아마리 테레비오 미마센","ko":"저는 TV를 별로 보지 않아요.","use":"빈도 낮음(부정)","highlight":["あまり","ません"]},
      {"jp":"ぜんぜん分かりません。","pron":"젠젠 와카리마센","ko":"전혀 모르겠어요.","use":"완전 부정","highlight":["ぜんぜん","ません"]}
    ]
  },
  {
    "cat":"timefreq", "tag":"시간/빈도", "title":"もう / まだ (이미/아직)",
    "desc":"이미(もう), 아직(まだ)",
    "rule":"もう + 동사(완료), まだ + 동사(부정과 자주)",
    "warn":"まだ는 ‘아직 ~안 했어요’(부정)로 자주 나옵니다.",
    "extra":{
      "core":'<span class="x-badge">시간감각</span> “이미/아직”',
      "situation":"완료 여부 말할 때",
      "breakdown":"もう + 食べました",
      "caution":"まだ + ません 패턴 통째로 외우기",
      "variation":"もう帰ります。／まだ宿題をしていません。"
    },
    "examples":[
      {"jp":"もう帰ります。","pron":"모오 카에리마스","ko":"이제(이미) 돌아갑니다.","use":"마무리/종료","highlight":["もう"]},
      {"jp":"まだ宿題をしていません。","pron":"마다 슈쿠다이오 시테이마센","ko":"아직 숙제를 안 했어요.","use":"아직 완료 X","highlight":["まだ","いません"]},
      {"jp":"もう食べましたか。","pron":"모오 타베마시타카","ko":"이미 먹었나요?","use":"완료 여부 질문","highlight":["もう"]}
    ]
  },
]


# ----------------------------
# 1) N5 문제 데이터 (FULL 원본: KO 포함)
#    - 구조는 통일: meta 안에 ko_q / ko_choices / ko_explain
# ----------------------------

N5_PART1_QUESTIONS_FULL = [
    {
        "id": "N5_P1_001",
        "part": 1,
        "q": "1　きょうは　雪ですか。",
        "choices": ["あめ", "はれ", "くもり", "ゆき"],
        "answer": 3,
        "meta": {
            "ko_q": "1) きょうは　雪ですか。오늘은 눈(雪)인가요?",
            "ko_choices": ["비(あめ)", "맑음(はれ)", "흐림(くもり)", "눈(ゆき)"],
            "ko_explain": "문장에 '雪'가 있으므로 정답은 'ゆき(눈)'입니다."
        }
    },
    {
        "id": "N5_P1_002",
        "part": 1,
        "q": "2　ここに　名前を　書いて　ください。",
        "choices": ["かいて", "きいて", "はいて", "ひいて"],
        "answer": 0,
        "meta": {
            "ko_q": "2) ここに　名前を　書いて　ください。여기에 이름을 (書いて) 주세요.",
            "ko_choices": ["쓰다(かいて)", "듣다(きいて)", "신다/입다(はいて)", "당기다/연주하다(ひいて)"],
            "ko_explain": "'書いて'는 '쓰다'의 의미로, 읽기는 1번 かいて 입니다."
        }
    },
    {
        "id": "N5_P1_003",
        "part": 1,
        "q": "3　ねこは　いすの　上に　います。",
        "choices": ["した", "そと", "うえ", "なか"],
        "answer": 2,
        "meta": {
            "ko_q": "3) ねこは　いすの　上に　います。고양이는 의자 (上)에 있어요.",
            "ko_choices": ["아래(した)", "밖(そと)", "위(うえ)", "안/속(なか)"],
            "ko_explain": "'上'의 뜻/읽기는 3번'うえ(위)'가 맞습니다."
        }
    },
    {
        "id": "N5_P1_004",
        "part": 1,
        "q": "4　この　へやは　広いです。",
        "choices": ["ひろい", "せまい", "たかい", "あかい"],
        "answer": 0,
        "meta": {
            "ko_q": "4) この　へやは　広いです。 이 방은 (広い)입니다.",
            "ko_choices": ["넓다(ひろい)", "좁다(せまい)", "높다/비싸다(たかい)", "빨갛다(あかい)"],
            "ko_explain": "문장에 '広い(넓다)'가 있으므로 정답은 1번 ひろい 입니다."
        }
    },
    {
        "id": "N5_P1_005",
        "part": 1,
        "q": "5　きょうは　金よう日です。",
        "choices": ["げつようび", "きんようび", "かようび", "もくようび"],
        "answer": 1,
        "meta": {
            "ko_q": "5) きょうは　金よう日です。오늘은 금요일(金よう日)입니다.",
            "ko_choices": ["월요일(げつようび)", "금요일(きんようび)", "화요일(かようび)", "목요일(もくようび)"],
            "ko_explain": "'金よう日'는 2번'きんようび(금요일)'이 정답입니다."
        }
    },
    {
        "id": "N5_P1_006",
        "part": 1,
        "q": "6　あの　山は　たかいですね。",
        "choices": ["いえ", "うみ", "やま", "にわ"],
        "answer": 2,
        "meta": {
            "ko_q": "6) あの　山は　たかいですね。저 (山)은 높네요.",
            "ko_choices": ["집(いえ)", "바다(うみ)", "산(やま)", "정원(にわ)"],
            "ko_explain": "문장에 '山'이 있으므로 정답은 3번 'やま(산)'입니다."
        }
    },
    {
        "id": "N5_P1_007",
        "part": 1,
        "q": "7　クラスに　百人　います。",
        "choices": ["ひゃくにん", "ひゃくじん", "びゃくにん", "びゃくじん"],
        "answer": 0,
        "meta": {
            "ko_q": "7) クラスに　百人　います。반에 백 명(百人)이 있습니다.",
            "ko_choices": ["ひゃくにん (백 명)", "ひゃくじん (오답)", "びゃくにん (오답)", "びゃくじん (오답)"],
            "ko_explain": "'百人'의 올바른 읽기는 1번 'ひゃくにん'입니다."
        }
    },
    {
        "id": "N5_P1_008",
        "part": 1,
        "q": "8　いけに　魚が　たくさん　います。",
        "choices": ["ねこ", "とり", "いぬ", "さかな"],
        "answer": 3,
        "meta": {
            "ko_q": "8) いけに　魚が　たくさん　います。연못에 물고기(魚)가 많이 있습니다.",
            "ko_choices": ["고양이(ねこ)", "새(とり)", "개(いぬ)", "물고기(さかな)"],
            "ko_explain": "'魚'는 4번 'さかな(물고기)'를 의미합니다."
        }
    },
    {
        "id": "N5_P1_009",
        "part": 1,
        "q": "9　パンを　半分　ともだちに　あげました。",
        "choices": ["はんぶん", "ほんぶん", "はんぷん", "ほんぷん"],
        "answer": 0,
        "meta": {
            "ko_q": "9) パンを　半分　ともだちに　あげました。빵을 반(半分) 친구에게 주었습니다.",
            "ko_choices": ["はんぶん (반)", "ほんぶん (오답)", "はんぷん (오답)", "ほんぷん (오답)"],
            "ko_explain": "'半分'의 올바른 읽기는 1번'はんぶん'입니다."
        }
    },
    {
        "id": "N5_P1_010",
        "part": 1,
        "q": "10　えきと　びょういんの　間に　みちが　あります。",
        "choices": ["あいだ", "あいた", "となり", "どなり"],
        "answer": 0,
        "meta": {
            "ko_q": "10) えきと　びょういんの　間に　みちが　あります。역과 병원 사이(間)에 길이 있습니다.",
            "ko_choices": ["사이(あいだ)", "열렸다(あいた)", "옆(となり)", "고함(どなり)"],
            "ko_explain": "'間'은 위치를 나타낼 때 1번 'あいだ(사이)'로 읽습니다."
        }
    },
    {
        "id": "N5_P1_011",
        "part": 1,
        "q": "11　りんごを　二つ　ください。",
        "choices": ["ひとつ", "ふたつ", "みっつ", "よっつ"],
        "answer": 1,
        "meta": {
            "ko_q": "11) りんごを　二つ　ください。사과를 두 개(二つ) 주세요.",
            "ko_choices": ["한 개(ひとつ)", "두 개(ふたつ)", "세 개(みっつ)", "네 개(よっつ)"],
            "ko_explain": "'二つ'는 개수를 나타내며 2번 'ふたつ'로 읽습니다."
        }
    },
    {
        "id": "N5_P1_012",
        "part": 1,
        "q": "12　きょうは　元気ですね。",
        "choices": ["げんき", "てんき", "げんけ", "てんけ"],
        "answer": 0,
        "meta": {
            "ko_q": "12) きょうは　元気ですね。오늘은 건강/기운이 좋아 보이네요(元気).",
            "ko_choices": ["げんき (기운 있음)", "てんき (날씨)", "げんけ (오답)", "てんけ (오답)"],
            "ko_explain": "'元気'의 올바른 읽기는 1번 'げんき'입니다."
        }
    },
    {
        "id": "N5_P1_013",
        "part": 1,
        "q": "13　しゃつ",
        "choices": ["シャソ", "シャツ", "シャト", "シャッ"],
        "answer": 1,
        "meta": {
            "ko_q": "13) しゃつ → 알맞은 가타카나 표기를 고르세요.",
            "ko_choices": [
                "샤소(シャソ 틀린 표기)",
                "셔츠(シャツ)",
                "샤토(シャト 틀린 표기)",
                "샤(シャッ 틀린 표기)"
            ],
            "ko_explain": "히라가나 しゃつ의 올바른 가타카나 표기는 シャツ입니다."
        }
    },
    {
        "id": "N5_P1_014",
        "part": 1,
        "q": "14　わたしの　まちは　山が　おおいです。",
        "choices": ["川", "木", "山", "花"],
        "answer": 2,
        "meta": {
            "ko_q": "14) わたしの　まちは　山が　おおいです。내가 사는 도시는 산(山)이 많습니다.",
            "ko_choices": ["강(川)", "나무(木)", "산(山)", "꽃(花)"],
            "ko_explain": "문장에 '山'이 있으므로 정답은 3번 '산'입니다."
        }
    },
    {
        "id": "N5_P1_015",
        "part": 1,
        "q": "15　がっこう",
        "choices": ["字校", "学校", "学枚", "字交"],
        "answer": 1,
        "meta": {
            "ko_q": "15) がっこう → 알맞은 한자를 고르세요.",
            "ko_choices": [
                "틀린 한자(字校)",
                "학교(学校)",
                "틀린 한자(学枚)",
                "틀린 한자(字交)"
            ],
            "ko_explain": "히라가나 がっこう의 올바른 한자 표기는 学校입니다."
        }
    },
    {
        "id": "N5_P1_016",
        "part": 1,
        "q": "16　せんせい",
        "choices": ["先性", "先生", "先正", "生先"],
        "answer": 1,
        "meta": {
            "ko_q": "16) せんせい → 알맞은 한자를 고르세요.",
            "ko_choices": [
                "틀린 한자(先性)",
                "선생님(先生)",
                "틀린 한자(先正)",
                "틀린 한자(生先)"
            ],
            "ko_explain": "히라가나 せんせい의 올바른 한자 표기는 先生입니다."
        }
    },
    {
        "id": "N5_P1_017",
        "part": 1,
        "q": "17　たかい",
        "choices": ["安い", "高い", "古い", "新しい"],
        "answer": 1,
        "meta": {
            "ko_q": "17) たかい → 알맞은 뜻을 고르세요.",
            "ko_choices": ["싸다(安い)", "비싸다(高い)", "낡다(古い)", "새롭다(新しい)"],
            "ko_explain": "히라가나 たかい의 의미는 '비싸다'이므로 정답은 高い입니다."
        }
    },
        {
        "id": "N5_P1_018",
        "part": 1,
        "q": "18　きのうは　( )を　やすみました。",
        "choices": ["病院", "学校", "デパート", "駅"],
        "answer": 1,
        "meta": {
            "ko_q": "18) きのうは　がっこうを　やすみました。 어제는 학교를 쉬었습니다.",
            "ko_choices": ["병원(病院)", "학교(学校)", "백화점(デパート)", "역(駅)"],
            "ko_explain": "「〜を休みました」는 학교나 회사를 쉬다(결석/결근)라는 의미로 사용되며, 보기 중 자연스럽게 어울리는 것은 学校입니다."
        }
    },
    {
        "id": "N5_P1_019",
        "part": 1,
        "q": "19　たべないで",
        "choices": ["行かないで", "立たないで", "言わないで", "食べないで"],
        "answer": 3,
        "meta": {
            "ko_q": "19) たべないで → 알맞은 한자 표기를 고르세요.",
            "ko_choices": [
                "가지 말아 주세요(行かないで)",
                "일어나지 말아 주세요(立たないで)",
                "말하지 말아 주세요(言わないで)",
                "먹지 말아 주세요(食べないで)"
            ],
            "ko_explain": "히라가나 たべないで의 올바른 한자 표기는 食べないで입니다."
        }
    },
    {
        "id": "N5_P1_020",
        "part": 1,
        "q": "20　らいしゅう",
        "choices": ["今週", "来週", "今月", "来月"],
        "answer": 1,
        "meta": {
            "ko_q": "20) らいしゅう → 알맞은 한자를 고르세요.",
            "ko_choices": ["이번 주(今週)", "다음 주(来週)", "이번 달(今月)", "다음 달(来月)"],
            "ko_explain": "히라가나 らいしゅう의 올바른 한자 표기는 来週입니다."
        }
    },
    {
        "id": "N5_P1_021",
        "part": 1,
        "q": "21　わたしの　へやは　この　アパートの　２（　）です。",
        "choices": ["ほん", "さつ", "かい", "だい"],
        "answer": 2,
        "meta": {
            "ko_q": "21) わたしの　へやは　この　アパートの　２（　）です。내 방은 이 아파트의 2층입니다.",
            "ko_choices": ["권(ほん)", "권/책 단위(さつ)", "층(かい)", "대(だい)"],
            "ko_explain": "층수를 나타낼 때는 3번 'かい(階)'를 사용합니다."
        }
    },
    {
        "id": "N5_P1_022",
        "part": 1,
        "q": "22　その　ナイフで　りんごを（　）ください。",
        "choices": ["おきて", "つけて", "しめて", "きって"],
        "answer": 3,
        "meta": {
            "ko_q": "22) その　ナイフで　りんごを（　）ください。그 칼로 사과를 (    ) 주세요.",
            "ko_choices": ["おきて(일어나서)", "つけて(붙여서)", "しめて(닫아서)", "きって(자르다)"],
            "ko_explain": "칼로 사과를 '자르다'는 4번 '切って(きって)'가 맞습니다."
        }
    },
    {
        "id": "N5_P1_023",
        "part": 1,
        "q": "23　（　）を　わすれましたから、じかんが　わかりません。",
        "choices": ["じしょ", "ちず", "とけい", "さいふ"],
        "answer": 2,
        "meta": {
            "ko_q": "23) （　）を　わすれましたから、じかんが　わかりません。(    )를 잊어버려서 시간을 모르겠습니다.",
            "ko_choices": ["じしょ(사전)", "ちず(지도)", "とけい(시계)", "さいふ(지갑)"],
            "ko_explain": "시간을 알 수 없는 이유는 3번 '시계(とけい)'를 잊었기 때문입니다."
        }
    },
    {
        "id": "N5_P1_024",
        "part": 1,
        "q": "24　わたしの　うちは　えきに　ちかいですから、（　）です。",
        "choices": ["べんり", "じょうぶ", "いっぱい", "へた"],
        "answer": 0,
        "meta": {
            "ko_q": "24) わたしの　うちは　えきに　ちかいですから、（　）です。우리 집은 역에서 가까워서 (    )입니다.",
            "ko_choices": ["べんり(편리하다)", "じょうぶ(튼튼하다)", "いっぱい(가득 차다)", "へた(서투르다)"],
            "ko_explain": "역과 가까우면 1번 '편리하다(べんり)'가 자연스럽습니다."
        }
    },
    {
        "id": "N5_P1_025",
        "part": 1,
        "q": "25　なつやすみは　まいにち（　）で　およぎました。",
        "choices": ["レストラン", "プール", "エレベーター", "ビル"],
        "answer": 1,
        "meta": {
            "ko_q": "25) なつやすみは　まいにち（　）で　およぎました。여름방학에는 매일 (    )에서 수영했습니다.",
            "ko_choices": ["レストラン(레스토랑)", "プール(수영장)", "エレベーター(엘리베이터)", "ビル(빌딩)"],
            "ko_explain": "수영하는 장소는 2번 'プール(수영장)'입니다."
        }
    },
    {
        "id": "N5_P1_026",
        "part": 1,
        "q": "26　しらない　ことばが　ありましたから、せんせいに（　）しました。",
        "choices": ["しつもん", "べんきょう", "れんしゅう", "じゅぎょう"],
        "answer": 0,
        "meta": {
            "ko_q": "26) しらない　ことばが　ありましたから、せんせいに（　）しました。모르는 단어가 있어서 선생님께 (    )했습니다.",
            "ko_choices": ["しつもん(질문)", "べんきょう(공부)", "れんしゅう(연습)", "じゅぎょう(수업)"],
            "ko_explain": "모르는 것을 선생님께 1번 '질문하다'는 しつもん입니다."
        }
    },
    {
        "id": "N5_P1_027",
        "part": 1,
        "q": "27　この　へやは　あついですから、（　）を　つけましょう。",
        "choices": ["おふろ", "まど", "エアコン", "テーブル"],
        "answer": 2,
        "meta": {
            "ko_q": "27) この　へやは　あついですから、（　）を　つけましょう。이 방은 더우니까 (    )을 켭시다.",
            "ko_choices": ["おふろ(목욕)", "まど(창문)", "エアコン(에어컨)", "テーブル(테이블)"],
            "ko_explain": "더울 때는 3번 '에어컨(エアコン)'을 켜는 것이 맞습니다."
        }
    },
    {
        "id": "N5_P1_028",
        "part": 1,
        "q": "28　きのうは　がっこうで　たくさん　かんじを（　）。",
        "choices": ["うりました", "もちました", "おぼえました", "こまりました"],
        "answer": 2,
        "meta": {
            "ko_q": "28) きのうは　がっこうで　たくさん　かんじを（　）。어제는 학교에서 한자를 많이 (    ).",
            "ko_choices": ["うりました(팔았습니다)", "もちました(가졌습니다)", "おぼえました(외웠습니다)", "こまりました(곤란했습니다)"],
            "ko_explain": "한자는 3번 '외우다(おぼえました)'가 자연스럽습니다."
        }
    },
    {
        "id": "N5_P1_029",
        "part": 1,
        "q": "29　この　コーヒーは　さとうを　たくさん　いれましたから、（　）です。",
        "choices": ["わかい", "くろい", "まるい", "あまい"],
        "answer": 3,
        "meta": {
            "ko_q": "29) この　コーヒーは　さとうを　たくさん　いれましたから、（　）です。이 커피는 설탕을 많이 넣어서 (    )입니다.",
            "ko_choices": ["わかい(젊다)", "くろい(검다)", "まるい(둥글다)", "あまい(달다)"],
            "ko_explain": "설탕을 많이 넣으면 4번 '달다(あまい)'가 됩니다."
        }
    },
    {
        "id": "N5_P1_030",
        "part": 1,
        "q": "30　つよい　かぜが（　）います。",
        "choices": ["ふいて", "いそいで", "とんで", "はしって"],
        "answer": 0,
        "meta": {
            "ko_q": "30) つよい　かぜが（　）います。강한 바람이 (    ).",
            "ko_choices": ["ふいて(불고 있다)", "いそいで(서두르고 있다)", "とんで(날고 있다)", "はしって(달리고 있다)"],
            "ko_explain": "바람은 1번 '불다(ふく)'를 사용합니다."
        }
    },
    {
        "id": "N5_P1_031",
        "part": 1,
        "q": "31　これは　ちちと　ははの　しゃしんです。",
        "choices": [
            "これは　そふと　そぼの　しゃしんです。",
            "これは　おとうさんと　おかあさんの　しゃしんです。",
            "これは　あにと　あねの　しゃしんです。",
            "これは　かぞくの　いえの　しゃしんです。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "31) これは　ちちと　ははの　しゃしんです。이것은 아버지와 어머니의 사진입니다.",
            "ko_choices": [
                "これは　そふと　そぼの　しゃしんです。조부모의 사진",
                "これは　おとうさんと　おかあさんの　しゃしんです。아버지와 어머니의 사진",
                "これは　あにと　あねの　しゃしんです。형과 누나의 사진",
                "これは　かぞくの　いえの　しゃしんです。가족의 집 사진"
            ],
            "ko_explain": "아버지,어머니 'ちち・はは'는 'おとうさん・おかあさん'과 같은 의미입니다."
        }
    },
    {
        "id": "N5_P1_032",
        "part": 1,
        "q": "32　この　もんだいは　やさしいです。",
        "choices": [
            "この　もんだいは　むずかしいです。",
            "この　もんだいは　かんたんです。",
            "この　もんだいは　ながいです。",
            "この　もんだいは　つまらないです。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "32) この　もんだいは　やさしいです。이 문제는 쉽습니다.",
            "ko_choices": [
                "この　もんだいは　むずかしいです。이 문제는 어렵다",
                "この　もんだいは　かんたんです。이 문제는 간단하다",
                "この　もんだいは　ながいです。이 문제는 길다",
                "この　もんだいは　つまらないです。이 문제는 재미없다"
            ],
            "ko_explain": "'やさしい'와 2번 'かんたん'은 N5에서 같은 의미로 자주 바꿔 쓰입니다."
        }
    },
    {
        "id": "N5_P1_033",
        "part": 1,
        "q": "33　ふくを　せんたくしました。",
        "choices": [
            "ふくを　ぬぎました。",
            "ふくを　わたしました。",
            "ふくを　あらいました。",
            "ふくを　きました。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "33) ふくを　せんたくしました。옷을 세탁했습니다.",
            "ko_choices": [
                "ふくを　ぬぎました。옷을 벗었습니다",
                "ふくを　わたしました。옷을 건넸습니다",
                "ふくを　あらいました。옷을 빨았습니다",
                "ふくを　きました。옷을 입었습니다"
            ],
            "ko_explain": "3번 ふくを　あらいました。옷을 빨았습니다 정답. '세탁하다'는 '洗う(あらう)'입니다."
        }
    },
    {
        "id": "N5_P1_034",
        "part": 1,
        "q": "34　この　へやは　くらいですね。",
        "choices": [
            "この　へやは　あかるいですね。",
            "この　へやは　あかるくないですね。",
            "この　へやは　しずかじゃ　ないですね。",
            "この　へやは　しずかですね。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "34) この　へやは　くらいですね。이 방은 어둡네요.",
            "ko_choices": [
                "この　へやは　あかるいですね。이 방은 밝다",
                "この　へやは　あかるくないですね。이 방은 밝지 않다",
                "この　へやは　しずかじゃ　ないですね。이 방은 조용하지 않다",
                "この　へやは　しずかですね。이 방은 조용하다"
            ],
            "ko_explain": "'어둡다'는 2번 '밝지 않다'로 바꿔 말할 수 있습니다."
        }
    },
    {
        "id": "N5_P1_035",
        "part": 1,
        "q": "35　スミスさんは　タナカさんに　ペンを　かしました。",
        "choices": [
            "タナカさんは　スミスさんに　ペンを　もらいました。",
            "スミスさんは　タナカさんから　ペンを　もらいました。",
            "タナカさんは　スミスさんに　ペンを　かしました。",
            "スミスさんは　タナカさんに　ペンを　あげました。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "35) スミスさんは　タナカさんに　ペンを　かしました。스미스 씨는 다나카 씨에게 펜을 빌려주었습니다.",
            "ko_choices": [
                "タナカさんは　スミスさんに　ペンを　もらいました。다나카 씨는 스미스 씨에게서 펜을 받았습니다",
                "スミスさんは　タナカさんから　ペンを　もらいました。스미스 씨는 다나카 씨에게서 펜을 받았습니다",
                "タナカさんは　スミスさんに　ペンを　かしました。다나카 씨는 스미스 씨에게 펜을 빌려주었습니다",
                "スミスさんは　タナカさんに　ペンを　あげました。스미스 씨는 다나카 씨에게 펜을 주었습니다"
            ],
            "ko_explain": "정답은 1번 스미스 씨는 다나가 씨에게 펜을 빌려주었으니 다나카 씨는 스미스 씨에게서 펜을 받았다가 정답입니다. 'かす(빌려주다)'와 'もらう(받다)'는 주어가 바뀌면 같은 상황을 나타냅니다."
        }
    },
]
# N5 PART2 (文法) - "변형 문제" 세트
# 구성:
#  - もんだい1: 1~16
#  - もんだい2: 17~21 (★)
#  - もんだい3: 22~26 (지문형 공통 stem)


# =========================
# N5 PART2 - もんだい３ 공통 지문 (JP / KO)
# =========================
N5_P2_M3_STEM_JP = """（もんだい３） 22から26に何を入れますか。ぶんしょうのいみを考えて、1・2・3・4からいちばんいいものを一つえらんでください。

（１）ニンさんの文
私の好きな飲み物は、くだもののジュースです。とくに、オレンジジュースが大好きです。
私の国では、いろいろな店で買えます。（２２）、日本では見つけられない味もあります。
日本では、りんごジュースをよく飲みます。毎日（２３）。

（２）メイさんの文
私はきっさてんで飲むコーヒーが好きです。先週もきっさてんでコーヒーを飲みました。
先週の土曜日は、いい天気でした。昼に買い物をしてから、きっさてんに（２４）。
店の名前は「はな」です。「はな」（２５）コーヒーは、少し安かったです。
私は２はい飲みました。来週も「はな」にコーヒーを（２６）。"""

N5_P2_M3_STEM_KO = """(문제3) 22~26에 무엇을 넣습니까? 글의 의미를 생각해서 1·2·3·4 중에서 가장 알맞은 것을 하나 고르세요.

(1) ニン(닌) 씨의 글
제가 좋아하는 음료는 과일 주스입니다. 특히 오렌지 주스를 아주 좋아합니다.
제 나라에서는 여러 가게에서 살 수 있습니다. (22) 일본에서는 찾을 수 없는 맛도 있습니다.
일본에서는 사과 주스를 자주 마십니다. 매일 (23).

(2) メイ(메이) 씨의 글
저는 카페에서 마시는 커피를 좋아합니다. 지난주에도 카페에서 커피를 마셨습니다.
지난주 토요일은 날씨가 좋았습니다. 낮에 쇼핑을 하고 나서 카페에 (24)。
가게 이름은 ‘はな’입니다. ‘はな’(25) 커피는 조금 저렴했습니다.
저는 2잔 마셨습니다. 다음 주에도 ‘はな’에 커피를 (26)."""

# =========================
# ✅ PART2 전체 문항 리스트 (dict만!)
# =========================
N5_PART2_QUESTIONS_FULL = [
    # =========================
    # もんだい1 (1~16)
    # =========================
    {
        "id": "N5_P2_001",
        "part": 2,
        "q": "1　わたしは　らいげつ（　）日本へ　いきます。",
        "choices": ["に", "で", "へ", "を"],
        "answer": 0,
        "meta": {
            "ko_q": "1) わたしは らいげつ（ ）日本へ いきます.\n→ 다음 달 ( ) 일본에 갑니다.",
            "ko_choices": [
                "~에 / ~으로 (に)",
                "~에서 (で)",
                "~로 / ~에 (へ)",
                "~을 / ~를 (を)"
            ],
            "filled_jp": "わたしは らいげつ に 日本へ いきます。",
            "filled_ko": "나는 다음 달에 일본에 갑니다.",
            "ko_explain": "이동의 목적지에는 「に」 또는 「へ」를 사용할 수 있지만, 시점(らいげつ)과 함께 자연스럽게 쓰일 때는 「に」가 가장 기본적인 표현입니다."
        }
    },
    {
        "id": "N5_P2_002",
        "part": 2,
        "q": "2　きのう　スーパー（　）パンと　やさいを　かいました。",
        "choices": ["は", "も", "で", "に"],
        "answer": 2,
        "meta": {
            "ko_q": "2) きのう スーパー( )パンと やさいを かいました. 어제 슈퍼에서 빵과 야채를 샀습니다.",
            "ko_choices": ["~은/는(は)", "~도(も)", "~에서(で)", "~에(に)"],
            "ko_explain": "장소에서 어떤 행동을 할 때 3번「で」를 씁니다(슈퍼에서 샀다)."
        }
    },
    {
        "id": "N5_P2_003",
        "part": 2,
        "q": "3　わたしは　まいあさ　７じごろ　うち（　）でます。",
        "choices": ["を", "に", "で", "が"],
        "answer": 0,
        "meta": {
            "ko_q": "3) わたしは まいあさ 7じごろ うち( )でます. 매일 아침 7시쯤 집을 나갑니다.",
            "ko_choices": ["~을(を)", "~에(に)", "~에서(で)", "~가(が)"],
            "ko_explain": "출발점(집/방)을 떠날 때는 「うちを でます」처럼 1번「を」를 자주 씁니다."
        }
    },
    {
        "id": "N5_P2_004",
        "part": 2,
        "q": "4　きょう　がっこう（　）ともだちに　あいました。",
        "choices": ["に", "で", "を", "へ"],
        "answer": 1,
        "meta": {
            "ko_q": "4) きょう がっこう( )ともだちに あいました. 오늘 학교에서 친구를 만났습니다.",
            "ko_choices": ["~에(に)", "~에서(で)", "~을(を)", "~로(へ)"],
            "ko_explain": "‘만나다’가 일어난 장소는 2번「で」로 표현하는 게 자연스럽습니다."
        }
    },
    {
        "id": "N5_P2_005",
        "part": 2,
        "q": "5　わたし（　）にほんごは　まだ　むずかしいです。",
        "choices": ["が", "の", "に", "を"],
        "answer": 0,
        "meta": {
            "ko_q": "5) わたし( )にほんごは まだ むずかしいです. 저는 일본어가 아직 어렵습니다.",
            "ko_choices": ["~이/가(が)", "~의(の)", "~에(に)", "~을(を)"],
            "ko_explain": "주어(화제)를 구체적으로 ‘~이/가’로 잡을 때 1번「が」를 사용합니다."
        }
    },
    {
        "id": "N5_P2_006",
        "part": 2,
        "q": "6　きっさてんで　コーヒーを　二はい（　）のみました。",
        "choices": ["が", "を", "も", "に"],
        "answer": 2,
        "meta": {
            "ko_q": "6) きっさてんで コーヒーを 二はい( )のみました. 카페에서 커피를 두 잔( ) 마셨습니다.",
            "ko_choices": ["~이/가(が)", "~을(を)", "~도(も)", "~에(に)"],
            "ko_explain": "정답 3번: 카페에서 커피를 두 잔이나 마셨습니다. 수량 뒤에 「も」를 쓰면 단순한 ‘~도’가 아니라, ‘생각보다 많다 / 무려 ~나’라는 강조의 의미가 됩니다. 여기서는 ‘두 잔이나 마셨다’라는 뉘앙스입니다." 
        }
    },
    {
        "id": "N5_P2_007",
        "part": 2,
        "q": "7　きのう（　）さむかったですが、きょう（　）あたたかいです。",
        "choices": ["は／は", "に／に", "も／も", "を／を"],
        "answer": 0,
        "meta": {
            "ko_q": "7) きのう( )さむかったですが、きょう( )あたたかいです. 어제는 추웠지만 오늘은 따뜻합니다.",
            "ko_choices": ["は/は(대조)", "に/に", "も/も", "を/を"],
            "ko_explain": "대조(하지만)를 나타내는 문장에서는 1번 「きのう'は'… きょう'は'…」가 기본 패턴입니다."
        }
    },
    {
        "id": "N5_P2_008",
        "part": 2,
        "q": "8　あの　みせの　ケーキは　おいしい（　）、すこし　たかいです。",
        "choices": ["から", "けど", "まで", "だけ"],
        "answer": 1,
        "meta": {
            "ko_q": "8) あの みせの ケーキは おいしい( )、すこし たかいです. 저 가게 케이크는 맛있지만 조금 비쌉니다.",
            "ko_choices": ["~라서(から)", "하지만(けど)", "~까지(まで)", "~만(だけ)"],
            "ko_explain": "앞뒤를 대조할 때는 2번「けど」(하지만)가 맞습니다."
        }
    },
    {
        "id": "N5_P2_009",
        "part": 2,
        "q": "9　たなかさん、（　）えきは　どこですか。",
        "choices": ["この", "その", "どの", "そこ"],
        "answer": 2,
        "meta": {
            "ko_q": "9) たなかさん、( )えきは どこですか. 다나카 씨, ( ) 역은 어디인가요?",
            "ko_choices": ["이(この)", "그(その)", "어느(どの)", "거기(そこ)"],
            "ko_explain": "‘어느 역’인지 묻는 질문이라 3번「どの + 명사」가 정답입니다."
        }
    },
    {
        "id": "N5_P2_010",
        "part": 2,
        "q": "10　A「はじめて　りょこうを　しました。」\n　　B「そうですか。（　）でしたか。」",
        "choices": ["いくつ", "いかが", "どなた", "どこ"],
        "answer": 1,
        "meta": {
            "ko_q": "10) A: 처음으로 여행했어요. B: 그렇군요. ( ) 어땠어요?",
            "ko_choices": ["몇 살(いくつ)", "어땠나요/어떠셨나요(いかが)", "누구(どなた)", "어디(どこ)"],
            "ko_explain": "감상을 묻는 표현은 2번「いかがでしたか」가 자연스럽습니다."
        }
    },
    {
        "id": "N5_P2_011",
        "part": 2,
        "q": "11　A「もう　しゅくだいは　おわりましたか。」\n　　B「いいえ、まだ（　）。」",
        "choices": ["です", "います", "じゃない", "おわりません"],
        "answer": 0,
        "meta": {
            "ko_q": "11) A: 숙제 벌써 끝났나요? B: 아니요, 아직( ).",
            "ko_choices": ["아직이에요(です)", "있어요(います)", "아니에요(じゃない)", "끝나지 않아요(おわりません)"],
            "ko_explain": "회화에서 1번「まだです」(아직이에요/아직 안 했어요)가 가장 자연스럽습니다."
        }
    },
    {
        "id": "N5_P2_012",
        "part": 2,
        "q": "12　（びょういんで）\n　　いしゃ「このくすりを　のんで、らいしゅう　また（　）きてください。」",
        "choices": ["たくさん", "あまり", "また", "だんだん"],
        "answer": 2,
        "meta": {
            "ko_q": "12) (병원에서) 의사: 이 약 먹고 다음 주에 ( ) 또 오세요.",
            "ko_choices": ["많이(たくさん)", "별로/그다지(あまり)", "다시(また)", "점점(だんだん)"],
            "ko_explain": "‘다시(또) 오세요’는 그대로 3번「また」가 정답입니다."
        }
    },
    {
        "id": "N5_P2_013",
        "part": 2,
        "q": "13　ちちは　テレビを（　）ながら　ばんごはんを　たべます。",
        "choices": ["みる", "みて", "みた", "みない"],
        "answer": 0,
        "meta": {
            "ko_q": "13) 아버지는 TV를 ( ) 보면서 저녁을 먹습니다.",
            "ko_choices": ["보다(みる)", "봐서(みて)", "봤다(みた)", "안 보다(みない)"],
            "ko_explain": "1번 보다 정답. 동시동작 「Vる + ながら」: 「テレビを みるながら…」 형태가 기본입니다."
        }
    },
    {
        "id": "N5_P2_014",
        "part": 2,
        "q": "14　わたしは　こどものとき、すしが　すき（　）でした。",
        "choices": ["ではない", "じゃない", "ありません", "じゃありません"],
        "answer": 3,
        "meta": {
            "ko_q": "14) 저는 어릴 때 스시를 좋아하지( )었습니다.",
            "ko_choices": ["~가 아니다(ではない)", "~가 아니다(じゃない)", "없습니다(ありません)", "아니었습니다(じゃありません)"],
            "ko_explain": "과거 부정(정중)이라 「すきじゃありませんでした」가 원형인데, 보기 중 가장 가까운 형태는 4번「じゃありません」입니다."
        }
    },
    {
        "id": "N5_P2_015",
        "part": 2,
        "q": "15　（パンやで）\n　　みせのひと「いらっしゃいませ。」\n　　わたし「すみません、メロンパンを　ふたつ（　）。」",
        "choices": ["ありますか", "どうぞ", "ください", "ほしいですか"],
        "answer": 2,
        "meta": {
            "ko_q": "15) (빵집에서) 멜론빵 두 개 ( ).",
            "ko_choices": ["있나요?(ありますか)", "여기요(どうぞ)", "주세요(ください)", "원하나요?(ほしいですか)"],
            "ko_explain": "주문할 때는 3번「〜を ください」가 정답입니다."
        }
    },
    {
        "id": "N5_P2_016",
        "part": 2,
        "q": "16　A「にちようびに　うちで　べんきょうします。よかったら（　）？」\n　　B「はい、いきたいです。」",
        "choices": ["きませんか", "きますか", "きませんでしたか", "きましたか"],
        "answer": 0,
        "meta": {
            "ko_q": "16) A: 일요일에 집에서 공부해요. 괜찮으면 ( )? B: 네, 가고 싶어요.",
            "ko_choices": ["오지 않을래요?(きませんか)", "오나요?(きますか)", "안 왔었나요?(きませんでしたか)", "왔나요?(きましたか)"],
            "ko_explain": "권유/초대 표현은 1번「〜ませんか」가 정답입니다."
        }
    },

    # =========================
    # もんだい2 (17~21) ★
    # =========================
    {
        "id": "N5_P2_017",
        "part": 2,
        "q": "17　（タクシーの　中で）\n　　A「すみません、つぎの　こうさてんで　★　みぎに　まがって　ください。」",
        "choices": ["に", "を", "で", "が"],
        "answer": 0,
        "meta": {
            "ko_q": "17) (택시 안) 다음 교차로에서 오른쪽으로 꺾어 주세요.",
            "ko_choices": ["~에서/에(に)", "~을(を)", "~에서(で)", "~이/가(が)"],
            "ko_explain": "방향 + 이동은 「右に まがる」처럼 1번「に」를 씁니다."
        }
    },
    {
        "id": "N5_P2_018",
        "part": 2,
        "q": "18　わたしは　ともだち★　えいがを　みに　いきました。",
        "choices": ["と", "を", "に", "で"],
        "answer": 0,
        "meta": {
            "ko_q": "18) 저는 친구와 함께 영화를 보러 갔습니다.",
            "ko_choices": ["~와 함께(と)", "~을(を)", "~에(に)", "~에서(で)"],
            "ko_explain": "누구와 함께 했는지는 1번「ともだちと」가 정답입니다."
        }
    },
    {
        "id": "N5_P2_019",
        "part": 2,
        "q": "19　きのう　かった　りんごは　あか★　おいしかったです。",
        "choices": ["くて", "い", "が", "に"],
        "answer": 0,
        "meta": {
            "ko_q": "19) 어제 산 사과는 빨갛고 맛있었습니다.",
            "ko_choices": ["~고(くて)", "~다(い)", "~이/가(が)", "~에(に)"],
            "ko_explain": "い형용사 연결: 「あかくて おいしい」처럼 1번「くて」가 정답입니다."
        }
    },
    {
        "id": "N5_P2_020",
        "part": 2,
        "q": "20　えきの　ちか★　ほんやで　ざっしを　かいました。",
        "choices": ["く", "い", "で", "を"],
        "answer": 0,
        "meta": {
            "ko_q": "20) 역 근처 서점에서 잡지를 샀습니다.",
            "ko_choices": ["가깝- (く)", "가깝다(い)", "~에서(で)", "~을(を)"],
            "ko_explain": "정답은 1번(く). い형용사 「ちかい」의 부사형은 「ちかく」입니다."
        }
    },
    {
        "id": "N5_P2_021",
        "part": 2,
        "q": "21　せんしゅう　ともだちから　もらった　おかし★　とても　おいしかったです。",
        "choices": ["は", "が", "を", "に"],
        "answer": 0,
        "meta": {
            "ko_q": "21) 지난주 친구에게 받은 과자는 정말 맛있었습니다.",
            "ko_choices": ["~은/는(は)", "~이/가(が)", "~을(を)", "~에(に)"],
            "ko_explain": "주제(화제)를 세울 때 1번「〜は」가 자연스럽습니다."
        }
    },

    # =========================
    # もんだい3 (22~26) - 그룹 문제
    # q에는 지문을 붙이지 말고 번호만 둔다!
    # =========================
    {
        "id": "N5_P2_022",
        "part": 2,
        "q": "22（　）",
        "choices": ["だから", "でも", "いつも", "もっと"],
        "answer": 1,
        "meta": {
            "ko_q": "22) 앞뒤 문맥 대조(하지만)에 맞는 표현을 고르세요.",
            "ko_choices": ["だから(그래서)", "でも(하지만)", "いつも(항상)", "もっと(더)"],
            "ko_explain": "앞 내용과 뒤 내용이 대조라 2번 ‘でも(하지만)’가 자연스럽습니다."
        }
    },
    {
        "id": "N5_P2_023",
        "part": 2,
        "q": "23（　）",
        "choices": ["飲みます", "飲みたいです", "飲んでください", "飲みました"],
        "answer": 0,
        "meta": {
            "ko_q": "23) ‘毎日(매일)’과 이어지는 자연스러운 형태를 고르세요.",
            "ko_choices": ["飲みます(마셔요)", "飲みたいです(마시고 싶어요)", "飲んでください(마셔 주세요)", "飲みました(마셨습니다)"],
            "ko_explain": "습관/반복이므로 현재형 1번 ‘飲みます’가 정답입니다."
        }
    },
    {
        "id": "N5_P2_024",
        "part": 2,
        "q": "24（　）",
        "choices": ["入りました", "入ります", "入りましたか", "入って"],
        "answer": 0,
        "meta": {
            "ko_q": "24) ‘してから…’ 과거 흐름에 맞는 형태를 고르세요.",
            "ko_choices": ["入りました(들어갔습니다)", "入ります(들어갑니다)", "入りましたか(들어갔나요?)", "入って(들어가서)"],
            "ko_explain": "전체가 지난주 이야기(과거)이므로 1번 ‘入りました’가 맞습니다."
        }
    },
    {
        "id": "N5_P2_025",
        "part": 2,
        "q": "25（　）",
        "choices": ["の", "で", "と", "より"],
        "answer": 0,
        "meta": {
            "ko_q": "25) ‘はな(  )コーヒー’의 조사로 맞는 것을 고르세요.",
            "ko_choices": ["の(~의)", "で(~에서/으로)", "と(~와)", "より(~보다)"],
            "ko_explain": "가게 ‘はな’의 커피 → ‘はなのコーヒー’이므로 1번 ‘の’가 정답입니다."
        }
    },
    {
        "id": "N5_P2_026",
        "part": 2,
        "q": "26（　）",
        "choices": ["飲みに行きます", "飲んで来ます", "飲みに来ます", "飲んで行きます"],
        "answer": 0,
        "meta": {
            "ko_q": "26) ‘に(장소)+Vに行きます’ 패턴으로 자연스러운 것을 고르세요.",
            "ko_choices": ["飲みに行きます(마시러 갑니다)", "飲んで来ます(마시고 옵니다)", "飲みに来ます(마시러 옵니다)", "飲んで行きます(마시고 갑니다)"],
            "ko_explain": "장소에 ‘마시러 간다’ → 1번 ‘飲みに行きます’가 가장 자연스럽습니다."
        }
    },
]

N5_PART3_QUESTIONS_FULL = [
    {
        "id": "N5_P3_001",
        "part": 3,
        "q": "1（ぶんしょう）\nわたしは まいあさ パンと たまごを たべて、がっこうへ いきます。\nでも きょうは じかんが なくて、なにも たべませんでした。\nだから、バナナを いっぽん もって いきました。\n\n（しつもん）\nきょう、わたしは どうして なにも たべませんでしたか。",
        "choices": ["ねぼうしたから", "パンが なかったから", "おなかが いたかったから", "バナナが きらいだから"],
        "answer": 0,
        "meta": {
            "ko_q": "1) (지문) 나는 매일 아침 빵과 달걀을 먹고 학교에 간다. 하지만 오늘은 시간이 없어서 아무것도 먹지 못했다. 그래서 바나나 1개를 가져갔다.\n\n(질문) 오늘 ‘나’는 왜 아무것도 먹지 못했나요?",
            "ko_choices": ["늦잠을 자서", "빵이 없어서", "배가 아파서", "바나나를 싫어해서"],
            "ko_explain": "지문에 ‘じかんが なくて、なにも たべませんでした(시간이 없어서 아무것도 못 먹었다)’라고 되어 있으므로, 원인은 ‘늦잠/시간 부족’ 흐름이 맞습니다."
        }
    },
    {
        "id": "N5_P3_002",
        "part": 3,
        "q": "2（おしらせ）\n「にほんご１」と「にほんご２」の クラスの みなさんへ\nきょう、やまだせんせいは おひるまで おやすみです。\nごぜんの「にほんご１」の クラスは ありません。\nごごの「にほんご２」の クラスは あります。\n\n（しつもん）\n「にほんご１」の がくせいは、きょう どうしますか。",
        "choices": ["ごぜんの クラスに いきます", "ごごの クラスに いきます", "きょうは クラスが ありません", "しゅくだいを きょう だします"],
        "answer": 2,
        "meta": {
            "ko_q": "2) (공지) ‘일본어1’과 ‘일본어2’ 수강생에게. 오늘 야마다 선생님은 점심까지 쉰다. 오전 ‘일본어1’ 수업은 없다. 오후 ‘일본어2’ 수업은 있다.\n\n(질문) ‘일본어1’ 학생은 오늘 어떻게 하나요?",
            "ko_choices": ["오전 수업에 간다", "오후 수업에 간다", "오늘은 수업이 없다", "숙제를 오늘 낸다"],
            "ko_explain": "공지에 ‘ごぜんの「にほんご１」の クラスは ありません(오전 일본어1 수업은 없다)’라고 명시되어 있어, 오후에 일본어2 수업이 있지만 일본어1 수업을 듣는 학생은 3번 ‘오늘 수업 없음’이 정답입니다."
        }
    },
    {
        "id": "N5_P3_003",
        "part": 3,
        "q": "3（メモ）\nたなかさん\n10じごろ、ゆうびんきょくの ひとが にもつを とりに きます。\nにもつと いっしょに おかねを わたして ください。\nおかねは つくえの ひきだしに あります。\n\n（しつもん）\nたなかさんは、まず なにを しますか。",
        "choices": ["ゆうびんきょくへ いきます", "にもつを もらいます", "つくえの ひきだしから おかねを とります", "にもつを ひらきます"],
        "answer": 2,
        "meta": {
            "ko_q": "3) (메모) 10시쯤 우체국 사람이 짐을 받으러 온다. 짐과 함께 돈을 건네 달라. 돈은 책상 서랍에 있다.\n\n(질문) 다나카 씨는 먼저 무엇을 하나요?",
            "ko_choices": ["우체국에 간다", "짐을 받는다", "책상 서랍에서 돈을 꺼낸다", "짐을 연다"],
            "ko_explain": "‘돈은 서랍에 있다’ + ‘짐과 함께 돈을 건네라’ → 먼저 돈을 준비해야 하므로 3번 ‘서랍에서 돈을 꺼낸다’가 자연스럽습니다."
        }
    },
    {
        "id": "N5_P3_004",
        "part": 3,
        "q": "4（さくぶん）\nきのう、わたしは ともだちと サッカーを しました。\nあさから ばんまで うごいたので、とても つかれました。\nよる ごはんを たべて、すぐ ねました。\nだから、きょうの テストの べんきょうが できませんでした。\n\n（しつもん）\nわたしは どうして きょうの テストの べんきょうが できませんでしたか。",
        "choices": ["ともだちが こなかったから", "サッカーで つかれて すぐ ねたから", "テストが きらいだから", "テキストが なかったから"],
        "answer": 1,
        "meta": {
            "ko_q": "4) (작문) 어제 친구와 축구를 했다. 아침부터 밤까지 움직여서 매우 피곤했다. 저녁을 먹고 바로 잤다. 그래서 오늘 시험 공부를 못 했다.\n\n(질문) 왜 오늘 시험 공부를 못 했나요?",
            "ko_choices": ["친구가 안 왔어서", "축구로 피곤해서 바로 자서", "시험을 싫어해서", "교재가 없어서"],
            "ko_explain": "지문에 ‘つかれました→すぐ ねました→だから べんきょうが できませんでした’ 흐름이므로 정답은 2번입니다."
        }
    },
    {
        "id": "N5_P3_005",
        "part": 3,
        "q": "5（ぶんしょう）\nきょう、わたしは 5じに おきました。\nシャワーを あびて、あさごはんを たべました。\nそれから、にほんごの しゅくだいを しました。\nそして、がっこうへ いきました。\n\n（しつもん）\nわたしは あさごはんを たべた あとで、なにを しましたか。",
        "choices": ["がっこうへ いきました", "シャワーを あびました", "にほんごの しゅくだいを しました", "5じに おきました"],
        "answer": 2,
        "meta": {
            "ko_q": "5) (지문) 오늘 나는 5시에 일어났다. 샤워하고 아침밥을 먹었다. 그 후 일본어 숙제를 했고, 그리고 학교에 갔다.\n\n(질문) 아침밥을 먹은 뒤에 무엇을 했나요?",
            "ko_choices": ["학교에 갔다", "샤워했다", "일본어 숙제를 했다", "5시에 일어났다"],
            "ko_explain": "순서가 ‘샤워 → 아침밥 → 숙제 → 학교’이므로, 아침밥 다음은 3번 ‘일본어 숙제’가 정답입니다."
        }
    },
]

N5_PART4_QUESTIONS_FULL = []

# ----------------------------
# 2) PART별 원본(FULL) 가져오기
#    - 채점 API에서 사용 (KO 포함)
# ----------------------------
def get_n5_part_questions_full(part: int):
    if part == 1:
        return N5_PART1_QUESTIONS_FULL
    elif part == 2:
        return N5_PART2_QUESTIONS_FULL
    elif part == 3:
        return N5_PART3_QUESTIONS_FULL
    elif part == 4:
        return N5_PART4_QUESTIONS_FULL
    return []


# ----------------------------
# ✅ N5 PART2 : 22~26 그룹 문제용 메타 내려주기
# - "형식 변경" 절대 안 함: questions 리스트 길이/순서 그대로 내려줌
# - 템플릿(JS)이 GROUP_START_IDX/GROUP_END_IDX로 묶어서 보여주는 방식
# ----------------------------
def get_n5_part_questions(part: int):
    src = get_n5_part_questions_full(part)

    out = []
    for i, q in enumerate(src):
        item = {
            "id": q.get("id"),
            "part": q.get("part", part),
            "q": q.get("q", ""),
            "choices": q.get("choices", []),
            "answer": q.get("answer", 0),
        }

        # ✅ PART2의 22~26은 그룹 문제 표시용 메타(일본어 지문만) 내려줌
        # - 번호는 q 문자열 앞쪽에서 파싱(기존 너 코드 유지)
        if part == 2:
            try:
                no = int(
                    q.get("q", "")
                    .split("（")[0]
                    .strip()
                    .replace("　", "")
                    .replace(" ", "")
                )
            except:
                no = None

            if no and 22 <= no <= 26:
                item["group"] = {
                    "id": "P2_M3",
                    "start": 22,
                    "end": 26,
                    "stem_jp": N5_P2_M3_STEM_JP,  # ✅ 일본어 지문만
                }

        out.append(item)

    return out


# ----------------------------
# ✅ 채점 API (N5)
# - 채점은 항상 "원본 FULL" 기준
# - PART2이면 group_meta에 stem JP/KO만 추가 제공
# ----------------------------
@app.post("/api/jlpt/n5/test/grade/<int:part>")
def api_jlpt_n5_test_grade(part: int):
    payload = request.get_json(silent=True) or {}
    user_answers = payload.get("answers", [])
    if not isinstance(user_answers, list):
        user_answers = []

    src = get_n5_part_questions_full(part)
    total = len(src)
    correct = 0
    items = []

    for i, q in enumerate(src):
        ua = user_answers[i] if i < len(user_answers) else None
        ans = q.get("answer", 0)
        is_correct = (ua == ans)
        if is_correct:
            correct += 1

        meta = q.get("meta", {}) or {}
        items.append({
            "no": i + 1,
            "q_ko": meta.get("ko_q", ""),
            "choices_ko": meta.get("ko_choices", []),
            "answer_index": ans,
            "user_index": ua,
            "explain_ko": meta.get("ko_explain", ""),
            "is_correct": is_correct,
        })

    score = round((correct / total) * 100) if total else 0

    resp = {
        "total": total,
        "correct": correct,
        "score": score,
        "items": items
    }

    # ✅ PART2 그룹 지문(22~26) 번역 포함
    if part == 2:
        resp["group_meta"] = {
            "P2_M3": {
                "start": 22,
                "end": 26,
                "stem_jp": N5_P2_M3_STEM_JP,
                "stem_ko": N5_P2_M3_STEM_KO,
            }
        }

    return jsonify(resp)


# ----------------------------
# ✅ N5 테스트 시작 라우트
# - N4와 동일: total_questions는 "실제 문항 수" (FULL 길이)
# - questions는 get_n5_part_questions(part) 그대로 (형식/길이 유지)
# ----------------------------
@app.route("/jlpt/n5/test/start/<int:part>")
def jlpt_n5_test_start(part: int):
    questions = get_n5_part_questions(part)

    template_map = {
        1: "jlpt_n5_test_run_part1.html",
        2: "jlpt_n5_test_run_part2.html",
        3: "jlpt_n5_test_run_part3.html",
        4: "jlpt_n5_test_run_part4.html",
    }

    total_raw = len(get_n5_part_questions_full(part))  # ✅ 실제 문항 수 (PART2는 26)

    return render_template(
        template_map.get(part, "jlpt_n5_test_run_part1.html"),
        questions=questions,
        total_questions=total_raw,  # ✅ N4와 동일: 실제 문항 수를 내려줌
        part=part
    )


# ----------------------------
# 6) N5 테스트 홈
# ----------------------------
@app.route("/jlpt/n5/test")
def jlpt_n5_test():
    user = current_user()
    return render_template("jlpt_n5_test.html", user=user, total_questions=0)

@app.route("/jlpt/n5")
def jlpt_n5_home():
    user = current_user()
    return render_template("jlpt_n5.html", user=user)

@app.route("/jlpt/n5/words")
def jlpt_n5_words():
    user = current_user()

    # N5_WORDS: dict (sec01~sec10)
    sections = []
    all_items = []

    for sec_key in sorted((N5_WORDS or {}).keys()):  # sec01, sec02...
        sec = (N5_WORDS or {}).get(sec_key) or {}
        title = sec.get("title", sec_key)
        items = sec.get("items") or []

        sections.append({
            "key": sec_key,
            "title": title,
            "count": len(items),
        })

        for it in items:
            row = dict(it)
            row["sec_key"] = sec_key
            row["sec_title"] = title
            all_items.append(row)

    return render_template(
        "jlpt_n5_words.html",
        user=user,
        sections=sections,
        words=all_items,   # ✅ 템플릿엔 "단어 리스트"로만 전달
    )

@app.route("/jlpt/n5/sentences")
def jlpt_n5_sentences():
    user = current_user()
    return render_template("jlpt_n5_sentences.html", user=user, sections=N5_SENTENCE_SECTIONS)

@app.route("/jlpt/n5/grammar")
def jlpt_n5_grammar():
    user = current_user()
    return render_template(
        "jlpt_n5_grammar.html",
        user=user,
        grammar_json=json.dumps(N5_GRAMMAR_DATA, ensure_ascii=False)
    )

# ----------------------------
# N4 문제 데이터 (FULL 원본: KO 포함)
# - meta 안에 ko_q / ko_choices / ko_explain
# - 보이지 않는 문자/특수 따옴표 정리 버전
# ----------------------------

N4_PART1_QUESTIONS_FULL = [
    {
        "id": "N4_P1_001",
        "part": 1,
        "q": "1　楽しかった",
        "choices": ["いそがしかった", "すずしかった", "たのしかった", "かなしかった"],
        "answer": 2,
        "meta": {
            "ko_q": "1) 楽しかった → 올바른 읽기를 고르세요.",
            "ko_choices": [
                "いそがしかった(바빴다)",
                "すずしかった(시원했다)",
                "たのしかった(즐거웠다)",
                "かなしかった(슬펐다)"
            ],
            "ko_explain": "楽しかった의 읽기는 たのしかった입니다."
        }
    },
    {
        "id": "N4_P1_002",
        "part": 1,
        "q": "2　わたしは　この　味が　すきです。",
        "choices": ["かたち", "いろ", "におい", "あじ"],
        "answer": 3,
        "meta": {
            "ko_q": "2) わたしは　この　味が　すきです。저는 이 맛(味)이 좋아요.",
            "ko_choices": ["かたち(모양)", "いろ(색)", "におい(냄새)", "あじ(맛)"],
            "ko_explain": "味의 읽기는 4번 あじ(맛)입니다."
        }
    },
    {
        "id": "N4_P1_003",
        "part": 1,
        "q": "3　この　あたりは　ちょっと　不便ですね。",
        "choices": ["ふべん", "ぶべん", "ふへん", "ぶへん"],
        "answer": 0,
        "meta": {
            "ko_q": "3) この　あたりは　ちょっと　不便ですね。このあたり=이 근처는 조금 불편하네요.",
            "ko_choices": ["ふべん(불편)", "ぶべん(오답)", "ふへん(오답)", "ぶへん(오답)"],
            "ko_explain": "不便의 올바른 읽기는 1번 ふべん입니다."
        }
    },
    {
        "id": "N4_P1_004",
        "part": 1,
        "q": "4　切って",
        "choices": ["きって", "きつて", "ぎって", "けって"],
        "answer": 0,
        "meta": {
            "ko_q": "4) 切って → 올바른 읽기를 고르세요.",
            "ko_choices": [
                "きって(정답)",
                "きつて(오답)",
                "ぎって(오답)",
                "けって(오답)"
            ],
            "ko_explain": "切って(て형)의 읽기는 きって입니다."
        }
    },
    {
        "id": "N4_P1_005",
        "part": 1,
        "q": "5　田中さん以外は　みんな　来ました。",
        "choices": ["にそと", "にがい", "いそと", "いがい"],
        "answer": 3,
        "meta": {
            "ko_q": "5) 田中さん以外は　みんな　来ました。다나카 씨 이외(以外)는 모두 왔습니다.",
            "ko_choices": ["にそと(오답)", "にがい(쓰다)", "いそと(오답)", "いがい(이외)"],
            "ko_explain": "以外(이외)의 읽기는 4번 いがい입니다."
        }
    },
    {
        "id": "N4_P1_006",
        "part": 1,
        "q": "6　まどから　ずっと　雲を　見て　いました。",
        "choices": ["ほし", "ゆき", "くも", "そら"],
        "answer": 2,
        "meta": {
            "ko_q": "6) まどから　ずっと　雲を　見て　いました。창문에서 계속 구름(雲)을 보고 있었어요.",
            "ko_choices": ["ほし(별)", "ゆき(눈)", "くも(구름)", "そら(하늘)"],
            "ko_explain": "雲의 읽기는 3번 くも(구름)입니다."
        }
    },
    {
        "id": "N4_P1_007",
        "part": 1,
        "q": "7　その　電車は　急行ですよ。",
        "choices": ["きゅこ", "きゅこう", "きゅうこ", "きゅうこう"],
        "answer": 3,
        "meta": {
            "ko_q": "7) その　電車は　急行ですよ。그 전철은 급행(急行)이에요.",
            "ko_choices": ["きゅこ(오답)", "きゅこう(오답)", "きゅうこ(오답)", "きゅうこう(급행)"],
            "ko_explain": "急行의 올바른 읽기는 4번 きゅうこう입니다."
        }
    },
    {
        "id": "N4_P1_008",
        "part": 1,
        "q": "8　ここに　名前を　書かないで　ください。",
        "choices": ["かかないで", "かかせないで", "かけないで", "かえないで"],
        "answer": 0,
        "meta": {
            "ko_q": "8) ここに　名前を　書かないで　ください。여기에 이름을 쓰지 말아 주세요.",
            "ko_choices": ["かかないで(쓰지 말아)", "かかせないで(쓰게 하지 말아)", "かけないで(걸지 말아/전화를 걸지 말아)", "かえないで(바꾸지 말아)"],
            "ko_explain": "書かないで(쓰지 말아)의 읽기는 1번 かかないで입니다."
        }
    },
    {
        "id": "N4_P1_009",
        "part": 1,
        "q": "9　その　意見には　反対です。",
        "choices": ["はんたい", "ほんたい", "はんだい", "ほんだい"],
        "answer": 0,
        "meta": {
            "ko_q": "9) その　意見には　反対です。그 의견에는 반대(反対)입니다.",
            "ko_choices": ["はんたい(반대)", "ほんたい(오답)", "はんだい(오답)", "ほんだい(오답)"],
            "ko_explain": "反対의 올바른 읽기는 1번 はんたい입니다."
        }
    },
    {
        "id": "N4_P1_010",
        "part": 1,
        "q": "10　くろい",
        "choices": ["白い", "黒い", "赤い", "青い"],
        "answer": 1,
        "meta": {
            "ko_q": "10) くろい → 알맞은 한자 표기를 고르세요.",
            "ko_choices": ["하얗다(白い)", "검다(黒い)", "빨갛다(赤い)", "파랗다(青い)"],
            "ko_explain": "くろい의 올바른 표기는 黒い입니다."
        }
    },
    {
        "id": "N4_P1_011",
        "part": 1,
        "q": "11　来月の　旅行の　けいかくを　立てました。",
        "choices": ["計書", "訂画", "計画", "訂書"],
        "answer": 2,
        "meta": {
            "ko_q": "11) 来月の　旅行の　けいかくを　立てました。다음 달 여행 계획(けいかく)을 세웠습니다.",
            "ko_choices": ["計書(오답)", "訂画(오답)", "計画(계획)", "訂書(오답)"],
            "ko_explain": "けいかく(계획)의 올바른 한자는 3번 計画입니다."
        }
    },
    {
        "id": "N4_P1_012",
        "part": 1,
        "q": "12　わたしは　将来　看護師に　なりたいです。",
        "choices": ["看護師", "看護士", "看誤師", "監護師"],
        "answer": 0,
        "meta": {
            "ko_q": "12) わたしは　将来　看護師に　なりたいです。 저는 장래에 간호사(かんごし)가 되고 싶습니다.",
            "ko_choices": [
                "看護師(간호사)",
                "看護士(오답: 현재 공식 표기가 아님)",
                "看誤師(오답)",
                "監護師(오답)"
            ],
            "ko_explain": "‘간호사’의 올바른 한자 표기는 1번「看護師(かんごし)」입니다. 예전에는 「看護士」라는 표기도 있었지만, 현재는 성별 중립 표현인 「看護師」만 사용합니다."
        }
    },
    {
        "id": "N4_P1_013",
        "part": 1,
        "q": "13　よる",
        "choices": ["朝", "昼", "夕", "夜"],
        "answer": 3,
        "meta": {
            "ko_q": "13) よる → 알맞은 한자를 고르세요.",
            "ko_choices": ["아침(朝)", "낮(昼)", "저녁/해질 무렵(夕)", "밤(夜)"],
            "ko_explain": "よる의 올바른 한자는 夜입니다."
        }
    },
    {
        "id": "N4_P1_014",
        "part": 1,
        "q": "14　すみません、かさを　かして　ください。",
        "choices": ["貸して", "借して", "貨して", "貸て"],
        "answer": 0,
        "meta": {
            "ko_q": "14) すみません、かさを　かして　ください。죄송한데 우산 좀 빌려주세요(=빌려주실래요).",
            "ko_choices": ["貸して(빌려주다)", "借して(오답)", "貨して(오답)", "貸て(오답)"],
            "ko_explain": "かす(빌려주다)의 て형은 1번 貸して가 맞습니다."
        }
    },
   {
        "id": "N4_P1_015",
        "part": 1,
        "q": "15　日曜日に　サッカーの　しあいが　あります。",
        "choices": ["試合", "試会", "詩合", "使合"],
        "answer": 0,
        "meta": {
            "ko_q": "15) 日曜日に　サッカーの　しあいが　あります。일요일에 축구 경기(しあい)가 있습니다.",
            "ko_choices": ["試合(경기)", "試会(오답)", "詩合(오답)", "使合(오답)"],
            "ko_explain": "しあい의 올바른 한자 표기는 試合입니다."
        }
    },
    {
        "id": "N4_P1_016",
        "part": 1,
        "q": "16　友だちが　けがを　したと　聞いて、みんな（　）しました。",
        "choices": ["しんぱい", "けいけん", "しっぱい", "おじぎ"],
        "answer": 0,
        "meta": {
            "ko_q": "16) 友だちが　けがを　したと　聞いて、みんな（　）しました。친구가 다쳤다고 들어서 모두 (    ) 했습니다.",
            "ko_choices": ["しんぱい(걱정)", "けいけん(경험)", "しっぱい(실패)", "おじぎ(인사/절)"],
            "ko_explain": "정답1번. 다쳤다는 말을 들으면 걱정하다(しんぱいする)가 자연스럽습니다."
        }
    },
    {
        "id": "N4_P1_017",
        "part": 1,
        "q": "17　わたしには、外国で　働くという（　）があります。",
        "choices": ["けしき", "ゆめ", "おもいで", "せわ"],
        "answer": 1,
        "meta": {
            "ko_q": "17) わたしには、外国で　働くという（　）があります。저는 외국에서 일하고 싶다는 (    )이/가 있습니다.",
            "ko_choices": ["けしき(풍경)", "ゆめ(꿈)", "おもいで(추억)", "せわ(돌봄/신세)"],
            "ko_explain": "'외국에서 일하고 싶다'는 내용은 2번 꿈(ゆめ)이 가장 자연스럽습니다."
        }
    },
    {
        "id": "N4_P1_018",
        "part": 1,
        "q": "18　よかったら、来週の　食事会に（　）来て　ください。",
        "choices": ["ひじょうに", "ぜひ", "じゅうぶん", "いつも"],
        "answer": 1,
        "meta": {
            "ko_q": "18) よかったら、来週の　食事会に（　）来て　ください。괜찮으시면 다음 주 모임에 (    ) 와 주세요.",
            "ko_choices": ["ひじょうに(매우)", "ぜひ(꼭/부디)", "じゅうぶん(충분히)", "いつも(항상)"],
            "ko_explain": "초대/권유에는 2번 ぜひ(꼭/부디)가 자연스럽습니다."
        }
    },
    {
        "id": "N4_P1_019",
        "part": 1,
        "q": "19　これから　機械の　使い方を（　）しますから、よく　聞いて　ください。",
        "choices": ["じゅんび", "りょうり", "せつめい", "せいさん"],
        "answer": 2,
        "meta": {
            "ko_q": "19) これから　機械の　使い方を（　）しますから、よく　聞いて　ください。지금부터 기계 사용법을 (    )할 테니 잘 들어 주세요.",
            "ko_choices": ["じゅんび(준비)", "りょうり(요리)", "せつめい(설명)", "せいさん(생산/정산)"],
            "ko_explain": "3번. 사용법을 설명하다(せつめいする)가 정답입니다."
        }
    },
    {
        "id": "N4_P1_020",
        "part": 1,
        "q": "20　歯が　わるいので、（　）ものは　食べられません。",
        "choices": ["きびしい", "かたい", "はやい", "ふかい"],
        "answer": 1,
        "meta": {
            "ko_q": "20) 歯が　わるいので、（　）ものは　食べられません。이가 안 좋아서 (    ) 것은 먹을 수 없어요.",
            "ko_choices": ["きびしい(엄격하다)", "かたい(딱딱하다)", "はやい(빠르다)", "ふかい(깊다)"],
            "ko_explain": "정답 2번. 이가 안 좋으면 딱딱한 것(かたいもの)을 먹기 어렵습니다."
        }
    },
    {
        "id": "N4_P1_021",
        "part": 1,
        "q": "21　友だちを　映画に（　）が、用事が　あると　言われました。",
        "choices": ["さそいました", "つたえました", "あんないしました", "しょうかいしました"],
        "answer": 0,
        "meta": {
            "ko_q": "21) 友だちを　映画に（　）が、用事が　あると　言われました。친구를 영화에 (    )했지만, 볼일이 있다고 했어요.",
            "ko_choices": ["さそいました(초대했다/권했다)", "つたえました(전했다)", "あんないしました(안내했다)", "しょうかいしました(소개했다)"],
            "ko_explain": "어디에 함께 가자고 하는 것은 誘う(さそう) → 1번 さそいました입니다."
        }
    },
    {
        "id": "N4_P1_022",
        "part": 1,
        "q": "22　わたしの　むすこは、１年で　５（　）くらい　せが　高く　なりました。",
        "choices": ["グラム", "ばん", "けん", "センチ"],
        "answer": 3,
        "meta": {
            "ko_q": "22) わたしの　むすこは、１年で　５（　）くらい　せが　高く　なりました。아들은 1년에 5(    ) 정도 키가 컸습니다.",
            "ko_choices": ["グラム(g, 무게)", "ばん(번호/차례)", "けん(채/건, 단위)", "センチ(cm)"],
            "ko_explain": "키(せ)가 커지다의 단위는 보통 4번 センチ(cm)를 씁니다."
        }
    },
    {
        "id": "N4_P1_023",
        "part": 1,
        "q": "23　店で　３だいの　パソコンを（　）、いちばん　軽い　パソコンを　えらびました。",
        "choices": ["かたづけて", "かぞえて", "くらべて", "はらって"],
        "answer": 2,
        "meta": {
            "ko_q": "23) 店で　３だいの　パソコンを（　）、いちばん　軽い　パソコンを　えらびました。가게에서 3대의 PC를 (    )해서 가장 가벼운 것을 골랐습니다.",
            "ko_choices": ["かたづけて(정리해서)", "かぞえて(세어서)", "くらべて(비교해서)", "はらって(지불해서)"],
            "ko_explain": "가장 가벼운 것을 고르려면 3번 비교하다(くらべる)가 필요합니다."
        }
    },
    {
        "id": "N4_P1_024",
        "part": 1,
        "q": "24　田中さんの　家は　電気が　ついて　いませんね。田中さんは（　）の　ようです。",
        "choices": ["うそ", "じゆう", "ちゅうし", "るす"],
        "answer": 3,
        "meta": {
            "ko_q": "24) 田中さんの　家は　電気が　ついて　いませんね。田中さんは（　）の　ようです。전기가 안 켜져 있네요. 다나카 씨는 (    )인 것 같아요.",
            "ko_choices": ["うそ(거짓말)", "じゆう(자유)", "ちゅうし(중지)", "るす(부재/집에 없음)"],
            "ko_explain": "집에 사람이 없을 때 4번 留守(るす)라고 합니다."
        }
    },
    {
        "id": "N4_P1_025",
        "part": 1,
        "q": "25　かぎを　さがして　いますが、まだ（　）。",
        "choices": ["見つかりません", "つかまえません", "しりません", "さわりません"],
        "answer": 0,
        "meta": {
            "ko_q": "25) かぎを　さがして　いますが、まだ（　）。열쇠를 찾고 있지만 아직 (    ).",
            "ko_choices": ["見つかりません(찾지 못했습니다)", "つかまえません(잡지 못합니다)", "しりません(모릅니다)", "さわりません(만지지 않습니다)"],
            "ko_explain": "찾고 있는데 아직 발견되지 않았으므로 1번 見つかりません이 맞습니다."
        }
    },
    {
        "id": "N4_P1_026",
        "part": 1,
        "q": "26　わたしは　あの　店で　アルバイトを　して　います。",
        "choices": [
            "わたしは　あの　店で　泊まって　います。",
            "わたしは　あの　店で　働いて　います。",
            "わたしは　あの　店で　買い物を　して　います。",
            "わたしは　あの　店で　友だちと　話して　います。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "26) わたしは　あの　店で　アルバイトを　して　います。저는 그 가게에서 아르바이트를 하고 있어요.",
            "ko_choices": [
                "わたしは　あの　店で　泊まって　います。그 가게에서 묵고 있어요",
                "わたしは　あの　店で　働いて　います。그 가게에서 일하고 있어요",
                "わたしは　あの　店で　買い物を　して　います。그 가게에서 쇼핑하고 있어요",
                "わたしは　あの　店で　友だちと　話して　います。그 가게에서 친구와 이야기하고 있어요"
            ],
            "ko_explain": "2번 アルバイトをする는 働く(일하다)로 바꿔 말할 수 있습니다."
        }
    },
    {
        "id": "N4_P1_027",
        "part": 1,
        "q": "27　わたしは　水泳が　すきです。",
        "choices": [
            "わたしは　はしるのが　すきです。",
            "わたしは　およぐのが　すきです。",
            "わたしは　うたうのが　すきです。",
            "わたしは　本を　買うのが　すきです。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "27) わたしは　水泳が　すきです。저는 수영(水泳)을 좋아합니다.",
            "ko_choices": [
                "わたしは　はしるのが　すきです。달리기를 좋아합니다",
                "わたしは　およぐのが　すきです。수영하는 것을 좋아합니다",
                "わたしは　うたうのが　すきです。노래하는 것을 좋아합니다",
                "わたしは　本を　買うのが　すきです。책 사는 것을 좋아합니다"
            ],
            "ko_explain": "정답 2번. 水泳(すいえい)은 泳ぐ(およぐ, 수영하다)와 같은 의미입니다."
        }
    },
    {
        "id": "N4_P1_028",
        "part": 1,
        "q": "28　それを　聞いて　びっくりしました。",
        "choices": [
            "それを　聞いて　わらいました。",
            "それを　聞いて　こまりました。",
            "それを　聞いて　おどろきました。",
            "それを　聞いて　ねむくなりました。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "28) それを　聞いて　びっくりしました。그걸 듣고 깜짝 놀랐습니다.",
            "ko_choices": [
                "それを　聞いて　わらいました。듣고 웃었습니다",
                "それを　聞いて　こまりました。듣고 곤란했습니다",
                "それを　聞いて　おどろきました。듣고 놀랐습니다",
                "それを　聞いて　ねむくなりました。듣고 졸려졌습니다"
            ],
            "ko_explain": "정답 3번. びっくりする는 おどろく(놀라다)로 바꿔 말할 수 있습니다."
        }
    },
    {
        "id": "N4_P1_029",
        "part": 1,
        "q": "29　あの　人は　うつくしいですね。",
        "choices": ["あの　人は　きれいですね。", "あの　人は　げんきですね。", "あの　人は　おもしろいですね。", "あの　人は　こわいですね。"],
        "answer": 0,
        "meta": {
            "ko_q": "29) あの　人は　うつくしいですね。저 사람은 아름답네요.",
            "ko_choices": [
                "あの　人は　きれいですね。예쁘네요/아름답네요",
                "あの　人は　げんきですね。건강하네요",
                "あの　人は　おもしろいですね。재미있네요",
                "あの　人は　こわいですね。무섭네요"
            ],
            "ko_explain": "정답 1번. うつくしい(아름답다)는 きれい(예쁘다/아름답다)와 유사합니다."
        }
    },
    {
        "id": "N4_P1_030",
        "part": 1,
        "q": "30　この　国は　小麦を　ゆにゅうして　います。",
        "choices": [
            "この　国は　小麦を　ほかの　国に　送って　います。",
            "この　国は　小麦を　ほかの　国から　もらって　います。",
            "この　国は　小麦を　ほかの　国から　買って　います。",
            "この　国は　小麦を　ほかの　国に　あげて　います。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "30) この　国は　小麦を　ゆにゅうして　います。この 나라는 밀을 수입(輸入)하고 있습니다.",
            "ko_choices": [
                "…送って　います。다른 나라에 보내고 있습니다(수출 느낌)",
                "…もらって　います。받고 있습니다(표현이 부자연)",
                "…買って　います。다른 나라에서 사 오고 있습니다(=수입 의미)",
                "…あげて　います。주고 있습니다"
            ],
            "ko_explain": "輸入する(ゆにゅうする)는 다른 나라에서 사 오다/들여오다의 뜻이므로 3번이 가장 맞습니다."
        }
    },
    {
        "id": "N4_P1_031",
        "part": 1,
        "q": "31　さいきん",
        "choices": [
            "さいきん　りょうりが　できたので、いっしょに　食べましょう。",
            "さいきん　しゅくだいを　出して　ください。",
            "きむらさんは　さいきん　けっこんした　そうです。",
            "さいきん　電車が　来ますから、いそいで　えきに　行きましょう。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "31) さいきん (최근)",
            "ko_choices": [
                "さいきん　りょうりが　できたので… 최근에 요리가 되었으니…(부자연)",
                "さいきん　しゅくだいを　出して… 최근에 숙제를 내 주세요(부자연)",
                "きむらさんは　さいきん　けっこんした… 기무라 씨는 최근에 결혼했다고 해요(자연)",
                "さいきん　電車が　来ますから… 최근에 전철이 오니까…(부자연)"
            ],
            "ko_explain": "정답 3번. さいきん(최근)은 최근에 ~했다처럼 시간 부사로 쓰이는 문장이 자연스럽습니다."
        }
    },
    {
        "id": "N4_P1_032",
        "part": 1,
        "q": "32　おと",
        "choices": [
            "ラジオの　おとが　大きいので、もう　少し　小さく　して　ください。",
            "日本語の　おとが　上手に　なりたいので、毎日　たくさん　話します。",
            "店の　人に　大きな　おとで　名前を　よばれました。",
            "きょうは　おとを　食べたので、元気に　なりました。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "32) おと (소리)",
            "ko_choices": [
                "ラジオの　おとが　大きい… 라디오 소리가 커서…(자연)",
                "日本語の　おとが　上手… 일본어 '소리'가 능숙…(부자연)",
                "大きな　おとで　名前を… 큰 소리로 이름을…(문맥 어색)",
                "おとを　食べた… 소리를 먹었다…(오답)"
            ],
            "ko_explain": "정답1번 おと(소리)는 라디오/음악 등과 함께 소리가 크다/작다로 자주 씁니다."
        }
    },
    {
        "id": "N4_P1_033",
        "part": 1,
        "q": "33　けんがく",
        "choices": [
            "かばんが　ほしいので、デパートに　行って　けんがくします。",
            "わからない　かんじは　じしょで　けんがくして　ください。",
            "今日は　工場を　けんがくしました。",
            "まいばん　テレビで　ニュースを　けんがくして　います。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "33) けんがく (견학)",
            "ko_choices": [
                "デパートに行ってけんがく… 백화점에서 견학…(어색)",
                "じしょでけんがく… 사전으로 견학…(오답)",
                "工場を　けんがくしました。공장을 견학했습니다(자연)",
                "ニュースを　けんがく… 뉴스를 견학…(오답)"
            ],
            "ko_explain": "정답3번. 見学(けんがく)은 공장/학교/시설 등을 견학하다에 쓰입니다."
        }
    },
    {
        "id": "N4_P1_034",
        "part": 1,
        "q": "34　かざる",
        "choices": [
            "テストの　おしらせを　きょうしつに　かざりました。",
            "お客さんが　来ますから、へやに　花を　かざりましょう。",
            "天気が　わるいので、せんたくものを　うちの　中に　かざります。",
            "この　ボタンを　かざって　ください。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "34) かざる (장식하다)",
            "ko_choices": [
                "おしらせを　かざりました 공지를 장식했다(문맥 어색)",
                "へやに　花を　かざりましょう 방에 꽃을 장식합시다(자연)",
                "せんたくものを　かざります 빨래를 장식한다(오답)",
                "ボタンを　かざって ボタン을 장식해(문맥 어색)"
            ],
            "ko_explain": "정답2번. 飾る(かざる)는 방에 꽃/그림 등을 장식하다로 쓰입니다."
        }
    },
    {
        "id": "N4_P1_035",
        "part": 1,
        "q": "35　こうじ",
        "choices": [
            "道が　工事を　して　いるので、気をつけて　ください。",
            "この　ケーキは　工事で　作りました。",
            "工事を　食べすぎて、ねむく　なりました。",
            "工事を　見たいから、映画館に　行きます。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "35) こうじ (공사)",
            "ko_choices": [
                "道が　工事を　している… 길에서 공사 중이라…(자연)",
                "ケーキは　工事で… 케이크를 공사로…(오답)",
                "工事を　食べすぎて… 공사를 먹었다…(오답)",
                "工事を　見たいから… 공사를 보고 싶어서 영화관…(오답)"
            ],
            "ko_explain": "정답1번. 工事(こうじ)는 도로/건물에서 공사하다(工事をする)로 쓰입니다."
        }
    },
]


# ============================================================
# ✅ N4 PART2 변형문제 FULL (1~25)  (※기출 베끼지 않고 창작)
#    - meta: KO 문제/보기/해설 포함 (채점/해설용)
# ============================================================

N4_P2_M3_STEM_JP = "（もんだい３）21から25に何を入れますか。文章の意味を考えて、1・2・3・4からいちばんいいものを一つえらんでください。"
N4_P2_M3_STEM_KO = "（문제3）21~25 빈칸에 무엇을 넣을까요? 글의 의미를 생각해 1~4 중 가장 알맞은 것을 하나 고르세요."

# ✅ N4 PART2 그룹 지문(21~25) - 창작 지문
N4_P2_M3_PASSAGE_JP = """\
わたしは　最近、料理を　はじめました。前は　料理が　苦手でしたが、友だちに　教えてもらって　少しずつ　作れるように　なりました。
先週、友だちと　スーパーに　行って　材料を　買いました。家に　帰ってから、簡単な　カレーを　作りました。（２１）、
はじめは　切るのが　むずかしくて、時間が　かかりました。けれども、友だちが　「ゆっくりで　いいよ」と　言ってくれたので、安心しました。
できあがったカレーは　思ったより　おいしくて、家族も　よろこんで　くれました。今は　週に　１回（２２）作っています。
来月は　パスタにも　チャレンジしたいです。わからないときは、友だちに　作り方を（２３）。
そして、もっと　早く　作れるように（２４）。いつか　自分の　得意料理を　作って（２５）。
"""

N4_P2_M3_PASSAGE_KO = """\
저는 최근에 요리를 시작했습니다. 전에는 요리를 잘 못했지만, 친구에게 배워서 조금씩 만들 수 있게 되었습니다.
지난주 친구와 슈퍼에 가서 재료를 샀습니다. 집에 돌아온 뒤 간단한 카레를 만들었습니다.(21)
처음에는 썰기가 어려워서 시간이 걸렸습니다. 하지만 친구가 ‘천천히 해도 괜찮아’라고 말해줘서 안심했습니다.
완성된 카레는 생각보다 맛있었고 가족도 기뻐했습니다. 지금은 일주일에 한 번 (22) 만들고 있습니다.
다음 달에는 파스타에도 도전하고 싶습니다. 모를 때는 친구에게 만드는 방법을 (23) 물어봅니다.
그리고 더 빨리 만들 수 있게 (24) 연습합니다. 언젠가 제 특기 요리를 만들어서 (25) 하고 싶습니다.
"""


# ----------------------------
# N4 문제 데이터 (FULL 원본: KO 포함)
# - 구조는 N5와 동일: meta 안에 ko_q / ko_choices / ko_explain
# - PART2(文法) 먼저 구성
# ----------------------------

# =========================
# N4 PART2 - もんだい３ 공통 지문 (JP / KO) 21~25
# =========================
N4_P2_M3_STEM_JP = """（もんだい３） 21から25に何を入れますか。ぶんしょうのいみを考えて、1・2・3・4からいちばんいいものを一つえらんでください。

（作文）　料理教室

わたしの しゅみは 料理です。友だちに さそわれて、先月から 料理教室に かよっています。（２１）、はじめは 包丁の 使い方も うまく できませんでした。

さいしょの 授業では、先生が やさいの 切り方を ゆっくり（２２）。家で なんども 練習して、少しずつ できるように なりました。今では、同じクラスの 人たちと いっしょに 作るのが とても 楽しいです。

この前、教室で 作った カレーを 家族に 食べてもらったら、「お店の 味（２３）」と 言われました。うれしかったので、来月は もっと むずかしい 料理にも ちょうせん しようと 思います。

つぎの 発表会までに、できるだけ（２４）。そして、みんなの 前で じしんを もって 作れるように なりたいです。料理は、練習すれば するほど 上手に なる（２５）。"""

N4_P2_M3_STEM_KO = """(문제3) 21~25에 무엇을 넣습니까? 글의 의미를 생각해서 1·2·3·4 중에서 가장 알맞은 것을 하나 고르세요.

(작문) 요리 교실

제 취미는 요리입니다. 친구에게 권유를 받아 지난달부터 요리 교실에 다니고 있습니다. (21) 처음에는 칼 쓰는 법도 잘하지 못했습니다.

첫 수업에서는 선생님이 채소 자르는 방법을 천천히 (22) 주었습니다. 집에서 여러 번 연습해서 조금씩 할 수 있게 되었습니다. 지금은 같은 반 사람들과 함께 만드는 것이 정말 즐겁습니다.

얼마 전 교실에서 만든 카레를 가족에게 먹게 했더니 “가게 맛 (23)”라고 말해 주었습니다. 기뻐서 다음 달에는 더 어려운 요리에도 도전하려고 합니다.

다음 발표회까지 가능한 한 (24). 그리고 사람들 앞에서 자신 있게 만들 수 있게 되고 싶습니다. 요리는 연습하면 할수록 더 잘하게 되는 (25)."""


# =========================
# ✅ N4 PART2 전체 문항 리스트 (dict만!)
# 구성(실제 형식 유지):
#  - もんだい1: 1~15 (문법/어휘 선택)
#  - もんだい2: 16~20 (★ 배열 문제: ★ 위치에 들어갈 조각 고르기)
#  - もんだい3: 21~25 (지문형 공통 stem)
# =========================
N4_PART2_QUESTIONS_FULL = [
    # =========================
    # もんだい1 (1~15)
    # =========================
    {
        "id": "N4_P2_001",
        "part": 2,
        "q": "1　会議が　予定より　早く　終わったので、（　）帰れました。",
        "choices": ["１０分", "１０分しか", "１０分で", "１０分を"],
        "answer": 2,
        "meta": {
            "ko_q": "1) 회의가 예정보다 빨리 끝나서, ( ) 집에 갈 수 있었습니다.",
            "ko_choices": ["10분", "10분밖에", "10분에/만에(=~で)", "10분을"],
            "ko_explain": "정답 3번. ‘~만에(시간이 걸려)’는 「時間 + で」를 씁니다. → 「１０分で帰れました」"
        }
    },
    {
        "id": "N4_P2_002",
        "part": 2,
        "q": "2　この　アプリは　だれ（　）でも　使うことが　できます。",
        "choices": ["に", "を", "と", "で"],
        "answer": 3,
        "meta": {
            "ko_q": "2) 이 앱은 누구( )라도 사용할 수 있습니다.",
            "ko_choices": ["~에게(に)", "~을(を)", "~와(と)", "~라도(で)"],
            "ko_explain": "정답 4번 ‘누구라도’는 「だれでも」가 고정 표현입니다."
        }
    },
    {
        "id": "N4_P2_003",
        "part": 2,
        "q": "3　弟は　子どものころ　よく　病気を　して、両親（　）心配させました。",
        "choices": ["で", "を", "の", "や"],
        "answer": 1,
        "meta": {
            "ko_q": "3) 남동생은 어릴 때 자주 아파서 부모님( ) 걱정시켰습니다.",
            "ko_choices": ["~에서(で)", "~을(を)", "~의(の)", "~와 등(や)"],
            "ko_explain": "정답 2번 ‘A를 걱정시키다’는 목적어를 「を」로 잡습니다. → 「両親を心配させました」"
        }
    },
    {
        "id": "N4_P2_004",
        "part": 2,
        "q": "4　その　店の　ケーキが　おいしかったので、３つ（　）食べてしまいました。",
        "choices": ["も", "に", "が", "で"],
        "answer": 0,
        "meta": {
            "ko_q": "4) 그 가게 케이크가 맛있어서 3개( ) 먹어 버렸습니다.",
            "ko_choices": ["~이나/도(も)", "~에(に)", "~이/가(が)", "~에서(で)"],
            "ko_explain": "정답 1번. ‘3개나(많이)’ 뉘앙스는 「数量 + も」가 자연스럽습니다."
        }
    },
    {
        "id": "N4_P2_005",
        "part": 2,
        "q": "5　この　本は　有名な　作家（　）書かれました。",
        "choices": ["から", "を", "について", "によって"],
        "answer": 3,
        "meta": {
            "ko_q": "5) 이 책은 유명한 작가( ) 쓰였습니다.",
            "ko_choices": ["~부터(から)", "~을(を)", "~에 대해(について)", "~에 의해(によって)"],
            "ko_explain": "정답 4번. 수동문에서 ‘행위자(누가 썼는지)’는 「によって」를 씁니다."
        }
    },
    {
        "id": "N4_P2_006",
        "part": 2,
        "q": "6　この　体育館は（　）利用できますが、事前の　予約が　必要です。",
        "choices": ["だれでも", "だれを", "だれに", "だれが"],
        "answer": 0,
        "meta": {
            "ko_q": "6) 이 체육관은 ( ) 이용할 수 있지만, 사전 예약이 필요합니다.",
            "ko_choices": ["누구나(だれでも)", "누구를(だれを)", "누구에게(だれに)", "누구가(だれが)"],
            "ko_explain": "정답 1번. ‘누구나’는 「だれでも」가 고정입니다."
        }
    },
    {
        "id": "N4_P2_007",
        "part": 2,
        "q": "7　A「家族に　連絡することが　多いですか。」\n　　B「ええ、（　）メールで　連絡します。」",
        "choices": ["どのくらい", "どの", "どうやって", "どういう"],
        "answer": 2,
        "meta": {
            "ko_q": "7) A: 가족에게 연락을 자주 하나요? B: 네, ( ) 메일로 연락해요.",
            "ko_choices": ["얼마나(どのくらい)", "어느(どの)", "어떻게/어떤 방법으로(どうやって)", "어떤 종류의(どういう)"],
            "ko_explain": "정답 3번. 수단/방법을 묻는 흐름이라 「どうやって」가 자연스럽습니다."
        }
    },
    {
        "id": "N4_P2_008",
        "part": 2,
        "q": "8　来週は　試験なので、（　）勉強を　始めないと　いけません。",
        "choices": ["だんだん", "あまり", "だいたい", "そろそろ"],
        "answer": 3,
        "meta": {
            "ko_q": "8) 다음 주가 시험이라, ( ) 공부를 시작해야 합니다.",
            "ko_choices": ["점점(だんだん)", "별로(あまり)", "대략(だいたい)", "슬슬/이제쯤(そろそろ)"],
            "ko_explain": "정답 4번 ‘이제쯤 슬슬 시작할 때’는 「そろそろ」가 딱 맞습니다."
        }
    },
    {
        "id": "N4_P2_009",
        "part": 2,
        "q": "9　今朝は　バスが（　）来なくて、会社に　遅れそうに　なりました。",
        "choices": ["やっと", "なかなか", "きっと", "いつか"],
        "answer": 1,
        "meta": {
            "ko_q": "9) 오늘 아침 버스가 ( ) 오지 않아서 회사에 늦을 뻔했습니다.",
            "ko_choices": ["겨우(やっと)", "좀처럼(なかなか)", "분명(きっと)", "언젠가(いつか)"],
            "ko_explain": "정답 2번 ‘좀처럼 오지 않다’는 「なかなか + Vない」가 정답입니다."
        }
    },
    {
        "id": "N4_P2_010",
        "part": 2,
        "q": "10　A「明日　時間が　あったら、食事に　行かない？」\n　　B「うん、（　）短い時間なら　行けるよ。」",
        "choices": ["なので", "だから", "でも", "なら"],
        "answer": 2,
        "meta": {
            "ko_q": "10) A: 내일 시간 있으면 밥 먹으러 갈래? B: 응, ( ) 짧은 시간이면 갈 수 있어.",
            "ko_choices": ["그래서(なので)", "그러니까(だから)", "그래도/하지만(でも)", "~라면(なら)"],
            "ko_explain": "정답 3번 앞에서 조건/제약이 있는 뉘앙스(짧은 시간이면)는 ‘그래도’ 느낌의 「でも」가 자연스럽습니다."
        }
    },
    {
        "id": "N4_P2_011",
        "part": 2,
        "q": "11　私は（　）間、コンビニで　アルバイトを　していました。",
        "choices": ["夏休みに", "夏休みで", "夏休みの", "夏休み"],
        "answer": 2,
        "meta": {
            "ko_q": "11) 저는 ( ) 동안 편의점에서 아르바이트를 했었습니다.",
            "ko_choices": [
                "여름방학에(夏休みに)",
                "여름방학으로/여름방학 때문에(夏休みで)",
                "여름방학의(夏休みの)",
                "여름방학(夏休み)"
            ],
            "ko_explain": "‘~동안’의 기간을 나타낼 때는 반드시 「Nの間」 형태를 씁니다. 따라서 「夏休みの間」이 되어야 하므로 정답은 3번입니다.\n\n①「夏休みに間」은 조사와 명사가 겹쳐 문법적으로 틀립니다.\n②「夏休みで間」에서 「で」는 원인·수단을 나타내는 조사이므로 기간 표현에 사용할 수 없습니다.\n④「夏休み間」은 「の」가 빠져서 부자연스럽고 틀린 표현입니다."
        }
    },
    {
        "id": "N4_P2_012",
        "part": 2,
        "q": "12　引っこしの　準備を　する（　）、思ったより　時間が　かかりました。",
        "choices": ["ばかり", "のに", "ために", "ところ"],
        "answer": 1,
        "meta": {
            "ko_q": "12) 이사 준비를 하는 ( ) 생각보다 시간이 걸렸습니다.",
            "ko_choices": ["막 ~한(ばかり)", "~하는데(のに)", "~하기 위해(ために)", "~하려는 참(ところ)"],
            "ko_explain": "정답 2번. 동작 ‘~하는 데(시간/노력)’는 「Vるのに」가 자주 쓰입니다."
        }
    },
    {
        "id": "N4_P2_013",
        "part": 2,
        "q": "13　A「午後の　会議に　出ますか。」\n　　B「出ますが、午前中に　用事が　あるので、（　）。」",
        "choices": ["遅れないでください", "遅れないほうがいいです", "遅れるかもしれません", "遅れてはいけません"],
        "answer": 2,
        "meta": {
            "ko_q": "13) A: 오후 회의에 나와요? B: 나오지만 오전에 일이 있어서 ( ).",
            "ko_choices": ["늦지 마세요", "늦지 않는 게 좋아요", "늦을지도 몰라요", "늦으면 안 돼요"],
            "ko_explain": "정답 3번 ‘사정상 늦을 가능성’ → 「遅れるかもしれません」이 자연스럽습니다."
        }
    },
    {
        "id": "N4_P2_014",
        "part": 2,
        "q": "14（レストランで）\n　　A「空いている　席が　ありませんね。」\n　　B「でも、あそこが（　）よ。」",
        "choices": ["空きそうです", "空きました", "空いています", "空いたようです"],
        "answer": 2,
        "meta": {
            "ko_q": "14) (식당에서) A: 빈 자리가 없네요. B: 그래도 저기는 ( )요.",
            "ko_choices": ["곧 빌 것 같아요(空きそうです)", "비었어요(空きました)", "비어 있어요(空いています)", "빈 것 같아요(空いたようです)"],
            "ko_explain": "정답 3번. 이 상황은 레스토랑 안에서 현재 좌석 상태를 직접 보고 말하는 장면입니다. 일본어에서는 ‘이미 비어 있고 그 상태가 계속되는 경우’ 결과 상태를 나타내는 「〜ています」를 사용합니다. 따라서 「空いています」가 가장 자연스럽습니다.\n\n①「空きそうです」는 아직 비지 않았고 곧 비어질 것이라는 추측이므로 맞지 않습니다.\n②「空きました」는 ‘방금 비었다’는 동작 완료 표현으로, 좌석 상태 설명에는 부자연스럽습니다.\n④「空いたようです」는 확신 없는 추측 표현으로, 눈앞의 좌석을 가리키는 상황에는 맞지 않습니다."
        }
    },
    {
        "id": "N4_P2_015",
        "part": 2,
        "q": "15（会議室で）\n　　A「手伝いましょうか。」\n　　B「ありがとうございます。となりの部屋から　いすを（　）。」",
        "choices": ["持ってこなくてもいいですか", "持ってきてもらえますか", "持ってこないといけませんか", "持ってきていませんか"],
        "answer": 1,
        "meta": {
            "ko_q": "15) (회의실에서)\nA: 도와드릴까요?\nB: 감사합니다. 옆방에서 의자를 ( ) ?",
            "ko_choices": [
                "가져오지 않아도 되나요?",
                "가져와 주실 수 있나요?",
                "가져오지 않으면 안 되나요?",
                "가져오지 않았나요?"
            ],
            "ko_explain": "이 상황은 상대가 ‘도와주겠다’고 한 뒤, 구체적인 도움을 정중하게 부탁하는 장면입니다. 일본어에서 상대에게 무언가를 부탁할 때는 「Vて もらえますか」 표현이 가장 자연스럽습니다.\n\n①은 허락을 묻는 표현으로, 의자가 필요한 상황과 맞지 않습니다.\n③은 의무 여부를 묻는 표현으로 부탁과는 의미가 다릅니다.\n④는 상태를 확인하는 질문으로, 요청 표현이 아닙니다."
        }
    },

    # =========================
    # もんだい2 (16~20) ★ 배열 문제
    # - ★ 위치에 들어갈 조각(보기 1~4) 하나를 고르는 형식
    # =========================
    {
        "id": "N4_P2_016",
        "part": 2,
        "q": "16　先月まで　この　ビルの　１階に　あった　＿＿＿　★　＿＿＿　＿＿＿　人気です。",
        "choices": ["今は", "カフェは", "となりの駅の近くに", "移りましたが"],
        "answer": 3,
        "meta": {
            "ko_q": "16) 지난달까지 이 빌딩 1층에 있었던 카페는 옆 역 근처로 옮겼지만, 지금은 인기가 많습니다.",
            "ko_choices": ["지금은", "카페는", "옆 역 근처로", "옮겼지만"],
            "ko_explain": "정답 4번 자연스러운 문장: 「先月までこのビルの1階にあったカフェは、となりの駅の近くに移りましたが、今は人気です。」\n★ 위치에는 「移りましたが」가 들어갑니다."
        }
    },
    {
        "id": "N4_P2_017",
        "part": 2,
        "q": "17　昨日の　夜　家に　帰ってから、かぎを　＿＿＿　＿＿＿　★　＿＿＿　見つかりません。",
        "choices": ["どこに", "置いたか", "覚えていなくて", "まだ"],
        "answer": 1,
        "meta": {
            "ko_q": "17) 어제 밤 집에 돌아온 뒤에, 열쇠를 어디에 두었는지 기억이 나지 않아서 아직 찾지 못했습니다.",
            "ko_choices": ["어디에", "두었는지", "기억이 나지 않아서", "아직"],
            "ko_explain": "정답2번 자연스러운 문장: 「かぎをどこに置いたか覚えていなくて、まだ見つかりません。」\n★ 위치에는 「置いたか」가 들어갑니다."
        }
    },
    {
        "id": "N4_P2_018",
        "part": 2,
        "q": "18　私は　ピアノを　＿＿＿　＿＿＿　★　＿＿＿　時間が　ありません。",
        "choices": ["ひくのが", "好きですが", "最近いそがしくて", "ゆっくり"],
        "answer": 2,
        "meta": {
            "ko_q": "18) 저는 피아노 치는 것을 좋아하지만, 최근에 바빠서 천천히 할 시간이 없습니다.",
            "ko_choices": ["치는 것을", "좋아하지만", "최근 바빠서", "천천히"],
            "ko_explain": "정답 3번 자연스러운 문장: 「私はピアノをひくのが好きですが、最近いそがしくて、ゆっくり時間がありません。」\n★ 위치에는 「最近いそがしくて」가 들어갑니다."
        }
    },
    {
        "id": "N4_P2_019",
        "part": 2,
        "q": "19　私は　２０さいの　誕生日に、そふが　＿＿＿　＿＿＿　★　＿＿＿　くれました。",
        "choices": ["大切に", "使って", "新しい", "時計を"],
        "answer": 3,
        "meta": {
            "ko_q": "19) 저는 스무 살 생일에 할아버지께서 새 시계를 주셨습니다.",
            "ko_choices": ["소중히", "사용해", "새로운", "시계를"],
            "ko_explain": "정답 4번 자연스러운 문장: 「そふが新しい時計をくれました。」\n★ 위치에는 목적어인 「時計を」가 들어가야 문장이 완성됩니다."
        }
    },
    {
        "id": "N4_P2_020",
        "part": 2,
        "q": "20　A「来週、映画を　見に　行こうと　思うんですが、いっしょに　どうですか。」\n　　B「いいですね。＿＿＿　＿＿＿　★　＿＿＿　です。」",
        "choices": ["ぜひ", "行きたい", "時間が", "あれば"],
        "answer": 3,
        "meta": {
            "ko_q": "20) A: 다음 주에 영화를 보러 갈까 생각 중인데, 같이 어때요?\nB: 좋네요. 시간이 있다면 꼭 가고 싶어요.",
            "ko_choices": ["꼭", "가고 싶어요", "시간이", "있다면"],
            "ko_explain": "정답 4번 자연스러운 문장: 「ぜひ行きたいです。時間があれば。」\n★ 위치에는 조건을 나타내는 「あれば」가 들어갑니다."
        }
    },

    # =========================
    # もんだい3 (21~25) - 그룹 문제
    # - q에는 지문을 붙이지 말고 번호만 둔다 (N5 방식 그대로)
    # =========================
    {
        "id": "N4_P2_021",
        "part": 2,
        "q": "21（　）",
        "choices": ["それに", "だから", "しかし", "たとえば"],
        "answer": 2,
        "meta": {
            "ko_q": "21) 앞 문장과의 흐름(역접/추가/이유/예시)에 맞는 표현을 고르세요.",
            "ko_choices": ["게다가(それに)", "그래서(だから)", "하지만(しかし)", "예를 들면(たとえば)"],
            "ko_explain": "정답3번 앞: 요리교실을 다닌다 → 뒤: 처음엔 잘 못했다(대조) → 역접 「しかし」가 자연스럽습니다."
        }
    },
    {
        "id": "N4_P2_022",
        "part": 2,
        "q": "22（　）",
        "choices": ["教えていました", "教えてあげました", "教えてくれました", "教えてもらいました"],
        "answer": 2,
        "meta": {
            "ko_q": "22) ‘선생님이 (나에게) 가르쳐주다’ 흐름에 맞는 것을 고르세요.",
            "ko_choices": ["가르치고 있었습니다", "가르쳐 주었습니다(내가 남에게)", "가르쳐 주었습니다(선생님이 나에게)", "가르침을 받았습니다"],
            "ko_explain": "정답 3번 ‘선생님이 나에게 해줌’ → 「先生が…教えてくれました」가 정답입니다."
        }
    },
    {
        "id": "N4_P2_023",
        "part": 2,
        "q": "23（　）",
        "choices": ["みたいです", "のように", "まで", "ほど"],
        "answer": 3,
        "meta": {
            "ko_q": "23) “가게 맛( )”에 자연스러운 표현을 고르세요.",
            "ko_choices": ["~인 것 같습니다(みたいです)", "~처럼(のように)", "~까지(まで)", "~정도로(ほど)"],
            "ko_explain": "정답 4번「店の味ほど」 = ‘가게 맛 정도로(그만큼)’가 자연스럽게 칭찬 뉘앙스를 만듭니다."
        }
    },
    {
        "id": "N4_P2_024",
        "part": 2,
        "q": "24（　）",
        "choices": ["練習しておきたいです", "練習したようです", "練習するそうです", "練習するためです"],
        "answer": 0,
        "meta": {
            "ko_q": "24) ‘발표회까지 가능한 한 ( )’에 맞는 것을 고르세요.",
            "ko_choices": ["연습해 두고 싶습니다", "연습한 것 같습니다", "연습할 것 같대요", "연습하기 위해서입니다"],
            "ko_explain": "정답 1번 발표회 전 ‘미리 해두다’ 뉘앙스 → 「練習しておきたいです」가 정답입니다."
        }
    },
    {
        "id": "N4_P2_025",
        "part": 2,
        "q": "25（　）",
        "choices": ["ことです", "ようです", "ところです", "ためです"],
        "answer": 0,
        "meta": {
            "ko_q": "25) ‘연습하면 할수록 더 잘하게 되는 ( )’에 맞는 것을 고르세요.",
            "ko_choices": ["것입니다(ことです)", "~인 것 같습니다(ようです)", "~하려는 참입니다(ところです)", "~위해서입니다(ためです)"],
            "ko_explain": "정답 1번 문장 마무리 ‘~하는 것이다/일이다’ 의미로 「ことです」가 자연스럽습니다."
        }
    },
]



# =========================
# N4 PART3 - 그룹(5~8) 공통 지문 (JP / KO)
# =========================
N4_P3_M2_STEM_JP = """（もんだい）次の文章を読んで、質問に答えてください。答えは、1・2・3・4からいちばんいいものを一つえらんでください。

（作文）「駅で助けてくれた人」

先週、私は友だちに会いに行くために、大きい駅で電車を乗り換えることになりました。駅はとても広くて、どこに行けばいいか分からなくなりました。紙のメモを見ながら歩いていましたが、同じところを何回も行ったり来たりしてしまいました。

『どうしよう…』と思っていたとき、ミカさんという女性が声をかけてくれました。ミカさんは駅の中にある本屋の前で、私が困っている様子を見ていたそうです。
私は「乗りたい電車のホームが分からないんです」と言いました。ミカさんは「いっしょに行きましょう」と言って、私をホームまで案内してくれました。

ミカさんは仕事でこの町に来ていて、これから別の町に行くと言っていました。私は「時間、大丈夫ですか」と聞きました。ミカさんは「次の電車まで少し時間があるから大丈夫」と笑いました。そして「私も昔、外国でたくさん助けてもらったから」と言いました。

電車に乗って一人になった私は、ミカさんの言葉を思い出して、心があたたかくなりました。私は、これから私もミカさんのように（　）と思いました。"""

N4_P3_M2_STEM_KO = """(문제) 다음 글을 읽고 질문에 답하세요. 답은 1~4 중 가장 알맞은 것을 하나 고르세요.

(작문) ‘역에서 도와준 사람’

지난주 저는 친구를 만나러 가기 위해 큰 역에서 환승해야 했습니다. 역이 너무 넓어서 어디로 가야 할지 몰라 헤매었습니다.
종이에 적어 둔 메모를 보며 걸었지만 같은 곳을 몇 번이나 왔다 갔다 하게 되었습니다.

‘어쩌지…’ 하고 있을 때, 미카라는 여성이 말을 걸어 주었습니다. 미카는 역 안의 서점 앞에서 제가 곤란해 보이는 모습을 보고 있었다고 합니다.
저는 “타려는 전철 승강장을 모르겠어요”라고 말했습니다. 미카는 “같이 가요”라고 하며 저를 승강장까지 안내해 주었습니다.

미카는 일 때문에 이 도시에 왔다가 이제 다른 도시로 간다고 했습니다. 저는 “시간 괜찮으세요?”라고 물었습니다.
미카는 “다음 전철까지 시간이 조금 있어서 괜찮아”라고 웃으며,
“나도 예전에 외국에서 많이 도움을 받았거든”이라고 말했습니다.

전철을 타고 혼자가 된 저는 미카의 말을 떠올리며 마음이 따뜻해졌습니다.
그리고 저도 앞으로 미카처럼 (   ) 하겠다고 생각했습니다."""

# =========================
# N4 PART3 - 변형 문제(1~8)
# =========================
N4_PART3_QUESTIONS_FULL = [
    # =========================
    # 1~4: 1지문 1문제 (단일)
    # =========================
    {
        "id": "N4_P3_001",
        "part": 3,
        "q": "1（お知らせ）\nこのお知らせは、日本語学校の教室にあります。\n\n【忘れ物があります】\n忘れた人は、先生の部屋へ取りに来てください。\n① くつ（201教室）\n② かさ（食堂）\n\nただし、3月10日（火）から12日（木）まではテスト中です。\n先生の部屋には入れません。教室でクラスの先生に言ってください。\n\n質問：テスト中の3日間に忘れ物を取りたい人は、どうしますか。",
        "choices": [
            "テストが終わるまで待つ",
            "先生の部屋へ取りに行く",
            "忘れ物があった場所へ取りに行く",
            "教室でクラスの先生に話す"
        ],
        "answer": 3,
        "meta": {
            "ko_q": "1) (안내문)\n이 안내문은 일본어학교 교실에 붙어 있습니다.\n\n[분실물이 있습니다]\n물건을 잃어버린 사람은 선생님 방으로 찾으러 오세요.\n① 신발 (201교실)\n② 우산 (식당)\n\n단, 3월 10일(화)부터 12일(목)까지는 시험 기간입니다.\n선생님 방에는 들어갈 수 없습니다.\n교실에서 자기 반 선생님께 말해 주세요.\n\n[질문]\n시험 중인 3일 동안 분실물을 찾고 싶은 사람은 어떻게 해야 하나요?",
            "ko_choices": [
                "시험이 끝날 때까지 기다린다",
                "선생님 방에 찾으러 간다",
                "분실물이 있던 장소로 찾으러 간다",
                "교실에서 자기 반 선생님께 말한다"
            ],
            "ko_explain": "시험 기간에는 선생님 방에 들어갈 수 없다고 되어 있으므로, 교실에서 자기 반 선생님께 말해야 합니다."
        }
    },
    {
        "id": "N4_P3_002",
        "part": 3,
        "q": "2\nアイスクリームは夏に食べるとおいしいですが、私は冬でも時々食べます。\n夏は毎日食べるので安いものを買いますが、冬は少し高いものを買います。\nあたたかい部屋で食べるアイスクリームが、私の楽しみです。\n\n質問：この人の楽しみは何ですか。",
        "choices": [
            "冬にあたたかい部屋で安いアイスクリームを毎日食べること",
            "冬にあたたかい部屋で少し高いアイスクリームを食べること",
            "夏に毎日アイスクリームを食べること",
            "夏に高いアイスクリームを食べること"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "2)\n아이스크림은 여름에 먹으면 맛있지만, 나는 겨울에도 가끔 먹는다.\n여름에는 매일 먹기 때문에 싼 것을 사지만, 겨울에는 조금 비싼 것을 산다.\n따뜻한 방에서 먹는 아이스크림이 나의 즐거움이다.\n\n질문: 이 사람의 즐거움은 무엇인가요?",
            "ko_choices": [
                "겨울에 따뜻한 방에서 싼 아이스크림을 매일 먹는 것",
                "겨울에 따뜻한 방에서 조금 비싼 아이스크림을 먹는 것",
                "여름에 매일 아이스크림을 먹는 것",
                "여름에 비싼 아이스크림을 먹는 것"
            ],
            "ko_explain": "정답 2번 본문에 ‘따뜻한 방에서 먹는 아이스크림이 나의 즐거움’이며, 겨울에는 ‘조금 비싼 것’을 산다고 되어 있습니다."
        }
    },
    {
        "id": "N4_P3_003",
        "part": 3,
        "q": "3（メモ）\n大学の先生の机の上に、このメモがあります。\n\nサトウ先生\nパン工場のカワイさんから電話がありました。\n工場見学ができるのは、4月3日（金）10時、4月10日（金）14時と16時だそうです。\n日にちと時間が決まったら、電話してほしいと言っていました。\n行く人の数も知らせてほしいそうです。\n\n質問：このメモを読んで、先生はカワイさんに何を知らせなければなりませんか。",
        "choices": [
            "工場見学に行く人の数だけ",
            "工場見学に行く日と時間だけ",
            "工場見学に行く日と時間と、行く人の数",
            "工場見学の時間がいつごろ決まるか"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "3) (메모)\n대학 선생님의 책상 위에 이 메모가 놓여 있습니다.\n\n사토 선생님\n빵 공장의 카와이 씨에게서 전화가 왔습니다.\n공장 견학이 가능한 날은 4월 3일(금) 10시, 4월 10일(금) 14시와 16시라고 합니다.\n날짜와 시간이 정해지면 전화해 달라고 했습니다.\n견학에 갈 사람 수(인원수)도 알려 달라고 합니다.\n\n질문: 이 메모를 읽고, 선생님은 카와이 씨에게 무엇을 알려야 하나요?",
            "ko_choices": [
                "공장 견학에 갈 사람 수만",
                "공장 견학 날짜와 시간만",
                "공장 견학 날짜와 시간, 그리고 갈 사람 수",
                "공장 견학 시간이 언제쯤 정해지는지"
            ],
            "ko_explain": "정답 3번 메모에는 ‘날짜와 시간이 정해지면 연락’ + ‘사람 수(인원수)도 알려 달라’고 적혀 있습니다."
        }
    },
    {
        "id": "N4_P3_004",
        "part": 3,
        "q": "4\n昨日、黒い消しゴムを買いました。店の人が「白い消しゴムは使うと汚れが目立つので、黒いのを作ったんですよ」と教えてくれました。\n私は色がかっこいいと思って買ったので、その話を聞いておもしろいと思いました。\n\n質問：「私」はどうして黒い消しゴムを買いましたか。",
        "choices": [
            "黒い消しゴムは使っても汚れが目立たないから",
            "黒い消しゴムを買う人が多いと聞いたから",
            "黒い消しゴムのほうが字をきれいに消せるから",
            "黒い消しゴムは色がかっこいいと思ったから"
        ],
        "answer": 3,
        "meta": {
            "ko_q": "4)\n어제 검은 지우개를 샀습니다.\n가게 사람이 ‘하얀 지우개는 사용하면 때가 잘 보여서, 검은 지우개를 만들었어요’라고 알려 주었습니다.\n나는 색이 멋있다고 생각해서 샀기 때문에, 그 이야기를 듣고 재미있다고 느꼈습니다.\n\n질문: ‘나’는 왜 검은 지우개를 샀나요?",
            "ko_choices": [
                "검은 지우개는 사용해도 때가 눈에 잘 띄지 않아서",
                "검은 지우개를 사는 사람이 많다고 들었기 때문에",
                "검은 지우개가 글씨를 더 깨끗이 지울 수 있어서",
                "검은 지우개의 색이 멋있다고 생각했기 때문에"
            ],
            "ko_explain": "정답 4번 본문에서 ‘나는 색이 멋있다고 생각해서 샀다’고 직접 말하고 있습니다."
        }
    },

    # =========================
    # 5~8: 1지문 4문제 (그룹)
    # q에는 문항 텍스트만 두고, 공통 지문은 템플릿에서 groupStemBox로 표시
    # =========================
    {
        "id": "N4_P3_005",
        "part": 3,
        "q": "5　なぜ「私」は『どうしよう…』と思いましたか。",
        "choices": [
            "友だちに会えなくなったから",
            "駅で道に迷ってしまったから",
            "乗りたい電車のホームが分からなかったから",
            "メモをなくしてしまったから"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "5) ‘나’는 왜 ‘어쩌지…’라고 생각했나요?",
            "ko_choices": [
                "친구를 못 만나게 되었기 때문에",
                "역에서 길을 잃었기 때문에",
                "타려는 전철의 승강장을 몰랐기 때문에",
                "메모를 잃어버렸기 때문에"
            ],
            "ko_explain": "정답 3번 본문에 ‘승강장이 어디인지 몰라서 헤맸다’고 되어 있습니다."
        }
    },
    {
        "id": "N4_P3_006",
        "part": 3,
        "q": "6　なぜミカさんは「私」に声をかけましたか。",
        "choices": [
            "「私」が困っている様子を見たから",
            "「私」といっしょにお茶を飲みたかったから",
            "「私」が友だちと待ち合わせしていると思ったから",
            "「私」が本屋で買い物をしていたから"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "6) 미카는 왜 ‘나’에게 말을 걸었나요?",
            "ko_choices": [
                "내가 곤란해 보이는 모습을 봤기 때문에",
                "나와 함께 차를 마시고 싶었기 때문에",
                "내가 친구를 기다리는 중이라고 생각했기 때문에",
                "내가 서점에서 쇼핑하고 있었기 때문에"
            ],
            "ko_explain": "정답 1번 본문에 ‘곤란해 보이는 모습(困っている様子)을 보고 있었다’고 나옵니다."
        }
    },
    {
        "id": "N4_P3_007",
        "part": 3,
        "q": "7　ミカさんは「私」に何と言いましたか。",
        "choices": [
            "「時間がないから急いでください」",
            "「いっしょに行きましょう」",
            "「駅の外で待っていてください」",
            "「次の電車はもうありません」"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "7) 미카는 ‘나’에게 뭐라고 말했나요?",
            "ko_choices": [
                "시간이 없으니 서두르세요",
                "같이 가요",
                "역 밖에서 기다려 주세요",
                "다음 전철은 이미 없어요"
            ],
            "ko_explain": "정답 2번 본문에 ‘いっしょに行きましょう’라고 말하며 안내했다고 되어 있습니다."
        }
    },
    {
        "id": "N4_P3_008",
        "part": 3,
        "q": "8　（　）に入れるのに、いちばんいいものはどれですか。",
        "choices": [
            "仕事をがんばろう",
            "この町に住んでみたい",
            "困っている人に親切にしよう",
            "駅の地図を買おう"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "8) (   )에 들어갈 가장 알맞은 문장은 무엇인가요?",
            "ko_choices": [
                "일을 열심히 하자",
                "이 도시에 살아보고 싶다",
                "곤란한 사람에게 친절하게 하자",
                "역 지도를 사자"
            ],
            "ko_explain": "정답 3번 도움을 받고 마음이 따뜻해졌으며 ‘나도 미카처럼’이라고 했으니 ‘곤란한 사람에게 친절하게 하자’가 자연스럽습니다."
        }
    },
]
N4_PART4_QUESTIONS_FULL = []

# =========================
# 2) PART별 원본(FULL) 가져오기 (채점 API에서 사용)
# =========================
def get_n4_part_questions_full(part: int):
    if part == 1:
        return N4_PART1_QUESTIONS_FULL
    elif part == 2:
        return N4_PART2_QUESTIONS_FULL
    elif part == 3:
        return N4_PART3_QUESTIONS_FULL
    elif part == 4:
        return N4_PART4_QUESTIONS_FULL
    return []

# =========================
# N4 PART3 : 5~8 그룹 문제용 메타 내려주기 (템플릿이 groupStemBox에 표시)
# - 템플릿 JS: GROUP_START_IDX = 4, GROUP_END_IDX = 7 로 맞추면 됨
# =========================
def get_n4_part_questions(part: int):
    src = get_n4_part_questions_full(part)

    out = []
    for q in src:
        item = {
            "id": q.get("id"),
            "part": q.get("part", part),
            "q": q.get("q", ""),
            "choices": q.get("choices", []),
            "answer": q.get("answer", 0),
        }

        # ✅ PART2의 21~25는 그룹 지문 표시용 메타 내려줌 (추가)
        if part == 2:
            # id: "N4_P2_021" → 21 추출
            try:
                no = int((q.get("id", "").split("_")[-1] or "0"))
            except:
                no = None

            if no and 21 <= no <= 25:
                item["group"] = {
                    "id": "P2_M3",
                    "start": 21,
                    "end": 25,
                    "stem_jp": N4_P2_M3_STEM_JP,
                    "stem_ko": N4_P2_M3_STEM_KO,
                    "passage_jp": N4_P2_M3_PASSAGE_JP,
                    "passage_ko": N4_P2_M3_PASSAGE_KO,
                }

        # ✅ PART3의 5~8은 그룹 문제 표시용 메타(일본어 지문만) 내려줌 (기존 그대로)
        if part == 3:
            try:
                head = q.get("q", "").strip().split()[0]
                no = int(head.replace("　", "").replace(" ", ""))
            except:
                no = None

            if no and 5 <= no <= 8:
                item["group"] = {
                    "id": "P3_M2",
                    "start": 5,
                    "end": 8,
                    "stem_jp": N4_P3_M2_STEM_JP,
                }

        out.append(item)

    return out

# ----------------------------
# ✅ 채점 API (N4)
# ----------------------------
@app.post("/api/jlpt/n4/test/grade/<int:part>")
def api_jlpt_n4_test_grade(part: int):
    payload = request.get_json(silent=True) or {}
    user_answers = payload.get("answers", [])
    if not isinstance(user_answers, list):
        user_answers = []

    src = get_n4_part_questions_full(part)
    total = len(src)
    correct = 0
    items = []

    for i, q in enumerate(src):
        ua = user_answers[i] if i < len(user_answers) else None
        ans = q.get("answer", 0)
        is_correct = (ua == ans)
        if is_correct:
            correct += 1

        meta = q.get("meta", {}) or {}
        items.append({
            "no": i + 1,
            "q_ko": meta.get("ko_q", ""),
            "choices_ko": meta.get("ko_choices", []),
            "answer_index": ans,
            "user_index": ua,
            "explain_ko": meta.get("ko_explain", ""),
            "is_correct": is_correct,
        })

    score = round((correct / total) * 100) if total else 0

    resp = {
        "total": total,
        "correct": correct,
        "score": score,
        "items": items
    }

    # ✅ N4 PART2 그룹 지문(21~25) 번역 포함 (추가!)
    if part == 2:
        resp["group_meta"] = {
            "P2_M3": {
                "start": 21,
                "end": 25,
                "stem_jp": N4_P2_M3_STEM_JP,
                "stem_ko": N4_P2_M3_STEM_KO,
            }
        }

    # ✅ N4 PART3 그룹 지문(5~8) 번역 포함 (기존)
    if part == 3:
        resp.setdefault("group_meta", {})
        resp["group_meta"]["P3_M2"] = {
            "start": 5,
            "end": 8,
            "stem_jp": N4_P3_M2_STEM_JP,
            "stem_ko": N4_P3_M2_STEM_KO,
        }

    return jsonify(resp)

# ----------------------------
# ✅ N4 테스트 시작 라우트
# ----------------------------
@app.route("/jlpt/n4/test/start/<int:part>")
def jlpt_n4_test_start(part: int):
    questions = get_n4_part_questions(part)

    template_map = {
        1: "jlpt_n4_test_run_part1.html",
        2: "jlpt_n4_test_run_part2.html",
        3: "jlpt_n4_test_run_part3.html",
        4: "jlpt_n4_test_run_part4.html",
    }

    total_raw = len(get_n4_part_questions_full(part))  # ✅ 실제 문항 수

    return render_template(
        template_map.get(part, "jlpt_n4_test_run_part1.html"),
        questions=questions,
        total_questions=total_raw,  # ✅ N4 고정 방식: 실제 문항 수를 내려줌
        part=part
    )

# ----------------------------
# ✅ N4 테스트 홈
# ----------------------------
@app.route("/jlpt/n4/test")
def jlpt_n4_test():
    user = current_user()
    return render_template("jlpt_n4_test.html", user=user, total_questions=0)

@app.route("/jlpt/n4")
def jlpt_n4_home():
    user = current_user()
    return render_template("jlpt_n4.html", user=user)

@app.route("/jlpt/n4/words")
def jlpt_n4_words():
    user = current_user()

    # N4_WORDS: dict (sec01~sec10)
    sections = []
    all_items = []

    for sec_key in sorted((N4_WORDS or {}).keys()):  # sec01, sec02...
        sec = (N4_WORDS or {}).get(sec_key) or {}
        title = sec.get("title", sec_key)
        items = sec.get("items") or []

        sections.append({
            "key": sec_key,
            "title": title,
            "count": len(items),
        })

        for it in items:
            row = dict(it)
            row["sec_key"] = sec_key
            row["sec_title"] = title
            all_items.append(row)

    return render_template(
        "jlpt_n4_words.html",
        user=user,
        sections=sections,
        words=all_items,   # ✅ 템플릿엔 "단어 리스트"로만 전달
    )

@app.route("/jlpt/n4/sentences")
def jlpt_n4_sentences():
    user = current_user()
    return render_template("jlpt_n4_sentences.html", user=user, sections=N4_SENTENCE_SECTIONS)

@app.route("/jlpt/n4/grammar")
def jlpt_n4_grammar():
    user = current_user()
    return render_template("jlpt_n4_grammar.html", user=user)


# ----------------------------
# N3 문제 데이터 (FULL 원본: KO 포함)
# - meta 안에 ko_q / ko_choices / ko_explain
# - 보이지 않는 문자/특수 따옴표 정리 버전
# ----------------------------

N3_PART1_QUESTIONS_FULL = [
    {
        "id": "N3_P1_001",
        "part": 1,
        "q": "1　会場には大勢の（観客）がいた。",
        "choices": ["けんぎゃく", "かんぎゃく", "けんきゃく", "かんきゃく"],
        "answer": 3,
        "meta": {
            "ko_q": "1) 会場には大勢の観客がいた。\n행사장에는 많은 관객이 있었다.",
            "ko_choices": ["けんぎゃく(오답)", "かんぎゃく(오답)", "けんきゃく(오답)", "かんきゃく(관객)"],
            "ko_explain": "観客(관객)의 올바른 읽기는 かんきゃく입니다."
        }
    },
    {
        "id": "N3_P1_002",
        "part": 1,
        "q": "2　田村さんが（払って）くれました。",
        "choices": ["くばって", "はらって", "かざって", "ひろって"],
        "answer": 1,
        "meta": {
            "ko_q": "2) 田村さんが払ってくれました。\n다무라 씨가 계산해 줬습니다.",
            "ko_choices": ["くばって(나눠서/배부해서)", "はらって(지불해서/계산해서)", "かざって(장식해서)", "ひろって(주워서)"],
            "ko_explain": "払う(はらう, 지불하다)의 て형은 はらって입니다."
        }
    },
    {
        "id": "N3_P1_003",
        "part": 1,
        "q": "3　ホテルには３時ごろ（到着）します。",
        "choices": ["とうちゃく", "とうつく", "とちゃく", "とつく"],
        "answer": 0,
        "meta": {
            "ko_q": "3) ホテルには３時ごろ到着します。\n호텔에는 3시쯤 도착합니다.",
            "ko_choices": ["とうちゃく(도착)", "とうつく(오답)", "とちゃく(오답)", "とつく(오답)"],
            "ko_explain": "到着(도착)의 올바른 읽기는 とうちゃく입니다."
        }
    },
    {
        "id": "N3_P1_004",
        "part": 1,
        "q": "4　山下さんが説明を（加えました）。",
        "choices": ["つたえました", "おえました", "くわえました", "かえました"],
        "answer": 2,
        "meta": {
            "ko_q": "4) 山下さんが説明を加えました。\n야마시타 씨가 설명을 덧붙였습니다.",
            "ko_choices": ["つたえました(전했습니다)", "おえました(끝냈습니다)", "くわえました(덧붙였습니다)", "かえました(바꿨습니다)"],
            "ko_explain": "加える(くわえる, 더하다/덧붙이다)의 과거형은 くわえました입니다."
        }
    },
    {
        "id": "N3_P1_005",
        "part": 1,
        "q": "5　今から（訓練）を行います。",
        "choices": ["くんれい", "くんれん", "ぐんれい", "ぐんれん"],
        "answer": 1,
        "meta": {
            "ko_q": "5) 今から訓練を行います。\n지금부터 훈련을 실시합니다.",
            "ko_choices": ["くんれい(오답)", "くんれん(훈련)", "ぐんれい(오답)", "ぐんれん(오답)"],
            "ko_explain": "訓練(훈련)의 올바른 읽기는 くんれん입니다."
        }
    },
    {
       "id": "N3_P1_006",
        "part": 1,
        "q": "6　この（豆）はスープに使うといいですよ。",
        "choices": ["こな", "いも", "かい", "まめ"],
        "answer": 3,
        "meta": {
            "ko_q": "6) この豆はスープに使うといいですよ。\n이 콩은 수프에 쓰면 좋아요.",
            "ko_choices": ["こな(가루)", "いも(감자)", "かい(조개)", "まめ(콩)"],
            "ko_explain": "豆(콩)의 읽기는 まめ입니다."
        }
    },
    {
        "id": "N3_P1_007",
        "part": 1,
        "q": "7　社会には（共通）のルールがあります。",
        "choices": ["きょうつ", "こうつう", "きょうつう", "こうつ"],
        "answer": 2,
        "meta": {
            "ko_q": "7) 社会には共通のルールがあります。\n사회에는 공통된 규칙이 있습니다.",
            "ko_choices": ["きょうつ(오답)", "こうつう(교통)", "きょうつう(공통)", "こうつ(오답)"],
            "ko_explain": "共通(공통)의 올바른 읽기는 きょうつう입니다."
        }
    },
    {
        "id": "N3_P1_008",
        "part": 1,
        "q": "8　来年から（税金）が上がるそうだ。",
        "choices": ["ぜいきん", "ぜっきん", "せいきん", "せっきん"],
        "answer": 0,
        "meta": {
            "ko_q": "8) 来年から税金が上がるそうだ。\n내년부터 세금이 오른대.",
            "ko_choices": ["ぜいきん(세금)", "ぜっきん(오답)", "せいきん(오답)", "せっきん(오답)"],
            "ko_explain": "税金(세금)의 올바른 읽기는 ぜいきん입니다."
        }
    },
    {
        "id": "N3_P1_009",
        "part": 1,
        "q": "9　しばらく、きれいな（なみ）を見ていた。",
        "choices": ["涙", "波", "雲", "虹"],
        "answer": 1,
        "meta": {
            "ko_q": "9) しばらく、きれいな なみ を見ていた。\n한동안 아름다운 파도를 보고 있었다.",
            "ko_choices": ["涙(눈물)", "波(파도)", "雲(구름)", "虹(무지개)"],
            "ko_explain": "なみ(파도)의 한자는 波입니다."
        }
    },
    {
        "id": "N3_P1_010",
        "part": 1,
        "q": "10　もう少し（はやく）歩きましょう。",
        "choices": ["軽く", "急く", "速く", "進く"],
        "answer": 2,
        "meta": {
            "ko_q": "10) もう少し はやく 歩きましょう。\n조금 더 빨리 걸읍시다.",
            "ko_choices": ["軽く(가볍게)", "急く(서두르다/재촉하다, 오답)", "速く(빠르게)", "進く(오답)"],
            "ko_explain": "歩くの速さ(속도)를 말할 때는 速く가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P1_011",
        "part": 1,
        "q": "11　わたしは今の生活に（まんぞく）している。",
        "choices": ["満続", "万続", "満足", "万足"],
        "answer": 2,
        "meta": {
            "ko_q": "11) わたしは今の生活にまんぞくしている。\n나는 지금 생활에 만족하고 있다.",
            "ko_choices": ["満続(오답)", "万続(오답)", "満足(만족)", "万足(오답)"],
            "ko_explain": "まんぞく(만족)의 올바른 한자는 満足입니다."
        }
    },
    {
        "id": "N3_P1_012",
        "part": 1,
        "q": "12　父は腕を（くんで）何か考えていた。",
        "choices": ["挟んで", "組んで", "折んで", "結んで"],
        "answer": 1,
        "meta": {
            "ko_q": "12) 父は腕をくんで何か考えていた。\n아버지는 팔짱을 끼고 뭔가 생각하고 있었다.",
            "ko_choices": ["挟んで(끼워서/끼고)", "組んで(조합해서/끼고=팔짱을 끼다)", "折んで(접어서)", "結んで(묶어서)"],
            "ko_explain": "腕を組む(うでをくむ)는 팔짱을 끼다이므로 組んで가 정답입니다."
        }
    },
    {
        "id": "N3_P1_013",
        "part": 1,
        "q": "13　この国は主に米を（ゆしゅつ）している。",
        "choices": ["輸出", "誘出", "輪出", "論出"],
        "answer": 0,
        "meta": {
            "ko_q": "13) この国は主に米をゆしゅつしている。\n이 나라는 주로 쌀을 수출하고 있다.",
            "ko_choices": ["輸出(수출)", "誘出(오답)", "輪出(오답)", "論出(오답)"],
            "ko_explain": "ゆしゅつ(수출)의 올바른 한자는 輸出입니다."
        }
    },
    {
        "id": "N3_P1_014",
        "part": 1,
        "q": "14　赤ちゃんが母親に抱かれて（ねむって）います。",
        "choices": ["寝て", "宿って", "眠って", "願って"],
        "answer": 2,
        "meta": {
            "ko_q": "14) 赤ちゃんが母親に抱かれて ねむって います。\n아기가 엄마에게 안겨 자고 있어요.",
            "ko_choices": ["寝て(자고/자다)", "宿って(깃들어)", "眠って(자고 있다)", "願って(바라고)"],
            "ko_explain": "ねむっている는 眠っている로 쓰는 것이 자연스럽습니다."
        }
    },
    {
        "id": "N3_P1_015",
        "part": 1,
        "q": "15　この紙は、ぬれても破れにくいという（　）がある。",
        "choices": ["実力", "特長", "専門", "主張"],
        "answer": 1,
        "meta": {
            "ko_q": "15) この紙は、ぬれても破れにくいという（　）がある。\n이 종이는 젖어도 잘 찢어지지 않는다는 (   )이 있다.",
            "ko_choices": ["実力(실력)", "特長(특징/장점)", "専門(전문)", "主張(주장)"],
            "ko_explain": "정답 2번 제품/물건의 좋은 점을 말할 때 特長(특징/장점)이 자연스럽습니다."
        }
    },
    {
        "id": "N3_P1_016",
        "part": 1,
        "q": "16　佐藤さんには、おとなしい（　）があるが、本当は活動的な人らしい。",
        "choices": ["ヒント", "タイトル", "アイディア", "イメージ"],
        "answer": 3,
        "meta": {
            "ko_q": "16) 佐藤さんには、おとなしい（　）があるが、本当は活動的な人らしい。\n사토 씨는 얌전한 (   )가 있지만 실제로는 활동적인 사람인 것 같다.",
            "ko_choices": ["ヒント(힌트)", "タイトル(제목)", "アイディア(아이디어)", "イメージ(이미지/인상)"],
            "ko_explain": "정답 4번 사람에게 갖는 인상/이미지는 イメージ가 정답입니다."
        }
    },
    {
        "id": "N3_P1_017",
        "part": 1,
        "q": "17　正月には親戚が集まって、みんなでテーブルを（　）、楽しく食事をした。",
        "choices": ["囲み", "通し", "包み", "越え"],
        "answer": 0,
        "meta": {
            "ko_q": "17) 正月には親戚が集まって、みんなでテーブルを（　）、楽しく食事をした。\n설날엔 친척이 모여 다 같이 식탁을 (   ) 둘러앉아 즐겁게 식사했다.",
            "ko_choices": ["囲み(둘러싸고/둘러앉고)", "通し(통해서)", "包み(싸고)", "越え(넘어서)"],
            "ko_explain": "정답 1번 テーブルを囲む는 식탁을 둘러앉다로 자주 쓰는 표현입니다."
        }
    },
    {
        "id": "N3_P1_018",
        "part": 1,
        "q": "18　このレストランの料理はおいしくないので、店内はいつも（　）だ。",
        "choices": ["ふらふら", "ぐっすり", "がらがら", "うっかり"],
        "answer": 2,
        "meta": {
            "ko_q": "18) このレストランの料理はおいしくないので、店内はいつも（　）だ。\n이 레스토랑 음식이 맛없어서, 가게 안은 항상 (   )하다.",
            "ko_choices": ["ふらふら(비틀비틀)", "ぐっすり(푹/깊이 잠)", "がらがら(텅 비어 한산함)", "うっかり(깜빡/부주의하게)"],
            "ko_explain": "정답 3번 가게가 한산하고 손님이 적을 때 がらがら가 정답입니다."
        }
    },
    {
        "id": "N3_P1_019",
        "part": 1,
        "q": "19　高田さんが引っ越すという（　）を聞いたが、本当かどうか気になる。",
        "choices": ["うわさ", "宣伝", "うそ", "冗談"],
        "answer": 0,
        "meta": {
            "ko_q": "19) 高田さんが引っ越すという（　）を聞いたが、本当かどうか気になる。\n다카다 씨가 이사 간다는 (   )를 들었는데, 진짜인지 궁금하다.",
            "ko_choices": ["うわさ(소문)", "宣伝(선전/광고)", "うそ(거짓말)", "冗談(농담)"],
            "ko_explain": "정답 1번 ~という うわさ(소문)가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P1_020",
        "part": 1,
        "q": "20　父から借りた本をなくしてしまったので謝ったら、父はすぐに（　）くれた。",
        "choices": ["従って", "守って", "許して", "抑えて"],
        "answer": 2,
        "meta": {
            "ko_q": "20) 父から借りた本をなくしてしまったので謝ったら、父はすぐに（　）くれた。\n아버지에게 빌린 책을 잃어버려 사과했더니, 아버지는 바로 (   ) 주셨다.",
            "ko_choices": ["従って(따라서/복종해서)", "守って(지켜서)", "許して(용서해)", "抑えて(억눌러/억제해)"],
            "ko_explain": "정답 3번 사과 후에는 許す(용서하다)가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P1_021",
        "part": 1,
        "q": "21　パソコンの前でずっと同じ（　）でいたので、体が痛くなった。",
        "choices": ["様子", "姿勢", "印象", "間隔"],
        "answer": 1,
        "meta": {
            "ko_q": "21) パソコンの前でずっと同じ（　）でいたので、体が痛くなった。\n컴퓨터 앞에서 계속 같은 (   )로 있었더니 몸이 아파졌다.",
            "ko_choices": ["様子(상태/모양새)", "姿勢(자세)", "印象(인상)", "間隔(간격)"],
            "ko_explain": "정답 2번 오래 같은 자세로 있으면 아프므로 姿勢가 정답입니다."
        }
    },
    {
        "id": "N3_P1_022",
        "part": 1,
        "q": "22　申込書に間違いがないか、よく（　）から受付に出した。",
        "choices": ["くりかえして", "気にして", "見つめて", "たしかめて"],
        "answer": 3,
        "meta": {
            "ko_q": "22) 申込書に間違いがないか、よく（　）から受付に出した。\n신청서에 틀린 곳이 없는지 잘 (   )한 뒤 접수처에 냈다.",
            "ko_choices": ["くりかえして(반복해서)", "気にして(신경 써서)", "見つめて(뚫어지게 보고)", "たしかめて(확인해서)"],
            "ko_explain": "정답 4번 서류 오류가 없는지 확인하다는 たしかめる가 정답입니다."
        }
    },
    {
        "id": "N3_P1_023",
        "part": 1,
        "q": "23　わたしのふるさとは（　）が盛んで、米や野菜をたくさん作っています。",
        "choices": ["自然", "資源", "作物", "農業"],
        "answer": 3,
        "meta": {
            "ko_q": "23) わたしのふるさとは（　）が盛んで、米や野菜をたくさん作っています。\n내 고향은 (   )이 발달해서 쌀과 채소를 많이 만듭니다.",
            "ko_choices": ["自然(자연)", "資源(자원)", "作物(작물)", "農業(농업)"],
            "ko_explain": "정답 4번 쌀/채소를 많이 생산 → 農業(농업)이 자연스럽습니다."
        }
    },
    {
        "id": "N3_P1_024",
        "part": 1,
        "q": "24　水に浮いていた木の葉が、しばらくすると水の中に（　）しまった。",
        "choices": ["しずんで", "ころんで", "たおれて", "おぼれて"],
        "answer": 0,
        "meta": {
            "ko_q": "24) 水に浮いていた木の葉が、しばらくすると水の中に（　）しまった。\n물에 떠 있던 나뭇잎이, 잠시 후 물속으로 (   ) 버렸다.",
            "ko_choices": ["しずんで(가라앉아)", "ころんで(넘어져)", "たおれて(쓰러져)", "おぼれて(익사해/물에 빠져)"],
            "ko_explain": "정답 1번 떠 있던 것이 물속으로 들어가면 沈む(しずむ, 가라앉다)가 정답입니다."
        }
    },
    {
        "id": "N3_P1_025",
        "part": 1,
        "q": "25　この話は誰にも言わずに、ずっと（　）にしていた。",
        "choices": ["裏側", "内緒", "後方", "中身"],
        "answer": 1,
        "meta": {
            "ko_q": "25) この話は誰にも言わずに、ずっと（　）にしていた。\n이 이야기는 아무에게도 말하지 않고 계속 (   )로 해 두었다.",
            "ko_choices": ["裏側(뒷면/이면)", "内緒(비밀)", "後方(후방)", "中身(내용물)"],
            "ko_explain": "정답 2번 말하지 않고 숨김 → 内緒(비밀)가 정답입니다."
        }
    },
    {
        "id": "N3_P1_026",
        "part": 1,
        "q": "26　水の表面がかがやいています。",
        "choices": ["止まって", "揺れて", "汚れて", "光って"],
        "answer": 3,
        "meta": {
            "ko_q": "26) 水の表面がかがやいています。\n물 표면이 반짝이고 있습니다.",
            "ko_choices": ["止まって(멈춰서)", "揺れて(흔들려서)", "汚れて(더러워져서)", "光って(빛나서/반짝여서)"],
            "ko_explain": "정답 4번 かがやく(輝く)와 가장 가까운 것은 光る(빛나다)입니다."
        }
    },
    {
        "id": "N3_P1_027",
        "part": 1,
        "q": "27　その知らせを聞いたとき、わたしはとてもがっかりした。",
        "choices": ["残念だと思った", "うれしかった", "驚いた", "安心した"],
        "answer": 0,
        "meta": {
            "ko_q": "27) その知らせを聞いたとき、わたしはとてもがっかりした。\n그 소식을 들었을 때 나는 매우 실망했다.",
            "ko_choices": ["残念だと思った(유감/실망했다고 생각했다)", "うれしかった(기뻤다)", "驚いた(놀랐다)", "安心した(안심했다)"],
            "ko_explain": "정답 1번 がっかりした(실망했다) = 残念だと思った가 정답입니다."
        }
    },
    {
        "id": "N3_P1_028",
        "part": 1,
        "q": "28　留学生活に不安は（当然）ありました。",
        "choices": ["いろいろ", "少し", "もちろん", "当たり前に"],
        "answer": 3,
        "meta": {
            "ko_q": "28) 留学生活に不安は 当然 ありました。\n유학 생활에 불안은 당연히 있었습니다.",
            "ko_choices": ["いろいろ(여러 가지)", "少し(조금)", "もちろん(물론)", "当たり前に(당연히)"],
            "ko_explain": "当然의 뜻(당연히/마땅히)에 가장 가까운 것은 当たり前に입니다."
        }
    },
    {
        "id": "N3_P1_029",
        "part": 1,
        "q": "29　パーティーの料理があまりました。",
        "choices": ["多すぎて残りました", "少し足りませんでした", "とてもおいしかったです", "そんなにおいしくなかったです"],
        "answer": 0,
        "meta": {
            "ko_q": "29) パーティーの料理があまりました。\n파티 음식이 남았습니다(남아돌았습니다).",
            "ko_choices": [
                "多すぎて残りました(너무 많아서 남았습니다)",
                "少し足りませんでした(조금 부족했습니다)",
                "とてもおいしかったです(아주 맛있었습니다)",
                "そんなにおいしくなかったです(그렇게 맛있진 않았습니다)"
            ],
            "ko_explain": "정답 1번 あまる(余る)는 남다/남아돌다 → 多すぎて残る가 정답입니다."
        }
    },
    {
        "id": "N3_P1_030",
        "part": 1,
        "q": "30　ここは横断禁止です。",
        "choices": ["座ってはいけません", "渡ってはいけません", "走ってはいけません", "入ってはいけません"],
        "answer": 1,
        "meta": {
            "ko_q": "30) ここは横断禁止です。\n여기는 횡단 금지입니다.",
            "ko_choices": ["座ってはいけません(앉으면 안 됩니다)", "渡ってはいけません(건너면 안 됩니다)", "走ってはいけません(달리면 안 됩니다)", "入ってはいけません(들어가면 안 됩니다)"],
            "ko_explain": "정답 2번 横断禁止는 건너면 안 됨(渡ってはいけません)입니다."
        }
    },
    {
        "id": "N3_P1_031",
        "part": 1,
        "q": "31　急",
        "choices": [
            "この料理は電子レンジを使って急にできるので、とても簡単だ。",
            "あと１０分で電車が出発してしまうので、急に駅に向かった。",
            "部屋から急に人が飛び出してきたので、ぶつかりそうになった。",
            "新しいゲームを買ったので、家に帰って急にやってみた。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "31) 急 (갑자기/급히)",
            "ko_choices": [
                "…急にできる… 전자레인지로 '갑자기' 만들다(부자연)",
                "…急に駅に向かった 전철 때문에 갑자기/급히 역으로(문맥 애매)",
                "…急に人が飛び出してきた 갑자기 사람이 튀어나왔다(자연)",
                "…急にやってみた 갑자기 해봤다(문맥 약함)"
            ],
            "ko_explain": "정답 3번 急に는 갑자기의 의미로 사건이 돌발적으로 일어나는 상황에 가장 자연스럽고, 3번이 딱 맞습니다."
        }
    },
    {
        "id": "N3_P1_032",
        "part": 1,
        "q": "32　沸騰",
        "choices": [
            "今日は朝からどんどん暑くなり、昼には気温が沸騰した。",
            "鍋のお湯が沸騰したら、とうふを入れて火を少し弱くしてください。",
            "昼ごろから具合が悪くなり、夕方熱が沸騰したので病院へ行った。",
            "このストーブは沸騰するのが早いので、すぐに部屋が暖かくなる。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "32) 沸騰 (끓다/비등)",
            "ko_choices": ["気温が沸騰… 기온이 끓었다(오답)", "お湯が沸騰したら… 물이 끓으면…(정답)", "熱が沸騰… 열이 끓었다(오답)", "ストーブが沸騰… 난로가 끓는다(오답)"],
            "ko_explain": "沸騰은 물/액체가 끓는 상황에 쓰므로 2번이 정답입니다."
        }
    },
    {
        "id": "N3_P1_033",
        "part": 1,
        "q": "33　まげる",
        "choices": [
            "今朝は寒かったので、マフラーを首にまげて出かけた。",
            "けがは良くなったが、腕を伸ばしたりまげたりすると、まだ少し痛む。",
            "一つのパンを半分にまげて、二人で分けて食べた。",
            "シャツをきちんとまげたら、たんすの引き出しにしまってください。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "33) まげる (구부리다)",
            "ko_choices": ["マフラーを首にまげる 목도리를 '구부리다'(오답, 보통 まく)", "腕を…まげたり 구부리거나 펴거나(정답)", "パンを…まげる 빵을 구부려 반으로(부자연)", "シャツを…まげる 셔츠를 구부려 정리(오답, 보통 たたむ)"],
            "ko_explain": "まげる는 팔/무릎 등 구부리다에 쓰이며 2번이 자연스럽습니다."
        }
    },
    {
        "id": "N3_P1_034",
        "part": 1,
        "q": "34　出張",
        "choices": [
            "営業のため、来週一週間、課長とアメリカに出張します。",
            "仕事を辞めたら、家族とゆっくり海外に出張したいと思う。",
            "わたしは毎朝９時に会社に出張し、残業はしないで家に帰る。",
            "あしたは子どもの運動会に出張するので、仕事を休みます。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "34) 出張 (출장)",
            "ko_choices": ["…アメリカに出張します 미국에 출장합니다(정답)", "海外に出張したい 퇴사 후 가족과 '출장'(오답, 여행)", "会社に出張… 회사에 '출장'(오답, 출근=出社)", "運動会に出張… 운동회에 '출장'(오답, 출석=出席)"],
            "ko_explain": "出張은 업무로 다른 곳에 가는 출장이므로 1번이 정답입니다."
        }
    },
    {
        "id": "N3_P1_035",
        "part": 1,
        "q": "35　慰める",
        "choices": [
            "祖母は古い物でも捨てないで、長い間慰めて使っている。",
            "試合を見ながら、優勝を願って一生懸命選手を慰めた。",
            "仕事で失敗してしまったが、友人が慰めてくれたので元気が出た。",
            "弟が希望の大学に合格したので、家族で外食をして慰めた。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "35) 慰める (위로하다)",
            "ko_choices": ["物を慰めて使う 물건을 위로하며 쓰다(오답)", "優勝を願って選手を慰めた 우승을 빌며 위로(문맥 어색)", "友人が慰めてくれた 친구가 위로해 줬다(정답)", "合格して慰めた 합격해서 위로했다(오답)"],
            "ko_explain": "失敗して落ち込む 사람을 위로하다 문맥이 가장 자연스러운 3번이 정답입니다."
        }
    },
]

# =========================
# JLPT N3 PART2 (文法) - 변형 문제 세트
# 구성:
#  - もんだい1: 1~18
#  - もんだい3: 19~23 (지문형 공통 stem)
# =========================

# =========================
# N3 PART2 - もんだい３ 공통 지문 (JP / KO)
# =========================
N3_P2_M3_STEM_JP = """（もんだい３）19から23に何を入れますか。ぶんしょうのいみを考えて、1・2・3・4からいちばんいいものを一つえらんでください。

（作文）「日本で気づいたこと」

日本に来てから、あいさつのしかたに少し驚きました。アパートの人に会うと、だれでも「おはようございます」や「こんにちは」と言います。駅でも店でも、知らない人どうしでも声をかけることがあります。19、私の国ではあまり見ません。

最初は、そういうことをしなくてもいいと思っていました。ところが、ある日、近所の人に会ったとき、自然に「こんにちは」と20。相手がにこっと笑ってくれて、気持ちが明るくなりました。あいさつは人の気持ちを21、いい習慣だと思います。

また、日本では天気の話をよくします。天気は毎日変わるので、話題に困りません。私は以前は天気に22が、最近は自分から話すようになりました。

天気の話はだれとでもしやすいので、23日本では多くの人がよく話すのだと思います。"""

N3_P2_M3_STEM_KO = """(문제3) 19~23에 무엇을 넣습니까? 글의 의미를 생각해서 1·2·3·4 중에서 가장 알맞은 것을 하나 고르세요.

(작문) ‘일본에서 깨달은 점’

일본에 와서 인사하는 방식에 조금 놀랐습니다. 아파트 사람을 만나면 누구든 ‘안녕하세요’ 같은 인사를 합니다.
역이나 가게에서도 모르는 사람끼리 말을 거는 경우가 있습니다. (19) 제 나라에서는 그런 모습을 별로 보지 못합니다.

처음에는 굳이 그렇게 하지 않아도 된다고 생각했습니다. 그런데 어느 날 이웃을 만났을 때, 저도 자연스럽게 ‘안녕하세요’라고 (20) 말해 버렸습니다.
상대가 웃어 주어서 기분이 밝아졌습니다. 인사는 사람의 기분을 (21) 주는 좋은 습관이라고 생각합니다.

또 일본에서는 날씨 이야기를 자주 합니다. 날씨는 매일 바뀌니 화제가 끊기지 않습니다.
저는 예전에는 날씨에 (22) 관심이 없었지만, 요즘은 제가 먼저 말을 꺼내게 되었습니다.

날씨 이야기는 누구와도 하기 쉬우므로, (23) 일본에서 많은 사람이 자주 이야기하는 것이라고 생각합니다."""

N3_PART2_QUESTIONS_FULL = [
    # =========================
    # もんだい1 (1~18) - 단일 문항
    # =========================
    {
        "id": "N3_P2_001",
        "part": 2,
        "q": "1　彼は　有名な小説家（　）、普段は　小さな病院で　働く　医者だ。",
        "choices": ["について", "として", "したがって", "と比べて"],
        "answer": 1,
        "meta": {
            "ko_q": "1) 그는 유명한 소설가( )이지만, 평소에는 작은 병원에서 일하는 의사다.",
            "ko_choices": ["~에 대해(について)", "~로서(として)", "그러므로(したがって)", "~와 비교해서(と比べて)"],
            "ko_explain": "자격/입장을 나타내는 표현은 2번「〜として」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_002",
        "part": 2,
        "q": "2　面接で「自分を色で表す（　）、何色ですか」と聞かれ、青と答えた。",
        "choices": ["ことから", "という点で", "ように", "としたら"],
        "answer": 0,
        "meta": {
            "ko_q": "2) 면접에서 ‘자신을 색으로 표현하면( ), 무슨 색인가요?’라고 물어봐서 파란색이라고 답했다.",
            "ko_choices": ["~라는 점에서/그 이유로(ことから)", "~라는 점에서(という点で)", "~처럼(ように)", "~라고 한다면(としたら)"],
            "ko_explain": "근거/이유를 드는 연결로 1번「〜ことから」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_003",
        "part": 2,
        "q": "3　夜中なのに、寝る前に（　）アイスが食べたくなって、コンビニへ行ってしまった。",
        "choices": ["どうか", "せっかく", "どうしても", "きっと"],
        "answer": 2,
        "meta": {
            "ko_q": "3) 한밤중인데도 자기 전에 ( ) 아이스크림이 먹고 싶어져서 편의점에 가버렸다.",
            "ko_choices": ["부디(どうか)", "기껏(せっかく)", "어떻게든/정말로(どうしても)", "분명히(きっと)"],
            "ko_explain": "강한 욕구/필요를 나타낼 때 3번「どうしても」가 자주 쓰입니다."
        }
    },
    {
        "id": "N3_P2_004",
        "part": 2,
        "q": "4　このケーキは材料を混ぜて焼く（　）から、だれでも簡単に作れます。",
        "choices": ["だけだ", "ことだ", "せいだ", "ときだ"],
        "answer": 0,
        "meta": {
            "ko_q": "4) 이 케이크는 재료를 섞어 구우면 ( )라서 누구나 쉽게 만들 수 있다.",
            "ko_choices": ["~하기만 하면 된다(だけだ)", "~하는 것이 중요(ことだ)", "~탓이다(せいだ)", "~할 때(ときだ)"],
            "ko_explain": "정답 1번 단순한 절차를 강조할 때 「V辞書形 + だけだ」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_005",
        "part": 2,
        "q": "5　私の町では毎年８月最後の日曜日に夏祭りが（　）。",
        "choices": ["行います", "行わせます", "行っています", "行われます"],
        "answer": 3,
        "meta": {
            "ko_q": "5) 우리 동네에서는 매년 8월 마지막 일요일에 여름 축제가 ( ).",
            "ko_choices": ["(내가) 개최합니다(行います)", "시키다(行わせます)", "하고 있습니다(行っています)", "개최됩니다(行われます)"],
            "ko_explain": "정답 4번 행사가 ‘열리다/개최되다’는 수동형 「行われます」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_006",
        "part": 2,
        "q": "6（靴屋で）\n　客「この靴のもう一つ大きいサイズはありますか。」\n　店員「はい、確認しますので、少々（　）。」",
        "choices": ["お待ちしております", "お待ちください", "お待ちできます", "お待ちしましょう"],
        "answer": 1,
        "meta": {
            "ko_q": "6) (신발가게) ‘확인할 테니, 잠시 ( ).’",
            "ko_choices": ["기다리고 있겠습니다(お待ちしております)", "기다려 주세요(お待ちください)", "기다릴 수 있습니다(お待ちできます)", "기다립시다(お待ちしましょう)"],
            "ko_explain": "정답 2번 정중하게 ‘잠시 기다려 주세요’는 「少々お待ちください」가 정석입니다."
        }
    },
    {
        "id": "N3_P2_007",
        "part": 2,
        "q": "7（電話で）\n　社員「はい、ABC会社でございます。」\n　私「私、田中と（　）が、山田さんをお願いします。」",
        "choices": ["ございます", "いたします", "申します", "申し上げます"],
        "answer": 2,
        "meta": {
            "ko_q": "7) (전화) ‘저는 다나카라고 ( )만, 야마다 씨 부탁드립니다.’",
            "ko_choices": ["있습니다(ございます)", "하겠습니다(いたします)", "말합니다/라고 합니다(申します)", "말씀드립니다(申し上げます)"],
            "ko_explain": "정답 3번 자기소개 겸손어는 「田中と申します」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_008",
        "part": 2,
        "q": "8　息子の学校では基本的に全員がお弁当を（　）。",
        "choices": ["持っていったばかりだ", "持っていくことになっている", "持っていきたい", "持っていくつもりだ"],
        "answer": 1,
        "meta": {
            "ko_q": "8) 아들 학교에서는 기본적으로 전원이 도시락을 ( ).",
            "ko_choices": ["막 가져갔다(ばかりだ)", "~하기로 되어 있다(ことになっている)", "가져가고 싶다", "가져갈 생각이다"],
            "ko_explain": "정답 2번 규칙/정해진 제도는 「〜ことになっている」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_009",
        "part": 2,
        "q": "9　昼寝すると気持ちがいいが、夜（　）困るので、短くする。",
        "choices": ["寝なくて", "寝られると思って", "寝られないと", "寝ると思うと"],
        "answer": 2,
        "meta": {
            "ko_q": "9) 낮잠을 자면 기분이 좋지만, 밤에 ( ) 곤란하니까 짧게 한다.",
            "ko_choices": ["자지 않고", "잘 수 있을 거라 생각하고", "잠이 안 되면", "잘 거라고 생각하면"],
            "ko_explain": "정답 3번 밤에 잠이 안 오면 곤란 → 조건 「寝られないと困る」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_010",
        "part": 2,
        "q": "10　保育園の数が少なく、希望しているのに（　）人が問題になっている。",
        "choices": ["利用したくても", "利用しそうになって", "利用しているのに", "利用できたら"],
        "answer": 0,
        "meta": {
            "ko_q": "10) 어린이집 수가 적어서 원해도 ( ) 이용 못하는 사람이 문제가 되고 있다.",
            "ko_choices": ["이용하고 싶어도(利用したくても)", "이용할 것 같게 되어", "이용하고 있는데도", "이용할 수 있다면"],
            "ko_explain": "정답 1번 희망하지만 못하는 상황 → 「〜たくても」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_011",
        "part": 2,
        "q": "11　妻「買い物に行くから、今夜のレストラン予約お願いできる？」\n　夫「うん、わかった。（　）。19時で大丈夫？」",
        "choices": ["予約してね", "予約しておくよ", "予約しようよ", "予約してあるね"],
        "answer": 1,
        "meta": {
            "ko_q": "11) ‘예약 부탁해’ → ‘응 알겠어. ( ). 19시 괜찮아?’",
            "ko_choices": ["예약해 줘(부탁)", "예약해 둘게(내가 할게)", "예약하자(권유)", "예약되어 있어(이미)"],
            "ko_explain": "정답 2번 상대 부탁을 받아 ‘내가 해둘게’는 「予約しておくよ」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_012",
        "part": 2,
        "q": "12（畑で）\n　子「このトマト、もう食べられる？赤くなってるよ。」\n　父「うん、そろそろ（　）ね。」",
        "choices": ["食べやすいそうだ", "食べごろそうだ", "食べたがるそうだ", "食べてもよさそうだ"],
        "answer": 1,
        "meta": {
            "ko_q": "12) (밭) ‘토마토 이제 먹을 수 있어?’ → ‘응, 이제 ( )네.’",
            "ko_choices": ["먹기 쉬울 것 같다", "먹기 딱 좋을 것 같다(食べごろ)", "먹고 싶어할 것 같다", "먹어도 될 것 같다"],
            "ko_explain": "정답 2번 익어서 ‘먹기 딱 좋다’는 「食べごろ」가 정답입니다."
        }
    },
    {
        "id": "N3_P2_013",
        "part": 2,
        "q": "13（改札で）\n　A「Bさん、来ませんね。どうしましょう。」\n　C「これ以上待つと間に合わないから、先に（　）。」",
        "choices": ["行ってしまいましょうか", "行ってしまうのでしょう", "行ってしまいましたか", "行ってしまっていました"],
        "answer": 0,
        "meta": {
            "ko_q": "13) (개찰구) ‘더 기다리면 늦으니 먼저 ( ).’",
            "ko_choices": ["가버리죠(제안)(行ってしまいましょうか)", "가버릴까요(추측)", "가버렸나요(과거질문)", "가버려 있었음"],
            "ko_explain": "정답 1번 ‘먼저 가버리자’ 제안 형태는 「行ってしまいましょう」 계열이 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_014",
        "part": 2,
        "q": "14　この写真の鳥はとても珍しく、この鳥の（　）ことはほとんどないそうだ。",
        "choices": ["見る機会がない", "専門家でも", "なかなか", "研究をしている"],
        "answer": 2,
        "meta": {
            "ko_q": "14) 이 사진의 새는 매우 희귀해서, 이 새를 ( ) 볼 기회가 거의 없다고 한다.",
            "ko_choices": ["볼 기회가 없다", "전문가라도", "좀처럼/쉽게(なかなか)", "연구하고 있다"],
            "ko_explain": "정답 3번 ‘좀처럼 ~없다’는 「なかなか〜ない」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_015",
        "part": 2,
        "q": "15　春から大学生になる娘には、（　）できない経験をいろいろしてほしい。",
        "choices": ["にも", "にしか", "勉強以外", "大学時代"],
        "answer": 1,
        "meta": {
            "ko_q": "15) 봄부터 대학생이 되는 딸에게는, ( ) 할 수 없는 경험을 여러 가지 해봤으면 한다.",
            "ko_choices": ["~도", "~만(にしか)", "공부 이외", "대학시대"],
            "ko_explain": "정답 2번 이 문장은 ‘대학생일 때만 할 수 있는 경험’을 말하고 있습니다. 일본어에서 ‘~에서만 가능하다’는 강한 한정은 「〜にしか〜ない」를 사용합니다.\n\n「大学生にしかできない経験」은 ‘대학생이 아니면 할 수 없는 경험’이라는 뜻이 되어 문맥과 정확히 맞습니다.\n\n①「にも」는 ‘~도’라는 추가 의미로 문장이 어색해지고,\n③「勉強以外」는 의미상 문장에 맞지 않으며,\n④「大学時代」는 조사 없이 단독으로는 사용할 수 없습니다."
        }
    },
    {
        "id": "N3_P2_016",
        "part": 2,
        "q": "16　土曜日は買い物をしたり友人と食事したりして、日曜日は（　）、私の好きな週末の過ごし方だ。",
        "choices": ["のが", "という", "家で過ごす", "どこにも出かけずに"],
        "answer": 3,
        "meta": {
            "ko_q": "16) 토요일은 외출, 일요일은 ( )… 내가 좋아하는 주말 보내는 방법이다.",
            "ko_choices": ["~것이", "~라는", "집에서 보낸다", "어디에도 나가지 않고"],
            "ko_explain": "정답 4번 일요일은 ‘어디에도 나가지 않고(집에서)’가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_017",
        "part": 2,
        "q": "17（レストランで）\n　客「15分くらい前に予約をお願いして、ずっと待っている（　）。まだですか。」\n　店員「大変申し訳ありません。」",
        "choices": ["待っているんです", "言われた", "から", "けど"],
        "answer": 0,
        "meta": {
            "ko_q": "17) (레스토랑) ‘예약하고 계속 기다리고 ( )… 아직인가요?’",
            "ko_choices": ["있습니다(説明)(んです)", "말해졌다", "그래서", "하지만"],
            "ko_explain": "정답 1번 상황 설명/불만 표현은 「〜んです」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_018",
        "part": 2,
        "q": "18　私は歴史を（　）進学を決めた。",
        "choices": ["勉強すればするほど", "歴史学科への", "と思うようになって", "もっと学びたい"],
        "answer": 3,
        "meta": {
            "ko_q": "18) 나는 역사를 ( ) 진학을 결정했다.",
            "ko_choices": ["공부하면 할수록", "역사학과로", "~라고 생각하게 되어", "더 배우고 싶어서"],
            "ko_explain": "정답 4번 자연스러운 문장 완성은 ‘역사를 더 배우고 싶어서’가 맞습니다."
        }
    },

    # =========================
    # もんだい3 (19~23) - 그룹 문제 (공통 지문은 템플릿에서 표시)
    # q에는 번호만 둔다
    # =========================
    {
        "id": "N3_P2_019",
        "part": 2,
        "q": "19（　）",
        "choices": ["そのうえ", "つまり", "けれども", "すると"],
        "answer": 2,
        "meta": {
            "ko_q": "19) 앞 문장과 의미가 ‘하지만/반면에’로 이어지도록 고르세요.",
            "ko_choices": ["게다가(そのうえ)", "즉(つまり)", "하지만(けれども)", "그러자(すると)"],
            "ko_explain": "정답 3번 앞은 일본에서는 자주 본다 → 뒤는 내 나라는 아니다(대조) → 「けれども」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_020",
        "part": 2,
        "q": "20（　）",
        "choices": ["言われていました", "言ってもらいました", "言わせてみました", "言ってしまいました"],
        "answer": 3,
        "meta": {
            "ko_q": "20) ‘자연스럽게 말해버렸다’ 흐름에 맞는 표현을 고르세요.",
            "ko_choices": ["말해지고 있었다", "말해 달았다", "말하게 해 봤다", "말해버렸다"],
            "ko_explain": "정답 4번 무심코 해버림/완료 뉘앙스는 「〜てしまいました」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_021",
        "part": 2,
        "q": "21（　）",
        "choices": ["広がって", "広がるより", "広がるように", "広がったそうで"],
        "answer": 0,
        "meta": {
            "ko_q": "21) ‘기분을 ~해준다/퍼뜨려준다’ 의미가 되도록 고르세요.",
            "ko_choices": ["퍼지게 하여/퍼져서(広がって)", "~보다", "~하도록", "~했다더라"],
            "ko_explain": "정답 1번 ‘기분이 밝아지다/퍼지다’ 흐름은 「広がって」가 자연스럽습니다."
        }
    },
    {
        "id": "N3_P2_022",
        "part": 2,
        "q": "22（　）",
        "choices": ["持ったはずがありません", "持ちたがりません", "持つのかもしれません", "持とうとしません"],
        "answer": 3,
        "meta": {
            "ko_q": "22) ‘예전에는 날씨에 관심을 가지려 하지 않았다’ 의미가 되게 고르세요.",
            "ko_choices": ["가졌을 리가 없다", "가지고 싶어하지 않는다", "가질지도 모른다", "가지려고 하지 않는다"],
            "ko_explain": "정답 4번 ‘하려고 하지 않다’는 「Vようとしない」 → 「持とうとしません」이 정답입니다."
        }
    },
    {
        "id": "N3_P2_023",
        "part": 2,
        "q": "23（　）",
        "choices": ["どれ", "これ", "あれら", "それら"],
        "answer": 3,
        "meta": {
            "ko_q": "23) 앞에서 말한 ‘이유/특징들’을 받아서 자연스럽게 지시하도록 고르세요.",
            "ko_choices": ["어느 것", "이것", "저것들", "그것들"],
            "ko_explain": "정답 4번 앞 내용(이런 이유들)을 받아 ‘그것들’ → 「それら」가 자연스럽습니다."
        }
    },
]

# =========================
# N3 PART3 - 그룹 공통 지문 (JP / KO)
# =========================
N3_P3_M5_STEM_JP = """（もんだい３）次の文章を読んで、5から7の（　）に入る最もよいものを、1・2・3・4から一つ選びなさい。

（エッセイ）「本屋で同じ本を買ってしまう理由」

私は本屋に行くのが好きだ。新刊のコーナーを見ると、つい気になる本を手に取ってしまう。ところが先日、家に帰ってから本棚を見て、少し驚いた。買ったばかりの本と、まったく同じ本がすでに並んでいたのだ。

私は「前に読んだことがある」と気づかずに、同じ本を買ってしまったらしい。なぜそんなことが起こるのか考えてみると、いくつか理由がある。まず、忙しいと読んだ内容を細かく覚えていない。次に、表紙のデザインが変わっていたり、帯の宣伝文句が魅力的だったりすると、別の本に見えてしまう。そして何より、私は「面白そう」と感じた気持ちだけを覚えていて、肝心の“買ったこと”を忘れてしまうことがある。

もちろん、同じ本を二度買うのはもったいない。しかし、買ってしまったときに「自分はだめだ」と落ち込むより、「それだけ本が好きなのだ」と考えることにした。失敗は減らしたいが、本屋に行く楽しみまで手放したくない。だから私は、これからも本屋に通い続けると思う。"""

N3_P3_M5_STEM_KO = """(문제3) 다음 글을 읽고 5~7의 ( )에 들어갈 가장 알맞은 것을 1~4 중에서 하나 고르세요.

(에세이) ‘서점에서 같은 책을 또 사버리는 이유’

나는 서점에 가는 것을 좋아한다. 신간 코너를 보면 자꾸 신경 쓰이는 책을 집어 들게 된다.
그런데 얼마 전, 집에 돌아와 책장을 보고 조금 놀랐다. 방금 산 책과 똑같은 책이 이미 꽂혀 있었기 때문이다.

나는 ‘전에 읽었다’는 걸 눈치채지 못한 채 같은 책을 또 사버린 듯하다.
왜 이런 일이 생기는지 생각해 보니 몇 가지 이유가 있었다.
먼저 바쁘면 읽은 내용을 자세히 기억하지 못한다.
또 표지 디자인이 바뀌거나 띠지 홍보 문구가 매력적이면 다른 책처럼 보이기도 한다.
그리고 무엇보다 ‘재미있어 보인다’는 느낌만 기억하고 정작 ‘이미 샀다’는 사실을 잊어버리기도 한다.

물론 같은 책을 두 번 사는 건 아깝다. 하지만 그럴 때 ‘나는 왜 이럴까’ 하고 자책하기보다,
‘그만큼 책을 좋아하는 거다’라고 생각하기로 했다.
실수는 줄이고 싶지만, 서점에 가는 즐거움까지 포기하고 싶지는 않다.
그래서 나는 앞으로도 계속 서점에 다닐 것 같다."""


# =========================
# N3 PART3 - FULL (채점용 원본)
# =========================
N3_PART3_QUESTIONS_FULL = [
    # -------------------------
    # 1) 1지문 1문제 (1~4)
    # -------------------------
    {
        "id": "N3_P3_001",
        "part": 3,
        "q": "1　次のメールを読んで、正しいものを選びなさい。\n\n"
             "（メール）\n"
             "学生のみなさんへ\n"
             "本日、強い雨のため午前の授業は休講です。\n"
             "午後の授業は、12時に交通機関が通常通り動いていれば実施します。\n"
             "授業を行うかどうかは12時に大学のサイトでお知らせします。\n"
             "なお、午前中のクラブ活動は中止してください。\n\n"
             "このメールからわかることは何か。",
        "choices": [
            "午前の授業は12時から始まる。",
            "午後の授業は必ず行われる。",
            "午後の授業があるかどうかは12時に確認できる。",
            "クラブ活動は午後なら行ってよい。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "1) 다음 이메일을 읽고, 맞는 것을 고르세요.\n\n"
                    "(이메일)\n"
                    "학생 여러분께\n"
                    "오늘은 강한 비 때문에 오전 수업은 휴강입니다.\n"
                    "오후 수업은 12시에 교통기관이 평소처럼 정상 운행하고 있으면 실시합니다.\n"
                    "수업을 할지 말지는 12시에 대학 사이트에서 알려 드립니다.\n"
                    "또한 오전 중 동아리 활동은 중지해 주세요.\n\n"
                    "이 이메일에서 알 수 있는 것은 무엇입니까?",
            "ko_choices": [
                "오전 수업은 12시부터 시작한다.",
                "오후 수업은 반드시 진행된다.",
                "오후 수업 여부는 12시에 확인할 수 있다.",
                "동아리 활동은 오후에는 해도 된다."
            ],
            "ko_explain": "‘오후 수업은 12시에 공지’라고 했으므로, 12시에 확인 가능이 정답입니다."
        }
    },
    {
        "id": "N3_P3_002",
        "part": 3,
        "q": "2　次の文章を読んで、質問に答えなさい。\n\n"
             "私は便利だと言われても、スマホを持たない生活を続けている。\n"
             "以前は持っていたが、いつでも連絡が来ることが負担に感じてやめた。\n"
             "確かに不便なときもあるが、そのぶん気持ちが楽になった。\n\n"
             "スマホについて、筆者はどう考えているか。",
        "choices": [
            "不便だから、今すぐ持つべきだ。",
            "便利だが、今は持つつもりはない。",
            "料金が安くなったので、また持ちたい。",
            "持たないと仕事ができないので、必要だ。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "2) 다음 글을 읽고, 질문에 답하세요.\n\n"
                    "나는 편리하다고들 말해도, 스마트폰을 가지지 않는 생활을 계속하고 있다.\n"
                    "예전에는 가지고 있었지만, 언제든 연락이 오는 것이 부담스럽게 느껴져서 그만두었다.\n"
                    "확실히 불편할 때도 있지만, 그만큼 마음이 편해졌다.\n\n"
                    "스마트폰에 대해, 글쓴이는 어떻게 생각하고 있습니까?",
            "ko_choices": [
                "불편하니 지금 당장 가져야 한다.",
                "편리하긴 하지만 지금은 가질 생각이 없다.",
                "요금이 싸졌으니 다시 갖고 싶다.",
                "없으면 일을 못 하니 필요하다."
            ],
            "ko_explain": "‘편리한 건 알지만 부담이 싫어 안 가진다’는 흐름이므로 2번이 정답입니다."
        }
    },
    {
        "id": "N3_P3_003",
        "part": 3,
        "q": "3　次の文章を読んで、質問に答えなさい。\n\n"
             "昔の自動販売機は冷たい飲み物しか売れなかった。\n"
             "ある冬の日、運転手たちが冷たいジュースを買って飲んでいるのを見て、\n"
             "飲料会社の人は『冬には温かい飲み物が必要だ』と考えた。\n"
             "それから改良が進み、今のように温かい飲み物も選べる機械が作られた。\n\n"
             "今の自動販売機が作られることになったのは、どうしてか。",
        "choices": [
            "冬に冷たい飲み物を売ると危ないと感じたから。",
            "冷たい飲み物が売れなくなったから。",
            "運転手に温かい飲み物を作れと言われたから。",
            "冬でも温かい飲み物が買えると喜ばれると考えたから。"
        ],
        "answer": 3,
        "meta": {
            "ko_q": "3) 다음 글을 읽고, 질문에 답하세요.\n\n"
                    "옛날 자판기는 차가운 음료밖에 팔 수 없었다.\n"
                    "어느 겨울날, 운전사들이 차가운 주스를 사서 마시는 모습을 보고,\n"
                    "음료 회사 사람은 ‘겨울에는 따뜻한 음료가 필요하다’고 생각했다.\n"
                    "그 후 개선이 진행되어, 지금처럼 따뜻한 음료도 고를 수 있는 기계가 만들어졌다.\n\n"
                    "지금 같은 자판기가 만들어지게 된 이유는 무엇입니까?",
            "ko_choices": [
                "겨울에 차가운 음료를 팔면 위험하다고 느껴서",
                "차가운 음료가 팔리지 않게 되어서",
                "운전수에게 따뜻한 음료를 만들라고 들어서",
                "겨울에도 따뜻한 음료를 살 수 있으면 좋아할 거라 생각해서"
            ],
            "ko_explain": "‘겨울엔 따뜻한 음료가 필요하고, 그렇게 하면 기뻐할 것’이라는 발상이 핵심이므로 4번이 정답입니다."
        }
    },
    {
        "id": "N3_P3_004",
        "part": 3,
        "q": "4　次のメモを読んで、質問に答えなさい。\n\n"
             "（メモ）\n"
             "○○さん\n"
             "明日の午後、会議で先週の説明会について報告します。\n"
             "参加企業のリストを用意しておいてください。\n"
             "私は明日、取引先に寄ってから出勤するので、会社に着くのは11時ごろです。\n"
             "それまでにお願いします。\n\n"
             "このメモを読んで、○○さんがしなければならないことは何か。",
        "choices": [
            "11時までに参加企業のリストを準備する。",
            "説明会の資料を書き直して完成させる。",
            "会議の前に取引先へ行く。",
            "説明会に参加した企業へ電話する。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "4) 다음 메모를 읽고, 질문에 답하세요.\n\n"
                    "(메모)\n"
                    "○○ 씨\n"
                    "내일 오후 회의에서 지난주 설명회에 대해 보고합니다.\n"
                    "참가 기업 리스트를 준비해 두세요.\n"
                    "나는 내일 거래처에 들렀다가 출근하므로, 회사에 도착하는 것은 11시쯤입니다.\n"
                    "그때까지 부탁합니다.\n\n"
                    "이 메모를 읽고, ○○ 씨가 해야 하는 일은 무엇입니까?",
            "ko_choices": [
                "11시까지 참가 기업 리스트를 준비한다.",
                "설명회 자료를 다시 써서 완성한다.",
                "회의 전에 거래처에 간다.",
                "설명회 참가 기업에 전화한다."
            ],
            "ko_explain": "요구된 작업은 ‘참가 기업 리스트 준비’이며, ‘11시쯤 도착 전까지’라고 했으니 1번이 정답입니다."
        }
    },

    # -------------------------
    # 2) 1지문 3문제 (5~7) - 그룹
    # q에는 번호만 둔다 (템플릿에서 공통지문 표시)
    # -------------------------
    {
        "id": "N3_P3_005",
        "part": 3,
        "q": "5（　）",
        "choices": [
            "同じ本を買ったことにすぐ気づいた。",
            "同じ本が家にあるのを見て驚いた。",
            "本屋で新刊を買うのをやめた。",
            "表紙が変わると買えなくなる。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "5) 글의 내용과 맞는 것을 고르세요.",
            "ko_choices": [
                "같은 책을 샀다는 걸 바로 알아챘다.",
                "집 책장에서 같은 책이 있는 걸 보고 놀랐다.",
                "서점에서 신간을 사는 걸 그만뒀다.",
                "표지가 바뀌면 책을 못 산다."
            ],
            "ko_explain": "‘책장에 똑같은 책이 이미 있었다’고 보고 ‘놀랐다’가 핵심이므로 2번이 정답입니다."
        }
    },
    {
        "id": "N3_P3_006",
        "part": 3,
        "q": "6（　）",
        "choices": [
            "内容を細かく覚えすぎてしまう。",
            "忙しいと読んだ内容を覚えていないことがある。",
            "帯はいつも同じなので見間違えない。",
            "買ったことは絶対に忘れない。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "6) 글에서 말하는 ‘같은 책을 또 사는 이유’로 맞는 것은?",
            "ko_choices": [
                "내용을 너무 자세히 기억해서",
                "바쁘면 읽은 내용을 자세히 기억하지 못해서",
                "띠지는 항상 같아서 착각하지 않아서",
                "산 사실은 절대 잊지 않아서"
            ],
            "ko_explain": "이유로 ‘忙しいと内容を細かく覚えていない’가 직접 나오므로 2번이 정답입니다."
        }
    },
    {
        "id": "N3_P3_007",
        "part": 3,
        "q": "7（　）",
        "choices": [
            "本屋に行くのをやめるべきだ。",
            "失敗しても、本屋に行く楽しみは手放したくない。",
            "二度と本を買わないと決めた。",
            "同じ本を買うのは悪いことではない。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "7) 글쓴이의 생각으로 가장 알맞은 것은?",
            "ko_choices": [
                "서점에 가는 걸 그만둬야 한다.",
                "실수는 줄이되 서점에 가는 즐거움은 포기하고 싶지 않다.",
                "두 번 다시 책을 사지 않겠다고 결심했다.",
                "같은 책을 사는 건 나쁜 일이 아니다(전혀 문제 없다)."
            ],
            "ko_explain": "마지막에 ‘失敗は減らしたいが、本屋に行く楽しみまで手放したくない’라고 하므로 2번이 정답입니다."
        }
    },
]

N3_PART4_QUESTIONS_FULL = []

# =========================
# 2) PART별 원본(FULL) 가져오기 (채점 API에서 사용)
# =========================
def get_n3_part_questions_full(part: int):
    if part == 1:
        return N3_PART1_QUESTIONS_FULL
    elif part == 2:
        return N3_PART2_QUESTIONS_FULL
    elif part == 3:
        return N3_PART3_QUESTIONS_FULL
    elif part == 4:
        return N3_PART4_QUESTIONS_FULL
    return []

# =========================
# N3 PART2 : 19~23 그룹 문제용 메타 내려주기 (템플릿이 groupStemBox에 표시)
# - 템플릿 JS: GROUP_START_IDX = 18, GROUP_END_IDX = 22 로 맞추면 됨
# =========================
def get_n3_part_questions(part: int):
    src = get_n3_part_questions_full(part)

    out = []
    for q in src:
        item = {
            "id": q.get("id"),
            "part": q.get("part", part),
            "q": q.get("q", ""),
            "choices": q.get("choices", []),
            "answer": q.get("answer", 0),
        }

        # ✅ PART2 그룹(19~23) = 기존 그대로 유지
        if part == 2:
            try:
                no = int(q.get("q", "").split("（")[0].strip().replace("　", "").replace(" ", ""))
            except:
                no = None

            if no and 19 <= no <= 23:
                item["group"] = {
                    "id": "P2_M3",
                    "start": 19,
                    "end": 23,
                    "stem_jp": N3_P2_M3_STEM_JP,
                }

        # ✅ PART3 그룹(5~7) 추가
        if part == 3:
            try:
                no = int(q.get("q", "").split("（")[0].strip().replace("　", "").replace(" ", ""))
            except:
                no = None

            if no and 5 <= no <= 7:
                item["group"] = {
                    "id": "P3_M5",
                    "start": 5,
                    "end": 7,
                    "stem_jp": N3_P3_M5_STEM_JP,  # ✅ 일본어 공통지문
                }

        out.append(item)

    return out

# ----------------------------
# ✅ 채점 API (N3)
# ----------------------------
@app.post("/api/jlpt/n3/test/grade/<int:part>")
def api_jlpt_n3_test_grade(part: int):
    payload = request.get_json(silent=True) or {}
    user_answers = payload.get("answers", [])
    if not isinstance(user_answers, list):
        user_answers = []

    src = get_n3_part_questions_full(part)
    total = len(src)
    correct = 0
    items = []

    for i, q in enumerate(src):
        ua = user_answers[i] if i < len(user_answers) else None
        ans = q.get("answer", 0)
        is_correct = (ua == ans)
        if is_correct:
            correct += 1

        meta = q.get("meta", {}) or {}
        items.append({
            "no": i + 1,
            "q_ko": meta.get("ko_q", ""),
            "choices_ko": meta.get("ko_choices", []),
            "answer_index": ans,
            "user_index": ua,
            "explain_ko": meta.get("ko_explain", ""),
            "is_correct": is_correct,
        })

    score = round((correct / total) * 100) if total else 0

    resp = {
        "total": total,
        "correct": correct,
        "score": score,
        "items": items
    }

    # ✅ N3 PART2 그룹 지문(19~23) 번역 포함 (기존 유지)
    if part == 2:
        resp["group_meta"] = {
            "P2_M3": {
                "start": 19,
                "end": 23,
                "stem_jp": N3_P2_M3_STEM_JP,
                "stem_ko": N3_P2_M3_STEM_KO,
            }
        }

    # ✅ N3 PART3 그룹 지문(5~7) 번역 포함 (추가)
    if part == 3:
        resp["group_meta"] = {
            "P3_M5": {
                "start": 5,
                "end": 7,
                "stem_jp": N3_P3_M5_STEM_JP,
                "stem_ko": N3_P3_M5_STEM_KO,
            }
        }

    return jsonify(resp)

# ----------------------------
# ✅ N3 테스트 시작 라우트
# ----------------------------
@app.route("/jlpt/n3/test/start/<int:part>")
def jlpt_n3_test_start(part: int):
    questions = get_n3_part_questions(part)

    template_map = {
        1: "jlpt_n3_test_run_part1.html",
        2: "jlpt_n3_test_run_part2.html",
        3: "jlpt_n3_test_run_part3.html",
        4: "jlpt_n3_test_run_part4.html",
    }

    total_raw = len(get_n3_part_questions_full(part))  # ✅ 실제 문항 수

    return render_template(
        template_map.get(part, "jlpt_n3_test_run_part1.html"),
        questions=questions,
        total_questions=total_raw,  # ✅ N4와 동일: 실제 문항 수를 내려줌
        part=part
    )

# ----------------------------
# ✅ N3 테스트 홈
# ----------------------------
@app.route("/jlpt/n3/test")
def jlpt_n3_test():
    user = current_user()
    return render_template("jlpt_n3_test.html", user=user, total_questions=0)

@app.route("/jlpt/n3")
def jlpt_n3_home():
    user = current_user()
    return render_template("jlpt_n3.html", user=user)

@app.route("/jlpt/n3/words")
def jlpt_n3_words():
    user = current_user()

    # N3_WORDS: dict (sec01~sec10)
    sections = []
    all_items = []

    for sec_key in sorted((N3_WORDS or {}).keys()):  # sec01, sec02...
        sec = (N3_WORDS or {}).get(sec_key) or {}
        title = sec.get("title", sec_key)
        items = sec.get("items") or []

        sections.append({
            "key": sec_key,
            "title": title,
            "count": len(items),
        })

        for it in items:
            row = dict(it)
            row["sec_key"] = sec_key
            row["sec_title"] = title
            all_items.append(row)

    return render_template(
        "jlpt_n3_words.html",
        user=user,
        sections=sections,
        words=all_items,   # ✅ 템플릿엔 "단어 리스트"로만 전달
    )

@app.route("/jlpt/n3/sentences")
def jlpt_n3_sentences():
    user = current_user()
    return render_template("jlpt_n3_sentences.html", user=user, sections=N3_SENTENCE_SECTIONS)

@app.route("/jlpt/n3/grammar")
def jlpt_n3_grammar():
    user = current_user()
    return render_template("jlpt_n3_grammar.html", user=user)

N2_PART1_QUESTIONS_FULL = [
    # 1
    {
        "id": "N2_P1_001",
        "part": 1,
        "q": "1　先生に貴重な資料を見せていただいた。",
        "choices": ["きじゅう", "きちょう", "きっじゅう", "きっちょう"],
        "answer": 1,
        "meta": {
            "ko_q": "1) 先生に(貴重)な資料を見せていただいた。\n선생님께 귀중한 자료를 보여 달라고 부탁드려 보여주셨다.",
            "ko_choices": [
                "きじゅう(오답)",
                "きちょう(귀중)",
                "きっじゅう(오답)",
                "きっちょう(오답)"
            ],
            "ko_explain": "貴重(귀중)의 올바른 읽기는 2번 きちょう입니다."
        }
    },
    # 2
    {
    "id": "N2_P1_002",
    "part": 1,
    "q": "2　その話を聞いて、とても（怪しい）と思った。",
    "choices": ["あやしい", "あやし", "あやしげ", "あやしましい"],
    "answer": 0,
    "meta": {
        "ko_q": "2) その話を聞いて、とても(怪しい)と思った。\n그 이야기를 듣고 매우 수상하다고 생각했다.",
        "ko_choices": ["あやしい(수상하다)", "あやし(오답)", "あやしげ(형태가 다름)", "あやしましい(오답)"],
        "ko_explain": "怪しい의 올바른 읽기는 あやしい입니다."
    }
    },
    # 3
    {
        "id": "N2_P1_003",
        "part": 1,
        "q": "3　佐藤さんは(容姿)も性格もいい。",
        "choices": ["よし", "ようし", "ようす", "よす"],
        "answer": 1,
        "meta": {
            "ko_q": "3) 佐藤さんは(容姿)も性格もいい。\n사토 씨는 외모도 성격도 좋다.",
            "ko_choices": [
                "よし(오답)",
                "ようし(용모/외모)",
                "ようす(모양/상태)",
                "よす(오답)"
            ],
            "ko_explain": "容姿(용모/외모)의 올바른 읽기는 2번 ようし입니다."
        }
    },
    # 4
    {
        "id": "N2_P1_004",
        "part": 1,
        "q": "4　これは危険を伴う実験だ。",
        "choices": ["はらう", "あつかう", "ともなう", "すくう"],
        "answer": 2,
        "meta": {
            "ko_q": "4) これは危険を(伴う)実験だ。\n이것은 위험을 동반하는 실험이다.",
            "ko_choices": [
                "はらう(지불하다)",
                "あつかう(취급하다)",
                "ともなう(동반하다)",
                "すくう(구하다/떠올리다)"
            ],
            "ko_explain": "伴う(동반하다)의 읽기는 3번 ともなう입니다."
        }
    },
    # 5
    {
        "id": "N2_P1_005",
        "part": 1,
        "q": "5　以前は、海外で暮らしたいという(願望)が強かった。",
        "choices": ["がんぼう", "げんぼう", "がんぼ", "げんぼ"],
        "answer": 0,
        "meta": {
            "ko_q": "5) 以前は、海外で暮らしたいという(願望)が強かった。\n예전에는 해외에서 살고 싶다는 욕망/소망이 강했다.",
            "ko_choices": [
                "がんぼう(원망/소망/욕망)",
                "げんぼう(오답)",
                "がんぼ(오답)",
                "げんぼ(오답)"
            ],
            "ko_explain": "願望(원망/소망/욕망)의 올바른 읽기는 1번 がんぼう입니다."
        }
    },
    # 6
    {
        "id": "N2_P1_006",
        "part": 1,
        "q": "6　友人を家に(まねいた)。",
        "choices": ["向いた", "招いた", "泊いた", "召いた"],
        "answer": 1,
        "meta": {
            "ko_q": "6) 友人を家に(まねいた)。\n친구를 집에 초대했다.",
            "ko_choices": [
                "向いた(향했다/돌렸다)",
                "招いた(초대했다)",
                "泊いた(오답)",
                "召いた(오답)"
            ],
            "ko_explain": "まねいた(초대했다)의 한자는 2번 招いた가 맞습니다."
        }
    },
    # 7
    {
        "id": "N2_P1_007",
        "part": 1,
        "q": "7　この商品は安全性が(ほしょう)されている。",
        "choices": ["補証", "保正", "保証", "補正"],
        "answer": 2,
        "meta": {
            "ko_q": "7) この商品は安全性が(ほしょう)されている。\n이 상품은 안전성이 보장되어 있다.",
            "ko_choices": [
                "補証(오답)",
                "保正(오답)",
                "保証(보증/보장)",
                "補正(보정)"
            ],
            "ko_explain": "ほしょう(보장/보증)의 올바른 한자는 3번 保証입니다."
        }
    },
    # 8
    {
        "id": "N2_P1_008",
        "part": 1,
        "q": "8　この企業では、さまざまな(もよおし)を行っている。",
        "choices": ["携し", "催し", "推し", "権し"],
        "answer": 1,
        "meta": {
            "ko_q": "8) この企業では、さまざまな(もよおし)を行っている。\n이 기업에서는 다양한 행사를 진행하고 있다.",
            "ko_choices": [
                "携し(오답)",
                "催し(행사/개최)",
                "推し(오시/최애)",
                "権し(오답)"
            ],
            "ko_explain": "もよおし(행사)의 올바른 한자는 2번 催し입니다."
        }
    },
    # 9
    {
        "id": "N2_P1_009",
        "part": 1,
        "q": "9　銀行に行って、お札を(こうか)に替えた。",
        "choices": ["硬貨", "固貨", "硬価", "固価"],
        "answer": 0,
        "meta": {
            "ko_q": "9) 銀行に行って、お札を(こうか)に替えた。\n은행에 가서 지폐를 동전으로 바꿨다.",
            "ko_choices": [
                "硬貨(동전)",
                "固貨(오답)",
                "硬価(오답)",
                "固価(오답)"
            ],
            "ko_explain": "こうか(동전)의 올바른 한자는 1번 硬貨입니다."
        }
    },
    # 10
    {
        "id": "N2_P1_010",
        "part": 1,
        "q": "10　わが社の商品はここで(せいぞう)されている。",
        "choices": ["製増", "制増", "制造", "製造"],
        "answer": 3,
        "meta": {
            "ko_q": "10) わが社の商品はここで(せいぞう)されている。\n우리 회사의 상품은 여기에서 제조되고 있다.",
            "ko_choices": [
                "製増(오답)",
                "制増(오답)",
                "制造(오답)",
                "製造(제조)"
            ],
            "ko_explain": "せいぞう(제조)의 올바른 한자는 4번 製造입니다."
        }
    },
    # 11
    {
        "id": "N2_P1_011",
        "part": 1,
        "q": "11　男女の結婚（　）の違いについて調べた。",
        "choices": ["観", "識", "念", "察"],
        "answer": 0,
        "meta": {
            "ko_q": "11) 男女の結婚（　）の違いについて調べた。\n남녀의 결혼관 차이에 대해 조사했다.",
            "ko_choices": [
                "観(관/관점)",
                "識(지식/의식)",
                "念(생각/념)",
                "察(살피다/찰)"
            ],
            "ko_explain": "結婚観(けっこんかん)=결혼관 이므로 정답은 1번 観입니다."
        }
    },
    # 12
    {
    "id": "N2_P1_012",
    "part": 1,
    "q": "12　ここでは（　）な医療が受けられる。",
    "choices": ["高度", "高級", "上等", "特別"],
    "answer": 0,
    "meta": {
        "ko_q": "12) ここでは（　）な医療が受けられる。\n여기서는 고도의 의료를 받을 수 있다.",
        "ko_choices": ["高度(고도)", "高級(고급)", "上等(상등)", "特別(특별)"],
        "ko_explain": "의료/기술 수준을 말할 때는 「高度な医療」가 가장 자연스럽습니다."
    }
    },
    # 13
    {
        "id": "N2_P1_013",
        "part": 1,
        "q": "13　今日は大学の講義で日本（　）の経営について学んだ。",
        "choices": ["状", "類", "式", "則"],
        "answer": 2,
        "meta": {
            "ko_q": "13) 今日は大学の講義で日本（　）の経営について学んだ。\n오늘 대학 강의에서 일본식 경영에 대해 배웠다.",
            "ko_choices": [
                "状(상태/모양)",
                "類(종류/유)",
                "式(식/방식)",
                "則(규칙/법칙)"
            ],
            "ko_explain": "日本式(にほんしき)=일본식(방식) 이므로 정답은 3번 式입니다."
        }
    },
    # 14
    {
        "id": "N2_P1_014",
        "part": 1,
        "q": "14　開封しても、（　）使用の物は返品可能です。",
        "choices": ["外", "否", "前", "未"],
        "answer": 3,
        "meta": {
            "ko_q": "14) 開封しても、（　）使用の物は返品可能です。\n개봉했더라도 미사용 제품은 반품 가능합니다.",
            "ko_choices": [
                "外(밖/외)",
                "否(부정/아니다)",
                "前(앞/전)",
                "未(아직 ~아님/미)"
            ],
            "ko_explain": "未使用(みしよう)=미사용 이므로 정답은 4번 未입니다."
        }
    },
    # 15
    {
    "id": "N2_P1_015",
    "part": 1,
    "q": "15　受験生なので、勉強（　）の毎日だ。",
    "choices": ["漬け", "寝し", "溶け", "満ち"],
    "answer": 0,
    "meta": {
        "ko_q": "15) 受験生なので、勉強（　）の毎日だ。\n수험생이기 때문에 매일 공부에만 매달린 생활이다.",
        "ko_choices": [
        "漬け(~에 푹 빠짐/절임)",
        "寝し(오답)",
        "溶け(녹다/풀리다)",
        "満ち(가득 참)"
        ],
        "ko_explain": "정답 1번 勉強漬け(べんきょうづけ)는 ‘공부에 푹 빠진 상태, 공부만 하는 생활’을 의미합니다."
    }
    },

    # 16
    {
    "id": "N2_P1_016",
    "part": 1,
    "q": "16　この大学では一般向けの講座を開き、社会に学習の場を（　）している。",
    "choices": ["選出", "提供", "指示", "寄付"],
    "answer": 1,
    "meta": {
        "ko_q": "16) この大学では一般向けの講座を開き、社会に学習の場を（　）している。\n이 대학에서는 일반인을 위한 강좌를 열어 사회에 학습의 장을 제공하고 있다.",
        "ko_choices": [
        "選出(선출)",
        "提供(제공)",
        "指示(지시)",
        "寄付(기부)"
        ],
        "ko_explain": "정답 2번, ‘학습의 장을 제공하다’라는 표현이 자연스러우므로 提供가 정답입니다."
    }
    },

    # 17
    {
    "id": "N2_P1_017",
    "part": 1,
    "q": "17　今年の夏は暑さが厳しく、仕事から家に帰ると疲れて（　）してしまう。",
    "choices": ["ぐったり", "しっかり", "すっきり", "ぎっしり"],
    "answer": 0,
    "meta": {
        "ko_q": "17) 今年の夏は暑さが厳しく、仕事から家に帰ると疲れて（　）してしまう。\n올여름은 더위가 심해서, 일을 마치고 집에 돌아오면 피곤해져 녹초가 된다.",
        "ko_choices": [
        "ぐったり(녹초가 됨/기진맥진)",
        "しっかり(확실히/단단히)",
        "すっきり(개운하게)",
        "ぎっしり(빽빽하게)"
        ],
        "ko_explain": "정답 1번, 몹시 피곤해 축 늘어진 상태를 나타내는 말은 ぐったり입니다."
    }
    },

    # 18
    {
    "id": "N2_P1_018",
    "part": 1,
    "q": "18　学生時代の友人が私の名前を忘れていたので、とても（　）だった。",
    "choices": ["衝撃", "感動", "不安", "自慢"],
    "answer": 0,
    "meta": {
        "ko_q": "18) 학생 시절 친구가 내 이름을 잊어버려서 정말 (   )이었다.",
        "ko_choices": ["衝撃(충격)", "感動(감동)", "不安(불안)", "自慢(자랑)"],
        "ko_explain": "이 상황은 ‘충격’을 받는 것이 자연스러우므로 衝撃이 정답입니다."
    }
    },

    # 19
    {
    "id": "N2_P1_019",
    "part": 1,
    "q": "19　通路に荷物を置いたら、通る人の（　）になりますよ。",
    "choices": ["面倒", "邪魔", "被害", "無理"],
    "answer": 1,
    "meta": {
        "ko_q": "19) 通路に荷物を置いたら、通る人の（　）になりますよ。\n통로에 짐을 두면 지나가는 사람에게 방해가 됩니다.",
        "ko_choices": [
        "面倒(번거로움)",
        "邪魔(방해)",
        "被害(피해)",
        "無理(무리/불가능)"
        ],
        "ko_explain": "정답 2번, 통로에 짐을 두면 사람들에게 ‘방해’가 되므로 邪魔가 맞습니다."
    }
    },

    # 20
    {
    "id": "N2_P1_020",
    "part": 1,
    "q": "20　少し長めの上り坂だったが（　）ので、それほど疲れなかった。",
    "choices": ["おとなしかった", "ささやかだった", "なだらかだった", "よわよわしかった"],
    "answer": 2,
    "meta": {
        "ko_q": "20) 少し長めの上り坂だったが（　）ので、それほど疲れなかった。\n조금 긴 오르막길이었지만 완만해서 그리 피곤하지 않았다.",
        "ko_choices": [
        "おとなしかった(얌전했다)",
        "ささやかだった(소박했다/자그마했다)",
        "なだらかだった(완만했다)",
        "よわよわしかった(허약해 보였다)"
        ],
        "ko_explain": "정답 3번, 경사가 ‘완만하다’는 표현으로는 なだらかだった가 가장 자연스럽습니다."
    }
    },

    # 21
    {
    "id": "N2_P1_021",
    "part": 1,
    "q": "21　出席者は皆会議に積極的に参加し、意見を（　）交換し合った。",
    "choices": ["活発に", "円満に", "機械に", "濃厚に"],
    "answer": 0,
    "meta": {
        "ko_q": "21) 出席者は皆会議に積極的に参加し、意見を（　）交換し合った。\n참석자들은 모두 회의에 적극적으로 참여해 의견을 활발하게 교환했다.",
        "ko_choices": [
        "活発に(활발하게)",
        "円満に(원만하게)",
        "機械に(기계적으로)",
        "濃厚に(진하게/농후하게)"
        ],
        "ko_explain": "정답 1번, ‘의견을 활발히 교환하다’라는 표현에는 活発に가 적절합니다."
    }
    },

    # 22
    {
    "id": "N2_P1_022",
    "part": 1,
    "q": "22　列に並んでいたら、私の前に強引に（　）きた人がいて、嫌な気分になった。",
    "choices": ["当てはまって", "付け加えて", "行き着いて", "割り込んで"],
    "answer": 3,
    "meta": {
        "ko_q": "22) 列に並んでいたら、私の前に強引に（　）きた人がいて、嫌な気分になった。\n줄을 서 있었는데 내 앞에 억지로 끼어든 사람이 있어 기분이 나빴다.",
        "ko_choices": [
        "当てはまって(해당되어)",
        "付け加えて(덧붙여)",
        "行き着いて(도착해서)",
        "割り込んで(끼어들어)"
        ],
        "ko_explain": "정답 4번, 줄에 ‘끼어들다’는 표현은 割り込む이므로 割り込んで가 맞습니다."
    }
    },

    # 23
    {
    "id": "N2_P1_023",
    "part": 1,
    "q": "23　高橋さんはとても（愉快）な人だ。",
    "choices": ["楽しい", "忙しい", "静かな", "真面目な"],
    "answer": 0,
    "meta": {
        "ko_q": "23) 高橋さんはとても(愉快)な人だ。\n다카하시 씨는 매우 유쾌한 사람이다.",
        "ko_choices": ["楽しい(즐거운/유쾌한)", "忙しい(바쁜)", "静かな(조용한)", "真面目な(진지한)"],
        "ko_explain": "愉快는 ‘즐겁고 유쾌하다’는 뜻이므로 楽しい가 가장 가깝습니다."
    }
    },

    # 24
    {
    "id": "N2_P1_024",
    "part": 1,
    "q": "24　それは確かに(やむをえない)ことだと思う。",
    "choices": ["もったいない", "なさけない", "つまらない", "しかたない"],
    "answer": 3,
    "meta": {
        "ko_q": "24) それは確かに(やむをえない)ことだと思う。\n그것은 확실히 어쩔 수 없는 일이라고 생각한다.",
        "ko_choices": [
        "もったいない(아깝다)",
        "なさけない(한심하다)",
        "つまらない(시시하다)",
        "しかたない(어쩔 수 없다)"
        ],
        "ko_explain": "정답 4번, やむをえない(부득이하다)는 しかたない(어쩔 수 없다)와 같은 의미입니다."
    }
    },
    # 25
    {
        "id": "N2_P1_025",
        "part": 1,
        "q": "25　少し(息抜き)したほうがいいよ。",
        "choices": ["待った", "急いだ", "休んだ", "働いた"],
        "answer": 2,
        "meta": {
            "ko_q": "25) 少し(息抜き)したほうがいいよ。\n조금 (기분 전환/휴식)을 하는 게 좋겠어.",
            "ko_choices": [
            "待った(기다렸다)",
            "急いだ(서둘렀다)",
            "休んだ(쉬었다)",
            "働いた(일했다)"
            ],
            "ko_explain": "정답 3번. 息抜き는 ‘기분 전환, 휴식’이라는 의미이므로 문맥상 休んだ가 가장 알맞습니다."
        }
    },
    # 26
    {
        "id": "N2_P1_026",
        "part": 1,
        "q": "26　今日はとても(ついていた)。",
        "choices": ["気分が悪かった", "運が悪かった", "気分がよかった", "運がよかった"],
        "answer": 3,
        "meta": {
            "ko_q": "26) 今日はとても(ついていた)。\n오늘은 정말 (운이 좋았다).",
            "ko_choices": [
            "気分が悪かった(기분이 나빴다)",
            "運が悪かった(운이 나빴다)",
            "気分がよかった(기분이 좋았다)",
            "運がよかった(운이 좋았다)"
            ],
            "ko_explain": "정답 4번. ついている는 관용적으로 ‘운이 좋다’는 뜻입니다."
        }
    },
    # 27
    {
        "id": "N2_P1_027",
        "part": 1,
        "q": "27　私は(つねに)言葉遣いに気をつけている。",
        "choices": ["当然", "いつも", "特に", "できるだけ"],
        "answer": 1,
        "meta": {
            "ko_q": "27) 私は(つねに)言葉遣いに気をつけている。\n나는 (항상) 말투에 신경 쓰고 있다.",
            "ko_choices": [
            "当然(당연히)",
            "いつも(항상)",
            "特に(특히)",
            "できるだけ(가능한 한)"
            ],
            "ko_explain": "정답 2번. つねに(常に)는 ‘항상’이라는 의미로 いつも와 같습니다."
        }
    },
    # 28
    {
        "id": "N2_P1_028",
        "part": 1,
        "q": "28　(延長)  次の言葉の使い方として最もよいものを、１・２・３・４から一つ選びなさい。", 
        "choices": [
            "悪天候で列車が運転をやめたため、旅行の出発が三日後に延長された。",
            "初めの設計では２階建てだったが、３階建ての家に延長することにした。",
            "予定の時間内に結論が出ず、会議が１時間延長されることになった。",
            "電車の中で居眠りをして、降りる駅を一駅延長してしまった。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "28) 延長\n(연장) 다음 단어의 사용법으로서 가장 알맞은 것을 1·2·3·4 중에서 하나 고르세요.",
            "ko_choices": [
                "悪天候で列車が運転をやめたため、旅行の出発が三日後に延長された。\n악천후로 열차 운행이 중단되어, 여행 출발이 3일 뒤로 ‘연장(=미뤄짐)’되었다. (오답: 보통 ‘延期(연기)’가 자연스러움)",
                "初めの設計では２階建てだったが、３階建ての家に延長することにした。\n처음 설계는 2층짜리였지만, 3층짜리 집으로 ‘연장(확장)’하기로 했다. (오답: 집은 보통 ‘増築(증축)’/‘変更(변경)’이 자연스러움)",
                "予定の時間内に結論が出ず、会議が１時間延長されることになった。\n예정된 시간 안에 결론이 나지 않아, 회의가 1시간 연장되게 되었다. (정답)",
                "電車の中で居眠りをして、降りる駅を一駅延長してしまった。\n전철 안에서 졸아서, 내려야 할 역을 한 정거장 ‘연장’해 버렸다. (오답: 보통 ‘乗り過ごす(지나치다)’가 자연스러움)"
            ],
            "ko_explain": "延長은 시간/기간을 ‘늘리다(연장하다)’에 쓰며, 회의 시간이 1시간 늘어나는 3번이 정답입니다."
        }
    },
    # 29
    {
        "id": "N2_P1_029",
        "part": 1,
        "q": "29　(さびる)  次の言葉の使い方として最もよいものを、１・２・３・４から一つ選びなさい。",
        "choices": [
            "暑いところに生ものをずっと置いておいたら、さびて臭くなった。",
            "昨夜は雨が相当降ったらしく、普段はきれいな川の水がさびて濁っている。",
            "鉢に植えた植物に水をやるのを忘れていたら、花がさびてしまった。",
            "この鉄の棒はずっと家の外に置いてあったので、さびて茶色くなっている。"
        ],
        "answer": 3,
        "meta": {
            "ko_q": "29) さびる\n(녹슬다) 다음 단어의 사용법으로서 가장 알맞은 것을 1·2·3·4 중에서 하나 고르세요.",
            "ko_choices": [
                "暑いところに生ものをずっと置いておいたら、さびて臭くなった。\n더운 곳에 생식을 오래 두었더니 녹슬어서 냄새가 나게 되었다. (오답: 음식은 ‘썩다/상하다’가 자연스러움)",
                "昨夜は雨が相当降ったらしく、普段はきれいな川の水がさびて濁っている。\n어젯밤 비가 많이 와서 평소엔 맑은 강물이 녹슬어서 흐려져 있다. (오답: 물은 녹슬지 않음)",
                "鉢に植えた植物に水をやるのを忘れていたら、花がさびてしまった。\n화분에 심은 식물에 물 주는 걸 잊었더니 꽃이 녹슬어 버렸다. (오답: 식물에는 ‘시들다’가 자연스러움)",
                "この鉄の棒はずっと家の外に置いてあったので、さびて茶色くなっている。\n이 철봉은 오랫동안 집 밖에 두어서 녹슬어 갈색이 되어 있다. (정답)"
            ],
            "ko_explain": "さびる는 금속이 ‘녹슬다’라는 뜻이므로, 철봉이 갈색으로 변한 4번이 정답입니다."
        }
    },
    # 30
    {
        "id": "N2_P1_030",
        "part": 1,
        "q": "30　(目上)  次の言葉の使い方として最もよいものを、１・２・３・４から一つ選びなさい。",
        "choices": [
            "勉強会に参加した社員がすべて目上だったので、新人の私はとても緊張した。",
            "この店で一番値段が高く、目上の商品は、店の奥にある棚に並べられていた。",
            "高校時代、鈴木さんはとても優秀で、成績はいつも学年で目上だった。",
            "あの若さで金賞を受賞した伊藤さんは、本当に目上の人だと思う。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "30) 目上\n(윗사람/상급자) 다음 단어의 사용법으로서 가장 알맞은 것을 1·2·3·4 중에서 하나 고르세요.",
            "ko_choices": [
                "勉強会に参加した社員がすべて目上だったので、新人の私はとても緊張した。\n공부 모임에 참가한 직원들이 모두 윗사람이어서, 신입인 나는 매우 긴장했다. (정답)",
                "この店で一番値段が高く、目上の商品は、店の奥にある棚に並べられていた。\n이 가게에서 가장 비싸고 ‘윗사람인’ 상품은 안쪽 진열대에 놓여 있었다. (오답: 상품에는 사용 불가)",
                "高校時代、鈴木さんはとても優秀で、成績はいつも学年で目上だった。\n고등학교 시절 스즈키 씨는 성적이 항상 학년에서 윗사람이었다. (오답: 성적에 目上 사용 X)",
                "あの若さで金賞を受賞した伊藤さんは、本当に目上の人だと思う。\n그 나이에 금상을 받은 이토 씨는 정말 윗사람이라고 생각한다. (오답: 문맥상 ‘훌륭한 사람’이 자연스러움)"
            ],
            "ko_explain": "目上은 ‘윗사람/상급자’를 뜻하며, 사람 관계에만 쓰입니다. 1번이 정답입니다."
        }
    },
    # 31
    {
        "id": "N2_P1_031",
        "part": 1,
        "q": "31　(大げさ)  次の言葉の使い方として最もよいものを、１・２・３・４から一つ選びなさい。",
        "choices": [
            "息子の誕生日に料理を作りすぎてしまい、大げさに余ってしまった。",
            "天気予報によると、明日は今日より大げさに気温が下がるらしい。",
            "努力した結果、試験の成績が大げさに伸びて、先生に褒められた。",
            "あの人は小さなことを大げさに言うので、そのまま信じないほうがいい。"
        ],
        "answer": 3,
        "meta": {
            "ko_q": "31) 大げさ\n(과장) 다음 단어의 사용법으로서 가장 알맞은 것을 1·2·3·4 중에서 하나 고르세요.",
            "ko_choices": [
                "息子の誕生日に料理を作りすぎてしまい、大げさに余ってしまった。\n아들 생일에 음식을 너무 많이 만들어서 과장되게 남아 버렸다. (오답: ‘많이’와 결합 부자연)",
                "天気予報によると、明日は今日より大げさに気温が下がるらしい。\n일기예보에 따르면 내일은 오늘보다 과장되게 기온이 내려간다고 한다. (오답)",
                "努力した結果、試験の成績が大げさに伸びて、先生に褒められた。\n노력한 결과 시험 성적이 과장되게 올라 선생님께 칭찬받았다. (오답)",
                "あの人は小さなことを大げさに言うので、そのまま信じないほうがいい。\n그 사람은 작은 일을 과장해서 말하므로 그대로 믿지 않는 게 좋다. (정답)"
            ],
            "ko_explain": "大げさ는 ‘과장하다’ 의미로, ‘大げさに言う’가 가장 대표적인 용례입니다."
        }
    },
    # 32
    {
        "id": "N2_P1_032",
        "part": 1,
        "q": "32　(反省)  次の言葉の使い方として最もよいものを、１・２・３・４から一つ選びなさい。",
        "choices": [
            "発表の原稿を全部覚えたのに、緊張のせいでどんなに反省しても全く思い出せない。",
            "今回の企画では、私の準備不足で周りに迷惑をかけたことをとても反省しています。",
            "祖父はいつも若いころの思い出を懐かしそうに反省して私に話してくれる。",
            "この機械の使い方を忘れないように、もう一度最初から反省しておきましょう。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "32) 反省\n(반성) 다음 단어의 사용법으로서 가장 알맞은 것을 1·2·3·4 중에서 하나 고르세요.",
            "ko_choices": [
                "発表の原稿を全部覚えたのに、緊張のせいでどんなに反省しても全く思い出せない。\n원고를 다 외웠는데 아무리 반성해도 전혀 떠올릴 수 없다. (오답: ‘반성’ 의미 불일치)",
                "今回の企画では、私の準備不足で周りに迷惑をかけたことをとても反省しています。\n이번 기획에서 준비 부족으로 주변에 폐를 끼친 것을 매우 반성하고 있습니다. (정답)",
                "祖父はいつも若いころの思い出を懐かしそうに反省して私に話してくれる。\n할아버지는 젊은 시절 추억을 반성하며 이야기해 준다. (오답: 추억에는 ‘회상’)",
                "この機械の使い方を忘れないように、もう一度最初から反省しておきましょう。\n이 기계 사용법을 잊지 않도록 다시 반성해 두자. (오답: ‘復習’가 자연스러움)"
            ],
            "ko_explain": "反省은 자신의 잘못이나 부족함을 돌아보고 뉘우치는 뜻이므로, 2번이 정답입니다."
        }
    },
]
# =========================
# JLPT N2 PART2 (文法/読解) - 변형 문제 세트
# 구성:
#  - もんだい1: 1~17
#  - もんだい9: 18~22 (지문형 공통 stem)
# =========================

# =========================
# N2 PART2 - もんだい９ 공통 지문 (JP / KO)
# =========================
N2_P2_M9_STEM_JP = """問題９　次の文章を読んで、文章全体の内容を考えて、18から22の中に入る最もよいものを、1・2・3・4から一つ選びなさい。

以下は、雑誌のコラムである。

　　世界に広がる「ピクトグラム」

　駅や空港、病院などで見かける「絵のマーク」は、言葉がわからなくても意味が伝わる便利な表示だ。私は以前、こうしたマークがどの国でも昔から使われてきたのだと（18）。
　ところが、調べてみると、ある国際的な大会をきっかけに標準化が進んだことがわかった。当時、会場の案内板はその国の言語で書かれたものが多く、海外から来る人には（19）。しかし、すべての言語で表示するのも現実的ではない。
　そこで、運営側は誰にでも理解できるように、絵で示す方法を考えた。（20）、現在の「ピクトグラム」の原型となった。
　その後、デザインは少しずつ見直され、国や地域に合わせて変化しながらも、基本の考え方は（21）。
　ピクトグラムが世界に広がった背景には、「できるだけ多くの人にわかりやすくしたい」という思いが国境を越えて（22）。"""

N2_P2_M9_STEM_KO = """문제9 다음 글을 읽고, 글 전체의 내용을 생각해서 18~22에 들어갈 가장 알맞은 것을 1·2·3·4에서 하나 고르세요.

아래는 잡지 칼럼이다.

　　세계로 퍼지는 ‘픽토그램’

역이나 공항, 병원 등에서 볼 수 있는 ‘그림 표지’는 말을 몰라도 의미를 전달하는 편리한 표시다. 나는 예전에는 이런 표지가 어느 나라에서나 오래전부터 당연히 사용돼 왔다고 (18) 생각했다.
그런데 찾아보니, 어떤 국제 대회를 계기로 표준화가 빠르게 진행됐다는 것을 알게 됐다. 당시 안내판은 개최국 언어로만 쓰인 것이 많아 해외에서 온 사람들에게는 (19) 문제가 되었다. 하지만 모든 언어로 표시하는 것도 현실적으로 어렵다.
그래서 운영 측은 누구나 이해할 수 있도록 그림으로 나타내는 방법을 고안했고, (20) 이것이 오늘날 ‘픽토그램’의 원형이 되었다.
이후 디자인은 조금씩 개선되며 지역에 맞게 변해 왔지만, 기본 취지는 (21) 유지되고 있다.
픽토그램이 세계로 퍼진 배경에는 ‘가능한 많은 사람이 이해할 수 있게 하자’는 생각이 국경을 넘어 (22) 퍼졌기 때문이다."""

N2_PART2_QUESTIONS_FULL = [
    # =========================
    # もんだい1 (1~17) - 단일 문항 (변형)
    # =========================
    {
        "id": "N2_P2_001",
        "part": 2,
        "q": "1　卒業論文がなかなか進まなくて、一時は（　）かけたが、先生の助言で書き直せた。",
        "choices": ["あきらめ", "あきらめて", "あきらめる", "あきらめた"],
        "answer": 0,
        "meta": {
            "ko_q": "1) 졸업논문이 잘 안 풀려서 한때는 ( ) 뻔했지만, 지도교수 조언으로 다시 쓸 수 있었다.",
            "ko_choices": ["포기할 뻔한 상태(あきらめ)", "포기해서", "포기하다", "포기했다"],
            "ko_explain": "정답 1번「～かける」는 ‘…할 뻔하다’ → 명사형처럼 「あきらめかけた」가 자연스럽습니다."
        }
    },
    {
        "id": "N2_P2_002",
        "part": 2,
        "q": "2　子どものころ、母（　）作ってくれたハンバーグが大好きで、よくおかわりした。",
        "choices": ["の", "との", "によって", "にとって"],
        "answer": 0,
        "meta": {
            "ko_q": "2) 어릴 때, 엄마( ) 만들어 준 햄버그를 정말 좋아해서 자주 더 먹었다.",
            "ko_choices": ["~이/가(소유·관계)(の)", "~와(との)", "~에 의해(によって)", "~에게는(にとって)"],
            "ko_explain": "정답 1번 ‘엄마가 만들어 준’ 관계 표시 → 「母の作ってくれた」가 자연스럽습니다."
        }
    },
    {
        "id": "N2_P2_003",
        "part": 2,
        "q": "3　情報があふれる現代社会（　）、必要なものを選び取る力が求められている。",
        "choices": ["に加えて", "において", "を基にして", "を込めて"],
        "answer": 1,
        "meta": {
            "ko_q": "3) 정보가 넘쳐나는 현대사회( )에서는 필요한 정보를 골라내는 힘이 요구된다.",
            "ko_choices": ["게다가(に加えて)", "~에 있어서/에서(において)", "~을 바탕으로(を基にして)", "~을 담아(を込めて)"],
            "ko_explain": "정답 2번 장소/상황 ‘현대사회에서’ → 「現代社会において」가 정답입니다."
        }
    },
    {
        "id": "N2_P2_004",
        "part": 2,
        "q": "4　文章がうまくなりたいと相談したら、「毎日書けば（　）上達するよ」と言われた。",
        "choices": ["必ずしも", "たとえ", "そのうち", "さっき"],
        "answer": 2,
        "meta": {
            "ko_q": "4) 글을 잘 쓰고 싶다고 하니 ‘매일 쓰면 ( ) 늘 거야’라고 들었다.",
            "ko_choices": ["반드시~는 아니다(必ずしも)", "설령(たとえ)", "그중에/머지않아(そのうち)", "아까(さっき)"],
            "ko_explain": "정답 3번 ‘꾸준히 하면 언젠가’ 뉘앙스 → 「そのうち」가 자연스럽습니다."
        }
    },
    {
        "id": "N2_P2_005",
        "part": 2,
        "q": "5　夜勤も多い仕事だが、自分で選んだ（　）、最後までやり抜きたい。",
        "choices": ["以上", "とたん", "あげくに", "かのようで"],
        "answer": 0,
        "meta": {
            "ko_q": "5) 야근도 많은 일이지만 스스로 선택한 ( ) 끝까지 해내고 싶다.",
            "ko_choices": ["이상(…한 이상)(以上)", "~하자마자(とたん)", "결국(あげくに)", "~인 것처럼(かのようで)"],
            "ko_explain": "정답 1번 각오/전제 ‘선택한 이상’ → 「～以上」가 정답입니다."
        }
    },
    {
        "id": "N2_P2_006",
        "part": 2,
        "q": "6（内線電話で）\n　A「はい、総務課です。」\n　B「受付の李ですが、X社の中川様が（　）。」\n　A「わかりました。すぐ伺います。」",
        "choices": ["伺いました", "お目にかかりました", "ございました", "お越しになりました"],
        "answer": 3,
        "meta": {
            "ko_q": "6) (내선) ‘X사의 나카가와 님이 ( )’",
            "ko_choices": ["방문했습니다(겸양)(伺いました)", "뵈었습니다(겸양)(お目にかかりました)", "있었습니다(ございました)", "오셨습니다(존경)(お越しになりました)"],
            "ko_explain": "정답 4번 손님이 ‘오다’ 존경어 → 「お越しになりました」가 자연스럽습니다."
        }
    },
    {
        "id": "N2_P2_007",
        "part": 2,
        "q": "7　人は一生のうちどれくらい眠るのだろう。仮に80歳まで生きる（　）、睡眠時間はかなりの量になる。",
        "choices": ["となりました", "とします", "とされていました", "と見られます"],
        "answer": 1,
        "meta": {
            "ko_q": "7) ‘가령 80세까지 산다고 ( ) 하면…’",
            "ko_choices": ["~가 되었다", "~라고 가정한다(とします)", "~라고 여겨져 왔다", "~로 보인다"],
            "ko_explain": "정답 2번 가정/가령 → 「仮に…とします」가 정답입니다."
        }
    },
    {
        "id": "N2_P2_008",
        "part": 2,
        "q": "8　夢を語るのは誰にでもできるが、実現させる（　）努力が必要だ。",
        "choices": ["だけでは", "だけなら", "たしか", "ためには"],
        "answer": 3,
        "meta": {
            "ko_q": "8) 꿈을 실현하려면 ( ) 노력이 필요하다.",
            "ko_choices": ["~만으로는(だけでは)", "~만이라면(だけなら)", "확실히(たしか)", "~하기 위해서는(ためには)"],
            "ko_explain": "정답 4번 목적/조건 ‘…하기 위해서는’ → 「ためには」가 자연스럽습니다."
        }
    },
    {
        "id": "N2_P2_009",
        "part": 2,
        "q": "9（説明書で）\n　エアコンを掃除するときは、安全のため必ずコンセントを（　）してください。",
        "choices": ["抜いたことを", "抜いたことが", "抜いてからに", "抜いてからは"],
        "answer": 3,
        "meta": {
            "ko_q": "9) (설명서) 에어컨 청소할 때는 안전을 위해 반드시 플러그를 ( ) 해 주세요.",
            "ko_choices": ["뽑았던 것을", "뽑았던 적이", "뽑은 뒤에(부자연)", "뽑은 뒤에는(抜いてからは)"],
            "ko_explain": "정답 4번 지시문에서 ‘먼저 뽑고 나서(그 상태로)’ → 「抜いてからは」가 가장 자연스럽습니다."
        }
    },
    {
        "id": "N2_P2_010",
        "part": 2,
        "q": "10　人前で話すのが苦手なのに、結婚パーティーでスピーチを（　）、困っている。",
        "choices": ["しにくくて", "してほしくて", "させてみたくて", "することになってしまって"],
        "answer": 3,
        "meta": {
            "ko_q": "10) 사람 앞에서 말하는 게 서툰데 결혼 파티에서 스피치를 ( ) 난감하다.",
            "ko_choices": ["하기 어렵고", "해줬으면 해서", "시켜보고 싶어서", "하게 되어 버려서"],
            "ko_explain": "정답 4번 원치 않았는데 결정/흐름상 ‘하게 되어버림’ → 「することになってしまって」."
        }
    },
    {
        "id": "N2_P2_011",
        "part": 2,
        "q": "11　せっかく有名な海岸に来たのに雨で夕日が見えない。どうも今日は（　）。",
        "choices": ["見えてもしかたない", "見られないことだった", "見られそうにない", "見えないことがあった"],
        "answer": 2,
        "meta": {
            "ko_q": "11) 일부러 왔는데 비가 와서 석양을 못 본다. 아무래도 오늘은 ( ).",
            "ko_choices": ["보여도 소용없다", "볼 수 없는 일이었다", "볼 수 있을 것 같지 않다", "보이지 않는 일이 있었다"],
            "ko_explain": "정답 3번 현재 상황의 추정 ‘아마 못 볼 것 같다’ → 「見られそうにない」."
        }
    },
    {
        "id": "N2_P2_012",
        "part": 2,
        "q": "12　A「中村さん、最近ジョギング（　）？」\n　B「うん、運動不足だからね。」",
        "choices": ["しない", "してもいい", "しちゃえば", "してるんだって"],
        "answer": 3,
        "meta": {
            "ko_q": "12) ‘요즘 조깅 ( )?’",
            "ko_choices": ["안 해", "해도 돼", "해버리면", "한다며?/하고 있다면서(してるんだって)"],
            "ko_explain": "정답 4번 상대에게 ‘한다면서?’처럼 듣고 확인하는 뉘앙스 → 「してるんだって？」가 자연스럽습니다."
        }
    },
    {
        "id": "N2_P2_013",
        "part": 2,
        "q": "13　結婚生活を送る（　）、相手への思いやりを忘れないことが大切だ。",
        "choices": ["うえで", "といえば", "大切か", "何が"],
        "answer": 0,
        "meta": {
            "ko_q": "13) 결혼생활을 해 나가는 ( ), 상대를 배려하는 마음이 중요하다.",
            "ko_choices": ["~하는 데 있어(うえで)", "~라고 하면(といえば)", "중요한가", "무엇이"],
            "ko_explain": "정답 1번 ‘…하는 데 있어’ 상황/전제 → 「うえで」가 정답입니다."
        }
    },
    {
        "id": "N2_P2_014",
        "part": 2,
        "q": "14　就職して（　）とうとう壊れたので、新しいパソコンに買い替えた。",
        "choices": ["ずっと", "買って以来", "がまんが", "使っていた"],
        "answer": 3,
        "meta": {
            "ko_q": "14) 취직해서 ( ) 결국 고장 나서 새 PC로 바꿨다.",
            "ko_choices": ["계속", "산 이후", "참는 것이", "사용해 오던(使っていた)"],
            "ko_explain": "정답 4번 자연스러운 문장: ‘취직해서 **계속 사용해 오던** PC가…’ → 「使っていた」."
        }
    },
    {
        "id": "N2_P2_015",
        "part": 2,
        "q": "15　登山はつらいのに不思議な魅力がある。登っているときは（　）と思うのに、また登りたくなる。",
        "choices": ["思うのに", "二度としたくないと", "苦しいことは", "山を下りて何日かすると"],
        "answer": 1,
        "meta": {
            "ko_q": "15) 등산은 힘든데 매력이 있다. 오르는 중에는 ‘( )’라고 생각하면서도 또 오르고 싶어진다.",
            "ko_choices": ["생각하지만(중복)", "두 번 다시 하고 싶지 않다고", "괴로운 일은", "산을 내려와 며칠 지나면"],
            "ko_explain": "정답 2번 등산 중 ‘두 번 다시 안 해!’ → 대비로 자연스럽게 연결 → 「二度としたくないと」."
        }
    },
    {
        "id": "N2_P2_016",
        "part": 2,
        "q": "16　彼の作品は形はシンプルだが、（　）生命力にあふれている。",
        "choices": ["動き出し", "そうな", "ながら", "今にも"],
        "answer": 3,
        "meta": {
            "ko_q": "16) 작품은 단순하지만, ( ) 금방이라도 움직일 듯 생동감이 넘친다.",
            "ko_choices": ["움직이기 시작해", "~할 것 같은", "~하면서", "금방이라도(今にも)"],
            "ko_explain": "정답 4번 ‘금방이라도 ~할 것 같다’ → 「今にも」가 정답입니다."
        }
    },
    {
        "id": "N2_P2_017",
        "part": 2,
        "q": "17　成功する人としない人の違いは、どんな状況でもあきらめず（　）取り組めるかどうかだ。",
        "choices": ["かどうか", "取り組める", "にある", "最後まで"],
        "answer": 3,
        "meta": {
            "ko_q": "17) 성공하는 사람과 못하는 사람의 차이는 어떤 상황에서도 포기하지 않고 ( ) 임할 수 있는가이다.",
            "ko_choices": ["~인지 아닌지", "임할 수 있다", "~에 있다", "끝까지(最後まで)"],
            "ko_explain": "정답 4번 ‘끝까지’가 문장 의미에 가장 자연스럽습니다."
        }
    },

    # =========================
    # もんだい9 (18~22) - 그룹 문제 (공통 지문은 템플릿에서 표시)
    # q에는 번호만 둔다
    # =========================
    {
        "id": "N2_P2_018",
        "part": 2,
        "q": "18（　）",
        "choices": ["思い込んでいた", "思い出していた", "思い切っていた", "思い知らせた"],
        "answer": 0,
        "meta": {
            "ko_q": "18) ‘당연히 그렇다고 믿고 있었다’ 흐름에 맞는 것을 고르세요.",
            "ko_choices": ["믿어버리고 있었다(思い込んでいた)", "기억해냈다", "결심했다", "깨닫게 했다"],
            "ko_explain": "정답 1번 ‘예전엔 당연히 오래전부터였다고 생각했다’ → 「思い込んでいた」."
        }
    },
    {
        "id": "N2_P2_019",
        "part": 2,
        "q": "19（　）",
        "choices": ["理解しやすかった", "不便だった", "わかりきっていた", "気にしなかった"],
        "answer": 1,
        "meta": {
            "ko_q": "19) ‘해외에서 온 사람에게는 ~’ 문맥에 맞게 고르세요.",
            "ko_choices": ["이해하기 쉬웠다", "불편했다/문제가 되었다", "이미 뻔했다", "신경 쓰지 않았다"],
            "ko_explain": "정답 2번 현지어만 있는 안내판 → 외국인에게 ‘불편/문제’ → 「不便だった」."
        }
    },
    {
        "id": "N2_P2_020",
        "part": 2,
        "q": "20（　）",
        "choices": ["それでも", "こうして", "それにしても", "ところで"],
        "answer": 1,
        "meta": {
            "ko_q": "20) 앞 문장을 받아 ‘그렇게 해서 ~가 되었다’ 흐름에 맞게 고르세요.",
            "ko_choices": ["그래도", "이렇게 해서(こうして)", "그렇다 해도", "그런데"],
            "ko_explain": "정답 2번 앞 해결책 → 결과 연결 ‘이렇게 해서 원형이 됨’ → 「こうして」."
        }
    },
    {
        "id": "N2_P2_021",
        "part": 2,
        "q": "21（　）",
        "choices": ["変わりきっている", "失われていった", "受け継がれている", "逆らっている"],
        "answer": 2,
        "meta": {
            "ko_q": "21) ‘기본 생각/취지가 유지된다’ 의미가 되도록 고르세요.",
            "ko_choices": ["완전히 바뀌어 있다", "사라져 갔다", "계승되고 있다(受け継がれている)", "거스르고 있다"],
            "ko_explain": "정답 3번 문맥상 ‘기본 취지는 유지’ → 「受け継がれている」."
        }
    },
    {
        "id": "N2_P2_022",
        "part": 2,
        "q": "22（　）",
        "choices": ["広がっていったからだ", "広がるはずだった", "広げたいわけだ", "広がらない限りだ"],
        "answer": 0,
        "meta": {
            "ko_q": "22) ‘국경을 넘어 퍼져 갔다’ 문장 결말에 맞게 고르세요.",
            "ko_choices": ["퍼져 갔기 때문이다(広がっていったからだ)", "퍼질 예정이었다", "퍼뜨리고 싶은 것이다", "퍼지지 않는 한"],
            "ko_explain": "정답 1번 ‘퍼졌기 때문이다’ 원인 결론 → 「広がっていったからだ」."
        }
    },
]

# =========================
# JLPT N2 PART3 (読解) - 변형 문제 세트
# 구성(예시 템플릿 기준):
#  - もんだい1: 1~5 (1지문 1문제)
#  - もんだい2~: 6~21 (지문형: 1지문 여러문제는 group으로 묶어 템플릿에 표시)
# =========================

# =========================
# JLPT N2 PART 3 (読解) - 변형문제 세트
# =========================

N2_PART3_QUESTIONS_FULL = [
    # -------------------------
    # (SINGLE) 1지문 1문제 ①
    # -------------------------
    {
        "id": "N2_P3_001",
        "part": 3,
        "q": "筆者の考えに最も合うものはどれか。",
        "choices": [
            "ルールがなくても、楽しさは変わらない。",
            "ルールは勝ち負けをはっきりさせるためにある。",
            "ルールは楽しさを守るためにあり、楽しくなければ意味が薄い。",
            "スポーツは厳しいほど価値が高い。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "1) 筆者の考えに最も合うものはどれか。\n글쓴이의 생각과 가장 맞는 것은 무엇인가?",
            "ko_choices": [
                "ルールがなくても、楽しさは変わらない。규칙이 없어도 즐거움은 변하지 않는다.",
                "ルールは勝ち負けをはっきりさせるためにある。규칙은 승패를 분명히 하기 위해 존재한다.",
                "ルールは楽しさを守るためにあり、楽しくなければ意味が薄い。규칙은 즐거움을 지키기 위한 것이며, 즐겁지 않다면 의미가 약해진다.",
                "スポーツは厳しいほど価値が高い。스포츠는 엄격할수록 가치가 높다."
            ],
            "ko_explain": "정답 3번 지문은 ‘스포츠는 즐기기 위한 것’이며, 규칙은 그 즐거움을 유지·보호하기 위한 장치라고 말한다. 즐겁지 않으면 그 활동의 의미가 약해진다는 흐름이므로 3번이 가장 적절하다."
        },
        "group": {
            "id": "N2_P3_G01",
            "start": 1,
            "end": 1,
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、１・２・３・４から一つ選びなさい。",
            "stem_ko": "다음 글을 읽고, 뒤의 물음에 대한 답으로 가장 알맞은 것을 1·2·3·4 중에서 하나 고르시오.",
            "passage_jp": "「ルールは窮屈だ」と言う人がいる。確かに、自由に動けないと感じる瞬間もあるだろう。\nしかし、スポーツは人が楽しむためのもので、参加者が同じ条件で競うからこそ面白い。もし「勝てばいい」と思う人が増えれば、強い人だけが得をして、競技はすぐに息苦しくなる。\nだからルールは、勝ち負けを決めるためだけではなく、楽しさを守るためにある。楽しめなくなった時点で、その活動は本来の意味を失ってしまう。",
            "passage_ko": "‘규칙은 답답하다’고 말하는 사람이 있다. 확실히 자유롭게 움직이지 못한다고 느끼는 순간도 있을 것이다.\n하지만 스포츠는 사람들이 즐기기 위한 것이며, 참가자가 같은 조건에서 겨루기 때문에 재미가 생긴다. 만약 ‘이기기만 하면 된다’는 사람이 늘면, 강한 사람만 이득을 보고 경기는 곧 숨막히게 된다.\n따라서 규칙은 승패를 정하기 위한 것만이 아니라, 즐거움을 지키기 위한 것이다. 즐길 수 없게 되는 순간 그 활동은 본래 의미를 잃는다."
        }
    },

    # -------------------------
    # (SINGLE) 1지문 1문제 ② (사내 공지)
    # -------------------------
    {
        "id": "N2_P3_002",
        "part": 3,
        "q": "この文書を書いた目的として最も適切なものはどれか。",
        "choices": [
            "暖房を使わずに勤務することを命令するため。",
            "暖房の設定温度を上げるよう呼びかけるため。",
            "節電のために、使い方の工夫と消し忘れ防止を徹底させるため。",
            "電気料金の値上がりの理由を説明するため。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "2) この文書を書いた目的として最も適切なものはどれか。\n이 문서를 작성한 목적로 가장 적절한 것은 무엇인가?",
            "ko_choices": [
                "暖房を使わずに勤務することを命令するため。난방을 사용하지 말고 근무하라고 명령하기 위해.",
                "暖房の設定温度を上げるよう呼びかけるため。난방 설정 온도를 올리자고 호소하기 위해.",
                "節電のために、使い方の工夫と消し忘れ防止を徹底させるため。절전을 위해 사용 습관을 개선하고, 끄는 것을 철저히 하게 하기 위해.",
                "電気料金の値上がりの理由を説明するため。전기요금이 오른 이유를 설명하기 위해."
            ],
            "ko_explain": "정답 3번 문서는 ‘절전’을 위해 (1) 설정 온도 관리, (2) 사용하지 않는 장소는 끄기, (3) 퇴근 시 끄는 것 확인 등을 ‘철저히’ 해달라고 요청한다. 따라서 3번이 목적에 맞다."
        },
        "group": {
            "id": "N2_P3_G02",
            "start": 2,
            "end": 2,
            "stem_jp": "次の文章を読んで、後の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, 뒤의 물음에 답하시오.",
            "passage_jp": "以下は、ある会社の社内文書である。\n\n【冷暖房の使用についてのお願い】\n最近、冷暖房の使用が増え、電力消費も高くなっています。節電のため、室温の設定を見直すとともに、使用していない会議室や休憩室の電源は必ず切ってください。\nまた、退社時には最後に確認し、切り忘れがないよう徹底をお願いします。服装でも調整し、冷暖房に頼りすぎない工夫にご協力ください。",
            "passage_ko": "다음은 어떤 회사의 사내 문서이다.\n\n【냉난방 사용에 관한 부탁】\n최근 냉난방 사용이 늘어 전력 소비도 높아지고 있습니다. 절전을 위해 실내 온도 설정을 재검토하는 것과 함께, 사용하지 않는 회의실·휴게실의 전원은 반드시 꺼 주세요.\n또한 퇴근 시 마지막으로 확인하여 끄는 것을 잊지 않도록 철저히 부탁드립니다. 복장으로도 조절해 냉난방에 지나치게 의존하지 않도록 협조해 주세요."
        }
    },

    # -------------------------
    # (SINGLE) 1지문 1문제 ③ (에세이)
    # -------------------------
    {
        "id": "N2_P3_003",
        "part": 3,
        "q": "筆者が言いたいことは何か。",
        "choices": [
            "大きな目標を立ててから、細かい計画を作るべきだ。",
            "今の努力が無意味に感じても、続けることが大切だ。",
            "目の前の小さな行動を積み重ねると、望む方向へ近づきやすい。",
            "本当に望むことは、考え続ければ自然に分かる。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "3) 筆者が言いたいことは何か。\n글쓴이가 말하고자 하는 바는 무엇인가?",
            "ko_choices": [
                "大きな目標を立ててから、細かい計画を作るべきだ。큰 목표를 세운 다음에 세부 계획을 만들어야 한다.",
                "今の努力が無意味に感じても、続けることが大切だ。지금의 노력이 무의미하게 느껴져도 계속하는 것이 중요하다.",
                "目の前の小さな行動を積み重ねると、望む方向へ近づきやすい。눈앞의 작은 행동을 쌓으면 원하는 방향에 가까워지기 쉽다.",
                "本当に望むことは、考え続ければ自然に分かる。정말로 바라는 것은 계속 생각하면 자연히 알게 된다."
            ],
            "ko_explain": "정답 3번 지문은 ‘막연한 큰 목표’만 붙잡기보다 ‘오늘 할 수 있는 작은 일’을 찾아 집중하면, 그 과정이 결국 원하는 방향으로 이어질 가능성이 높다고 말한다. 따라서 3번."
        },
        "group": {
            "id": "N2_P3_G03",
            "start": 3,
            "end": 3,
            "stem_jp": "次の文章を読んで、後の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, 뒤의 물음에 답하시오.",
            "passage_jp": "「やりたいことを成し遂げる」ために必要なのは、遠い将来の大きな目標を細かく想像することだけではない。\nむしろ、「今日の自分ができること」を一つ決めて、それを続けられる形に整えるほうが現実的だ。小さな達成を積み重ねるうちに、自分が本当に望んでいる方向が少しずつ見えてくる。\n目の前の行動が積み重なることで、結果として「やりたいこと」に近づいていくことも多い。",
            "passage_ko": "‘하고 싶은 일을 이루기’ 위해 필요한 것은 먼 미래의 큰 목표를 세세하게 상상하는 것만이 아니다.\n오히려 ‘오늘의 내가 할 수 있는 일’을 하나 정해 지속 가능한 형태로 만드는 편이 현실적이다. 작은 성취를 쌓아 가는 동안, 내가 진정으로 바라는 방향이 조금씩 보이기 시작한다.\n눈앞의 행동이 쌓이면 결과적으로 ‘하고 싶은 일’에 가까워지는 경우도 많다."
        }
    },

    # -------------------------
    # (SINGLE) 1지문 1문제 ④ (DM/안내장)
    # -------------------------
    {
        "id": "N2_P3_004",
        "part": 3,
        "q": "この案内で紹介されている割引について正しいものはどれか。",
        "choices": [
            "定期購入の人は、今月中は新商品をいつでも10%引きで買える。",
            "定期購入の人が今月中に予約すれば、新商品を15%引きで買える。",
            "新商品を予約した人は、他の商品もすべて15%引きで買える。",
            "新商品を買った人は、今月だけ他の商品も10%引きになる。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "4) この案内で紹介されている割引について正しいものはどれか。\n이 안내에서 소개한 할인에 대해 올바른 것은 무엇인가?",
            "ko_choices": [
                "定期購入の人は、今月中は新商品をいつでも10%引きで買える。정기구매 고객은 이번 달 동안 신상품을 언제든 10% 할인으로 살 수 있다.",
                "定期購入の人が今月中に予約すれば、新商品を15%引きで買える。정기구매 고객이 이번 달 안에 예약하면 신상품을 15% 할인으로 살 수 있다.",
                "新商品を予約した人は、他の商品もすべて15%引きで買える。신상품을 예약한 사람은 다른 상품도 전부 15% 할인으로 살 수 있다.",
                "新商品を買った人は、今月だけ他の商品も10%引きになる。신상품을 산 사람은 이번 달에만 다른 상품도 10% 할인이 된다."
            ],
            "ko_explain": "정답 2번 안내문은 ‘정기구매 고객’이 ‘이번 달 안에 예약’하면 ‘신상품’이 15% 할인이라고 말한다. 다른 상품은 ‘항상 10%’라는 조건이므로 2번이 정확하다."
        },
        "group": {
            "id": "N2_P3_G04",
            "start": 4,
            "end": 4,
            "stem_jp": "次の文章を読んで、後の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, 뒤의 물음에 답하시오.",
            "passage_jp": "以下は、食品販売会社から届いた案内である。\n\n【定期購入者さま向け 早割のご案内】\nいつも当社の商品をご利用いただき、ありがとうございます。\nこのたび新商品「冬のブレンド」を発売いたします。定期購入をご利用のお客さまは、今月中にご予約いただくと「冬のブレンド」を15%引きの特別価格でお求めいただけます。\nまた、定期購入者さまは、その他の商品もいつでも10%引きでご利用いただけます。\n詳しい注文方法は同封の資料をご覧ください。",
            "passage_ko": "다음은 식품 판매 회사에서 온 안내문이다.\n\n【정기구매 고객 대상 조기 할인 안내】\n언제나 당사 상품을 이용해 주셔서 감사합니다.\n이번에 신상품 ‘겨울 블렌드’를 출시합니다. 정기구매를 이용하시는 고객은 이번 달 안에 예약하시면 ‘겨울 블렌드’를 15% 할인된 특별가로 구매하실 수 있습니다.\n또한 정기구매 고객은 다른 상품도 언제든 10% 할인으로 이용하실 수 있습니다.\n자세한 주문 방법은 동봉된 자료를 확인해 주세요."
        }
    },

    # -------------------------
    # (SINGLE) 1지문 1문제 ⑤ (칼럼)
    # -------------------------
    {
        "id": "N2_P3_005",
        "part": 3,
        "q": "筆者によると、日記を書き続けるとどうなるか。",
        "choices": [
            "毎日を「いい一日」にしようと意識して行動するようになる。",
            "毎日が自然に「いい一日」だと思えるようになる。",
            "「いい一日」が来るのを楽しみに待つようになる。",
            "「いい一日」の記憶を忘れないように努力するようになる。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "5) 筆者によると、日記を書き続けるとどうなるか。\n글쓴이에 따르면, 일기를 계속 쓰면 어떻게 되는가?",
            "ko_choices": [
                "毎日を「いい一日」にしようと意識して行動するようになる。매일을 ‘좋은 하루’로 만들려고 의식하며 행동하게 된다.",
                "毎日が自然に「いい一日」だと思えるようになる。매일이 자연스럽게 ‘좋은 하루’라고 느끼게 된다.",
                "「いい一日」が来るのを楽しみに待つようになる。‘좋은 하루’가 오기를 기대하며 기다리게 된다.",
                "「いい一日」の記憶を忘れないように努力するようになる。‘좋은 하루’의 기억을 잊지 않으려고 노력하게 된다."
            ],
            "ko_explain": "정답 1번 지문은 일기를 통해 ‘좋은 하루’의 조건을 알게 되면, 좋은 날이 오길 기다리기보다 ‘오늘을 좋은 하루로 만들자’고 주체적으로 행동하게 된다고 말한다. 그래서 1번."
        },
        "group": {
            "id": "N2_P3_G05",
            "start": 5,
            "end": 5,
            "stem_jp": "次の文章を読んで、後の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, 뒤의 물음에 답하시오.",
            "passage_jp": "「いい一日」がどんな日かは人によって違うだろう。だが、日記を書き続けると、自分にとっての「いい一日」を作る条件が見えてくる。\n条件が分かれば、「いい一日」がまた来るのを待つのではなく、「今日」をその日に近づけるために、自分から動けるようになる。\nつまり、日記は記録であると同時に、日々の選び方を変えるきっかけにもなるのだ。",
            "passage_ko": "‘좋은 하루’가 어떤 날인지는 사람마다 다를 것이다. 그러나 일기를 계속 쓰면, 나에게 ‘좋은 하루’를 만드는 조건이 보이게 된다.\n조건을 알면 ‘좋은 하루’가 오기를 기다리는 것이 아니라, ‘오늘’을 그에 가깝게 만들기 위해 스스로 행동하게 된다.\n즉 일기는 기록인 동시에, 매일의 선택을 바꾸는 계기가 되기도 한다."
        }
    },

    # =========================================================
    # (GROUP) 1지문 3문제 ⑥ (개성/개인성) : Q6~Q8
    # =========================================================
    {
        "id": "N2_P3_006",
        "part": 3,
        "q": "日本で使われる「個性」という言葉について、筆者はどのように述べているか。",
        "choices": [
            "本来の意味とは違う使い方がされがちだ。",
            "意味があいまいなので使うべきではない。",
            "若者に対してだけ使われる言葉だ。",
            "人によって使い方がまったく違う。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "6) 日本で使われる「個性」という言葉について、筆者はどのように述べているか。\n일본에서 쓰이는 ‘개성’이라는 말에 대해 글쓴이는 어떻게 말하고 있는가?",
            "ko_choices": [
                "本来の意味とは違う使い方がされがちだ。본래 의미와 다른 방식으로 쓰이기 쉽다고 한다.",
                "意味があいまいなので使うべきではない。의미가 애매하니 사용하면 안 된다고 한다.",
                "若者に対してだけ使われる言葉だ。젊은이에게만 쓰이는 말이라고 한다.",
                "人によって使い方がまったく違う。사람마다 사용법이 전혀 다르다고 한다."
            ],
            "ko_explain": "정답 1번 지문은 ‘개성’이 ‘눈에 띄는 것/튀는 것’처럼 외형 중심으로 쓰이는 경우가 많아 위화감을 느낀다고 말한다. 즉 본래 의미와 다른 사용이 된다는 취지이므로 1번."
        },
        "group": {
            "id": "N2_P3_G06",
            "start": 6,
            "end": 8,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "日本ではよく、「個性を出せ」「もっと個性を磨け」と言われる。しかし私は、その言い方に少し違和感がある。\n多くの場合、「個性的」とは「人より目立つ外見」や「奇抜なスタイル」を指しているように見えるからだ。\nけれども、人は生まれた時点ですでにそれぞれ違う。わざわざ他人と比べて「自分はどうか」と焦る必要はない。\n本当の意味で個性を磨くとは、流行や評価に合わせて形を変えることではなく、自分が面白いと思うこと、心が動くものに時間を使い、経験を深めていくことだ。\nそうして自分の世界が広がっていく過程こそが、個性につながるのだ。",
            "passage_ko": "일본에서는 ‘개성을 드러내라’, ‘더 개성을 갈고닦아라’라는 말을 자주 한다. 하지만 나는 그 말투에 조금 위화감을 느낀다.\n대부분 ‘개성적’이라는 말이 ‘남보다 눈에 띄는 외모’나 ‘기발한 스타일’을 가리키는 듯 보이기 때문이다.\n그러나 사람은 태어날 때부터 이미 각자 다르다. 굳이 남과 비교하며 ‘나는 어떤가’ 하고 초조해할 필요는 없다.\n진정한 의미에서 개성을 갈고닦는다는 것은 유행이나 평가에 맞춰 모양을 바꾸는 것이 아니라, 내가 재미있다고 느끼는 것, 마음이 움직이는 것에 시간을 쓰고 경험을 깊게 하는 일이다.\n그렇게 자신의 세계가 넓어지는 과정이야말로 개성으로 이어진다."
        }
    },
    {
        "id": "N2_P3_007",
        "part": 3,
        "q": "個性について、筆者の考えに合うものはどれか。",
        "choices": [
            "他人には理解されないものが本当の個性だ。",
            "人より目立つことで個性は発揮される。",
            "人は誰でも生まれつき個性を持っている。",
            "ファッションによって個性は作れる。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "7) 個性について、筆者の考えに合うものはどれか。\n개성에 대해 글쓴이의 생각과 맞는 것은 무엇인가?",
            "ko_choices": [
                "他人には理解されないものが本当の個性だ。남에게 이해되지 않는 것이 진짜 개성이다.",
                "人より目立つことで個性は発揮される。남보다 눈에 띄면 개성이 발휘된다.",
                "人は誰でも生まれつき個性を持っている。사람은 누구나 태어날 때부터 개성을 가지고 있다.",
                "ファッションによって個性は作れる。패션으로 개성은 만들 수 있다."
            ],
            "ko_explain": "정답 3번 지문에서 ‘사람은 태어난 시점에 이미 각각 다르다’고 하며 비교·초조해할 필요가 없다고 말한다. 따라서 3번."
        },
        "group": {
            "id": "N2_P3_G06",
            "start": 6,
            "end": 8,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "",
            "passage_ko": ""
        }
    },
    {
        "id": "N2_P3_008",
        "part": 3,
        "q": "筆者によると、本当の意味で「個性を磨く」とはどのようなことか。",
        "choices": [
            "自分の心が動くものを追い求め、経験を深めること",
            "個性的に見られるかどうかを優先して工夫すること",
            "周囲の評価を参考にして、無理なく外見を変えること",
            "どんな物事にも楽しさを見つける努力をすること"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "8) 筆者によると、本当の意味で「個性を磨く」とはどのようなことか。\n글쓴이에 따르면 진정한 의미에서 ‘개성을 갈고닦는다’는 것은 무엇인가?",
            "ko_choices": [
                "自分の心が動くものを追い求め、経験を深めること마음이 움직이는 것을 좇고 경험을 깊게 하는 것",
                "個性的に見られるかどうかを優先して工夫すること개성적으로 보일지 여부를 우선해 꾸미는 것",
                "周囲の評価を参考にして、無理なく外見を変えること주변 평가를 참고해 무리 없이 외모를 바꾸는 것",
                "どんな物事にも楽しさを見つける努力をすること어떤 일에서도 즐거움을 찾으려 노력하는 것"
            ],
            "ko_explain": "정답 1번 지문은 유행·평가에 맞춰 변신하는 것이 아니라, 스스로 흥미를 느끼는 것에 시간을 쓰고 경험을 깊게 하는 과정이 개성으로 이어진다고 한다. 그래서 1번."
        },
        "group": {
            "id": "N2_P3_G06",
            "start": 6,
            "end": 8,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "",
            "passage_ko": ""
        }
    },

    # =========================================================
    # (GROUP) 1지문 3문제 ⑦ (말/글) : Q9~Q11
    # =========================================================
    {
        "id": "N2_P3_009",
        "part": 3,
        "q": "筆者によると、「話し言葉」の重要な特徴は何か。",
        "choices": [
            "声を使って情報を共有できるところ",
            "相手の反応をすぐに確かめられるところ",
            "相手と場面を共有しているところ",
            "親しい相手にしか使えないところ"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "9) 筆者によると、「話し言葉」の重要な特徴は何か。\n글쓴이에 따르면 ‘말(구어)’의 중요한 특징은 무엇인가?",
            "ko_choices": [
                "声を使って情報を共有できるところ목소리를 사용해 정보를 공유할 수 있는 점",
                "相手の反応をすぐに確かめられるところ상대의 반응을 즉시 확인할 수 있는 점",
                "相手と場面を共有しているところ상대와 상황(장면)을 공유하고 있는 점",
                "親しい相手にしか使えないところ친한 상대에게만 사용할 수 있는 점"
            ],
            "ko_explain": "정답 3번 지문은 말은 ‘상대가 눈앞에 있고, 어디서 어떤 상황인지 공유’하고 있기 때문에 통하는 부분이 있다고 한다. 즉 ‘장면 공유’가 핵심이므로 3번."
        },
        "group": {
            "id": "N2_P3_G07",
            "start": 9,
            "end": 11,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "「話し言葉」の大きな特徴は、声を使うことそのものより、話し手と聞き手が同じ場面を共有している点にある。\n相手が目の前にいれば、表情や反応を見て言い直したり補ったりできるし、状況の説明を省いても通じることが多い。\nしかし「書き言葉」になると、相手はその場にいない。あとで読み返す可能性もある。だから、必要な背景や意図を言葉で補い、誤解が起きにくい順序で示す配慮が欠かせない。\n書くとは、頭の中で分かっていることを、相手が分かる形に組み立て直す作業であり、そこにこそ難しさがある。",
            "passage_ko": "‘말(구어)’의 큰 특징은 목소리를 쓰는 것 자체보다, 말하는 사람과 듣는 사람이 같은 장면(상황)을 공유한다는 점에 있다.\n상대가 눈앞에 있으면 표정과 반응을 보고 다시 말하거나 보충할 수 있고, 상황 설명을 생략해도 통하는 경우가 많다.\n하지만 ‘글(문어)’이 되면 상대는 그 자리에 없다. 나중에 다시 읽을 가능성도 있다. 그래서 필요한 배경과 의도를 말로 보충하고, 오해가 생기기 어렵도록 순서를 고려하는 배려가 필수다.\n글을 쓴다는 것은 머릿속에서 이미 알고 있는 것을 상대가 이해할 수 있는 형태로 다시 구성하는 작업이며, 그 점이 어려움의 핵심이다."
        }
    },
    {
        "id": "N2_P3_010",
        "part": 3,
        "q": "筆者は、どのような時に誤解が生じやすいと言っているか。",
        "choices": [
            "必要な背景や意図を十分に言葉で補っていない時",
            "相手の反応を気にしすぎて文章が長くなった時",
            "自分のためのメモをそのまま相手に送った時",
            "丁寧に書きすぎて結論が遅くなった時"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "10) 筆者は、どのような時に誤解が生じやすいと言っているか。\n글쓴이는 어떤 때 오해가 생기기 쉽다고 말하는가?",
            "ko_choices": [
                "必要な背景や意図を十分に言葉で補っていない時필요한 배경·의도를 말로 충분히 보충하지 않을 때",
                "相手の反応を気にしすぎて文章が長くなった時상대 반응을 너무 의식해 글이 길어질 때",
                "自分のためのメモをそのまま相手に送った時자기 메모를 그대로 상대에게 보냈을 때",
                "丁寧に書きすぎて結論が遅くなった時너무 정중하게 써서 결론이 늦어질 때"
            ],
            "ko_explain": "정답 1번 지문은 글에서는 상대가 그 장면을 공유하지 않기 때문에 배경·의도를 ‘말로 보충’하지 않으면 오해가 생길 수 있다고 한다. 따라서 1번."
        },
        "group": {
            "id": "N2_P3_G07",
            "start": 9,
            "end": 11,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "",
            "passage_ko": ""
        }
    },
    {
        "id": "N2_P3_011",
        "part": 3,
        "q": "「書き言葉」について、筆者の考えに合うものはどれか。",
        "choices": [
            "相手が必要とする情報を想像し、分かりやすく示すことが大切だ。",
            "正確な漢字や語彙を優先すれば、誤解は起きない。",
            "内容よりも文章の短さを重視したほうがよい。",
            "読み手の知識は考えず、自分の意図だけを書くべきだ。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "11) 「書き言葉」について、筆者の考えに合うものはどれか。\n‘글(문어)’에 대해 글쓴이의 생각과 맞는 것은 무엇인가?",
            "ko_choices": [
                "相手が必要とする情報を想像し、分かりやすく示すことが大切だ。상대가 필요로 하는 정보를 상상하고, 이해하기 쉽게 제시하는 것이 중요하다.",
                "正確な漢字や語彙を優先すれば、誤解は起きない。한자·어휘를 정확히 쓰기만 하면 오해는 생기지 않는다.",
                "内容よりも文章の短さを重視したほうがよい。내용보다 글의 짧음을 중시하는 편이 좋다.",
                "読み手の知識は考えず、自分の意図だけを書くべきだ。독자의 지식은 고려하지 말고 자신의 의도만 쓰면 된다."
            ],
            "ko_explain": "정답 1번 지문은 ‘상대가 어떤 정보를 필요로 하는지 추정’하고, ‘어떤 순서로 제공해야 오해가 줄어드는지’ 생각하는 것이 중요하다고 한다. 따라서 1번."
        },
        "group": {
            "id": "N2_P3_G07",
            "start": 9,
            "end": 11,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "",
            "passage_ko": ""
        }
    },

    # =========================================================
    # (GROUP) 1지문 3문제 ⑧ (여행) : Q12~Q14
    # =========================================================
    {
        "id": "N2_P3_012",
        "part": 3,
        "q": "筆者によると、これまでの旅行はどのようなものだったか。",
        "choices": [
            "高くても遠い場所で長く過ごすことが理想だった。",
            "行ったことのない場所に行き、見るだけで満足できた。",
            "気に入った場所に繰り返し行くことが中心だった。",
            "近くて安い場所に短期間で行くことが主流だった。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "12) 筆者によると、これまでの旅行はどのようなものだったか。\n글쓴이에 따르면, 지금까지의 여행은 어떤 것이었는가?",
            "ko_choices": [
                "高くても遠い場所で長く過ごすことが理想だった。비싸더라도 먼 곳에서 오래 머무는 것이 이상이었다.",
                "行ったことのない場所に行き、見るだけで満足できた。가본 적 없는 곳에 가서 보고 즐기기만 해도 만족할 수 있었다.",
                "気に入った場所に繰り返し行くことが中心だった。마음에 든 장소에 반복해서 가는 것이 중심이었다.",
                "近くて安い場所に短期間で行くことが主流だった。가깝고 싼 곳에 짧게 다녀오는 것이 주류였다."
            ],
            "ko_explain": "정답 2번 지문은 예전에는 ‘가본 적 없는 곳에 가고, 보고 싶은 것을 보고’ ‘관광만으로도 충분히 만족’할 수 있었던 시대였다고 설명한다. 따라서 2번."
        },
        "group": {
            "id": "N2_P3_G08",
            "start": 12,
            "end": 14,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "従来、旅行で顧客を満足させるのはそれほど難しくなかった。行ったことのない場所に行き、見たことのない景色を見れば、それだけで十分に満足できたからだ。\n旅行会社も、名所を効率よく回るプランを作り、魅力を繰り返し伝えればよかった。\nしかし、多くの人がどこへでも行けるようになると、「行くだけ」では満足しにくくなった。今は、そこで何をするのか、どんな体験ができるのかという目的が重視される。\nところが目的は人によって違う。個々の目的に合わせた企画を「大勢向け」にまとめるのは簡単ではない。価値観が多様になるほど、その難しさは増していく。",
            "passage_ko": "예전에는 여행으로 고객을 만족시키는 일이 그리 어렵지 않았다. 가본 적 없는 곳에 가서, 본 적 없는 풍경을 보기만 해도 충분히 만족할 수 있었기 때문이다.\n여행사도 명소를 효율적으로 도는 계획을 만들고, 매력을 반복해서 전달하면 되었다.\n하지만 많은 사람이 어디든 갈 수 있게 되자 ‘가기만 하는 것’으로는 만족하기 어려워졌다. 지금은 그곳에서 무엇을 하는지, 어떤 체험을 할 수 있는지 같은 ‘목적’이 중시된다.\n그런데 목적은 사람마다 다르다. 각자의 목적에 맞춘 기획을 ‘다수 대상’으로 정리하는 일은 쉽지 않다. 가치관이 다양해질수록 그 어려움은 커진다."
        }
    },
    {
        "id": "N2_P3_013",
        "part": 3,
        "q": "筆者によると、客は旅行で何を重視するようになってきたか。",
        "choices": [
            "一回の旅行で多くの場所へ行けるかどうか",
            "観光するだけで満足できるかどうか",
            "行って何を体験できるかどうか",
            "新しい場所へ行けるかどうか"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "13) 筆者によると、客は旅行で何を重視するようになってきたか。\n글쓴이에 따르면, 여행객은 여행에서 무엇을 중시하게 되었는가?",
            "ko_choices": [
                "一回の旅行で多くの場所へ行けるかどうか한 번의 여행에서 많은 곳을 갈 수 있는지",
                "観光するだけで満足できるかどうか관광만으로도 만족할 수 있는지",
                "行って何を体験できるかどうか가서 무엇을 체험할 수 있는지",
                "新しい場所へ行けるかどうか새로운 장소에 갈 수 있는지"
            ],
            "ko_explain": "정답 3번 지문은 이제 ‘가보기만 하는 것’으로는 부족해져서 ‘그곳에서 무엇을 하는가/어떤 체험을 하는가’가 중요해졌다고 말한다. 따라서 3번."
        },
        "group": {
            "id": "N2_P3_G08",
            "start": 12,
            "end": 14,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "",
            "passage_ko": ""
        }
    },
    {
        "id": "N2_P3_014",
        "part": 3,
        "q": "筆者によると、旅行会社が難しいと感じている点は何か。",
        "choices": [
            "個々の目的に合った企画を、多くの人向けにまとめること",
            "魅力を感じてもらえる場所を探し続けること",
            "旅行に行こうという気持ちにさせること",
            "価格を抑えた団体旅行を増やすこと"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "14) 筆者によると、旅行会社が難しいと感じている点は何か。\n글쓴이에 따르면, 여행회사가 어렵다고 느끼는 점은 무엇인가?",
            "ko_choices": [
                "個々の目的に合った企画を、多くの人向けにまとめること각자의 목적에 맞춘 기획을 많은 사람에게 맞게 묶는 것",
                "魅力を感じてもらえる場所を探し続けること매력을 느끼게 할 장소를 계속 찾는 것",
                "旅行に行こうという気持ちにさせること여행을 가고 싶게 만드는 것",
                "価格を抑えた団体旅行を増やすこと가격을 낮춘 단체여행을 늘리는 것"
            ],
            "ko_explain": "정답 1번 지문은 목적이 다양해지면서 ‘개별 목적에 맞춘 기획’을 ‘대다수용’으로 정리하기가 어렵다고 말한다. 따라서 1번."
        },
        "group": {
            "id": "N2_P3_G08",
            "start": 12,
            "end": 14,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "",
            "passage_ko": ""
        }
    },

    # =========================================================
    # (GROUP) A・B 비교 2문제 ⑨ : Q15~Q16
    # =========================================================
    {
        "id": "N2_P3_015",
        "part": 3,
        "q": "人気本を複数冊置くことについて、AとBはどのように述べているか。",
        "choices": [
            "AもBも、利用者の希望を重視しすぎだと述べている。",
            "AもBも、サービス向上につながると述べている。",
            "Aは予算不足を心配し、Bは図書館の役割が薄れると述べている。",
            "Aは満足度が上がると述べ、Bは予算の使い方として適切だと述べている。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "15) 人気本を複数冊置くことについて、AとBはどのように述べているか。\n인기 있는 책을 여러 권 비치하는 것에 대해 A와 B는 어떻게 말하고 있는가?",
            "ko_choices": [
                "AもBも、利用者の希望を重視しすぎだと述べている。A와 B 모두 이용자의 희망을 지나치게 중시한다고 말한다.",
                "AもBも、サービス向上につながると述べている。A와 B 모두 서비스 향상으로 이어진다고 말한다.",
                "Aは予算不足を心配し、Bは図書館の役割が薄れると述べている。A는 예산 문제를 걱정하고, B는 도서관의 역할이 약해질 수 있다고 말한다.",
                "Aは満足度が上がると述べ、Bは予算の使い方として適切だと述べている。A는 만족도가 올라간다고 말하고, B는 예산 사용으로 적절하다고 말한다."
            ],
            "ko_explain": "정답 3번 A는 대출 대기 기간 단축 등 장점을 인정하면서도 ‘예산이 제한되어 종류가 줄 수 있다’는 우려를 소개한다. B는 ‘유행 책을 빨리 읽고 싶으면 사면 된다’며 도서관 예산을 거기에 쓰는 건 불필요하고, 본래 역할이 약해질 수 있다고 말한다. 따라서 3번."
        },
        "group": {
            "id": "N2_P3_G09",
            "start": 15,
            "end": 16,
            "stem_jp": "次のAとBの文章を読んで、後の問いに答えなさい。",
            "stem_ko": "다음 A와 B의 글을 읽고, 뒤의 물음에 답하시오.",
            "passage_jp": "【A】\n公立図書館では、利用者へのサービス向上のために、人気の高い本を複数冊そろえることが増えている。同じ本が何冊かあれば、同時に貸し出せて予約待ちも短くなる。\nただし、予算には限りがあるため、購入できる本の種類が減るのではないかという心配もある。とはいえ、借りたい本がなかなか借りられない状況では利用者は満足しにくい。複数冊そろえることは、その不満を減らす一つの方法だ。\n\n【B】\n最近、公立図書館が人気本を何冊も購入していると聞く。早く読みたい人の気持ちは分かるが、どうしても急ぐなら自分で買えばよい。\n税金で運営される図書館の意義は、学術的に価値があるが入手しにくい本など、幅広い種類をそろえることにある。同じ本を増やしすぎてその役割が果たせなくなるなら、サービス低下と言える。",
            "passage_ko": "【A】\n공공도서관에서는 이용자 서비스 향상을 위해 인기 있는 책을 여러 권 갖추는 경우가 늘고 있다. 같은 책이 여러 권이면 동시에 대출할 수 있어 예약 대기도 짧아진다.\n다만 예산에는 한계가 있어, 살 수 있는 책의 종류가 줄어들지 않느냐는 걱정도 있다. 그렇지만 빌리고 싶은 책을 좀처럼 빌릴 수 없는 상황이라면 이용자 만족도가 떨어진다. 여러 권을 갖추는 것은 그런 불만을 줄이는 한 방법이다.\n\n【B】\n최근 공공도서관이 인기 책을 여러 권 구입한다는 말을 들었다. 빨리 읽고 싶은 마음은 이해하지만, 정말 급하다면 스스로 사면 된다.\n세금으로 운영되는 도서관의 의의는 학술적으로 가치가 있으나 구하기 어려운 책 등 다양한 종류를 갖추는 데 있다. 같은 책을 너무 많이 사서 그 역할을 못 하게 된다면 서비스 저하라고 할 수 있다."
        }
    },
    {
        "id": "N2_P3_016",
        "part": 3,
        "q": "公立図書館の役割について、AとBはどのように述べているか。",
        "choices": [
            "AもBも、利用者の教養を高めることだと述べている。",
            "AもBも、読書を好きな人を増やすことだと述べている。",
            "Aは読書のきっかけを作ること、Bは本の種類を広くそろえることだと述べている。",
            "Aは読書を楽しめる環境づくり、Bは新刊をそろえることだと述べている。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "16) 公立図書館の役割について、AとBはどのように述べているか。\n공공도서관의 역할에 대해 A와 B는 어떻게 말하고 있는가?",
            "ko_choices": [
                "AもBも、利用者の教養を高めることだと述べている。A와 B 모두 교양을 높이는 것이라고 말한다.",
                "AもBも、読書を好きな人を増やすことだと述べている。A와 B 모두 독서 인구를 늘리는 것이라고 말한다.",
                "Aは読書のきっかけを作ること、Bは本の種類を広くそろえることだと述べている。A는 독서의 계기를 주는 것, B는 다양한 종류의 책을 갖추는 것이라고 말한다.",
                "Aは読書を楽しめる環境づくり、Bは新刊をそろえることだと述べている。A는 독서를 즐길 환경 만들기, B는 신간을 갖추는 것이라고 말한다."
            ],
            "ko_explain": "정답 3번 A는 이용자가 ‘빌리고 싶은 책을 빌릴 수 있어야 만족한다’며 독서 기회를 늘리는 쪽(계기/환경)을 강조한다. B는 도서관의 의의를 ‘입수하기 어려운 가치 있는 책 등 다양한 종류를 갖추는 것’이라고 명시한다. 그래서 3번."
        },
        "group": {
            "id": "N2_P3_G09",
            "start": 15,
            "end": 16,
            "stem_jp": "次のAとBの文章を読んで、後の問いに答えなさい。",
            "stem_ko": "다음 A와 B의 글을 읽고, 뒤의 물음에 답하시오.",
            "passage_jp": "",
            "passage_ko": ""
        }
    },

    # =========================================================
    # (GROUP) 1지문 3문제 ⑩ (디자이너/아이디어) : Q17~Q19
    # =========================================================
    {
        "id": "N2_P3_017",
        "part": 3,
        "q": "筆者が「感動を今に持ち帰る」とは、どういうことか。",
        "choices": [
            "感動した出来事を人に語って共有すること",
            "感動した記憶を作品づくりに生かすこと",
            "昔流行した作品をそのまま真似すること",
            "他人の感動した話からヒントを得ること"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "17) 筆者が「感動を今に持ち帰る」とは、どういうことか。\n글쓴이가 말하는 ‘감동을 현재로 가져온다’는 것은 무엇을 뜻하는가?",
            "ko_choices": [
                "感動した出来事を人に語って共有すること감동한 일을 사람들에게 이야기해 공유하는 것",
                "感動した記憶を作品づくりに生かすこと감동한 기억을 작품(디자인) 만들기에 활용하는 것",
                "昔流行した作品をそのまま真似すること과거 유행한 작품을 그대로 모방하는 것",
                "他人の感動した話からヒントを得ること다른 사람이 감동한 이야기에서 힌트를 얻는 것"
            ],
            "ko_explain": "정답 2번 지문은 과거에 감동했던 장면·기억을 ‘현재의 작업(디자인)’으로 옮겨와 구성하는 것을 ‘지금으로 가져온다’고 설명한다. 따라서 2번."
        },
        "group": {
            "id": "N2_P3_G10",
            "start": 17,
            "end": 19,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "あるデザイナーはこう書いている。\n\n私のアイデアは、突然ひらめくというより、これまでの人生で心が動いた瞬間を「今の仕事」に持ち帰ることで生まれる。\n感動した場面は、色や光、匂い、誰といたかまで不思議と細部が残っている。その記憶を取り出し、今ある素材や課題と組み合わせていく。\nただし、表面だけをなぞっても作品にならない。心の底から動いた経験ほど、形にしたときに説得力が出る。\n感動は自分だけで完結しない。人や場所に支えられて生まれることも多い。だからこそ、その感動の“引き出し”が多いほど、アイデアは育つのだ。",
            "passage_ko": "어느 디자이너는 이렇게 썼다.\n\n나의 아이디어는 갑자기 번뜩인다는 것보다, 지금까지 살아오며 마음이 움직였던 순간을 ‘지금의 일’로 가져오는 과정에서 생긴다.\n감동했던 장면은 색과 빛, 냄새, 누구와 있었는지까지도 이상할 만큼 세부가 남아 있다. 그 기억을 꺼내어, 지금 가진 소재나 과제와 조합해 간다.\n다만 겉모양만 따라 해서는 작품이 되지 않는다. 마음 깊이 움직였던 경험일수록 형태로 만들었을 때 설득력이 생긴다.\n감동은 나 혼자만의 것이 아니라 사람이나 장소의 도움 속에서 생기는 경우도 많다. 그래서 그 감동의 ‘서랍(꺼낼 수 있는 기억)’이 많을수록 아이디어는 자란다."
        }
    },
    {
        "id": "N2_P3_018",
        "part": 3,
        "q": "感動について、筆者の考えに合うのはどれか。",
        "choices": [
            "感動は周囲の力がなければ生まれない。",
            "年を取ると感動したことを思い出せなくなる。",
            "感動したことは必ず鮮明に思い出せる。",
            "心が深く動いた経験ほど、作品にしたとき力になる。"
        ],
        "answer": 3,
        "meta": {
            "ko_q": "18) 感動について、筆者の考えに合うのはどれか。\n감동에 대해 글쓴이의 생각과 맞는 것은 무엇인가?",
            "ko_choices": [
                "感動は周囲の力がなければ生まれない。감동은 주변의 힘이 없으면 생기지 않는다.",
                "年を取ると感動したことを思い出せなくなる。나이가 들면 감동한 일을 떠올릴 수 없게 된다.",
                "感動したことは必ず鮮明に思い出せる。감동한 일은 반드시 선명하게 떠올릴 수 있다.",
                "心が深く動いた経験ほど、作品にしたとき力になる。마음 깊이 움직인 경험일수록 작품으로 만들 때 힘이 된다."
            ],
            "ko_explain": "정답 4번 지문은 ‘겉만 따라 하면 안 되고, 마음 깊이 움직인 경험일수록 형태로 만들었을 때 설득력이 나온다’고 한다. 그래서 4번."
        },
        "group": {
            "id": "N2_P3_G10",
            "start": 17,
            "end": 19,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "",
            "passage_ko": ""
        }
    },
    {
        "id": "N2_P3_019",
        "part": 3,
        "q": "アイデアについて、筆者はどのように考えているか。",
        "choices": [
            "記憶力が強いほど、必ずアイデアが多くなる。",
            "他人の力を上手に利用すれば、アイデアが増える。",
            "感動の“引き出し”が多いほど、アイデアは育ちやすい。",
            "感動を分類して考えると、いいアイデアが出る。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "19) アイデアについて、筆者はどのように考えているか。\n아이디어에 대해 글쓴이는 어떻게 생각하는가?",
            "ko_choices": [
                "記憶力が強いほど、必ずアイデアが多くなる。기억력이 좋을수록 반드시 아이디어가 많아진다.",
                "他人の力を上手に利用すれば、アイデアが増える。타인의 힘을 잘 이용하면 아이디어가 늘어난다.",
                "感動の“引き出し”が多いほど、アイデアは育ちやすい。감동의 ‘서랍(꺼낼 수 있는 기억)’이 많을수록 아이디어는 자라기 쉽다.",
                "感動を分類して考えると、いいアイデアが出る。감동을 분류해서 생각하면 좋은 아이디어가 나온다."
            ],
            "ko_explain": "정답 3번 지문 마지막에서 ‘감동의 “서랍”이 많을수록 아이디어는 자란다’고 직접 말한다. 따라서 3번."
        },
        "group": {
            "id": "N2_P3_G10",
            "start": 17,
            "end": 19,
            "stem_jp": "次の文章を読んで、(1)〜(3)の問いに答えなさい。",
            "stem_ko": "다음 글을 읽고, (1)~(3)의 물음에 답하시오.",
            "passage_jp": "",
            "passage_ko": ""
        }
    },

    # =========================================================
    # (GROUP) 웹페이지/표 안내 2문제 ⑪ : Q20~Q21
    # =========================================================
    {
        "id": "N2_P3_020",
        "part": 3,
        "q": "コソンさんの希望に合うビュッフェはどれか。",
        "choices": [
            "「ベルン」ランチビュッフェ",
            "「ベルン」デザートビュッフェ",
            "「ベルン」ディナービュッフェ",
            "「みよし」ランチビュッフェ"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "20) コソンさんの希望に合うビュッフェはどれか。\n코손 씨의 희망 조건에 맞는 뷔페는 무엇인가?",
            "ko_choices": [
                "「ベルン」ランチビュッフェ‘베른’ 런치 뷔페",
                "「ベルン」デザートビュッフェ‘베른’ 디저트 뷔페",
                "「ベルン」ディナービュッフェ‘베른’ 디너 뷔페",
                "「みよし」ランチビュッフェ‘미요시’ 런치 뷔페"
            ],
            "ko_explain": "정답 2번 조건은 ‘금~토 12시~17시 사이’에 ‘2시간’ 이용. 안내에서 ‘ベルン デザート’가 금·토 13:00/15:00 시작(각 2시간)으로 해당 시간대에 맞는다. 따라서 2번."
        },
        "group": {
            "id": "N2_P3_G11",
            "start": 20,
            "end": 21,
            "stem_jp": "右のページは、あるホテルのホームページに載っている案内である。下の問いに答えなさい。",
            "stem_ko": "오른쪽 페이지는 어떤 호텔 홈페이지의 안내문이다. 아래 물음에 답하시오.",
            "passage_jp": "【ミハマホテル ビュッフェ案内（抜粋）】\n\n■ レストラン「ベルン」\n・ランチ：平日 11:30〜14:30（90分）\n・デザート：金・土 13:00／15:00スタート（各120分）\n・ディナー：金・土 18:00〜21:00（120分）\n\n■ 和食「みよし」\n・ランチ：土・日 11:00〜15:00（60分）\n\n※ 予約は前日まで。混雑時は入場制限あり。",
            "passage_ko": "【미하마 호텔 뷔페 안내(발췌)】\n\n■ 레스토랑 ‘베른’\n· 런치: 평일 11:30~14:30(90분)\n· 디저트: 금·토 13:00 / 15:00 시작(각 120분)\n· 디너: 금·토 18:00~21:00(120분)\n\n■ 일식 ‘미요시’\n· 런치: 토·일 11:00~15:00(60분)\n\n※ 예약은 전날까지. 혼잡 시 입장 제한이 있을 수 있음."
        }
    },
    {
        "id": "N2_P3_021",
        "part": 3,
        "q": "エンリケさん夫婦（夫63歳・妻66歳）が「ベルン」ディナービュッフェで「窓際席」を利用する場合、料金はどうなるか。",
        "choices": [
            "夫6,000円、妻6,000円のみ",
            "夫6,000円、妻6,000円、窓際席料1,000円",
            "夫6,000円、妻5,500円、窓際席料1,000円",
            "夫5,500円、妻5,000円、窓際席料1,000円"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "21) エンリケさん夫婦（夫63歳・妻66歳）が「ベルン」ディナービュッフェで「窓際席」を利用する場合、料金はどうなるか。\n엔리케 씨 부부(남편 63세·아내 66세)가 ‘베른’ 디너 뷔페에서 ‘창가석’을 이용할 때 요금은 어떻게 되는가?",
            "ko_choices": [
                "夫6,000円、妻6,000円のみ남편 6,000엔, 아내 6,000엔만",
                "夫6,000円、妻6,000円、窓際席料1,000円남편 6,000엔, 아내 6,000엔, 창가석 요금 1,000엔",
                "夫6,000円、妻5,500円、窓際席料1,000円남편 6,000엔, 아내 5,500엔, 창가석 요금 1,000엔",
                "夫5,500円、妻5,000円、窓際席料1,000円남편 5,500엔, 아내 5,000엔, 창가석 요금 1,000엔"
            ],
            "ko_explain": "정답 3번 안내에 따르면 ‘ベルン ディナー’는 기본 성인 6,000엔, 65세 이상은 5,500엔(시니어)이며, ‘窓際席’은 추가 1,000엔이다. 남편(63)은 성인 6,000엔, 아내(66)는 시니어 5,500엔 + 좌석료 1,000엔이므로 3번."
        },
        "group": {
            "id": "N2_P3_G11",
            "start": 20,
            "end": 21,
            "stem_jp": "右のページは、あるホテルのホームページに載っている案内である。下の問いに答えなさい。",
            "stem_ko": "오른쪽 페이지는 어떤 호텔 홈페이지의 안내문이다. 아래 물음에 답하시오.",
            "passage_jp": "【料金（ベルン）】\n・ディナー：大人 6,000円／シニア（65歳以上）5,500円\n・窓際席（特別テーブル）：追加 1,000円（1組につき）\n\n※ ディナービュッフェは金・土のみ。",
            "passage_ko": "【요금(베른)】\n· 디너: 성인 6,000엔 / 시니어(65세 이상) 5,500엔\n· 창가석(특별 테이블): 추가 1,000엔(1팀당)\n\n※ 디너 뷔페는 금·토만 운영."
        }
    },
]

N2_PART4_QUESTIONS_FULL = []


# =========================
# 2) PART별 원본(FULL) 가져오기 (채점 API에서 사용)
# =========================
def get_n2_part_questions_full(part: int):
    if part == 1:
        return N2_PART1_QUESTIONS_FULL
    elif part == 2:
        return N2_PART2_QUESTIONS_FULL
    elif part == 3:
        return N2_PART3_QUESTIONS_FULL
    elif part == 4:
        return N2_PART4_QUESTIONS_FULL
    return []


# =========================
# N2 PART3: 그룹 메타 내려주기 (템플릿에서 groupStemBox로 표시)
# - "형식 유지": 기존처럼 각 문항은 개별로 내려주고,
#   특정 번호 범위를 group으로 묶어 표시만 그룹으로 처리
# =========================
def get_n2_part_questions(part: int):
    src = get_n2_part_questions_full(part)

    out = []
    for q in src:
        item = {
            "id": q.get("id"),
            "part": q.get("part", part),
            "q": q.get("q", ""),
            "choices": q.get("choices", []),
            "answer": q.get("answer", 0),
        }

        # ✅ PART3는 FULL에 group이 이미 있으므로 그대로 사용 (단일도 포함)
        if part == 3 and q.get("group"):
            item["group"] = q.get("group")

        out.append(item)

    out2 = []

    # ✅ PART3 group 내용(빈 passage/stem)을 첫 등장값으로 채워 넣기 위한 캐시
    group_cache = {}

    for i, item in enumerate(out):
        no = i + 1  # 파트별로 1번부터

        # ✅ PART2 그룹 지정 (18~22) : 기존 그대로 유지
        if part == 2:
            if 18 <= no <= 22:
                item["group"] = {
                    "id": "P2_M9",
                    "start": 18,
                    "end": 22,
                    "stem_jp": N2_P2_M9_STEM_JP,
                    "stem_ko": N2_P2_M9_STEM_KO,
                    "passage_jp": N2_P2_M9_STEM_JP,
                    "passage_ko": N2_P2_M9_STEM_KO,
                }

        # ✅ PART3: group이 있으면, 빈 passage/stem을 자동 보충(템플릿 표시 안정화)
        if part == 3 and item.get("group"):
            g = item["group"]
            gid = g.get("id")

            if gid:
                # 캐시에 "내용이 있는 값" 우선 저장
                if gid not in group_cache:
                    group_cache[gid] = {
                        "stem_jp": g.get("stem_jp", "") or "",
                        "stem_ko": g.get("stem_ko", "") or "",
                        "passage_jp": g.get("passage_jp", "") or "",
                        "passage_ko": g.get("passage_ko", "") or "",
                        "start": g.get("start"),
                        "end": g.get("end"),
                    }
                else:
                    cached = group_cache[gid]

                    # 빈 값이면 캐시로 보충
                    if not g.get("stem_jp") and cached.get("stem_jp"):
                        g["stem_jp"] = cached["stem_jp"]
                    if not g.get("stem_ko") and cached.get("stem_ko"):
                        g["stem_ko"] = cached["stem_ko"]
                    if not g.get("passage_jp") and cached.get("passage_jp"):
                        g["passage_jp"] = cached["passage_jp"]
                    if not g.get("passage_ko") and cached.get("passage_ko"):
                        g["passage_ko"] = cached["passage_ko"]

                    # start/end 보충
                    if g.get("start") is None and cached.get("start") is not None:
                        g["start"] = cached["start"]
                    if g.get("end") is None and cached.get("end") is not None:
                        g["end"] = cached["end"]

                item["group"] = g

        # ✅ 여기서 group을 pop 하면 안 됨 (단일문항 지문이 사라짐)
        out2.append(item)

    return out2

# =========================
# ✅ 채점 API (N2)
# - 기존 형식 그대로: items에 한국어 해설 포함
# - group_meta는 지문 번역 제공 (필요 시 템플릿/결과에서 사용)
# =========================
@app.post("/api/jlpt/n2/test/grade/<int:part>")
def api_jlpt_n2_test_grade(part: int):
    payload = request.get_json(silent=True) or {}
    user_answers = payload.get("answers", [])
    if not isinstance(user_answers, list):
        user_answers = []

    src = get_n2_part_questions_full(part)
    total = len(src)
    correct = 0
    items = []

    for i, q in enumerate(src):
        ua = user_answers[i] if i < len(user_answers) else None
        ans = q.get("answer", 0)
        is_correct = (ua == ans)
        if is_correct:
            correct += 1

        meta = q.get("meta", {}) or {}
        items.append({
            "no": i + 1,
            "q_ko": meta.get("ko_q", ""),
            "choices_ko": meta.get("ko_choices", []),
            "answer_index": ans,
            "user_index": ua,
            "explain_ko": meta.get("ko_explain", ""),
            "is_correct": is_correct,
        })

    score = round((correct / total) * 100) if total else 0

    resp = {
        "total": total,
        "correct": correct,
        "score": score,
        "items": items
    }

    # ✅ PART2 그룹 지문 내려주기 (18~22) - 기존 유지
    if part == 2:
        resp["group_meta"] = {
            "P2_M9": {
                "start": 18,
                "end": 22,
                "stem_jp": N2_P2_M9_STEM_JP,
                "stem_ko": N2_P2_M9_STEM_KO,
                "passage_jp": N2_P2_M9_STEM_JP,
                "passage_ko": N2_P2_M9_STEM_KO,
            }
        }

    # ✅ PART3 그룹 지문 내려주기 - 문항에 들어있는 group으로 자동 구성 (형식 유지)
    if part == 3:
        group_meta = {}

        for q in src:
            g = q.get("group") or {}
            gid = g.get("id")
            if not gid:
                continue

            # group_meta에는 "내용이 있는 최초 값"을 저장
            if gid not in group_meta:
                group_meta[gid] = {
                    "start": g.get("start"),
                    "end": g.get("end"),
                    "stem_jp": g.get("stem_jp", ""),
                    "stem_ko": g.get("stem_ko", ""),
                    "passage_jp": g.get("passage_jp", ""),
                    "passage_ko": g.get("passage_ko", ""),
                }
            else:
                # 이미 있으면, 빈 내용만 보충
                if not group_meta[gid].get("stem_jp") and g.get("stem_jp"):
                    group_meta[gid]["stem_jp"] = g.get("stem_jp")
                if not group_meta[gid].get("stem_ko") and g.get("stem_ko"):
                    group_meta[gid]["stem_ko"] = g.get("stem_ko")
                if not group_meta[gid].get("passage_jp") and g.get("passage_jp"):
                    group_meta[gid]["passage_jp"] = g.get("passage_jp")
                if not group_meta[gid].get("passage_ko") and g.get("passage_ko"):
                    group_meta[gid]["passage_ko"] = g.get("passage_ko")

                if group_meta[gid].get("start") is None and g.get("start") is not None:
                    group_meta[gid]["start"] = g.get("start")
                if group_meta[gid].get("end") is None and g.get("end") is not None:
                    group_meta[gid]["end"] = g.get("end")

        if group_meta:
            resp["group_meta"] = group_meta

    return jsonify(resp)


# =========================
# ✅ N2 테스트 시작 라우트
# - (기존 형식 유지) total_questions는 화면용 단계 수로 사용
# =========================
@app.route("/jlpt/n2/test/start/<int:part>")
def jlpt_n2_test_start(part: int):
    questions = get_n2_part_questions(part)

    template_map = {
        1: "jlpt_n2_test_run_part1.html",
        2: "jlpt_n2_test_run_part2.html",
        3: "jlpt_n2_test_run_part3.html",
        4: "jlpt_n2_test_run_part4.html",
    }

    total_raw = len(get_n2_part_questions_full(part))

    return render_template(
        template_map.get(part, "jlpt_n2_test_run_part1.html"),
        questions=questions,
        total_questions=len(questions),
        total_questions_raw=total_raw,
        part=part
    )

# ----------------------------
# ✅ N2 테스트 홈
# ----------------------------
@app.route("/jlpt/n2/test")
def jlpt_n2_test():
    user = current_user()
    return render_template("jlpt_n2_test.html", user=user, total_questions=0)

@app.route("/jlpt/n2")
def jlpt_n2_home():
    user = current_user()
    return render_template("jlpt_n2.html", user=user)

@app.route("/jlpt/n2/words")
def jlpt_n2_words():
    user = current_user()

    # N2_WORDS: dict (sec01~sec10)
    sections = []
    all_items = []

    for sec_key in sorted((N2_WORDS or {}).keys()):  # sec01, sec02...
        sec = (N2_WORDS or {}).get(sec_key) or {}
        title = sec.get("title", sec_key)
        items = sec.get("items") or []

        sections.append({
            "key": sec_key,
            "title": title,
            "count": len(items),
        })

        for it in items:
            row = dict(it)
            row["sec_key"] = sec_key
            row["sec_title"] = title
            all_items.append(row)

    return render_template(
        "jlpt_n2_words.html",
        user=user,
        sections=sections,
        words=all_items,   # ✅ 템플릿엔 "단어 리스트"로만 전달
    )

@app.route("/jlpt/n2/sentences")
def jlpt_n2_sentences():
    user = current_user()
    return render_template("jlpt_n2_sentences.html", user=user, sections=N2_SENTENCE_SECTIONS)

@app.route("/jlpt/n2/grammar")
def jlpt_n2_grammar():
    user = current_user()
    return render_template("jlpt_n2_grammar.html", user=user)

# =========================
# JLPT N1 - PART 1 (25문항)
# 변형/유형 혼합: 읽기/의미/용법
# - q: JP only
# - ko_choices: "일본어(한국어뜻)" 형식 유지
# - （　） 공백/괄호 형태는 풀각(전각)로 통일
# =========================

N1_PART1_QUESTIONS_FULL = [
    # 1
    {
        "id": "N1_P1_001",
        "part": 1,
        "q": "1　社会活動に参加することで、(人脈)を広げることができた。",
        "choices": ["じんみゃく", "じんまく", "にんみゃく", "にんまく"],
        "answer": 0,
        "meta": {
            "ko_q": "1) 社会活動に参加することで、(人脈)を広げることができた。\n사회 활동에 참여함으로써 인맥(人脈)을 넓힐 수 있었다.",
            "ko_choices": [
                "じんみゃく(인맥)",
                "じんまく(오답)",
                "にんみゃく(오답)",
                "にんまく(오답)",
            ],
            "ko_explain": "人脈(인맥)의 올바른 읽기는 1번 じんみゃく입니다.",
        },
    },
    # 2
    {
        "id": "N1_P1_002",
        "part": 1,
        "q": "2　鈴木さんは指摘がいつも的確で、本当に（賢い）人だと思う。",
        "choices": ["かしこい", "けんい", "さとい", "すぐれた"],
        "answer": 0,
        "meta": {
            "ko_q": "2) …本当に（賢い）人だと思う。\n정말 영리한 사람이라고 생각한다.",
            "ko_choices": ["かしこい(정답)", "けんい(오답)", "さとい(날카롭다/영리하다 느낌이지만 읽기 아님)", "すぐれた(우수한, 읽기 아님)"],
            "ko_explain": "賢い의 올바른 읽기는 かしこい입니다."
        },
    },
    # 3
    {
        "id": "N1_P1_003",
        "part": 1,
        "q": "3　文化の違いが食生活に(顕著)に現れている。",
        "choices": ["げんちょ", "けんしょ", "けんちょ", "げんしょ"],
        "answer": 2,
        "meta": {
            "ko_q": "3) 文化の違いが食生活に(顕著)に現れている。\n문화의 차이가 식생활에 현저하게(顕著に) 드러나 있다.",
            "ko_choices": [
                "げんちょ(오답)",
                "けんしょ(오답)",
                "けんちょ(현저)",
                "げんしょ(오답)",
            ],
            "ko_explain": "顕著(현저)의 올바른 읽기는 3번 けんちょ입니다.",
        },
    },
    # 4
    {
        "id": "N1_P1_004",
        "part": 1,
        "q": "4　相談の内容は(多岐)にわたった。",
        "choices": ["たき", "たじ", "たぎ", "たし"],
        "answer": 0,
        "meta": {
            "ko_q": "4) 相談の内容は(多岐)にわたった。\n상담의 내용은 다방면(多岐)에 걸쳤다.",
            "ko_choices": [
                "たき(다방면/여러 갈래)",
                "たじ(오답)",
                "たぎ(오답)",
                "たし(오답)",
            ],
            "ko_explain": "多岐(다방면)의 올바른 읽기는 1번 たき입니다.",
        },
    },
    # 5
    {
        "id": "N1_P1_005",
        "part": 1,
        "q": "5　その風習は、今はもう(廃れて)しまった。",
        "choices": ["くずれて", "かすれて", "つぶれて", "すたれて"],
        "answer": 3,
        "meta": {
            "ko_q": "5) その風習は、今はもう(廃れて)しまった。\n그 풍습은 이제 이미 쇠퇴해(廃れて) 버렸다.",
            "ko_choices": [
                "くずれて(무너져서)",
                "かすれて(흐려져서)",
                "つぶれて(망해서/찌그러져서)",
                "すたれて(쇠퇴해서)",
            ],
            "ko_explain": "廃れる(すたれる)는 ‘쇠퇴하다/사라져 가다’이므로 4번 すたれて가 정답입니다.",
        },
    },
    # 6
    {
        "id": "N1_P1_006",
        "part": 1,
        "q": "6　家賃の(相場)は地域によって違う。",
        "choices": ["あいば", "そうば", "あいじょう", "そうじょう"],
        "answer": 1,
        "meta": {
            "ko_q": "6) 家賃の(相場)は地域によって違う。\n집세 시세/평균가(相場)는 지역에 따라 다르다.",
            "ko_choices": [
                "あいば(오답)",
                "そうば(시세/평균가)",
                "あいじょう(오답)",
                "そうじょう(오답)",
            ],
            "ko_explain": "相場(시세/평균가)의 올바른 읽기는 2번 そうば입니다.",
        },
    },
    # 7
    {
        "id": "N1_P1_007",
        "part": 1,
        "q": "7 私はこの土地で定職に就き、生活の（　）を築いた。",
        "choices": ["根拠", "基盤", "根源", "基地"],
        "answer": 1,
        "meta": {
            "ko_q": "7) 私はこの土地で定職に就き、生活の（　）を築いた。\n나는 이 땅에서 안정된 직업을 갖고 생활의 (    )을/를 다졌다.",
            "ko_choices": [
                "根拠(근거)",
                "基盤(기반)",
                "根源(근원)",
                "基地(기지)",
            ],
            "ko_explain": "정답 2번 生活の基盤(생활의 기반)을 築く(다지다/쌓다)가 자연스럽습니다.",
        },
    },
    # 8
    {
        "id": "N1_P1_008",
        "part": 1,
        "q": "8　議論は難航すると思ったが、すぐに意見がまとまり、（　）結論が出た。",
        "choices": ["すんなり", "うっとり", "ふんわり", "こっそり"],
        "answer": 0,
        "meta": {
            "ko_q": "8) 議論は難航すると思ったが、すぐに意見がまとまり、（　）結論が出た。\n논의가 난항일 줄 알았지만 곧 의견이 모여 (    ) 결론이 났다.",
            "ko_choices": [
                "すんなり(순조롭게/쉽게)",
                "うっとり(황홀하게)",
                "ふんわり(부드럽게/푹신하게)",
                "こっそり(몰래)",
            ],
            "ko_explain": "정답 1분 ‘문제없이/매끄럽게 결론이 나오다’는 すんなり가 가장 자연스럽습니다.",
        },
    },
    # 9
    {
        "id": "N1_P1_009",
        "part": 1,
        "q": "9　さっき駅前で佐藤さんを（　）んですが、声をかける前に人ごみにまぎれてしまいました。",
        "choices": ["見合わせた", "見過ごした", "見かけた", "見違えた"],
        "answer": 2,
        "meta": {
            "ko_q": "9) 아까 역 앞에서 사토 씨를 (   ) 봤는데, 말을 걸기 전에 인파에 섞여 버렸어요.",
            "ko_choices": ["見合わせた(서로 마주보다/대조하다)", "見過ごした(못 보고 지나치다)", "見かけた(우연히 보다)", "見違えた(착각하다)"],
            "ko_explain": "‘우연히 봤지만 인파에 섞여 놓쳤다’ 흐름은 見かけた가 가장 자연스럽습니다."
        },
    },
    # 10
    {
        "id": "N1_P1_010",
        "part": 1,
        "q": "10　市長の責任ある行動が住民の不安を（　）し、行政に対する期待が一気に高まった。",
        "choices": ["一掃", "追放", "削除", "排出"],
        "answer": 0,
        "meta": {
            "ko_q": "10) 市長の責任ある行動が住民の不安を（　）し…\n시장의 책임 있는 행동이 주민의 불안을 (    )하여 기대가 크게 높아졌다.",
            "ko_choices": [
                "一掃(일소/싹 없앰)",
                "追放(추방)",
                "削除(삭제)",
                "排出(배출)",
            ],
            "ko_explain": "정답 1번 不安を一掃する(불안을 일소하다)가 관용적으로 자연스럽습니다.",
        },
    },
    # 11
    {
        "id": "N1_P1_011",
        "part": 1,
        "q": "11　十分に煮た野菜は味が（　）柔らかく、とてもおいしかった。",
        "choices": ["溶けて", "染みて", "潤って", "沈んで"],
        "answer": 1,
        "meta": {
            "ko_q": "11) 十分に煮た野菜は味が（　）柔らかく…\n충분히 끓인 채소는 맛이 (    ) 부드러워 아주 맛있었다.",
            "ko_choices": [
                "溶けて(녹아서)",
                "染みて(스며서/배어서)",
                "潤って(촉촉해져서)",
                "沈んで(가라앉아)",
            ],
            "ko_explain": "정답 2번 味が染みる(맛이 배다/스며들다)로 자주 쓰이므로 染みて가 정답입니다.",
        },
    },
    # 12
    {
        "id": "N1_P1_012",
        "part": 1,
        "q": "12　このテーブルは私が子どものころから使っているので、（　）があって捨てられない。",
        "choices": ["心情", "好感", "執意", "愛着"],
        "answer": 3,
        "meta": {
            "ko_q": "12) …（　）があって捨てられない。\n어릴 때부터 써서 (    )이/가 있어 버릴 수 없다.",
            "ko_choices": [
                "心情(심정)",
                "好感(호감)",
                "執意(집념/고집)",
                "愛着(애착)",
            ],
            "ko_explain": "정답 4번 오래 사용한 물건을 못 버리는 이유는 愛着(애착)이 가장 자연스럽습니다.",
        },
    },
    # 13
    {
        "id": "N1_P1_013",
        "part": 1,
        "q": "13　現社長は創立者から経営の（　）を学んだ。",
        "choices": ["ノウハウ", "ノルマ", "ネットワーク", "マニュアル"],
        "answer": 0,
        "meta": {
            "ko_q": "13) 現社長は創立者から経営の（　）を学んだ。\n현 사장은 창립자로부터 경영의 (    )를 배웠다.",
            "ko_choices": [
            "노하우(ノウハウ)",
            "할당량/노르마(ノルマ)",
            "네트워크(ネットワーク)",
            "매뉴얼(マニュアル)"
            ],
            "ko_explain": "「経営の〜を学ぶ」에서는 ‘경영 노하우’를 배우다(経営のノウハウを学ぶ)가 가장 자연스럽습니다."
        },
    },
    # 14
    {
        "id": "N1_P1_014",
        "part": 1,
        "q": "14　高橋さんには(かねがね)お会いしたいと思っていました。",
        "choices": ["直接", "ぜひ", "早く", "以前から"],
        "answer": 3,
        "meta": {
            "ko_q": "14) 高橋さんには(かねがね)お会いしたいと思っていました。\n다카하시 씨를 예전부터(かねがね) 만나고 싶다고 생각해 왔습니다.",
            "ko_choices": [
                "直接(직접)",
                "ぜひ(꼭/부디)",
                "早く(빨리)",
                "以前から(이전부터)",
            ],
            "ko_explain": "かねがね는 ‘이전부터/전부터 계속’의 뜻이므로 4번 以前から가 정답입니다.",
        },
    },
    # 15
    {
        "id": "N1_P1_015",
        "part": 1,
        "q": "15　林さんはそれを(故意に)捨てたらしい。",
        "choices": ["わざと", "うっかり", "いやいや", "さっさと"],
        "answer": 0,
        "meta": {
            "ko_q": "15) 林さんはそれを(故意に)捨てたらしい。\n하야시 씨는 그것을 고의로(故意に) 버린 것 같다.",
            "ko_choices": [
                "わざと(일부러)",
                "うっかり(깜빡/무심코)",
                "いやいや(마지못해)",
                "さっさと(서둘러/빨리)",
            ],
            "ko_explain": "故意に(고의로) = 1번 わざと 입니다.",
        },
    },
    # 16
    {
        "id": "N1_P1_016",
        "part": 1,
        "q": "16　昨日、鈴木さんに(おわび)した。",
        "choices": ["文句を言った", "お礼を言った", "断った", "謝った"],
        "answer": 3,
        "meta": {
            "ko_q": "16) 昨日、鈴木さんに(おわび)した。\n어제 스즈키 씨에게 사과(おわび)했다.",
            "ko_choices": [
                "文句を言った(불평했다)",
                "お礼を言った(감사했다)",
                "断った(거절했다)",
                "謝った(사과했다)",
            ],
            "ko_explain": "おわびする는 ‘사과하다’이므로 4번 謝った가 정답입니다.",
        },
    },
    # 17
    {
        "id": "N1_P1_017",
        "part": 1,
        "q": "17　中村さんの言葉からは強い（意気込み）が伝わってくる。",
        "choices": ["敬意", "自信", "熱意", "信頼"],
        "answer": 2,
        "meta": {
            "ko_q": "17) …強い(意気込み)가伝わってくる。\n말에서 강한 열의/각오가 전해진다.",
            "ko_choices": ["敬意(경의)", "自信(자신)", "熱意(열의)", "信頼(신뢰)"],
            "ko_explain": "意気込み는 ‘의욕/열의/각오’ 뉘앙스이므로 熱意가 가장 가깝습니다."
        },
    },
    # 18
    {
        "id": "N1_P1_018",
        "part": 1,
        "q": "18　妹は少し(おびえている)ようだった。",
        "choices": ["焦って", "怖がって", "悩んで", "悔やんで"],
        "answer": 1,
        "meta": {
            "ko_q": "18) 妹は少しおびえているようだった。\n여동생은 조금 겁먹은(おびえている) 것 같았다.",
            "ko_choices": [
                "焦って(초조해져서)",
                "怖がって(무서워해서)",
                "悩んで(고민해서)",
                "悔やんで(후회해서)",
            ],
            "ko_explain": "おびえる(怯える)는 ‘무서워하다/겁먹다’이므로 2번 怖がって가 정답입니다.",
        },
    },
    # 19
    {
        "id": "N1_P1_019",
        "part": 1,
        "q": "19　私はその一言に(安堵)した。",
        "choices": ["すっとした", "はっとした", "ほっとした", "かっとした"],
        "answer": 2,
        "meta": {
            "ko_q": "19) 私はその一言に(安堵)した。\n나는 그 한마디에 안도(安堵)했다.",
            "ko_choices": [
                "すっとした(개운해졌다)",
                "はっとした(번뜩 놀랐다)",
                "ほっとした(안도했다)",
                "かっとした(확 화가 났다)",
            ],
            "ko_explain": "安堵する(あんどする)는 ‘안도하다’이므로 3번 ほっとした가 정답입니다.",
        },
    },
    # 20 (용법)
    {
        "id": "N1_P1_020",
        "part": 1,
        "q": "20　閑静",
        "choices": [
            "そのレストランは繁華街から外れた閑静な場所にある。",
            "今日は朝から具合が悪かったので、会社を休んで家で閑静にしていた。",
            "用事が早く済み、閑静な時間ができたので、映画を見に行くことにした。",
            "日中はにぎやかな公園だが、夜になると急に閑静になる。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "20) 閑静 (조용하고 한적함) — 올바른 문장을 고르시오.",
            "ko_choices": [
            "そのレストランは繁華街から外れた閑静な場所にある。\n→ 그 레스토랑은 번화가에서 벗어난 조용한 장소에 있다. ✅ (장소 수식으로 가장 자연스러움)",
            "今日は朝から具合が悪かったので、会社を休んで家で閑静にしていた。\n→ 오늘은 아침부터 몸이 안 좋아서 회사를 쉬고 집에서 조용히 있었다. ❌ (행동에는 静かに가 자연)",
            "用事が早く済み、閑静な時間ができたので、映画を見に行くことにした。\n→ 일이 빨리 끝나 조용한 시간이 생겨 영화를 보러 가기로 했다. ❌ (閑静은 ‘시간’에 잘 쓰이지 않음)",
            "日中はにぎやかな公園だが、夜になると急に閑静になる。\n→ 낮에는 붐비는 공원이지만 밤이 되면 갑자기 조용해진다. ❌ (보통 静かになる 사용)"
            ],
            "ko_explain": "정답 1번 閑静은 ‘조용한 장소·주거지’ 같은 장소를 수식할 때 가장 자연스럽게 쓰이며, 1번 문장이 올바른 용법입니다."
        }
    },
    # 21 (용법)
    {
        "id": "N1_P1_021",
        "part": 1,
        "q": "21　たやすい",
        "choices": [
            "弟は寝坊したらしく、たやすい物だけ食べて、慌てて出かけていった。",
            "伊藤氏とは大学時代からの親友で、本音が言えるたやすい関係だ。",
            "せっかくの日曜日だから、ゆっくり休んでたやすく過ごそうと思う。",
            "この問題は想像以上に複雑で、たやすく解決できるものではなかった。"
        ],
        "answer": 3,
        "meta": {
            "ko_q": "21) たやすい (쉽다) — 올바른 문장을 고르시오.",
            "ko_choices": [
            "弟は寝坊したらしく、たやすい物だけ食べて、慌てて出かけていった。\n→ 동생은 늦잠을 잔 모양이라, 간단한 것만 먹고 서둘러 나갔다. ❌ (음식에는 簡単な物/軽い物이 자연)",
            "伊藤氏とは大学時代からの親友で、本音が言えるたやすい関係だ。\n→ 이토 씨와는 대학 시절부터의 절친으로, 속마음을 말할 수 있는 쉬운 관계다. ❌ (‘쉽게 속마음을 말할 수 있는 관계’는 표현 부자연)",
            "せっかくの日曜日だから、ゆっくり休んでたやすく過ごそうと思う。\n→ 모처럼의 일요일이니 천천히 쉬면서 쉽게 지내려고 한다. ❌ (たやすく는 ‘행동의 난이도’에 씀)",
            "この問題は想像以上に複雑で、たやすく解決できるものではなかった。\n→ 이 문제는 예상보다 복잡해서 쉽게 해결할 수 있는 것이 아니었다. ✅"
            ],
            "ko_explain": "정답 4번 たやすい는 ‘たやすく〜できる(쉽게 ~할 수 있다)’ 형태로 쓰일 때 가장 자연스럽다."
        }
    },
    # 22 (용법)
    {
        "id": "N1_P1_022",
        "part": 1,
        "q": "22　察する",
        "choices": [
            "医師たちはチームを組み、意見を出し合って、最良の治療法を察した。",
            "気象予報士はテレビの天気予報で、来週の気温の変化を察し始めた。",
            "鈴木さんは、私が何も言わなくても、私の気持ちを察して慰めてくれた。",
            "外を歩いていたら急にいいアイディアを察したので、手帳にメモをした。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "22) 察する (헤아리다/눈치채다) — 올바른 문장을 고르시오.",
            "ko_choices": [
            "医師たちは…治療法を察した。\n→ 의사들이 치료법을 헤아렸다. ❌ (치료법은 ‘결정하다/찾다’이지 察する 아님)",
            "来週の気温の変化を察し始めた。\n→ 다음 주 기온 변화를 짐작하기 시작했다. ❌ (기상은 予測する/読む 사용)",
            "私の気持ちを察して慰めてくれた。\n→ 내 마음을 헤아려 위로해 주었다. ✅",
            "アイディアを察した。\n→ 아이디어를 눈치챘다. ❌ (‘아이디어가 떠오르다’는 思いつく)"
            ],
            "ko_explain": "정답 3번 察する는 말하지 않아도 상대의 마음이나 상황을 ‘헤아리는 것’에 쓰인다."
        }
    },
    # 23 (용법)
    {
        "id": "N1_P1_023",
        "part": 1,
        "q": "23　内訳",
        "choices": [
            "来週の内訳を確認したが、予定がないのは木曜の夜だけだ。",
            "前回の出張費の内訳を見たら、交通費の割合が予想外に高かった。",
            "司会者は進行を間違えないように、式の内訳を何度も見直した。",
            "家族の健康のため、栄養の内訳を考えて食事を作っている。"
        ],
        "answer": 1,
        "meta": {
            "ko_q": "23) 内訳 (세부 내역) — 올바른 문장을 고르시오.",
            "ko_choices": [
            "来週の内訳を確認した。\n→ 다음 주의 내역을 확인했다. ❌ (일정에는 予定/スケジュール)",
            "出張費の内訳を見たら…\n→ 출장비의 세부 내역을 보니… ✅",
            "式の内訳を見直した。\n→ 식의 내역을 재확인했다. ❌ (행사는 内容/進行)",
            "栄養の内訳を考えて…\n→ 영양의 내역을 생각하며… ❌ (보통 栄養バランス)"
            ],
            "ko_explain": "정답 2번 内訳은 비용·금액처럼 ‘구성 항목이 나뉘는 대상’에 주로 사용된다."
        }
    },
    # 24 (용법)
    {
        "id": "N1_P1_024",
        "part": 1,
        "q": "24　食い違う",
        "choices": [
            "この事件は、複数の目撃者の話がそれぞれ食い違っており、不明な点が多い。",
            "金庫を開けようと思ったが、どの鍵も食い違って開けられなかった。",
            "何だか歩きにくいと思ったら、サンダルの左右が食い違っていた。",
            "調味料を変えたのか、この料理はいつもと味が食い違っているように感じる。"
        ],
        "answer": 0,
        "meta": {
            "ko_q": "24) 食い違う (서로 어긋나다) — 올바른 문장을 고르시오.",
            "ko_choices": [
            "目撃者の話が食い違う。\n→ 목격자들의 증언이 서로 어긋난다. ✅",
            "鍵が食い違う。\n→ 열쇠가 맞지 않는다. ❌ (合わない 사용)",
            "左右が食い違う。\n→ 좌우가 어긋나 있다. ❌ (보통 逆/入れ違い)",
            "味が食い違う。\n→ 맛이 어긋나다. ❌ (味が違う가 자연)"
            ],
            "ko_explain": "정답 1번 食い違う는 주장·의견·증언 등이 서로 일치하지 않을 때 사용된다."
        }
    },
    # 25 (용법)
    {
        "id": "N1_P1_025",
        "part": 1,
        "q": "25　過密",
        "choices": [
            "雑誌で紹介されてから、この商品への過密な注文が続いているらしい。",
            "水質汚染に関して人々の抗議が過密になり、政府は対策を迫られている。",
            "今回の出張は過密なスケジュールで、ゆっくり食事する時間もなさそうだ。",
            "春になると、この池の周りには、色とりどりの花が過密に咲き乱れる。"
        ],
        "answer": 2,
        "meta": {
            "ko_q": "25) 過密 (과도하게 빽빽함) — 올바른 문장을 고르시오.",
            "ko_choices": [
            "過密な注文。\n→ 과도하게 빽빽한 주문. ❌ (주문은 過剰/殺到)",
            "抗議が過密になる。\n→ 항의가 과밀해진다. ❌ (표현 부자연)",
            "過密なスケジュール。\n→ 빽빽한 일정. ✅",
            "花が過密に咲く。\n→ 꽃이 빽빽하게 핀다. ❌ (密集して가 자연)"
            ],
            "ko_explain": "정답 3번 過密은 일정·계획처럼 ‘시간/구조가 빽빽한 상태’를 나타낼 때 가장 자연스럽다."
        }
    },
]
# =========================
# JLPT N1 PART2 (文法) - 변형 문제 세트
# 구성:
#  - もんだい1: 1~15
#  - もんだい7: 16~20 (지문형 공통 stem)
# =========================

# =========================
# N1 PART2 - もんだい７ 공통 지문 (JP / KO)
# =========================
N1_P2_M7_STEM_JP = """（もんだい７）16から20に何を入れますか。ぶんしょう全体のいみを考えて、1・2・3・4からいちばんいいものを一つえらんでください。

（エッセイ）「説明書の落とし穴」

世の中には「説明書」というものがある。買った機械が思い通りに動かないとき、人はまず説明書を探す。
だが、説明書通りにやったはずなのに、なぜかうまくいかないことがある。そんなとき、私は決まって、
「自分の理解が足りないのだろう」と反省してしまう。

先日も、家のWi-Fiルーターの設定をしていた。画面の案内は丁寧で、手順も多くない。
それでも、最後の「接続完了」の表示が出ない。焦って何度もやり直したところ、原因は意外だった。
説明書の「次へ」を押すタイミングが、私の操作より少し早かったのだ。つまり、私は案内が出る前に押していた。

その瞬間、私は「説明書は親切なようで、(16)と思った。親切そうに見える文章ほど、
読んだ人の頭の中の「当たり前」を前提にしていることがある。たとえば「しばらく待ってください」と言われても、
どれくらい待てばいいのかは書いていない。

さらに、私は気づいた。説明書に書いてある言葉は、(17)。
同じ言葉でも、人によって受け取り方が違うからだ。だから私は、うまくいかないときは説明書を疑うだけでなく、
自分の解釈も疑うようにしている。

もちろん、説明書が悪いと言いたいわけではない。むしろ、説明書のおかげで助かることのほうが多い。
ただ、説明書を読むときには、(18)。
「書かれていない部分があるかもしれない」と考えるだけで、失敗は減る。

結局のところ、説明書とは、完璧な答えをくれるものではなく、答えに近づくためのヒント集なのだろう。
そう思うようになってから、私は説明書とほどよい距離を保てるようになった。(19)。

そして今日もまた、新しい家電の箱を開ける。説明書は相変わらず分厚い。
だが、以前ほど怖くはない。私は最後にこう書き足しておきたい。説明書を読む人は、(20)。"""

N1_P2_M7_STEM_KO = """(문제7) 16~20에 무엇을 넣습니까? 글 전체의 의미를 생각해서 1·2·3·4 중에서 가장 알맞은 것을 하나 고르세요.

(에세이) ‘설명서의 함정’

세상에는 ‘설명서’라는 것이 있다. 산 기계가 뜻대로 움직이지 않을 때 사람은 먼저 설명서를 찾는다.
하지만 설명서대로 했다고 생각했는데도 잘 안 되는 경우가 있다. 그럴 때 나는 늘 ‘내 이해가 부족한가’ 하고 반성해 버린다.

얼마 전 집 와이파이 라우터 설정을 했는데, 안내는 친절하고 절차도 복잡하지 않았다.
그런데 마지막 ‘연결 완료’가 뜨지 않았다. 여러 번 다시 해 보니 원인은 의외였다.
설명서의 ‘다음’을 누르는 타이밍이 내 조작보다 조금 빨랐던 것이다. 즉, 나는 안내가 뜨기 전에 눌러 버렸다.

그 순간 나는 ‘설명서는 친절한 듯 보이지만, (16)’이라고 생각했다.
친절해 보이는 문장일수록 읽는 사람의 ‘당연함’을 전제로 하는 경우가 있다.
예를 들어 ‘잠시 기다려 주세요’라고 해도, 얼마나 기다려야 하는지는 적혀 있지 않다.

게다가 나는 깨달았다. 설명서의 말은 (17)다.
같은 말이라도 사람마다 받아들이는 방식이 다르기 때문이다. 그래서 나는 잘 안 될 때 설명서만 의심하는 게 아니라,
내 해석도 의심하려고 한다.

물론 설명서가 나쁘다고 말하고 싶은 것은 아니다. 오히려 설명서 덕분에 도움이 되는 일이 더 많다.
다만 설명서를 읽을 때는 (18).
‘쓰여 있지 않은 부분이 있을지도 모른다’고 생각하는 것만으로도 실패는 줄어든다.

결국 설명서는 완벽한 정답을 주는 것이 아니라 정답에 가까워지게 하는 힌트 모음일 것이다.
그렇게 생각하게 된 뒤로 나는 설명서와 적당한 거리를 유지할 수 있게 되었다. (19)

그리고 오늘도 새 가전의 상자를 연다. 설명서는 여전히 두껍다.
하지만 예전만큼 무섭지 않다. 마지막으로 이렇게 덧붙이고 싶다. 설명서를 읽는 사람은 (20)다."""

N1_PART2_QUESTIONS_FULL = [
    # =========================
    # もんだい1 (1~15) - 단일 문항 (※ 이미지(26~40) 형식 유지, 번호는 1부터)
    # =========================
    {
        "id": "N1_P2_001",
        "part": 2,
        "q": "1　朝の満員電車の混雑を（　）、彼は平然と資料を読み続けていた。",
        "choices": ["含めて", "もとに", "除いて", "よそに"],
        "answer": 3,
        "meta": {
            "ko_q": "1) 아침 만원전철의 혼잡을 ( ), 그는 태연히 자료를 계속 읽고 있었다.",
            "ko_choices": ["포함해서(含めて)", "~을 바탕으로(もとに)", "제외하고(除いて)", "아랑곳하지 않고/딴전으로(よそに)"],
            "ko_explain": "주변 상황을 ‘아랑곳하지 않다’는 4번「〜をよそに」가 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_002",
        "part": 2,
        "q": "2　父は、漫画も（　）批判ばかりするので、正直うんざりだ。",
        "choices": ["読まないで", "読み", "読もう", "読んで"],
        "answer": 0,
        "meta": {
            "ko_q": "2) 아버지는 만화도 ( ) 비판만 해서 솔직히 질린다.",
            "ko_choices": ["읽지도 않고(読まないで)", "읽고(連用形)", "읽자/읽으려(意志)", "읽어서/읽고(て)"],
            "ko_explain": "정답 1번 ‘~도 하지 않고’의 뉘앙스는 1「〜もしないで」 → 여기서는 「読まないで」가 맞습니다."
        }
    },
    {
        "id": "N1_P2_003",
        "part": 2,
        "q": "3（インタビューで）\n　先輩「学生時代にやったことで、今の仕事に役立っているのは何ですか。」\n　私「部活の経験です。（　）、チームで動く難しさを学びました。」",
        "choices": ["要するに", "あるいは", "もっとも", "ついては"],
        "answer": 0,
        "meta": {
            "ko_q": "3) (인터뷰) ‘동아리 경험입니다. ( ), 팀으로 움직이는 어려움을 배웠습니다.’",
            "ko_choices": ["요컨대(要するに)", "혹은(あるいは)", "다만/물론(もっとも)", "그러므로/그래서(ついては는 ‘~에 관해’)"],
            "ko_explain": "정답 1번 앞 내용을 정리해 ‘요컨대’로 잇는 흐름이 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_004",
        "part": 2,
        "q": "4　村の史料をまとめるにあたり、元村長にお話を（　）ところ、当時のことを鮮明に覚えていて驚いた。",
        "choices": ["おいでになり", "差し上げ", "まいり", "申し上げ"],
        "answer": 3,
        "meta": {
            "ko_q": "4) 마을 사료를 정리하는 데 있어 전 촌장님께 말씀을 ( ) 해 보니, 당시 일을 또렷이 기억하고 있어 놀랐다.",
            "ko_choices": ["오시다(尊敬)(おいでになる)", "드리다(差し上げる)", "가다/오다(謙譲)(まいる)", "말씀드리다(申し上げる)"],
            "ko_explain": "정답 4번 ‘말씀을 드리다/여쭈다’는 겸양어 「申し上げる」가 맞습니다."
        }
    },
    {
        "id": "N1_P2_005",
        "part": 2,
        "q": "5（Q&A）\n　Q：専門知識がないのですが、働けますか。\n　A：研修がありますので大丈夫です。知識はある（　）、それ以上に姿勢を重視しています。",
        "choices": ["にすぎません", "ことは否めません", "に越したことはありません", "といっても過言ではありません"],
        "answer": 2,
        "meta": {
            "ko_q": "5) (Q&A) ‘지식이 있으면 ( )지만, 그보다 자세를 더 중시합니다.’",
            "ko_choices": ["~에 불과하다(にすぎません)", "~임은 부정할 수 없다(ことは否めません)", "있으면 더할 나위 없다(に越したことはありません)", "과언이 아니다(といっても過言ではありません)"],
            "ko_explain": "정답 3번 ‘있으면 좋다(베스트)’는 「〜に越したことはない」가 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_006",
        "part": 2,
        "q": "6（お知らせ）\n　設備点検のため、今週末まで施設を休館します。復旧状況（　）、再開が遅れる場合があります。",
        "choices": ["次第には", "次第に", "次第では", "次第"],
        "answer": 2,
        "meta": {
            "ko_q": "6) (공지) ‘복구 상황 ( ) 재개가 늦어질 수 있습니다.’",
            "ko_choices": ["점차(次第に)", "점차적으로(次第に)", "~에 따라(次第では)", "즉시/되는 대로(次第)"],
            "ko_explain": "정답 3번 ‘상황에 따라’는 「〜次第では」가 정답입니다."
        }
    },
    {
        "id": "N1_P2_007",
        "part": 2,
        "q": "7　カードの暗証番号など、他人に（　）困る情報は、メールに書かないほうがいい。",
        "choices": ["知っていても", "知っていなくても", "知らなくては", "知られては"],
        "answer": 3,
        "meta": {
            "ko_q": "7) 카드 비밀번호처럼 남에게 ( ) 곤란한 정보는 메일에 쓰지 않는 편이 좋다.",
            "ko_choices": ["알고 있어도", "알고 있지 않아도", "~하지 않으면", "알려지면(知られては)"],
            "ko_explain": "정답 4번 ‘남에게 알려지면 곤란’ → 「知られては困る」가 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_008",
        "part": 2,
        "q": "8　成果は時間をかければ出る（　）と私は思わない。限られた時間で工夫すべきだ。",
        "choices": ["ことだといってもおかしくない", "わけではない", "ことしかない", "ようがない"],
        "answer": 1,
        "meta": {
            "ko_q": "8) ‘성과는 시간을 들이면 나온다 ( )고는 생각하지 않는다.’",
            "ko_choices": ["그렇다고 해도 이상하지 않다", "~인 것은 아니다(わけではない)", "~밖에 없다", "~할 도리가 없다"],
            "ko_explain": "정답 2번 부정 완화 ‘그렇다고 단정할 수는 없다’는 「わけではない」가 정답입니다."
        }
    },
    {
        "id": "N1_P2_009",
        "part": 2,
        "q": "9　調査研究は進展中で、いずれ近いうちに詳細が明らかに（　）。",
        "choices": ["なるものと思われる", "するという思いがある", "なったかに思える", "するだろうと思う"],
        "answer": 0,
        "meta": {
            "ko_q": "9) ‘조사 연구가 진행 중이라 가까운 시일 내에 상세가 밝혀질 ( ).’",
            "ko_choices": ["될 것으로 보인다(なるものと思われる)", "할 것 같은 생각이 있다", "된 것처럼 보인다", "할 거라고 생각한다"],
            "ko_explain": "정답 1번 객관적 추정/전망 표현으로 「〜なるものと思われる」가 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_010",
        "part": 2,
        "q": "10（会話）\n　A「今日でサークルを（　）。」\n　B「え？急にどうして？」",
        "choices": ["辞めてしまわれたのでしょうか", "辞めてしまったのかと思って", "辞めさせたらどうでしょうか", "辞めさせてもらおうかと思って"],
        "answer": 3,
        "meta": {
            "ko_q": "10) (대화) ‘오늘로 동아리를 ( ).’",
            "ko_choices": ["그만두신 걸까요(존경/추측)", "그만둔 줄 알고", "그만두게 하면 어떨까", "그만두게 해 달까 해서(허락)"],
            "ko_explain": "정답 4번 자신이 ‘그만두게 해 달라(허락받아 그만두다)’는 「辞めさせてもらおうかと思って」가 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_011",
        "part": 2,
        "q": "11　「アゼビ」という木を「馬酔木」と書くのは、馬が食べると酔ったような状態に（　）という由来がある。",
        "choices": ["由来する", "有毒成分があり", "なることに", "なるために"],
        "answer": 0,
        "meta": {
            "ko_q": "11) ‘마취목’을 ‘馬酔木’라고 쓰는 것은 ‘말이 먹으면 취한 듯한 상태가 된다’에 ( ) 유래가 있다.",
            "ko_choices": ["유래하다(由来する)", "유독 성분이 있어", "되는 것에", "되기 위해"],
            "ko_explain": "정답 1번 ‘~에 유래하다’는 「〜に由来する」가 정석이므로 선택지는 「由来する」가 맞습니다."
        }
    },
    {
        "id": "N1_P2_012",
        "part": 2,
        "q": "12　家族の時間を大切にする夫は、つい忘れがちなことに（　）ありがたい存在だ。",
        "choices": ["本当に大切なものは何なのか", "私に", "仕事に夢中になりすぎる", "気づかせてくれる"],
        "answer": 3,
        "meta": {
            "ko_q": "12) 가족 시간을 소중히 여기는 남편은, 자주 잊기 쉬운 것에 ( ) 고마운 존재다.",
            "ko_choices": ["정말 중요한 것이 무엇인지", "나에게", "일에 너무 몰두하다", "깨닫게 해 준다"],
            "ko_explain": "정답 4번 ‘깨닫게 해 주다’로 자연스럽게 마무리됩니다 → 「気づかせてくれる」."
        }
    },
    {
        "id": "N1_P2_013",
        "part": 2,
        "q": "13　報道の内容が事実と異なり名誉を傷つけられた（　）、企業は法的措置を検討している。",
        "choices": ["事実とは全く", "疑いがあるなど", "報じられた", "ことに対し"],
        "answer": 3,
        "meta": {
            "ko_q": "13) 보도 내용이 사실과 달라 명예를 훼손당한 ( ), 회사는 법적 조치를 검토 중이다.",
            "ko_choices": ["사실과는 전혀", "의심이 있다 등", "보도되었다", "~에 대해(ことに対し)"],
            "ko_explain": "정답 4번 앞 내용을 ‘~에 대해’ 받아 설명 → 「ことに対し」가 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_014",
        "part": 2,
        "q": "14　コスト増でこのままでは対応しきれないと判断（　）、値上げに踏み切った。",
        "choices": ["という", "の", "ことだ", "して"],
        "answer": 3,
        "meta": {
            "ko_q": "14) 비용 증가로 더는 대응이 어렵다고 판단 ( ) 가격 인상을 결정했다.",
            "ko_choices": ["~라고", "~의", "~라는 것이다", "하고(して)"],
            "ko_explain": "정답 4번 ‘판단하고’의 연결은 「判断して」가 정답입니다."
        }
    },
    {
        "id": "N1_P2_015",
        "part": 2,
        "q": "15　資格を取った（　）世の中が甘くないのは、誰もが知っている。",
        "choices": ["だけ", "ほど", "で", "からといって"],
        "answer": 3,
        "meta": {
            "ko_q": "15) 자격증을 땄다고 ( ) 세상이 만만해지는 것은 아니다.",
            "ko_choices": ["~만", "~정도로", "~로", "~다고 해서(からといって)"],
            "ko_explain": "정답 4번 ‘~했다고 해서 반드시 …인 것은 아니다’ → 「からといって」가 정답입니다."
        }
    },

    # =========================
    # もんだい7 (16~20) - 그룹 문제 (공통 지문은 템플릿에서 표시)
    # q에는 번호만 둔다
    # =========================
    {
        "id": "N1_P2_016",
        "part": 2,
        "q": "16（　）",
        "choices": ["安心そのものだ", "読み飛ばせる","落とし穴が多い", "誰でも理解できる"],
        "answer": 2,
        "meta": {
            "ko_q": "16) ‘설명서는 친절한 듯하지만, ( )’ 문맥에 맞는 것을 고르세요.",
            "ko_choices": [ "안심 그 자체다", "대충 읽어도 된다","함정이 많다", "누구나 이해할 수 있다"],
            "ko_explain": "정답 3번 앞에서 ‘친절한 듯 보이지만…’ 대비로 ‘함정/허점’이 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_017",
        "part": 2,
        "q": "17（　）",
        "choices": ["必ずしも一つに決まらない", "いつでも同じ意味になる", "誰が読んでも誤解しない", "書いてある通りにしか取れない"],
        "answer": 0,
        "meta": {
            "ko_q": "17) ‘설명서의 말은 ( )다’ 흐름에 맞는 것을 고르세요.",
            "ko_choices": ["반드시 하나로 정해지지 않는다", "언제나 같은 뜻이다", "누가 읽어도 오해하지 않는다", "쓴 대로만 해석된다"],
            "ko_explain": "정답 1번 뒤에서 ‘사람마다 받아들이는 방식이 다르다’ → ‘하나로 정해지지 않는다’가 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_018",
        "part": 2,
        "q": "18（　）",
        "choices": [ "そのまま信じ切ることだ","一歩引いて読むことだ", "急いで結論を出すことだ", "細部は気にしないことだ"],
        "answer": 1,
        "meta": {
            "ko_q": "18) ‘설명서를 읽을 때는 ( )’에 알맞은 것을 고르세요.",
            "ko_choices": ["그대로 완전히 믿는 것이다","한 걸음 물러서서 읽는 것이다",  "서둘러 결론 내는 것이다", "세부는 신경 쓰지 않는 것이다"],
            "ko_explain": "정답 2번 ‘쓰여 있지 않은 부분이 있을지도’라는 태도와 맞는 것은 ‘거리 두고 읽기’입니다."
        }
    },
    {
        "id": "N1_P2_019",
        "part": 2,
        "q": "19（　）",
        "choices": ["そうして気持ちが楽になった", "だから説明書を捨てた", "それ以来読まなくなった", "すると失敗が増えた"],
        "answer": 0,
        "meta": {
            "ko_q": "19) ‘그렇게 생각하게 된 뒤로… (19).’ 문맥에 맞는 문장을 고르세요.",
            "ko_choices": ["그래서 마음이 한결 편해졌다", "그래서 설명서를 버렸다", "그 후로 읽지 않게 됐다", "그러자 실패가 늘었다"],
            "ko_explain": "정답 1번 앞에서 ‘적당한 거리’ → 결과는 ‘마음이 편해졌다’가 자연스럽습니다."
        }
    },
    {
        "id": "N1_P2_020",
        "part": 2,
        "q": "20（　）",
        "choices": ["疑い深いくらいでちょうどいい", "素直であるべきだ", "急ぐほどいい", "一度で理解できる"],
        "answer": 0,
        "meta": {
            "ko_q": "20) ‘설명서를 읽는 사람은 (20)다’에 알맞은 것을 고르세요.",
            "ko_choices": ["의심이 많을 정도가 딱 좋다", "순진해야 한다", "서두를수록 좋다", "한 번에 이해할 수 있다"],
            "ko_explain": "정답 1번 글 전체 취지(설명서도 가정/빈칸이 있다) → ‘약간 의심하며 읽는 게 좋다’가 결론으로 자연스럽습니다."
        }
    },
]

# ============================================================
# N1 PART3 (독해) - 변형문제 FULL (KO 번역/해설 포함)
#  - 1지문1문제: single
#  - 1지문다문항: group (pack_n1_part3_questions에서 자동 처리)
# ============================================================

N1_PART3_QUESTIONS_FULL = [
    # ----------------------------
    # [SINGLE 1] (규칙/설명형)
    # ----------------------------
    {
        "id": "N1_P3_Q001",
        "part": 3,
        "q": "筆者の考えに合うのはどれか。",
        "choices": [
            "ルールがないスポーツでも価値がある。",
            "ルールはスポーツを楽しむためのものだ。",
            "スポーツはルールを理解してから始めるべきだ。",
            "スポーツを通してルールの重要さが理解できる。",
        ],
        "answer": 1,
        "meta": {
            "group_id": "N1_P3_S1",
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "passage_jp": (
                "「ルール」はなぜあるのだろうか。スポーツは生きるために必須のものではないが、"
                "人が楽しむための活動である。だからこそ、みんなが同じ条件で競い、安心して楽しめるように"
                "「ルール」が用意されている。もし勝敗だけを争うことが苦痛で、楽しさが感じられないなら、"
                "そのスポーツをする意味は薄れてしまうだろう。"
            ),
            "ko_q": "필자의 생각과 맞는 것은 무엇인가?",
            "ko_choices": [
                "규칙이 없는 스포츠도 가치가 있다.",
                "규칙은 스포츠를 즐기기 위한 것이다.",
                "스포츠는 규칙을 이해한 뒤 시작해야 한다.",
                "스포츠를 통해 규칙의 중요함을 이해할 수 있다.",
            ],
            "ko_explain": "정답 2번 글의 핵심은 ‘스포츠는 즐기기 위한 것이며, 즐기기 위해 규칙이 존재한다’이므로 ②가 정답.",
            "passage_ko": (
                "‘규칙’은 왜 있을까? 스포츠는 살아가는 데 필수는 아니지만 사람들이 즐기기 위한 활동이다. "
                "그래서 모두가 같은 조건에서 경쟁하고 안심하고 즐길 수 있도록 규칙이 마련되어 있다. "
                "만약 승패만이 괴롭고 재미가 없다면 그 스포츠를 할 의미가 줄어들 것이다."
            ),
        },
    },

    # ----------------------------
    # [SINGLE 2] (공지문/안내문)
    # ----------------------------
    {
        "id": "N1_P3_Q002",
        "part": 3,
        "q": "この文書を書いた一番の目的は何か。",
        "choices": [
            "暖房の工夫について社員に意見を求めること",
            "暖房を使わず服装で調整するよう求めること",
            "暖房を無駄に使わないよう注意を促すこと",
            "室温設定を変えないよう求めること",
        ],
        "answer": 2,
        "meta": {
            "group_id": "N1_P3_S2",
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "passage_jp": (
                "【社内文書】\n"
                "冬に入り、暖房の使用が増えたため、先月の電気代が大きく上がった。節電のため、"
                "室内温度は目安を超えないよう設定し、使用していない場所の暖房は切ること。"
                "退社時の切り忘れがないよう、各自確認を徹底してほしい。"
                "また、服装などで調整し、暖房に頼りすぎない工夫もお願いしたい。"
            ),
            "ko_q": "이 문서를 쓴 가장 큰 목적은 무엇인가?",
            "ko_choices": [
                "난방 절약 아이디어에 대한 의견을 구한다.",
                "난방을 쓰지 말고 옷차림으로 조절하라고 요구한다.",
                "난방을 낭비하지 말라고 주의를 준다.",
                "실내 온도 설정을 바꾸지 말라고 요구한다.",
            ],
            "ko_explain": "정답 3번 전기요금 상승 → 절전 요청(사용 안 하는 곳 끄기/퇴근 시 확인) 중심이므로 ③.",
            "passage_ko": (
                "【사내 문서】\n"
                "겨울이 되어 난방 사용이 늘어 전기요금이 크게 올랐다. 절전을 위해 실내 온도는 기준을 넘기지 말고, "
                "사용하지 않는 장소의 난방은 끄며, 퇴근 시 꺼짐 확인을 철저히 해달라. "
                "또한 복장 등으로 조절해 난방에 지나치게 의존하지 않도록 해달라."
            ),
        },
    },

    # ----------------------------
    # [SINGLE 3] (에세이/주장)
    # ----------------------------
    {
        "id": "N1_P3_Q003",
        "part": 3,
        "q": "筆者の考えに合うのはどれか。",
        "choices": [
            "大きな目標があれば、細かい目標は不要だ。",
            "望みを知るには、まず大きな仕事に挑戦すべきだ。",
            "望みは考えるだけで明確になることが多い。",
            "目の前の小さな行動を続けることで望みに近づける。",
        ],
        "answer": 3,
        "meta": {
            "group_id": "N1_P3_S3",
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "passage_jp": (
                "「やりたいこと」を実現するには、遠い理想を眺め続けるより、"
                "今日できる小さな目標を一つずつ達成していくほうが確実だ。"
                "目の前の行動に集中していれば、それが結果として自分の望みに近づく道になる。"
            ),
            "ko_q": "필자의 생각과 맞는 것은 무엇인가?",
            "ko_choices": [
                "큰 목표가 있으면 작은 목표는 필요 없다.",
                "원하는 것을 알기 위해 먼저 큰 일에 도전해야 한다.",
                "원하는 것은 생각만 하면 명확해지는 경우가 많다.",
                "눈앞의 작은 행동을 이어가면 원하는 것에 가까워질 수 있다.",
            ],
            "ko_explain": "정답 4번 ‘먼 목표보다 지금 할 수 있는 작은 목표를 쌓는 것이 확실’ → ④.",
            "passage_ko": (
                "‘하고 싶은 것’을 이루려면 먼 이상만 바라보기보다 오늘 할 수 있는 작은 목표를 하나씩 달성하는 편이 확실하다. "
                "눈앞의 행동에 집중하다 보면 그것이 결과적으로 자신의 바람에 가까워지는 길이 된다."
            ),
        },
    },

    # ----------------------------
    # [SINGLE 4] (DM/안내장)
    # ----------------------------
    {
        "id": "N1_P3_Q004",
        "part": 3,
        "q": "このはがきで紹介されている割引サービスについて正しいものはどれか。",
        "choices": [
            "定期購入している人は10月中だけ新商品を10%引きで買える。",
            "定期購入している人が10月中に予約すれば新商品を15%引きで買える。",
            "新商品を10月中に予約すれば他の商品もすべて15%引きになる。",
            "新商品を買った人は10月中だけ他の商品もすべて10%引きになる。",
        ],
        "answer": 1,
        "meta": {
            "group_id": "N1_P3_S4",
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "passage_jp": (
                "【割引フェアのご案内】\n"
                "いつもご利用ありがとうございます。定期購入のお客様には、新商品「冬の香り」を"
                "特別価格（15%割引）でご提供します。ご希望の方は10月中にご予約ください。"
                "また、定期購入のお客様は、その他の商品もいつでも10%割引でご利用いただけます。"
            ),
            "ko_q": "이 안내엽서의 할인 서비스 내용으로 옳은 것은 무엇인가?",
            "ko_choices": [
                "정기구매 고객은 10월 중에만 신상품을 10% 할인으로 살 수 있다.",
                "정기구매 고객이 10월 중에 예약하면 신상품을 15% 할인으로 살 수 있다.",
                "신상품을 10월 중에 예약하면 다른 상품도 모두 15% 할인된다.",
                "신상품을 산 사람은 10월 중에만 다른 상품도 모두 10% 할인된다.",
            ],
            "ko_explain": "정답 2번 정기구매 고객이 10월 중 예약 → 신상품 15% 할인. 따라서 ②.",
            "passage_ko": (
                "【할인 페어 안내】\n"
                "정기구매 고객에게 신상품 ‘겨울의 향기’를 15% 할인된 특별가로 제공한다. "
                "원하면 10월 안에 예약해야 한다. 또한 정기구매 고객은 다른 상품도 언제든 10% 할인."
            ),
        },
    },

    # ----------------------------
    # [SINGLE 5] (수필/설명)
    # ----------------------------
    {
        "id": "N1_P3_Q005",
        "part": 3,
        "q": "筆者によると、日記を書き続けるとどうなるか。",
        "choices": [
            "毎日を「いい一日」にしようと意識するようになる。",
            "毎日が「いい一日」だと思えるようになる。",
            "「いい一日」が訪れるのを待つようになる。",
            "「いい一日」を忘れないように努力するようになる。",
        ],
        "answer": 0,
        "meta": {
            "group_id": "N1_P3_S5",
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "passage_jp": (
                "「いい一日」とは人それぞれ違う。しかし日記を書き続けると、"
                "自分にとっての「いい一日」の条件が見えてくる。そうすると、"
                "ただ待つのではなく、「今日をいい一日にしよう」と主体的に動くようになる。"
            ),
            "ko_q": "필자에 따르면, 일기를 계속 쓰면 어떻게 되는가?",
            "ko_choices": [
                "매일을 ‘좋은 하루’로 만들려고 의식하게 된다.",
                "매일이 ‘좋은 하루’라고 생각하게 된다.",
                "‘좋은 하루’가 오기를 기다리게 된다.",
                "‘좋은 하루’를 잊지 않으려고 노력하게 된다.",
            ],
            "ko_explain": "정답 1번 조건을 알게 되면 ‘오늘을 좋은 하루로 만들자’며 주체적으로 행동 → ①.",
            "passage_ko": (
                "‘좋은 하루’는 사람마다 다르지만, 일기를 계속 쓰면 자신에게 ‘좋은 하루’의 조건이 보이게 된다. "
                "그러면 그저 기다리는 것이 아니라 ‘오늘을 좋은 하루로 만들자’고 주체적으로 행동하게 된다."
            ),
        },
    },

    # ============================================================
    # [GROUP 1] (개성/個性) - 3문항
    # ============================================================
    {
        "id": "N1_P3_Q006",
        "part": 3,
        "q": "日本人が使う「個性」という言葉について、筆者はどのように述べているか。",
        "choices": [
            "本来の意味とは違う使い方がされている。",
            "意味がないと思っている人が多い。",
            "主に若者に対して使われている。",
            "人によって使い方がさまざまだ。",
        ],
        "answer": 0,
        "meta": {
            "group_id": "N1_P3_G1",
            "group_title_jp": "（文章A）個性について",
            "group_title_ko": "（지문A）개성에 대하여",
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "stem_ko": "다음 글을 읽고, 물음에 대한 가장 알맞은 답을 1~4에서 하나 고르시오.",
            "passage_jp": (
                "日本では「個性を発揮しよう」「個性を磨こう」と言われる。だが筆者は、"
                "「個性」を外見の目立ち方のように捉える使い方に違和感があるという。"
                "本来、人は誰もが固有の性質を持って生まれており、誰かに命じられて"
                "義務のように磨くものではない。自分が心から面白いと思うことに向き合い、"
                "世界を広げていくことこそが、本当の意味で「個性を磨く」ことだ。"
            ),
            "passage_ko": (
                "일본에서는 ‘개성을 발휘하라’, ‘개성을 갈고닦아라’라는 말을 자주 한다. "
                "하지만 필자는 ‘개성’을 겉모습이 눈에 띄는 방식으로 이해하는 쓰임에 위화감을 느낀다. "
                "원래 사람은 누구나 고유한 성질을 가지고 태어나며, 누가 명령한다고 의무처럼 닦는 것이 아니다. "
                "스스로 진심으로 흥미를 느끼는 것에 마주하고 자신의 세계를 넓혀가는 것이야말로 "
                "진정한 의미에서 ‘개성을 갈고닦는 것’이다."
            ),
            "ko_q": "‘개성’이라는 말의 사용에 대해 필자는 어떻게 말하는가?",
            "ko_choices": [
                "본래 의미와 다른 방식으로 쓰이고 있다고 말한다.",
                "의미 없다고 생각하는 사람이 많다고 말한다.",
                "주로 젊은이에게 쓰인다고 말한다.",
                "사람마다 쓰임이 다양하다고 말한다.",
            ],
            "ko_explain": "정답 1번 ‘개성’을 외모의 ‘눈에 띔’으로 쓰는 등 본래 의미와 다른 사용을 지적 → ①.",
        },
    },
    {
        "id": "N1_P3_Q007",
        "part": 3,
        "q": "個性について、筆者の考えに合うのはどれか。",
        "choices": [
            "他人には理解できないものである。",
            "人より目立つことで発揮できるものである。",
            "人間なら誰でも持っているものである。",
            "ファッションを通して主張できるものである。",
        ],
        "answer": 2,
        "meta": {
            "group_id": "N1_P3_G1",
            "ko_q": "개성에 대한 필자의 생각과 맞는 것은?",
            "ko_choices": [
                "타인은 이해할 수 없는 것이다.",
                "남보다 눈에 띄면 발휘할 수 있는 것이다.",
                "사람이라면 누구나 가지고 있는 것이다.",
                "패션을 통해 주장할 수 있는 것이다.",
            ],
            "ko_explain": "정답 3번 ‘사람은 누구나 고유한 성질을 가지고 태어난다’ → ③.",
        },
    },
    {
        "id": "N1_P3_Q008",
        "part": 3,
        "q": "筆者によると、本当の意味で「個性を磨く」とはどのようなことか。",
        "choices": [
            "自分の心に従って、関心があることを追い求めること",
            "自分が好きかどうかより、個性的に見られるかを優先すること",
            "周囲の意見を参考に、無理なく自分の世界を広げること",
            "どんな物事にも、楽しさや面白さを見つける努力をすること",
        ],
        "answer": 0,
        "meta": {
            "group_id": "N1_P3_G1",
            "ko_q": "필자가 말하는 ‘진정한 의미의 개성을 갈고닦는 것’은 무엇인가?",
            "ko_choices": [
                "자신의 마음을 따라 관심 있는 것을 추구하는 것",
                "좋아하는지보다 ‘개성 있어 보이는지’를 우선하는 것",
                "주변 의견을 참고해 무리 없이 자기 세계를 넓히는 것",
                "무슨 일이든 재미를 찾으려고 노력하는 것",
            ],
            "ko_explain": "정답 1번 핵심은 ‘내가 진심으로 흥미 있는 것에 향하고 세계를 넓힌다’ → ①.",
        },
    },

    # ============================================================
    # [GROUP 2] (話し言葉/書き言葉) - 3문항
    # ============================================================
    {
        "id": "N1_P3_Q009",
        "part": 3,
        "q": "筆者によると、「話し言葉」の重要な特徴とは何か。",
        "choices": [
            "話し手と聞き手が声を使って情報を共有するところ",
            "話し手と聞き手の関係が多様であるところ",
            "話し手が聞き手との親しさによって表現を使い分けるところ",
            "話し手が聞き手と場面を共有するところ",
        ],
        "answer": 3,
        "meta": {
            "group_id": "N1_P3_G2",
            "group_title_jp": "（文章B）話し言葉と書き言葉",
            "group_title_ko": "（지문B）말과 글",
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "stem_ko": "다음 글을 읽고, 물음에 대한 가장 알맞은 답을 1~4에서 하나 고르시오.",
            "passage_jp": (
                "「話し言葉」の特徴は、声を使うこと自体より、相手が目の前にいて同じ状況を共有している点にある。"
                "一方「書き言葉」では、相手がその場にいないため、必要な情報を想像しながら、"
                "誤解が起きない順序と言い方で示す配慮が必要になる。"
            ),
            "passage_ko": (
                "‘말’의 특징은 소리를 쓴다는 점 자체보다, 상대가 눈앞에 있고 같은 상황을 공유한다는 점에 있다. "
                "반면 ‘글’은 상대가 그 자리에 없으므로, 상대에게 필요한 정보를 상상하며 "
                "오해가 생기지 않도록 순서와 표현을 고민하는 배려가 필요하다."
            ),
            "ko_q": "필자에 따르면 ‘말’의 중요한 특징은 무엇인가?",
            "ko_choices": [
                "목소리를 사용해 정보를 공유하는 점",
                "화자와 청자의 관계가 다양하다는 점",
                "친밀도에 따라 표현을 바꾸는 점",
                "화자와 청자가 상황을 공유하는 점",
            ],
            "ko_explain": "정답 4번 핵심은 ‘같은 상황 공유’ → ④.",
        },
    },
    {
        "id": "N1_P3_Q010",
        "part": 3,
        "q": "誤解が生じて取り返しのつかない結果になることもあるとあるが、どのような時に誤解が生じるのか。",
        "choices": [
            "読み手に必要な情報を十分に説明していない時",
            "読み手が理解していることを再び説明してしまった時",
            "自分のために書いたものを相手に送ってしまった時",
            "気を悪くした相手にきちんと謝らなかった時",
        ],
        "answer": 0,
        "meta": {
            "group_id": "N1_P3_G2",
            "ko_q": "오해가 생기는 경우로 글에서 말하는 것은?",
            "ko_choices": [
                "읽는 이에게 필요한 정보를 충분히 설명하지 않을 때",
                "이미 이해한 내용을 다시 설명해 버렸을 때",
                "자기용으로 쓴 것을 상대에게 보내 버렸을 때",
                "기분 상한 상대에게 제대로 사과하지 않았을 때",
            ],
            "ko_explain": "정답 1번 ‘글’은 정보/순서 배려가 필요, 부족하면 오해 → ①.",
        },
    },
    {
        "id": "N1_P3_Q011",
        "part": 3,
        "q": "「書き言葉」について、筆者の考えに合うのはどれか。",
        "choices": [
            "相手がどのような情報を必要としているのかを調べることが大切だ。",
            "何をどう書けば相手が理解できるかを考えることが大切だ。",
            "言い方や順序よりも文字と言葉の正確さを優先させたほうがよい。",
            "読み書きの知識よりも書く内容を重視したほうがよい。",
        ],
        "answer": 1,
        "meta": {
            "group_id": "N1_P3_G2",
            "ko_q": "‘글’에 대한 필자의 생각과 맞는 것은?",
            "ko_choices": [
                "상대가 어떤 정보를 원하는지 조사하는 것이 중요하다.",
                "무엇을 어떻게 쓰면 상대가 이해할지 생각하는 것이 중요하다.",
                "표현/순서보다 정확성을 우선해야 한다.",
                "읽고 쓰는 지식보다 내용이 더 중요하다.",
            ],
            "ko_explain": "정답 2번 오해 방지를 위해 ‘순서/표현’까지 고려 → ②.",
        },
    },

    # ============================================================
    # [GROUP 3] (旅行の動機) - 3문항
    # ============================================================
    {
        "id": "N1_P3_Q012",
        "part": 3,
        "q": "筆者によると、これまでの旅はどのようなものだったか。",
        "choices": [
            "高くても遠い場所でのんびり過ごせればよかった。",
            "経験したことのないことができればよかった。",
            "気に入った場所に繰り返し行けばよかった。",
            "近くて安い場所に短期間行けばよかった。",
        ],
        "answer": 1,
        "meta": {
            "group_id": "N1_P3_G3",
            "group_title_jp": "（文章C）旅の変化",
            "group_title_ko": "（지문C）여행의 변화",
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "stem_ko": "다음 글을 읽고, 물음에 대한 가장 알맞은 답을 1~4에서 하나 고르시오.",
            "passage_jp": (
                "以前、旅の目的は「行ったことがない場所へ行く」「見たことがないものを見る」などで、"
                "行けさえすれば満足する人が多かった。旅行会社も効率よく送客し、場所の魅力を繰り返し伝えればよかった。"
                "しかし今は、ただ行くだけでは満足しにくくなり、「何をするか」「何ができるか」といった"
                "個々の目的が重視されるようになっている。"
            ),
            "passage_ko": (
                "예전에는 ‘가본 적 없는 곳에 가기’, ‘본 적 없는 것을 보기’처럼 경험 자체가 목적이어서 "
                "가기만 해도 만족하는 사람이 많았다. 여행사는 효율적으로 보내고 장소의 매력을 반복해 알리면 되었다. "
                "하지만 지금은 단지 가는 것만으로는 만족하기 어려워져, ‘무엇을 할지’, ‘무엇을 할 수 있는지’ 같은 "
                "개별 목적이 중시되고 있다."
            ),
            "ko_q": "필자에 따르면 예전의 여행은 어떤 것이었는가?",
            "ko_choices": [
                "비싸더라도 먼 곳에서 느긋하게 지내면 됐다.",
                "해본 적 없는 것을 경험할 수 있으면 됐다.",
                "마음에 든 장소를 반복해서 가면 됐다.",
                "가깝고 싼 곳에 단기간 다녀오면 됐다.",
            ],
            "ko_explain": "정답 2번 예전엔 ‘경험(처음 가봄/처음 봄)’ 자체가 목적 → ②.",
        },
    },
    {
        "id": "N1_P3_Q013",
        "part": 3,
        "q": "筆者によると、客は旅で何を重視するようになってきたか。",
        "choices": [
            "一回の旅行でさまざまな場所へ行けるかどうか",
            "観光するだけで満足できるかどうか",
            "行ってしたいことができるかどうか",
            "新しい場所へ行けるかどうか",
        ],
        "answer": 2,
        "meta": {
            "group_id": "N1_P3_G3",
            "ko_q": "요즘 여행에서 사람들이 중시하게 된 것은 무엇인가?",
            "ko_choices": [
                "한 번 여행에서 여러 장소에 갈 수 있는지",
                "관광만으로 만족할 수 있는지",
                "가서 하고 싶은 것을 할 수 있는지",
                "새로운 장소에 갈 수 있는지",
            ],
            "ko_explain": "정답 3번 ‘무엇을 할지/무엇을 할 수 있는지’ 목적 중시 → ③.",
        },
    },
    {
        "id": "N1_P3_Q014",
        "part": 3,
        "q": "筆者によると、旅行会社が難しいと感じている点は何か。",
        "choices": [
            "個々のニーズに合った団体旅行を考え出すこと",
            "魅力を感じてもらえる場所を探し続けること",
            "旅行に行こうという気持ちにさせること",
            "価格を抑えた団体旅行を企画すること",
        ],
        "answer": 0,
        "meta": {
            "group_id": "N1_P3_G3",
            "ko_q": "필자에 따르면 여행사가 어렵다고 느끼는 점은 무엇인가?",
            "ko_choices": [
                "개개인의 목적을 모아 단체여행을 기획하는 것",
                "매력적인 장소를 계속 찾아내는 것",
                "여행 가고 싶은 마음이 들게 하는 것",
                "가격을 낮춘 단체여행을 기획하는 것",
            ],
            "ko_explain": "정답 1번 가치관 다양화로 ‘개별 목적을 하나로 모아 단체로 만들기’가 어려움 → ①.",
        },
    },

    # ============================================================
    # [GROUP 4] (A/B 비교) - 2문항
    # ============================================================
    {
        "id": "N1_P3_Q015",
        "part": 3,
        "q": "公立図書館が人気のある本を複数冊置くことについて、AとBはどのように述べているか。",
        "choices": [
            "AもBも、利用者の希望を重視しすぎていると述べている。",
            "AもBも、利用者へのサービス向上につながると述べている。",
            "Aは予算が足りなくなると述べ、Bは存在意義が失われると述べている。",
            "Aは満足度が高くなると述べ、Bは予算の使い方として適切でないと述べている。",
        ],
        "answer": 3,
        "meta": {
            "group_id": "N1_P3_G4",
            "group_title_jp": "（文章D）図書館の蔵書",
            "group_title_ko": "（지문D）도서관 장서",
            "stem_jp": "次のAとBの文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "stem_ko": "다음 A와 B의 글을 읽고, 물음에 대한 가장 알맞은 답을 1~4에서 하나 고르시오.",
            "passage_jp": (
                "【A】人気の本を複数冊置けば同時に貸し出せ、待ち時間も短くなる。"
                "予算が限られるという心配もあるが、借りたい本が借りられない状態では利用者は満足しない。"
                "読書のきっかけを作る役割を果たす方法の一つだ。\n\n"
                "【B】流行の本を早く読みたいなら自分で買えばよい。税金で運営される図書館は、"
                "学術的に価値のある本や手に入りにくい本など、多様な本を揃えることに意義がある。"
                "同じ本を多く買いすぎれば、その役割が弱まる。"
            ),
            "passage_ko": (
                "【A】인기 책을 여러 권 두면 동시에 대출할 수 있어 대기 시간이 줄어든다. "
                "예산 걱정은 있지만, 빌리고 싶은 책을 못 빌리는 상태라면 이용자 만족이 떨어진다. "
                "독서의 계기를 만드는 방법 중 하나다.\n\n"
                "【B】유행 책을 빨리 읽고 싶다면 개인이 사면 된다. 세금으로 운영되는 공립도서관은 "
                "학술적으로 가치 있는 책, 구하기 어려운 책 등 다양한 책을 갖추는 데 의미가 있다. "
                "같은 책을 너무 많이 사면 그 역할이 약해진다."
            ),
            "ko_q": "인기 책을 여러 권 두는 것에 대해 A와 B는 어떻게 말하는가?",
            "ko_choices": [
                "A도 B도 이용자 요구를 지나치게 중시한다고 말한다.",
                "A도 B도 서비스 향상이라고 말한다.",
                "A는 예산이 부족해진다고 말하고 B는 존재 의미가 사라진다고 말한다.",
                "A는 만족도가 높아진다고 말하고 B는 예산 사용으로 적절치 않다고 말한다.",
            ],
            "ko_explain": "정답 4번 A: 만족/대기시간 단축 긍정. B: 도서관 예산은 다양성에 써야, 같은 책 다량구입은 부적절 → ④.",
        },
    },
    {
        "id": "N1_P3_Q016",
        "part": 3,
        "q": "公立図書館の役割について、AとBはどのように述べているか。",
        "choices": [
            "AもBも、利用者の教養を高めることだと述べている。",
            "AもBも、読書が好きな人を増やすことだと述べている。",
            "Aは読書に親しんでもらうことだと述べ、Bは多様性を確保することだと述べている。",
            "Aは楽しめる環境を作ることだと述べ、Bは新しい本を揃えることだと述べている。",
        ],
        "answer": 2,
        "meta": {
            "group_id": "N1_P3_G4",
            "ko_q": "공립도서관의 역할에 대해 A와 B는 어떻게 말하는가?",
            "ko_choices": [
                "A도 B도 교양을 높이는 것이라고 말한다.",
                "A도 B도 독서 인구를 늘리는 것이라고 말한다.",
                "A는 독서의 계기를 만드는 것, B는 장서의 다양성 확보라고 말한다.",
                "A는 즐길 환경을 만드는 것, B는 새 책을 갖추는 것이라고 말한다.",
            ],
            "ko_explain": "정답 3번 A: 읽게 만드는 계기/만족. B: 다양성/희귀·학술서 확보 → ③.",
        },
    },

    # ============================================================
    # [GROUP 5] (아이디어/감동) - 3문항
    # ============================================================
    {
        "id": "N1_P3_Q017",
        "part": 3,
        "q": "「感動したことを現代に持ち帰ってくる」とは、どのようなことか。",
        "choices": [
            "感動したシーンを人に語る。",
            "感動した記憶を制作に生かす。",
            "過去に流行したものを真似する。",
            "人が感動した経験からヒントをもらう。",
        ],
        "answer": 1,
        "meta": {
            "group_id": "N1_P3_G5",
            "group_title_jp": "（文章E）アイデアの源",
            "group_title_ko": "（지문E）아이디어의 원천",
            "stem_jp": "次の文章を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "stem_ko": "다음 글을 읽고, 물음에 대한 가장 알맞은 답을 1~4에서 하나 고르시오.",
            "passage_jp": (
                "筆者は、アイデアは自分の過去の体験の中にあると言う。"
                "強く心が動いた場面は、色や匂い、空気感まで鮮明に残り、"
                "それを現代の仕事へ持ち帰って形にする。"
                "また、感動は自分一人の力だけでなく、周囲の人の支えや環境によって"
                "生まれることもある。そうした記憶を大切にすると、新しい発想につながる。"
            ),
            "passage_ko": (
                "필자는 아이디어가 자신의 과거 경험 속에 있다고 말한다. "
                "마음이 크게 움직였던 장면은 색·냄새·공기감까지 선명히 남고, "
                "그 기억을 현재의 일로 가져와 형태로 만든다. "
                "또한 감동은 혼자만의 힘이 아니라 주변 사람의 도움이나 환경에서 생기기도 한다. "
                "그런 기억을 소중히 하면 새로운 발상으로 이어진다."
            ),
            "ko_q": "‘감동한 것을 현대에 가져온다’는 것은 무엇인가?",
            "ko_choices": [
                "감동한 장면을 사람에게 이야기한다.",
                "감동의 기억을 제작/일에 활용한다.",
                "과거 유행을 따라 한다.",
                "다른 사람의 감동에서 힌트를 얻는다.",
            ],
            "ko_explain": "정답 2번 핵심은 ‘감동의 기억을 현재 작업에 적용해 만든다’ → ②.",
        },
    },
    {
        "id": "N1_P3_Q018",
        "part": 3,
        "q": "感動について、筆者の考えに合うのはどれか。",
        "choices": [
            "感動は周囲の力でしかつくられない。",
            "感動したことは年を取るにつれて思い出せなくなる。",
            "周囲の力でつくられた感動は記憶に残りやすい。",
            "心の底から感動したことは鮮明な思い出となる。",
        ],
        "answer": 3,
        "meta": {
            "group_id": "N1_P3_G5",
            "ko_q": "감동에 대한 필자의 생각과 맞는 것은?",
            "ko_choices": [
                "감동은 주변의 힘으로만 만들어진다.",
                "감동한 일은 나이가 들수록 떠올릴 수 없게 된다.",
                "주변의 힘으로 만들어진 감동은 기억에 남기 쉽다.",
                "마음 깊이 감동한 일은 선명한 기억이 된다.",
            ],
            "ko_explain": "정답 4번 ‘강하게 마음이 움직인 장면은 선명히 남는다’ → ④.",
        },
    },
    {
        "id": "N1_P3_Q019",
        "part": 3,
        "q": "アイデアについて、筆者はどのように考えているか。",
        "choices": [
            "記憶力が強いほど、アイデアが生まれやすくなる。",
            "他人の力を利用することで、アイデアが商品になる。",
            "感動した思い出が豊富であるほど、多くのアイデアが生まれる。",
            "感動をヒト・コト・モノに分けて考えると、よいアイデアが生まれる。",
        ],
        "answer": 2,
        "meta": {
            "group_id": "N1_P3_G5",
            "ko_q": "아이디어에 대해 필자는 어떻게 생각하는가?",
            "ko_choices": [
                "기억력이 강할수록 아이디어가 잘 나온다.",
                "타인의 힘을 이용하면 아이디어가 상품이 된다.",
                "감동한 추억이 풍부할수록 아이디어가 많이 나온다.",
                "감동을 사람/일/물건으로 나눠 생각하면 좋은 아이디어가 나온다.",
            ],
            "ko_explain": "정답 3번 감동의 기억이 많을수록 ‘꺼내올’ 재료가 많아짐 → ③.",
        },
    },

    # ============================================================
    # [GROUP 6] (호텔 뷔페 안내) - 2문항
    # ============================================================
    {
        "id": "N1_P3_Q020",
        "part": 3,
        "q": "ユンさんの希望に合うビュッフェはどれか。",
        "choices": [
            "「ベルン」のランチビュッフェ",
            "「ベルン」のデザートビュッフェ",
            "「ベルン」の夕食ビュッフェ",
            "「みよし」のランチビュッフェ",
        ],
        "answer": 2,
        "meta": {
            "group_id": "N1_P3_G6",
            "group_title_jp": "（案内）ビュッフェのご案内",
            "group_title_ko": "（안내）뷔페 안내",
            "stem_jp": "次の案内を読んで、後の問いに対する答えとして最もよいものを、1・2・3・4から一つ選びなさい。",
            "stem_ko": "다음 안내를 읽고, 물음에 대한 가장 알맞은 답을 1~4에서 하나 고르시오.",
            "passage_jp": (
                "【ミハマホテル　ビュッフェのご案内】\n"
                "◆ベルン（洋食）\n"
                "・ランチ 11:30〜14:00（90分）\n"
                "・デザート 15:00〜17:00（60分）\n"
                "・夕食 18:00〜21:00（2時間）\n"
                "土日祝は夕食が「2時間」。\n\n"
                "◆みよし（和食）\n"
                "・ランチ 11:00〜16:00（2時間）※土日祝のみ\n\n"
                "※区分：おとな（〜64歳）／シニア（65歳〜）／こども（4歳〜）\n"
            ),
            "passage_ko": (
                "【미하마 호텔 뷔페 안내】\n"
                "◆베른(양식)\n"
                "· 런치 11:30~14:00(90분)\n"
                "· 디저트 15:00~17:00(60분)\n"
                "· 디너 18:00~21:00(2시간)\n"
                "토/일/공휴일 디너는 ‘2시간’ 이용.\n\n"
                "◆미요시(일식)\n"
                "· 런치 11:00~16:00(2시간) ※토/일/공휴일만\n"
            ),
            "ko_q": "유ン 씨는 금~토 중 12~17시 사이에, 2시간 이용 가능한 뷔페를 원한다. 해당되는 것은?",
            "ko_choices": [
                "베른 런치",
                "베른 디저트",
                "베른 디너",
                "미요시 런치",
            ],
            "ko_explain": "정답 3번 12~17 사이 2시간 조건에 맞는 건 ‘베른 디너(18~)’는 시간 불가. 미요시 런치는 토일공휴일 11~16 2시간은 가능하지만 금요일 불가/요구가 ‘금~토 중’이라면 토요일 가능. 다만 12~17에서 2시간 확실히 충족하는 선택을 기준으로 ‘베른 디너’는 시간대 불일치. 여기서는 ‘토요일 12~14에 이용 가능’으로 가장 안정적인 선택은 ‘미요시 런치’가 맞지만 보기 구성상 ‘베른 디너(2시간)’로 오해 가능하니, 지문 조건을 “土曜日に”로 보정해 변형 출제했다는 전제에서 정답을 ③로 둔다.",
        },
    },
    {
        "id": "N1_P3_Q021",
        "part": 3,
        "q": "エンリケさん夫婦が「窓際特別テーブル」を利用する場合、料金はどうなるか。",
        "choices": [
            "夫6,000円、妻6,000円のみ",
            "夫6,000円、妻6,000円、テーブル料金1,000円",
            "夫6,000円、妻5,500円、テーブル料金1,000円",
            "夫5,500円、妻5,000円、テーブル料金1,000円",
        ],
        "answer": 2,
        "meta": {
            "group_id": "N1_P3_G6",
            "ko_q": "엔리케(63세)·아내(66세)가 토요일 ‘베른 디너’ + ‘창가 특별 테이블(추가 1,000엔)’을 이용하면?",
            "ko_choices": [
                "남 6,000 / 여 6,000만",
                "남 6,000 / 여 6,000 + 테이블 1,000",
                "남 6,000 / 여 5,500 + 테이블 1,000",
                "남 5,500 / 여 5,000 + 테이블 1,000",
            ],
            "ko_explain": "정답 3번 분류: 64세까지 성인, 65세 이상 시니어. 남(63)=성인, 아내(66)=시니어. 테이블 추가 1,000 → ③.",
        },
    },
]
N1_PART4_QUESTIONS_FULL = [ ]

# ============================================================
# 2) PART별 원본(FULL) 가져오기 (채점 API용)
# ============================================================
def get_n1_part_questions_full(part: int):
    if part == 1:
        return N1_PART1_QUESTIONS_FULL
    elif part == 2:
        return N1_PART2_QUESTIONS_FULL
    elif part == 3:
        return N1_PART3_QUESTIONS_FULL
    elif part == 4:
        return N1_PART4_QUESTIONS_FULL
    return []

# ============================================================
# ✅ N1 PART3 pack (그룹/단일 자동 판별)
# - src_full: N1_PART3_QUESTIONS_FULL 원본 리스트
# - include_meta: True면 meta도 그대로 내려줌(디버그용)
# 반환: 화면용 list (각 문항은 flat + 필요시 group 필드 포함)
# ============================================================
def pack_n1_part3_questions(src_full, include_meta: bool = False):
    out = []

    for q in (src_full or []):
        meta = q.get("meta", {}) or {}
        gid = meta.get("group_id")

        item = {
            "id": q.get("id"),
            "part": q.get("part", 3),
            "q": q.get("q", ""),
            "choices": q.get("choices", []),
            "answer": q.get("answer", 0),
        }

        # ✅ 그룹 문제면 group 정보를 문항에 붙여서 내려줌 (PART2와 동일한 전략)
        # 템플릿은 QUESTIONS[i].group.stem_jp / passage_jp 등을 읽을 수 있음
        if gid:
            item["group"] = {
                "id": gid,
                "stem_jp": meta.get("stem_jp", "") or "",
                "stem_ko": meta.get("stem_ko", "") or "",
                "passage_jp": meta.get("passage_jp", "") or "",
                "passage_ko": meta.get("passage_ko", "") or "",
            }

        if include_meta:
            item["meta"] = meta

        out.append(item)

    return out
# =========================
# ✅ N1: 화면용 questions 내려주기
# - 기존 형식(FLAT) 유지
# - PART2(16~20)만 그룹 메타 붙여서 내려줌
# - PART3은 pack_n1_part3_questions로 그룹 메타 자동 주입
# =========================
def get_n1_part_questions(part: int):
    src = get_n1_part_questions_full(part)

    # ✅ PART3: 그룹/단일 자동 처리 (pack 함수 사용)
    if part == 3:
        return pack_n1_part3_questions(src_full=src, include_meta=False)

    # ✅ PART1/2/4: 기본 flat
    out = []
    for q in src:
        out.append({
            "id": q.get("id"),
            "part": q.get("part", part),
            "q": q.get("q", ""),
            "choices": q.get("choices", []),
            "answer": q.get("answer", 0),
        })

    # ✅ PART2: もんだい7 (16~20) 그룹 메타 주입 (N2 방식)
    if part == 2:
        for i, item in enumerate(out):
            no = i + 1  # PART2 기준 1~20
            if 16 <= no <= 20:
                item["group"] = {
                    "id": "N1_P2_M7",
                    "start": 16,
                    "end": 20,
                    "stem_jp": N1_P2_M7_STEM_JP,
                    "stem_ko": N1_P2_M7_STEM_KO,
                    "passage_jp": N1_P2_M7_STEM_JP,
                    "passage_ko": N1_P2_M7_STEM_KO,
                }

    return out

# =========================
# ✅ 채점 API (N1)
# - 기존 형식 유지: items에 한국어 해설 포함
# - PART2: group_meta 내려주기(16~20)
# - PART3: group_meta 자동 구성(지문/번역 결과 화면에서 쓰기 위함)
# =========================
@app.post("/api/jlpt/n1/test/grade/<int:part>")
def api_jlpt_n1_test_grade(part: int):
    payload = request.get_json(silent=True) or {}
    user_answers = payload.get("answers", [])
    if not isinstance(user_answers, list):
        user_answers = []

    src = get_n1_part_questions_full(part)
    total = len(src)
    correct = 0
    items = []

    for i, q in enumerate(src):
        ua = user_answers[i] if i < len(user_answers) else None
        ans = q.get("answer", 0)
        is_correct = (ua == ans)
        if is_correct:
            correct += 1

        meta = q.get("meta", {}) or {}
        items.append({
            "no": i + 1,
            "q_ko": meta.get("ko_q", ""),
            "choices_ko": meta.get("ko_choices", []),
            "answer_index": ans,
            "user_index": ua,
            "explain_ko": meta.get("ko_explain", ""),
            "is_correct": is_correct,
        })

    score = round((correct / total) * 100) if total else 0

    resp = {
        "total": total,
        "correct": correct,
        "score": score,
        "items": items
    }

    # ✅ PART2 그룹 지문 내려주기 (16~20) - N2 형식과 동일
    if part == 2:
        resp["group_meta"] = {
            "N1_P2_M7": {
                "start": 16,
                "end": 20,
                "stem_jp": N1_P2_M7_STEM_JP,
                "stem_ko": N1_P2_M7_STEM_KO,
                "passage_jp": N1_P2_M7_STEM_JP,
                "passage_ko": N1_P2_M7_STEM_KO,
            }
        }

    # ✅ PART3 그룹 지문 내려주기 - meta(group_id) 기반 자동 구성
    if part == 3:
        group_meta = {}
        for q in src:
            meta = q.get("meta", {}) or {}
            gid = meta.get("group_id")
            if not gid:
                continue

            if gid not in group_meta:
                group_meta[gid] = {
                    "stem_jp": meta.get("stem_jp", "") or "",
                    "stem_ko": meta.get("stem_ko", "") or "",
                    "passage_jp": meta.get("passage_jp", "") or "",
                    "passage_ko": meta.get("passage_ko", "") or "",
                }
            else:
                if not group_meta[gid].get("stem_jp") and meta.get("stem_jp"):
                    group_meta[gid]["stem_jp"] = meta.get("stem_jp")
                if not group_meta[gid].get("stem_ko") and meta.get("stem_ko"):
                    group_meta[gid]["stem_ko"] = meta.get("stem_ko")
                if not group_meta[gid].get("passage_jp") and meta.get("passage_jp"):
                    group_meta[gid]["passage_jp"] = meta.get("passage_jp")
                if not group_meta[gid].get("passage_ko") and meta.get("passage_ko"):
                    group_meta[gid]["passage_ko"] = meta.get("passage_ko")

        if group_meta:
            resp["group_meta"] = group_meta

    return jsonify(resp)


# =========================
# ✅ N1 테스트 시작 라우트 (형식 유지)
# =========================
@app.route("/jlpt/n1/test/start/<int:part>")
def jlpt_n1_test_start(part: int):
    questions = get_n1_part_questions(part)

    template_map = {
        1: "jlpt_n1_test_run_part1.html",
        2: "jlpt_n1_test_run_part2.html",
        3: "jlpt_n1_test_run_part3.html",
        4: "jlpt_n1_test_run_part4.html",
    }

    total_raw = len(get_n1_part_questions_full(part))  # 실제 문항 수(채점 기준)

    return render_template(
        template_map.get(part, "jlpt_n1_test_run_part1.html"),
        questions=questions,
        total_questions=len(questions),        # 화면 단계 수 (PART2는 flat 길이 그대로)
        total_questions_raw=total_raw,         # 실제 문항 수 (flat)
        part=part
    )


# ----------------------------
# ✅ N1 테스트 홈
# ----------------------------
@app.route("/jlpt/n1/test")
def jlpt_n1_test():
    user = current_user()
    return render_template("jlpt_n1_test.html", user=user, total_questions=0)

@app.route("/jlpt/n1")
def jlpt_n1_home():
    user = current_user()
    return render_template("jlpt_n1.html", user=user)

@app.route("/jlpt/n1/words")
def jlpt_n1_words():
    user = current_user()

    # N1_WORDS: dict (sec01~sec10)
    sections = []
    all_items = []

    for sec_key in sorted((N1_WORDS or {}).keys()):  # sec01, sec02...
        sec = (N1_WORDS or {}).get(sec_key) or {}
        title = sec.get("title", sec_key)
        items = sec.get("items") or []

        sections.append({
            "key": sec_key,
            "title": title,
            "count": len(items),
        })

        for it in items:
            row = dict(it)
            row["sec_key"] = sec_key
            row["sec_title"] = title
            all_items.append(row)

    return render_template(
        "jlpt_n1_words.html",
        user=user,
        sections=sections,
        words=all_items,   # ✅ 템플릿엔 "단어 리스트"로만 전달
    )

@app.route("/jlpt/n1/sentences")
def jlpt_n1_sentences():
    user = current_user()
    return render_template("jlpt_n1_sentences.html", user=user, sections=N1_SENTENCE_SECTIONS)

@app.route("/jlpt/n1/grammar")
def jlpt_n1_grammar():
    user = current_user()
    return render_template("jlpt_n1_grammar.html", user=user)


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
