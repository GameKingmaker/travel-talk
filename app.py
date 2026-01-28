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

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, abort
)
from werkzeug.security import generate_password_hash, check_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "phrases.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "a9f3c1f8f2d64b7f9f2c7e1a5d8b3c2f__CHANGE_ME_ONCE"


UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}

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
    conn = sqlite3.connect(DB_PATH)
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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
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
    {"jp": "これを探しています。", "pron": "코레오 사가시테이마스", "ko": "이거 찾고 있어요."}
]


Item = Tuple[str, str, str]

SITUATIONS: Dict[str, Dict[str, Any]] = {
    # 1) 공항
    "airport": {
        "title": "공항",
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
        "title": "호텔",
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
                ],
            },
            "problem": {
                "title": "요청/문제",
                "items": [
                    ("タオルを追加してください。", "타오루오 츠이카시테 쿠다사이", "수건 추가해주세요."),
                    ("部屋の掃除をお願いします。", "헤야노 소-지오 오네가이시마스", "방 청소 부탁해요."),
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
        "title": "교통",
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
        "title": "음식점",
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
        "title": "관광",
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
        "title": "카페",
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
        "title": "편의점/마트",
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
        "title": "응급/병원",
        "subs": {
            "pharmacy": {
                "title": "약국",
                "items": [
                    ("薬局はどこですか？", "야쿠쿄쿠와 도코데스카", "약국은 어디예요?"),
                    ("頭が痛いです。", "아타마가 이타이데스", "머리가 아파요."),
                    ("お腹が痛いです。", "오나카가 이타이데스", "배가 아파요."),
                    ("熱があります。", "네츠가 아리마스", "열이 있어요."),
                    ("風邪薬はありますか？", "카제구스리와 아리마스카", "감기약 있나요?"),
                    ("酔い止めはありますか？", "요이도메와 아리마스카", "멀미약 있나요?"),
                    ("絆創膏はありますか？", "반소-코-와 아리마스카", "밴드 있나요?"),
                    ("アレルギーがあります。", "아레루기-가 아리마스", "알레르기가 있어요."),
                    ("英語は話せますか？", "에-고와 하나세마스카", "영어 하실 수 있나요?"),
                    ("助けてください。", "타스케테 쿠다사이", "도와주세요."),
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
        "title": "도움요청",
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
                ],
            },
        },
    },

    # 10) 통신/인터넷
    "internet": {
        "title": "통신/인터넷",
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
        "title": "쇼핑/백화점",
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
                ],
            },
            "cosmetics": {
                "title": "화장품/면세",
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
                ],
            },
        },
    },

    # ---------------------------
    #  추가 12) 길찾기/관광안내
    # ---------------------------
    "directions": {
        "title": "길찾기/관광안내",
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
        "title": "버스/정류장",
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
        "title": "경찰/분실신고",
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
        "title": "놀이공원",
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
        "title": "영화관",
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
        "title": "보관/코인락커",
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
        "title": "세탁/코인세탁",
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
        "title": "술집/이자카야",
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
        "title": "체크아웃/이동",
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
        "title": "여행 유형별 회화",
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
        "title": "길찾기/소요시간",
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
                    ("まっすぐ行けばいいですか？", "맛스구 이케바 이이데스카", "곧장 가면 되나요?")
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
        "title": "예약변경/취소",
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
        "title": "음식 요청/제한",
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
        "title": "문제/클레임",
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
        "title": "사진 요청 심화",
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
        "title": "현지 추천",
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
        "title": "날씨 대응",
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
            ],
        },

        # 2) 시간
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
                ("1分", "잇푼", "1분"),
                ("10分", "쥬푼", "10분"),
                ("1時間", "잇지칸", "1시간"),
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

        # 24) 자연/관광지(단어)
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
        # 30) 아이/가족 여행
        "family_travel": {
            "title": "아이/가족 여행",
            "items": [
                ("子供", "코도모", "아이"),
                ("ベビーカー", "베비-카-", "유모차"),
                ("おむつ", "오무츠", "기저귀"),
                ("病院", "뵤-인", "병원"),
                ("薬", "쿠스리", "약"),
                ("椅子", "이스", "의자"),
                ("危ない", "아부나이", "위험하다"),
                ("保護", "호고", "보호"),
                ("迷子", "마이고", "미아"),
                ("応急", "오-큐-", "응급"),
            ],
        },
        # 31) 앱/전자/QR
        "digital_qr": {
            "title": "앱/전자/QR",
            "items": [
                ("QRコード", "큐아르 코-도", "QR 코드"),
                ("Wi-Fi", "와이파이", "와이파이"),
                ("パスワード", "파스와-도", "비밀번호"),
                ("接続", "세츠조쿠", "연결"),
                ("充電", "쥬-덴", "충전"),
                ("電池", "덴치", "배터리"),
                ("地図", "치즈", "지도"),
                ("位置", "이치", "위치"),
                ("翻訳", "혼야쿠", "번역"),
                ("検索", "켄사쿠", "검색"),
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
        # 40) 교통(심화)
        "transport_plus": {
            "title": "교통(심화)",
            "items": [
                ("乗り換え", "노리카에", "환승"),
                ("次", "츠기", "다음"),
                ("次の駅", "츠기노에키", "다음 역"),
                ("終点", "슈-텐", "종점"),
                ("方面", "호-멘", "~방면"),
                ("急行", "큐-코-", "급행"),
                ("快速", "카이소쿠", "쾌속"),
                ("各駅停車", "카쿠에키테이샤", "완행"),
                ("何番線", "난반센", "몇 번 플랫폼"),
                ("発車", "핫샤", "출발"),
                ("到着", "토-챠쿠", "도착"),
                ("遅延", "치엔", "지연"),
                ("運休", "운큐-", "운행중지"),
                ("改札口", "카이사츠구치", "개찰구"),
                ("乗り場", "노리바", "타는 곳"),
                ("入口", "이리구치", "입구"),
                ("出口", "데구치", "출구"),
                ("時刻表", "지코쿠효-", "시간표"),
                ("料金", "료-킨", "요금"),
                ("片道", "카타미치", "편도"),
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

    return render_template(
        "mypage.html",
        user=user,
        grade=grade,
        score=score,   # ✅ 템플릿에서 보여주고 싶으면 사용
        post_cnt=post_cnt,
        comment_cnt=comment_cnt,
        received_cnt=received_cnt,
        unread_cnt=unread_cnt,
        recent=recent,
    )


ADMIN_USERNAME = "cjswoaostk"

def is_admin(user):
    return bool(user and user.get("username") == ADMIN_USERNAME)

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

@app.post("/quiz/dialog/check")
def dialog_typing_check():
    user_input = request.form.get("user_input", "")
    answer_pron = request.form.get("answer_pron", "")
    answer_jp = request.form.get("answer_jp", "")
    answer_ko = request.form.get("answer_ko", "")

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
        # DB 문제나 초기화 문제여도 홈은 무조건 떠야 함
        daily = {"jp": "", "pron": "", "ko": ""}
    return render_template("index.html", user=user, daily=daily)

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

    return render_template(
        "words_categories.html",
        user=user,
        categories=categories
    )


@app.route("/words/<cat_key>")
def words_detail(cat_key):
    user = current_user()

    cat = (WORDS or {}).get(cat_key)
    if not cat:
        return render_template("words_detail.html", user=user, title="없음", cat_key=cat_key, rows=[], fav_jp_set=set())

    title = cat.get("title", cat_key)
    rows = cat.get("items", [])

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

    return render_template(
        "words_detail.html",
        user=user,
        title=title,
        cat_key=cat_key,
        rows=rows,
        fav_jp_set=fav_jp_set
    )



@app.route("/situations")
def situations():
    user = current_user()
    return render_template(
        "situation.html",
        user=user,
        situations=SITUATIONS  # ← 가공 ❌, 그대로
    )


@app.route("/situations/<cat>/<sub>")
def situation_detail(cat: str, sub: str):
    user = current_user()

    cat_obj = SITUATIONS.get(cat)
    if not cat_obj:
        abort(404)

    sub_obj = cat_obj["subs"].get(sub)
    if not sub_obj:
        abort(404)

    fav_set = set()
    if user:
        conn = db()
        rows = conn.execute(
            "SELECT phrase_key FROM favorites WHERE user_id=?",
            (user["id"],),
        ).fetchall()
        conn.close()
        fav_set = {r["phrase_key"] for r in rows}

    items = []
    for i, item in enumerate(sub_obj.get("items", []), start=1):
        # item이 (jp, pron, ko) 또는 (jp, pron, ko, source)여도 OK
        jp, pron, ko = item[:3]
        phrase_key = f"{cat}:{sub}:{i}"
        items.append({
            "phrase_key": phrase_key,
            "jp": jp,
            "pron": pron,
            "ko": ko,
            "is_fav": (phrase_key in fav_set),
        })

    return render_template(
        "situation_detail.html",
        user=user,
        cat=cat,
        sub=sub,
        cat_title=cat_obj["title"],
        sub_title=sub_obj["title"],
        items=items,
    )


@app.route("/quiz")
def quiz():
    user = current_user()
    return render_template("quiz.html", user=user)

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


@app.post("/api/word_game/submit_score")
def api_word_game_submit_score():
    user = current_user()
    if not user:
        return jsonify(ok=False, error="login_required"), 401

    data = request.get_json(silent=True) or {}
    score = int(data.get("score") or 0)
    if score < 0:
        score = 0

    uid = user["id"]
    conn = db()
    try:
        row = conn.execute(
            "SELECT best_word_score FROM users WHERE id=?",
            (uid,)
        ).fetchone()
        best = int(row["best_word_score"] or 0) if row else 0

        updated = False
        if score > best:
            conn.execute(
                "UPDATE users SET best_word_score=?, best_word_score_at=? WHERE id=?",
                (score, kst_now_iso(), uid)
            )
            conn.commit()
            best = score
            updated = True

        return jsonify(ok=True, updated=updated, best=best)
    finally:
        conn.close()


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

    # (선택) 조회수 증가가 있다면 여기서 실행 (너 코드에 이미 있으면 유지)
    # conn.execute("UPDATE board_posts SET views = views + 1 WHERE id=?", (post_id,))
    # conn.commit()

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
            return render_template("register.html", user=None, form=form, errors=errors)

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

        if not u or not check_password_hash(u["password_hash"], password):
            conn.close()
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
            return redirect(url_for("login"))

        session["user_id"] = u["id"]

        mark_attendance(u["id"])  # ✅ 여기 추가 (로그인 성공 시 1일 1회 출석)

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


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("로그아웃 완료!", "success")
    return redirect(url_for("index"))


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
        u = conn.execute(
            "SELECT * FROM users WHERE username=? AND email=?",
            (username, email),
        ).fetchone()

        if not u:
            conn.close()
            flash("일치하는 계정을 찾을 수 없습니다.", "error")
            return redirect(url_for("forgot_password"))

        code = f"{random.randint(0, 999999):06d}"
        code_hash = generate_password_hash(code)

        now = datetime.now(timezone.utc).astimezone(_KST)
        expires_at = (now + timedelta(minutes=10)).isoformat()

        conn.execute(
            "INSERT INTO password_resets(username, email, code_hash, expires_at, created_at) VALUES(?,?,?,?,?)",
            (username, email, code_hash, expires_at, now.isoformat()),
        )
        conn.commit()
        conn.close()

        print(f"[RESET CODE] username={username} email={email} code={code} (expires 10m)")

        flash("인증코드를 발급했습니다. (개발 단계: 서버 콘솔에 표시)", "success")
        return redirect(url_for("reset_password"))

    return render_template("forgot.html", user=None)


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
        row = conn.execute(
            """
            SELECT * FROM password_resets
            WHERE username=? AND email=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (username, email),
        ).fetchone()

        if not row:
            conn.close()
            flash("인증 요청 기록이 없습니다. 먼저 인증코드를 받아주세요.", "error")
            return redirect(url_for("forgot_password"))

        expires_at = datetime.fromisoformat(row["expires_at"])
        now = datetime.now(timezone.utc).astimezone(_KST)
        if now > expires_at:
            conn.close()
            flash("인증코드가 만료되었습니다. 다시 요청해주세요.", "error")
            return redirect(url_for("forgot_password"))

        if not check_password_hash(row["code_hash"], code):
            conn.close()
            flash("인증코드가 올바르지 않습니다.", "error")
            return redirect(url_for("reset_password"))

        pw_hash = generate_password_hash(new_password)
        conn.execute(
            "UPDATE users SET password_hash=? WHERE username=? AND email=?",
            (pw_hash, username, email),
        )
        conn.commit()
        conn.close()

        flash("비밀번호가 변경되었습니다. 로그인해주세요.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", user=None)

from sqlite3 import IntegrityError

@app.route("/word_game/ranking")
def word_game_ranking():
    return redirect(url_for("word_game_ranking_page"))

@app.get("/api/word_game/rankings")
def api_word_game_rankings():
    try:
        conn = db()
        cur = conn.cursor()

        # 최고점수 0은 제외
        rows = cur.execute(
            """
            SELECT nickname, best_word_score, best_word_score_at
            FROM users
            WHERE COALESCE(best_word_score, 0) > 0
            ORDER BY best_word_score DESC, COALESCE(best_word_score_at, '') ASC
            LIMIT 50
            """
        ).fetchall()

        conn.close()

        items = []
        for r in rows:
            # row가 sqlite Row일 수도/튜플일 수도 있어서 둘 다 대응
            nickname = r["nickname"] if isinstance(r, dict) or hasattr(r, "keys") else r[0]
            best = r["best_word_score"] if isinstance(r, dict) or hasattr(r, "keys") else r[1]
            at = r["best_word_score_at"] if isinstance(r, dict) or hasattr(r, "keys") else r[2]

            items.append({
                "nickname": nickname,
                "score": int(best or 0),
                "at": at or ""
            })

        return jsonify({"ok": True, "items": items})

    except Exception as e:
        try:
            conn.close()
        except Exception:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

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
def board_upvote(post_id: int):
    conn = db()
    try:
        post = conn.execute(
            "SELECT id, COALESCE(is_notice,0) AS is_notice, COALESCE(upvotes,0) AS upvotes FROM board_posts WHERE id=?",
            (post_id,),
        ).fetchone()

        if not post:
            return jsonify(ok=False, msg="게시글이 없습니다."), 404

        if post["is_notice"] == 1:
            return jsonify(ok=False, msg="공지글은 추천할 수 없어요.", upvotes=post["upvotes"]), 403

        # 여기부터는 기존 업보트 로직 그대로
        conn.execute("UPDATE board_posts SET upvotes = COALESCE(upvotes,0) + 1 WHERE id=?", (post_id,))
        conn.commit()

        row = conn.execute(
            "SELECT COALESCE(upvotes,0) AS upvotes FROM board_posts WHERE id=?",
            (post_id,),
        ).fetchone()

        return jsonify(ok=True, msg="추천 완료!", upvotes=row["upvotes"])

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

    return render_template(
        "note.html",
        user=user,
        fav_items=fav_items,
        word_fav_items=word_fav_items,
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
        SELECT nickname, username, best_word_score, best_word_score_at
        FROM users
        WHERE best_word_score IS NOT NULL
        ORDER BY best_word_score DESC, best_word_score_at ASC
        LIMIT 50
    """).fetchall()
    conn.close()

    items = []
    rank = 0
    for r in rows:
        rank += 1
        items.append({
            "rank": rank,
            "nickname": r["nickname"],
            "username": r["username"],
            "score": int(r["best_word_score"] or 0),
            "at": r["best_word_score_at"]
        })
    return jsonify({"ok": True, "items": items})

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

        # 작성글 수
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM board_posts WHERE user_id=?",
            (u["id"],),
        ).fetchone()
        post_cnt = int(row["cnt"] or 0) if row else 0

        # 작성댓글 수
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM board_comments WHERE user_id=?",
            (u["id"],),
        ).fetchone()
        comment_cnt = int(row["cnt"] or 0) if row else 0

        # 계급 처리
        if u["nickname"] == "SW" or u["id"] == 1:
            grade = "총관리자 👑"
        else:
            grade = (u.get("custom_grade") or "").strip() or "일반"



        # 최근접속일: last_seen_at 우선, 없으면 last_login_at
        last_seen = u["last_seen_at"] or u["last_login_at"] or ""

        return jsonify(
            ok=True,
            member={
                "nickname": u["nickname"],
                "username": u["username"],   # (아이디)
                "grade": grade,
                "post_cnt": post_cnt,
                "comment_cnt": comment_cnt,
                "last_seen_at": last_seen,
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
        "explain_ko": "대화에서 사진을 찍어달라는 표현..."
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
    "id": 8,
    "title": "- 8번문제 -",
    "image": "dialog_quiz/park_bench_seat.png",

    "lines": [
        {
            "role": "남자",
            "jp": "すみません、ここに座ってもいいですか？",
            "pron": "스미마센, 코코니 스왓테모 이이데스카",
            "ko": "저기 실례합니다, 여기 앉아도 될까요?"
        },
        {
            "role": "남자",
            "jp": "少し休みたいんです。",
            "pron": "스코시 야스미타인데스",
            "ko": "조금 쉬고 싶어서요."
        },
        {
            "role": "남자",
            "jp": "ありがとうございます。",
            "pron": "아리가토- 고자이마스",
            "ko": "감사합니다."
        }
    ],

    "choices": [
        "공원에서 자리를 비켜 달라고 요청하고 있다.",
        "벤치에 앉아도 되는지 허락을 구하고 있다.",
        "길을 물어보고 있다.",
        "책을 빌려달라고 부탁하고 있다.",
    ],

    "answer": 2,

    "explain_ko": "‘ここに座ってもいいですか？’는 상대방에게 자리에 앉아도 되는지 정중하게 허락을 구할 때 쓰는 표현입니다."
    },
    {
    "id": 8,
    "title": "- 8번문제 -",
    "image": "dialog_quiz/park_bench_seat.png",

    "lines": [
        {
            "role": "남자",
            "jp": "すみません、ここに座ってもいいですか？",
            "pron": "스미마센, 코코니 스왓테모 이이데스카",
            "ko": "저기 실례합니다, 여기 앉아도 될까요?"
        },
        {
            "role": "남자",
            "jp": "少し休みたいんです。",
            "pron": "스코시 야스미타인데스",
            "ko": "조금 쉬고 싶어서요."
        },
        {
            "role": "남자",
            "jp": "ありがとうございます。",
            "pron": "아리가토- 고자이마스",
            "ko": "감사합니다."
        }
    ],

    "choices": [
        "공원에서 자리를 비켜 달라고 요청하고 있다.",
        "벤치에 앉아도 되는지 허락을 구하고 있다.",
        "길을 물어보고 있다.",
        "책을 빌려달라고 부탁하고 있다.",
    ],

    "answer": 2,

    "explain_ko": "‘ここに座ってもいいですか？’는 상대방에게 자리에 앉아도 되는지 정중하게 허락을 구할 때 쓰는 표현입니다."
    },
    {
        "id": 9,
        "title": "- 9번문제 -",
        "image": "dialog_quiz/amusement_ticket.png",

        "lines": [
            {
                "role": "남자",
                "jp": "すみません、チケットはどこで買えますか？",
                "pron": "스미마센, 치켓토와 도코데 카에마스카",
                "ko": "저기 실례합니다, 티켓은 어디서 살 수 있나요?"
            },
            {
                "role": "남자",
                "jp": "初めて来たので分からなくて。",
                "pron": "하지메테 키타노데 와카라나쿠테",
                "ko": "처음 와서 잘 몰라서요."
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
            "화장실 위치를 물어보고 있다.",
        ],

        "answer": 3,

        "explain_ko": "‘チケットはどこで買えますか？’는 티켓을 어디에서 살 수 있는지 묻는 표현으로, 놀이공원 입장 상황과 잘 맞는 질문입니다."
    },
    {
        "id": 10,
        "title": "- 10번문제 -",
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
        "id": 11,
        "title": "- 11번문제 -",
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
        "id": 12,
        "title": "- 12번문제 -",
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
        "id": 13,
        "title": "- 13번문제 -",
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
        "id": 14,
        "title": "- 14번문제 -",
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
        "id": 15,
        "title": "- 15번문제 -",
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


]
@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory(".", "sitemap.xml", mimetype="application/xml")

@app.get("/quiz/dialog")
def quiz_dialog_list():
    user = current_user()
    quizzes = [{"id": q["id"], "title": q["title"]} for q in DIALOG_SCENE_QUIZZES]
    return render_template("dialog_quiz_list.html", user=user, quizzes=quizzes)


@app.get("/quiz/dialog/<int:quiz_id>")
def dialog_quiz_play(quiz_id: int):
    user = current_user()
    q = next((x for x in DIALOG_SCENE_QUIZZES if x["id"] == quiz_id), None)
    if not q:
        abort(404)
    return render_template("dialog_quiz_play.html", user=user, quiz=q)
@app.post("/quiz/dialog/check")
def dialog_quiz_check():
    user = current_user()
    quiz_id = request.form.get("quiz_id", type=int)
    choice = request.form.get("choice", type=int)

    q = next((x for x in DIALOG_SCENE_QUIZZES if x["id"] == quiz_id), None)
    if not q:
        abort(404)

    ok = (choice == q["answer"])
    result = {
        "ok": ok,
        "answer_no": q["answer"],
        "answer_ko": q["answer_ko"],
        "explain_ko": q["explain_ko"],
    }
    return render_template("dialog_quiz_play.html", user=user, quiz=q, result=result)

@app.context_processor
def inject_helpers():
    return {"is_admin": is_admin}

if __name__ == "__main__":
    init_db()
    app.run(debug=True)


