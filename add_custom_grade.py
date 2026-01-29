import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "phrases.db")

print("DB_PATH =", DB_PATH)
print("DB exists?", os.path.exists(DB_PATH))

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# users 테이블 컬럼 확인
cur.execute("PRAGMA table_info(users)")
cols = [row[1] for row in cur.fetchall()]
print("users columns:", cols)

if "grade" not in cols:
    cur.execute("ALTER TABLE users ADD COLUMN grade TEXT DEFAULT '입문'")
    conn.commit()
    print("✅ grade column added!")
else:
    print("✅ grade column already exists.")

conn.close()
print("Done.")
