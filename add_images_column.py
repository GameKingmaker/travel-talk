import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "phrases.db")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

try:
    cur.execute("""
        ALTER TABLE board_posts
        ADD COLUMN images_json TEXT
    """)
    print("✅ images_json 컬럼 추가 완료")
except Exception as e:
    print("⚠️ 이미 있거나 실패:", e)

conn.commit()
conn.close()
