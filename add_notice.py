import sqlite3

conn = sqlite3.connect("phrases.db")
cur = conn.cursor()

try:
    cur.execute("ALTER TABLE board_posts ADD COLUMN is_notice INTEGER DEFAULT 0")
    print("✅ board_posts.is_notice 컬럼 추가 완료")
except Exception as e:
    print("⚠️ 이미 있거나 실패:", e)

conn.commit()
conn.close()
