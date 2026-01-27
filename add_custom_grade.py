import sqlite3

conn = sqlite3.connect("phrases.db")
cur = conn.cursor()

try:
    cur.execute("ALTER TABLE users ADD COLUMN custom_grade TEXT")
    print("✅ custom_grade 컬럼 추가 완료")
except Exception as e:
    print("⚠️ 에러:", e)

conn.commit()
conn.close()
