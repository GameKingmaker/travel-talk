from collections import Counter
from kanji_data import KANJI_DATA

print("===== 일본어 한자 데이터 검사 시작 =====\n")

# -----------------------
# 1. 총 개수 검사
# -----------------------
total = len(KANJI_DATA)
print(f"총 한자 개수: {total}")

if total != 2136:
    print("⚠️ 경고: 총 개수가 2136이 아닙니다.\n")

# -----------------------
# 2. slug 중복 검사
# -----------------------
slugs = [item["slug"] for item in KANJI_DATA]
slug_counter = Counter(slugs)

duplicate_slugs = [s for s, c in slug_counter.items() if c > 1]

if duplicate_slugs:
    print("\n❌ slug 중복 발견:")
    for s in duplicate_slugs:
        print(f" - {s}")
else:
    print("✔ slug 중복 없음")

# -----------------------
# 3. 한자 중복 검사
# -----------------------
kanji_list = [item["kanji"] for item in KANJI_DATA]
kanji_counter = Counter(kanji_list)

duplicate_kanji = [k for k, c in kanji_counter.items() if c > 1]

if duplicate_kanji:
    print("\n❌ 한자 중복 발견:")
    for k in duplicate_kanji:
        print(f" - {k}")
else:
    print("✔ 한자 중복 없음")

# -----------------------
# 4. 레벨 개수 검사
# -----------------------
levels = [item["level"] for item in KANJI_DATA]
level_counter = Counter(levels)

print("\n레벨별 개수:")
for level in ["N5", "N4", "N3", "N2", "N1"]:
    print(f"{level}: {level_counter.get(level, 0)}")

# -----------------------
# 5. related slug 검사
# -----------------------
slug_set = set(slugs)

missing_related = []

for item in KANJI_DATA:
    for rel in item.get("related", []):
        if rel not in slug_set:
            missing_related.append((item["slug"], rel))

if missing_related:
    print("\n❌ 존재하지 않는 related slug:")
    for base, rel in missing_related:
        print(f"{base} -> {rel}")
else:
    print("\n✔ related slug 오류 없음")

print("\n===== 검사 완료 =====")