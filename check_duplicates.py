from collections import defaultdict
from meaning_data import MEANING_ITEMS

dup = defaultdict(list)

for i, item in enumerate(MEANING_ITEMS, start=1):
    yomi = (item.get("yomi") or "").strip()
    if yomi:
        dup[yomi].append({
            "index": i,
            "slug": item.get("slug", ""),
            "jp": item.get("jp", ""),
            "ko": item.get("ko", "")
        })

found = False

for yomi, items in dup.items():
    if len(items) > 1:
        found = True
        print(f"\n[yomi 중복] {yomi} ({len(items)}개)")
        for x in items:
            print(f"  - #{x['index']} | slug={x['slug']} | jp={x['jp']} | ko={x['ko']}")

if not found:
    print("중복된 yomi가 없습니다.")