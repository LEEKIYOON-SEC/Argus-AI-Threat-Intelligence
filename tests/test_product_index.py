#!/usr/bin/env python3
"""영향 제품 인덱스 — 검색이 '내가 쓰는 제품'을 놓치지 않는지.

    python3 tests/test_product_index.py

왜 있나: 대시보드는 영향 제품을 3개만 싣고 있었다. 실측(2026-09-01, 664건)으로
CVE 의 51.9%가 3개를 넘고 **전체 제품 항목의 71%가 잘려 나갔다.** 그 상태에서는
검색이 거짓말을 한다 — CVE-2026-14164 는 Red Hat 제품 14개에 영향을 주는데
OpenShift 는 7번째라 'OpenShift' 로 검색하면 나오지 않았다.

전량을 그대로 실으면 cves.json 에 12.3MB 가 더 붙는다(이미 22.7MB). 그런데 제품
이름은 지독하게 반복돼서(항목 4,653개 → 고유 이름 321개) 사전으로 접으면 1.6MB 다.
그래서 이름을 한 번만 담고 CVE 는 번호만 참조하는 별도 파일로 뺐다.

여기서 지키는 계약은 둘이다.
  · 왕복(encode → decode)에서 제품이 하나도 사라지지 않는다
  · 사전이 실제로 접힌다 (안 접히면 파일 크기 전제가 무너진다)
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

if importlib.util.find_spec("supabase") is None:
    print("supabase 미설치 — 이 검사는 건너뜁니다 (pip install -r requirements.txt)")
    sys.exit(0)

for _k in ("GH_TOKEN", "SUPABASE_URL", "SUPABASE_KEY", "SLACK_WEBHOOK_URL", "GEMINI_API_KEY"):
    os.environ.setdefault(_k, "test")

_spec = importlib.util.spec_from_file_location(
    "export_dashboard_data", os.path.join(ROOT, "src", "export_dashboard_data.py"))
edd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(edd)


def rh(product, versions="정보 없음"):
    return {"vendor": "Red Hat", "product": product, "versions": versions}


# 실제 CVE-2026-14164 의 모양 (Red Hat 이 스트림마다 한 줄씩 낸다)
BIG = [rh("Red Hat Enterprise Linux 10"), rh("Red Hat Enterprise Linux 10.0 Extended Update Support"),
       rh("Red Hat Enterprise Linux 9"), rh("Red Hat Enterprise Linux 9.2 Update Services for SAP Solutions"),
       rh("Red Hat Enterprise Linux 9.4 Update Services for SAP Solutions"),
       rh("Red Hat Enterprise Linux 9.6 Extended Update Support"),
       rh("Red Hat OpenShift Container Platform 4.22"), rh("Red Hat Discovery 2"),
       rh("Red Hat Hardened Images"), rh("Red Hat Update Infrastructure 5")]

ENTRIES = [
    {"id": "CVE-2026-14164", "affected": BIG},
    {"id": "CVE-2026-0001", "affected": [{"vendor": "Acme", "product": "Gateway", "versions": "< 2.0"}]},
    {"id": "CVE-2026-0002", "affected": []},
    # 이름이 겹치는 건 — 사전이 접히는지 보는 표본
    {"id": "CVE-2026-0003", "affected": [rh("Red Hat Enterprise Linux 9"), rh("Red Hat Discovery 2")]},
]


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def main() -> int:
    failures = []
    index = edd.build_product_index(ENTRIES)
    back = edd.decode_product_index(index)

    print("── 왕복에서 제품이 사라지지 않는다 ──")
    for e in ENTRIES:
        want = e["affected"]
        got = back.get(e["id"], [])
        check(len(got) == len(want), f"{e['id']}: {len(want)}개 → {len(got)}개", failures)
        for a, b in zip(want, got):
            if (a["vendor"], a["product"], a["versions"]) != (b["vendor"], b["product"], b["versions"]):
                check(False, f"{e['id']}: {a['product']} 가 {b['product']} 로 바뀜", failures)
                break

    print("\n── 예전 상한 3 이었다면 못 찾았을 제품 ──")
    deep = [a["product"] for a in back["CVE-2026-14164"]][3:]
    for name in ("SAP Solutions", "OpenShift", "Update Infrastructure"):
        found = any(name.lower() in p.lower() for p in deep)
        check(found, f"'{name}' 은 4번째 이후에 있다 — 이제 인덱스에 있다", failures)

    print("\n── 사전이 실제로 접힌다 ──")
    items = sum(len(v) for v in index["map"].values())
    check(len(index["products"]) < items,
          f"제품 항목 {items}개 → 고유 이름 {len(index['products'])}개", failures)
    check("Red Hat" in index["vendors"] and len(index["vendors"]) == 2,
          f"벤더는 2종만 담긴다 (={index['vendors']})", failures)

    print("\n── 빈 목록 / 깨진 입력 ──")
    check("CVE-2026-0002" not in index["map"], "영향 제품이 없으면 인덱스에 안 넣는다", failures)
    check(edd.decode_product_index({}) == {}, "빈 인덱스는 빈 dict", failures)
    check(edd.decode_product_index({"map": {"X": [[99, 99, 99]]}}) == {
        "X": [{"vendor": "", "product": "", "versions": ""}]},
        "범위 밖 번호는 빈 문자열로 (터지지 않는다)", failures)

    print("\n── JSON 직렬화 ──")
    check(json.loads(json.dumps(index, ensure_ascii=False))["map"] == index["map"],
          "그대로 직렬화된다", failures)

    kev_fallback(failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


def kev_fallback(failures):
    # 옛날 CVE 레코드에는 affected 블록이 없어 vendor/product 가 'n/a' 다. 실측으로
    # CISA KEV 무작위 120건 중 39건(32%)이 그랬다 — 하필 지금 악용 중인 것들이라
    # 제품 이름으로 찾을 수가 없었다(제목에만 있었다). CISA 가 KEV 에 붙여 둔
    # vendorProject/product 는 사람이 정리한 값이라 그걸 폴백으로 쓴다.
    from collector import Collector

    col = Collector()
    col.kev_product = {
        "CVE-2015-5119": ("Adobe", "Flash Player"),
        "CVE-2013-5065": ("Microsoft", "Windows"),
        "CVE-2026-0001": ("Acme", "Gateway"),
    }

    print("\n── 제품명이 없는 KEV 를 CISA 표기로 메운다 ──")
    cases = (
        ("affected 가 n/a 뿐", {"id": "CVE-2015-5119",
                              "affected": [{"vendor": "n/a", "product": "n/a", "versions": "모든 버전"}]},
         "Adobe", "Flash Player"),
        ("affected 가 아예 없음", {"id": "CVE-2013-5065", "affected": []},
         "Microsoft", "Windows"),
        ("affected 가 Unknown", {"id": "CVE-2026-0001",
                                "affected": [{"vendor": "Unknown", "product": "Unknown", "versions": ""}]},
         "Acme", "Gateway"),
    )
    for desc, data, want_v, want_p in cases:
        col.fill_product_from_kev(data)
        got = (data["affected"] or [{}])[0]
        ok = got.get("vendor") == want_v and got.get("product") == want_p
        check(ok, f"{desc} → {got.get('vendor')} / {got.get('product')}", failures)

    print("\n── 레코드가 멀쩡하면 손대지 않는다 (그쪽이 더 상세하다) ──")
    real = {"id": "CVE-2015-5119",
            "affected": [{"vendor": "Adobe", "product": "Adobe Flash Player Desktop Runtime",
                          "versions": "18.0.0.194 이전"}]}
    col.fill_product_from_kev(real)
    check(len(real["affected"]) == 1
          and real["affected"][0]["product"] == "Adobe Flash Player Desktop Runtime",
          "이미 있는 상세한 제품명을 KEV 표기로 덮어쓰지 않는다", failures)

    print("\n── KEV 가 아니면 아무것도 하지 않는다 ──")
    other = {"id": "CVE-2026-9999", "affected": [{"vendor": "n/a", "product": "n/a", "versions": ""}]}
    col.fill_product_from_kev(other)
    check(other["affected"][0]["product"] == "n/a",
          "KEV 목록에 없는 CVE 는 그대로 둔다", failures)

    print("\n── 버전 정보는 살린다 ──")
    keep = {"id": "CVE-2015-5119",
            "affected": [{"vendor": "n/a", "product": "n/a", "versions": "18.0.0.194 이전",
                          "patch_version": "18.0.0.194"}]}
    col.fill_product_from_kev(keep)
    check(keep["affected"][0]["versions"] == "18.0.0.194 이전"
          and keep["affected"][0]["patch_version"] == "18.0.0.194",
          "제품명만 갈아끼우고 버전·패치 정보는 그대로 둔다", failures)


if __name__ == "__main__":
    sys.exit(main())
