#!/usr/bin/env python3
"""
SBOM → assets.json 변환기

"무엇을 지켜야 하는가(자산)"를 먼저 명확히 하는 것이 취약점 관리의 출발점이다.
syft(Linux) 또는 Microsoft sbom-tool(Windows)로 생성한 SBOM에서 소프트웨어
컴포넌트를 추출해 Argus의 감시 대상(assets.json)으로 변환한다.

지원 포맷:
  - CycloneDX JSON (syft -o cyclonedx-json)
  - SPDX JSON       (syft -o spdx-json / Microsoft sbom-tool)

추출 우선순위 (CVE 매칭 정확도 순):
  1) CPE  (cpe:2.3:a:vendor:product:...) → NVD/CVE와 동일 명명 체계라 가장 정확
  2) PURL (pkg:type/namespace/name@ver)  → namespace를 vendor 후보로
  3) name/version만 → product=name, vendor=name (부분일치 매칭이라 대체로 잡힘)

사용 예:
  # 1) 자산 스캔 (사용자 인프라/이미지/프로젝트)
  syft dir:/opt/myapp -o cyclonedx-json > sbom.json
  #   또는 Windows:  sbom-tool generate -b . -bc . -pn app -pv 1.0 ...

  # 2) SBOM → assets.json
  python tools/sbom_to_assets.py sbom.json            # assets.json 새로 생성
  python tools/sbom_to_assets.py sbom.json --merge    # 기존 assets.json에 병합
  python tools/sbom_to_assets.py sbom.json --dry-run  # 미리보기(파일 미기록)
"""
import argparse
import datetime
import json
import re
import sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

# CVE affected에 흔히 등장하는 과다 일반명 — 오탐(모든 CVE 매칭)을 유발해 제외한다.
_NOISE = {
    "test", "tests", "common", "core", "utils", "util", "lib", "libs", "api",
    "json", "yaml", "xml", "http", "client", "server", "app", "application",
    "main", "src", "data", "config", "types", "example", "examples", "demo",
}


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _from_cpe(cpe: str) -> Optional[Tuple[str, str]]:
    """CPE 2.3 또는 2.2에서 (vendor, product) 추출."""
    if not cpe:
        return None
    # cpe:2.3:a:vendor:product:version:...
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor, product = parts[3], parts[4]
        else:
            return None
    # cpe:/a:vendor:product:version
    elif cpe.startswith("cpe:/"):
        parts = cpe[5:].split(":")
        if len(parts) >= 3:
            vendor, product = parts[1], parts[2]
        else:
            return None
    else:
        return None
    vendor, product = _norm(vendor), _norm(product)
    if vendor in ("", "*", "-") or product in ("", "*", "-"):
        return None
    return vendor.replace("\\", ""), product.replace("\\", "")


def _from_purl(purl: str) -> Optional[Tuple[str, str]]:
    """PURL(pkg:type/namespace/name@version)에서 (vendor, product) 추출.
    namespace의 마지막 세그먼트를 vendor 후보로, name을 product로 본다."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]  # qualifiers/subpath 제거
    body = body.split("@", 1)[0]                        # @version 제거
    segs = [unquote(s) for s in body.split("/") if s]
    if len(segs) < 2:
        return None
    # segs[0] = type, 마지막 = name, 중간 = namespace
    name = _norm(segs[-1])
    namespace_last = _norm(segs[-2]) if len(segs) >= 3 else ""
    vendor = namespace_last or name
    # npm scope(@scope)·golang host(github.com) 등 접두 정리
    vendor = vendor.lstrip("@")
    if not name or name in ("", "*", "-"):
        return None
    return vendor, name


def _extract_pair(name: str, cpe: Optional[str], purl: Optional[str]) -> Optional[Tuple[str, str]]:
    """컴포넌트 하나에서 (vendor, product) 결정 — CPE > PURL > name 순."""
    return (_from_cpe(cpe or "")
            or _from_purl(purl or "")
            or ((_norm(name), _norm(name)) if name and _norm(name) not in ("", "*", "-") else None))


def _iter_cyclonedx(doc: Dict):
    """CycloneDX components(중첩 포함) 순회 → (name, cpe, purl)."""
    def walk(comps):
        for c in comps or []:
            # syft는 여러 CPE를 properties/evidence로 넣기도 하지만 우선 표준 cpe 필드 사용
            yield c.get("name", ""), c.get("cpe"), c.get("purl")
            yield from walk(c.get("components"))
    # metadata.component(대상 자체)는 제외, components 목록만
    yield from walk(doc.get("components"))


def _iter_spdx(doc: Dict):
    """SPDX packages 순회 → (name, cpe, purl). externalRefs에서 cpe23Type/purl 추출."""
    for pkg in doc.get("packages", []) or []:
        cpe = purl = None
        for ref in pkg.get("externalRefs", []) or []:
            rtype = (ref.get("referenceType") or "").lower()
            loc = ref.get("referenceLocator") or ""
            if rtype in ("cpe23type", "cpe23") or loc.startswith("cpe:2.3:"):
                cpe = cpe or loc
            elif rtype == "purl" or loc.startswith("pkg:"):
                purl = purl or loc
        yield pkg.get("name", ""), cpe, purl


def detect_and_iter(doc: Dict):
    """SBOM 포맷 자동 감지 후 컴포넌트 반복자 반환."""
    if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
        return "CycloneDX", _iter_cyclonedx(doc)
    if str(doc.get("spdxVersion", "")).upper().startswith("SPDX") or "packages" in doc:
        return "SPDX", _iter_spdx(doc)
    raise ValueError("지원하지 않는 SBOM 포맷 (CycloneDX/SPDX JSON만 지원)")


def sbom_to_rules(doc: Dict, keep_noise: bool = False) -> Tuple[str, List[Dict[str, str]]]:
    """SBOM 문서 → active_rules 목록([{vendor, product}], 중복 제거)."""
    fmt, it = detect_and_iter(doc)
    seen = set()
    rules: List[Dict[str, str]] = []
    for name, cpe, purl in it:
        pair = _extract_pair(name, cpe, purl)
        if not pair:
            continue
        vendor, product = pair
        if not keep_noise and product in _NOISE and vendor in _NOISE:
            continue
        key = (vendor, product)
        if key in seen:
            continue
        seen.add(key)
        rules.append({"vendor": vendor, "product": product})
    rules.sort(key=lambda r: (r["vendor"], r["product"]))
    return fmt, rules


def load_existing(path: str) -> List[Dict[str, str]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("active_rules", [])
        # 전체 감시(*/*)는 구체 자산으로 대체되므로 병합 시 제거
        return [r for r in rules if isinstance(r, dict)
                and not (r.get("vendor") == "*" and r.get("product") == "*")]
    except (OSError, ValueError):
        return []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SBOM(CycloneDX/SPDX) → Argus assets.json 변환")
    ap.add_argument("sbom", help="SBOM JSON 파일 경로 (syft/sbom-tool 출력)")
    ap.add_argument("-o", "--output", default="assets.json", help="출력 파일 (기본: assets.json)")
    ap.add_argument("--merge", action="store_true", help="기존 assets.json active_rules와 병합")
    ap.add_argument("--keep-noise", action="store_true", help="일반명(test/common 등)도 유지")
    ap.add_argument("--dry-run", action="store_true", help="파일 기록 없이 결과만 출력")
    args = ap.parse_args(argv)

    try:
        with open(args.sbom, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        print(f"❌ SBOM 읽기 실패: {e}", file=sys.stderr)
        return 1

    try:
        fmt, rules = sbom_to_rules(doc, keep_noise=args.keep_noise)
    except ValueError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1

    if args.merge:
        existing = load_existing(args.output)
        seen = {(r["vendor"], r["product"]) for r in rules}
        for r in existing:
            if (r.get("vendor"), r.get("product")) not in seen:
                rules.append({"vendor": r["vendor"], "product": r["product"]})
        rules.sort(key=lambda r: (r["vendor"], r["product"]))

    if not rules:
        print("⚠️  추출된 자산이 없습니다. SBOM에 컴포넌트가 있는지 확인하세요.", file=sys.stderr)
        return 1

    out = {
        "_comment": "active_rules의 vendor/product와 매칭되는 CVE만 추적합니다. (* = 전체)",
        "_generated_from": f"{fmt} SBOM ({args.sbom})",
        "_generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "active_rules": rules,
    }
    text = json.dumps(out, ensure_ascii=False, indent=2)

    print(f"✅ {fmt} SBOM에서 자산 {len(rules)}건 추출", file=sys.stderr)
    for r in rules[:15]:
        print(f"   - {r['vendor']} / {r['product']}", file=sys.stderr)
    if len(rules) > 15:
        print(f"   … 외 {len(rules) - 15}건", file=sys.stderr)

    if args.dry_run:
        print(text)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"📝 {args.output} 저장 완료 (자산 {len(rules)}건)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
