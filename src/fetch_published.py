#!/usr/bin/env python3
"""배포 직전, 이번 실행이 만들지 않은 데이터 파일을 현재 사이트에서 받아 온다.

GitHub Pages를 아티팩트로 배포하면 한 번의 배포가 사이트 전체를 갈아끼운다. 그래서
매시간 도는 파이프라인이 cves.json만 담아 올리면, 주 1회 만들어지는 패키지 인덱스가
사이트에서 사라진다. 반대도 마찬가지다.

각 잡이 배포 직전에 "내가 안 만든 파일"을 지금 서비스 중인 사이트에서 받아 채운다.
받지 못하면 체크아웃에 남은 사본이 있으면 그걸 쓰고, 그것도 없으면 0이 아닌 값을
반환해 호출부(워크플로)가 배포를 건너뛰게 한다 — 반쪽짜리 사이트를 올리느니 직전
배포를 그대로 두는 편이 낫다.

    python src/fetch_published.py cve-packages.json malicious-packages.json
"""
import os
import sys
import urllib.request

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(os.path.dirname(_THIS_DIR), "docs", "data")

# 없으면 배포를 막을 파일. 나머지는 없어도 대시보드가 degrade만 된다.
_REQUIRED = {"cves.json", "stats.json"}


def _base_url() -> str:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        return f"https://{owner.lower()}.github.io/{name}/data"
    return os.environ.get("ARGUS_PAGES_DATA_URL", "")


def fetch(name: str, base: str) -> bool:
    """현재 사이트의 파일을 docs/data/에 내려받는다. 성공하면 True."""
    if not base:
        return False
    url = f"{base}/{name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "argus-deploy"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            if resp.status != 200:
                return False
            data = resp.read()
    except Exception as e:
        print(f"  {name}: 내려받기 실패 ({e})", flush=True)
        return False
    if not data:
        return False
    path = os.path.join(_DATA_DIR, name)
    os.makedirs(_DATA_DIR, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  {name}: 현재 사이트에서 이어받음 ({len(data) / 1e6:.1f} MB)", flush=True)
    return True


def main(names) -> int:
    base = _base_url()
    missing = []
    for name in names:
        path = os.path.join(_DATA_DIR, name)
        # 이번 실행이 이미 만들었으면 그대로 둔다 — 최신본을 덮어쓰면 안 된다.
        if os.path.exists(path) and os.path.getsize(path) > 0:
            if name in _fresh():
                print(f"  {name}: 이번 실행 생성분 사용", flush=True)
                continue
        if not fetch(name, base) and not (
                os.path.exists(path) and os.path.getsize(path) > 0):
            missing.append(name)

    blocking = [m for m in missing if m in _REQUIRED]
    if blocking:
        print(f"[!] 필수 파일 없음: {', '.join(blocking)} — 배포를 건너뜁니다", flush=True)
        return 1
    if missing:
        print(f"[!] 없는 파일(무시): {', '.join(missing)}", flush=True)
    return 0


def _fresh() -> set:
    """이번 실행이 생성한 파일 이름. 워크플로가 ARGUS_FRESH_FILES로 알려준다."""
    return {n.strip() for n in os.environ.get("ARGUS_FRESH_FILES", "").split(",") if n.strip()}


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["cves.json", "stats.json",
                                   "cve-packages.json", "malicious-packages.json"]))
