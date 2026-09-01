#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(os.path.dirname(_THIS_DIR), "docs", "data")

_REQUIRED = {"cves.json", "stats.json"}


def _base_url() -> str:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        return f"https://{owner.lower()}.github.io/{name}/data"
    return os.environ.get("ARGUS_PAGES_DATA_URL", "")


def fetch(name: str, base: str) -> bool:
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
    if name.endswith(".json"):
        try:
            json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            print(f"  {name}: 내려받은 내용이 온전치 않음({e}) — 무시", flush=True)
            return False
    path = os.path.join(_DATA_DIR, name)
    os.makedirs(_DATA_DIR, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    print(f"  {name}: 현재 사이트에서 이어받음 ({len(data) / 1e6:.1f} MB)", flush=True)
    return True


def main(names) -> int:
    base = _base_url()
    missing = []
    for name in names:
        path = os.path.join(_DATA_DIR, name)
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
    return {n.strip() for n in os.environ.get("ARGUS_FRESH_FILES", "").split(",") if n.strip()}


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["cves.json", "stats.json", "cve-products.json",
                                   "cve-packages.json", "malicious-packages.json",
                                   "detection-rules.json"]))
