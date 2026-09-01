#!/usr/bin/env python3
import importlib.util
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = ("src", "tools", "tests")

ALLOW = (
)


def main() -> int:
    if importlib.util.find_spec("pyflakes") is None:
        print("pyflakes 미설치 — 이 검사는 건너뜁니다 "
              "(pip install pyflakes 후 다시 실행하세요)")
        return 0

    paths = [os.path.join(ROOT, t) for t in TARGETS
             if os.path.isdir(os.path.join(ROOT, t))]
    proc = subprocess.run(
        [sys.executable, "-m", "pyflakes", *paths],
        capture_output=True, text=True, cwd=ROOT,
    )
    lines = [ln for ln in (proc.stdout + proc.stderr).splitlines() if ln.strip()]
    lines = [ln for ln in lines if "unable to detect undefined names" not in ln]
    lines = [ln for ln in lines if not any(a in ln for a in ALLOW)]

    if not lines:
        print(f"정적 검사 통과 ({', '.join(TARGETS)})")
        return 0

    undefined = [ln for ln in lines if "undefined name" in ln]
    other = [ln for ln in lines if "undefined name" not in ln]

    if undefined:
        print(f"\n[치명] 정의되지 않은 이름 {len(undefined)}건 — 실행 중 터집니다:")
        for ln in undefined:
            print("  " + ln.replace(ROOT + os.sep, ""))
    if other:
        print(f"\n[정리] 그 밖의 지적 {len(other)}건:")
        for ln in other:
            print("  " + ln.replace(ROOT + os.sep, ""))
    return 1


if __name__ == "__main__":
    sys.exit(main())
