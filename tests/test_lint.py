#!/usr/bin/env python3
"""정적 검사 게이트 — 정의되지 않은 이름을 배포 전에 잡는다.

    python3 tests/test_lint.py

왜 이게 테스트로 있어야 하나: 이 저장소는 모듈을 크게 쪼갠 적이 있고(collector →
feed/risk/state/pipeline), 그때 함수를 옮기면서 호출부를 안 고친 버그가 **두 번** 났다.

  · main.py 가 state.py 로 옮긴 read_backfill_offset() 을 그대로 불렀다
    → 번역이 통째로 안 돌았는데 except 가 삼켜서 "번역 생략(오류)" 한 줄로만 보였다
  · report.py 에 새 블록을 넣으면서 signal_lines 정의보다 앞에 놓았다
    → AI 발견 CVE 의 리포트 생성이 실패했는데 create_github_issue 의 except 가 삼켰다

둘 다 import 는 통과하고 컴파일도 통과한다. 그 함수가 **실제로 불릴 때만** 터지는데,
파이프라인 곳곳이 넓은 except 로 감싸여 있어 조용한 실패가 된다. 정적 검사가 유일하게
싼 방어선이다.

pyflakes 가 없으면 이 테스트는 통과 처리한다 — 개발 환경에 없다고 CI 를 막을 이유는 없고,
워크플로에는 별도로 설치해 돌린다.
"""
import importlib.util
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = ("src", "tools", "tests")

#: 지적을 무시할 항목. 실수로 넓히면 게이트가 무의미해지므로 사유를 반드시 적는다.
ALLOW = (
    # (없음)
)


def main() -> int:
    # import 대신 find_spec 을 쓴다 — pyflakes 는 noqa 를 모르므로, 여기서 import 하면
    # 이 파일 자체가 '미사용 import' 로 지적돼 게이트가 늘 빨갛게 된다.
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
    # pyflakes 가 'from x import *' 에 내는 안내는 지적이 아니다
    lines = [ln for ln in lines if "unable to detect undefined names" not in ln]
    lines = [ln for ln in lines if not any(a in ln for a in ALLOW)]

    if not lines:
        print(f"정적 검사 통과 ({', '.join(TARGETS)})")
        return 0

    # 정의되지 않은 이름은 런타임 폭발이라 별도로 세운다
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
