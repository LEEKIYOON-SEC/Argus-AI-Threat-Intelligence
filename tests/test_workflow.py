#!/usr/bin/env python3
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, ".github", "workflows")

try:
    import yaml
except ImportError:
    print("PyYAML 없음 — 워크플로 검사 생략")
    sys.exit(0)


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def _steps(path, job):
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    return doc["jobs"][job]["steps"], doc


def _runs_on_schedule(step) -> bool:
    cond = str(step.get("if") or "")
    return not cond or "schedule" in cond


def publish_is_not_blocked(failures):
    print("── 주간 잡: 발행 앞 단계가 발행을 막지 않는가 ──")
    steps, _ = _steps(os.path.join(WF, "maintenance.yml"), "maintenance")
    names = [s.get("name", "") for s in steps]
    carry = next(i for i, n in enumerate(names) if "Carry forward" in n)
    upload = next(i for i, n in enumerate(names) if "Upload Pages" in n)
    check(carry < upload, "발행은 이어받기 뒤에 온다", failures)

    builders = {"Build package index", "Build detection rule index"}
    for step in steps[:carry]:
        name = step.get("name", "")
        run = str(step.get("run") or "")
        if "src/" not in run or not _runs_on_schedule(step) or name in builders:
            continue
        check(step.get("continue-on-error") is True,
              f"'{name}' 는 주간 스케줄에 돌면서 발행보다 앞에 있다 → "
              f"continue-on-error 없으면 이 단계 실패가 그 주 인덱스 발행을 통째로 막는다",
              failures)

    print("\n── 인덱스 생성기는 실패해도 직전 파일을 잃지 않는가 ──")
    carry_step = steps[carry]
    fresh = str(carry_step.get("env", {}).get("ARGUS_FRESH_FILES", ""))
    for name in ("cve-packages.json", "detection-rules.json"):
        check(name in fresh, f"{name} 가 ARGUS_FRESH_FILES 에 있다", failures)
    src = open(os.path.join(ROOT, "src", "fetch_published.py"), encoding="utf-8").read()
    check("if not fetch(name, base) and not (" in src,
          "생성기가 파일을 안 만들었으면 라이브 사본을 받아온다 "
          "(fresh 표시만 믿고 건너뛰면 사이트에서 파일이 사라진다)", failures)


def lanes_are_separate(failures):
    print("\n── 두 레인이 서로를 막지 않는가 ──")
    _, fast = _steps(os.path.join(WF, "argus-fast.yml"), "fast")
    _, bulk = _steps(os.path.join(WF, "argus.yml"), "argus-run")
    fg = (fast.get("concurrency") or {}).get("group")
    bg = (bulk.get("concurrency") or {}).get("group")
    check(fg and bg and fg != bg,
          f"동시성 그룹이 다르다 (fast={fg} · bulk={bg}) — 같으면 38분짜리 "
          f"bulk 뒤에 알림이 통째로 밀린다", failures)
    check((fast.get("concurrency") or {}).get("cancel-in-progress") is not True,
          "fast-lane 은 진행 중 실행을 취소하지 않는다 (워터마크 경합)", failures)

    fast_cron = [c.get("cron") for c in (fast.get(True) or fast.get("on"))["schedule"]]
    bulk_cron = [c.get("cron") for c in (bulk.get(True) or bulk.get("on"))["schedule"]]
    check(fast_cron == ["*/5 * * * *"], f"fast-lane 은 5분 (={fast_cron})", failures)
    check(len(bulk_cron) == 1 and bulk_cron[0].split()[0].isdigit()
          and bulk_cron[0].split()[1:] == ["*", "*", "*", "*"],
          f"bulk-lane 은 시간별 (={bulk_cron})", failures)

    fast_names = " ".join(s.get("run", "") for s in
                          _steps(os.path.join(WF, "argus-fast.yml"), "fast")[0])
    check("src/main.py" not in fast_names,
          "fast-lane 은 번역·AI분석(main.py)을 돌리지 않는다", failures)
    check("src/fast_lane.py" in fast_names, "fast-lane 은 fast_lane.py 를 돌린다", failures)


def gates_before_deploy(failures):
    print("\n── 배포 전 게이트 ──")
    for wf, job in (("argus.yml", "argus-run"), ("argus-fast.yml", "fast")):
        steps, _ = _steps(os.path.join(WF, wf), job)
        runs = " ".join(s.get("run", "") for s in steps)
        check("tests/test_lint.py" in runs, f"{wf}: 정적 검사가 있다", failures)
        check("tests/test_" in runs and "for t in" in runs or "test_lint" in runs,
              f"{wf}: 회귀 테스트가 있다", failures)


def main() -> int:
    failures = []
    publish_is_not_blocked(failures)
    lanes_are_separate(failures)
    gates_before_deploy(failures)
    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
