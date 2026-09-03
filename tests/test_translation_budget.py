#!/usr/bin/env python3
"""번역 처리량 — 고정값이 아니라 API 한도와 시간으로 멈추는지.

    python3 tests/test_translation_budget.py

왜 있나: 번역은 회차당 24건 고정이었다. 그런데 bulk-lane 은 cron 이 시간당 1회여도
**실제로는 하루 5.0회밖에 안 돈다** — GitHub 이 그만큼만 띄운다. 실측(스케줄 실행 30회,
6일치): 간격 중앙값 4.8시간 · 최대 13.3시간 · 설계 대비 21%.

    24건 x 5회 = 120건/일   →  미번역 2,340건 지우는 데 20일

정작 bulk-lane 은 38분 예산 중 **23초**만 쓰고 끝났다(실측). 시간이 아니라 고정값이
유일한 병목이었다. 지금은 남은 시간과 남은 RPD/TPD 가 허락하는 만큼 돌리고, 한도가
소진되면 그 자리에서 멈춘다 — 버킷이 24시간 롤링이라 저절로 풀리고 다음 회차가 이어받는다.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

for _k in ("GH_TOKEN", "SUPABASE_URL", "SUPABASE_KEY", "SLACK_WEBHOOK_URL", "GEMINI_API_KEY"):
    os.environ.setdefault(_k, "test")

import main  # noqa: E402
from config import config  # noqa: E402
from rate_limiter import RateLimitManager  # noqa: E402


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def fresh():
    """깨끗한 매니저로 갈아 끼운다 — 전역 상태가 검사끼리 새지 않게."""
    m = RateLimitManager()
    main.rate_limit_manager = m
    return m


def main_() -> int:
    failures = []
    real = main.rate_limit_manager
    try:
        print("── 고정값이 남아 있지 않다 ──")
        check("translation_backfill_per_run" not in config.PERFORMANCE,
              "회차당 고정 건수 설정이 사라졌다", failures)
        for key in ("translation_minutes", "translation_max_per_run",
                    "translation_daily_reserve"):
            check(key in config.PERFORMANCE, f"{key} 가 있다", failures)

        print("\n── 한도가 넉넉하면 안전 상한까지 쓴다 ──")
        m = fresh()
        cap = config.PERFORMANCE["translation_max_per_run"]
        check(main._translation_budget() == cap,
              f"예산 = 안전 상한 {cap:,}건", failures)

        print("\n── 남은 RPD 가 적으면 그만큼만 ──")
        m = fresh()
        batch = config.PERFORMANCE["translation_batch_size"]
        reserve = config.PERFORMANCE["translation_daily_reserve"]
        for key in ("gemini", "gemini_fb"):
            m._rpd_buckets[key] = {m._rpd_bucket_key(): m._rpd_limits[key] - 100}
        want = int(100 * (1 - reserve)) * batch
        got = main._translation_budget()
        check(got == want, f"요청 100회 남음 → {got}건 (기대 {want})", failures)
        check(got < cap, "안전 상한보다 작다", failures)

        print("\n── TPD 를 설정하면 그것도 예산을 깎는다 ──")
        # TPD 는 예전에 추적조차 안 했다. RPD 는 남았는데 토큰만 소진되면 429 를 받고
        # 그때서야 알게 된다.
        m = fresh()
        for key in ("gemini", "gemini_fb"):
            m._tpd_limits[key] = 100_000
            m._tpd_buckets[key] = {m._rpd_bucket_key(): 90_000}
        want = int(10_000 * (1 - reserve)) // main._TOKENS_PER_ITEM
        got = main._translation_budget()
        check(got == want, f"토큰 10,000 남음 → {got}건 (기대 {want})", failures)

        print("\n── 한도가 다 소진되면 회차를 건너뛴다 ──")
        m = fresh()
        for key in ("gemini", "gemini_fb"):
            m.mark_rpd_exhausted(key)
        check(main._translation_budget() == 0, "예산 0", failures)
        check(main._translation_exhausted(), "소진으로 읽는다", failures)

        print("\n── 한 단만 소진이면 다른 단으로 계속한다 ──")
        m = fresh()
        m.mark_rpd_exhausted("gemini")
        check(not main._translation_exhausted(), "폴백이 살아 있으면 계속", failures)
        check(main._translation_budget() > 0, f"예산 {main._translation_budget():,}건", failures)

        print("\n── 소진 상태가 실행 사이에 이월된다 (한도 리셋 이후 재개) ──")
        m = fresh()
        for key in ("gemini", "gemini_fb"):
            m.mark_rpd_exhausted(key)
        state = m.export_rpd_state()
        check("rpd" in state, f"저장 키 {sorted(state)}", failures)
        again = RateLimitManager()
        again.import_rpd_state(state)
        check(again.is_rpd_exhausted("gemini"), "다시 읽어도 소진 유지", failures)

        print("\n  ── 24시간이 지난 버킷은 저절로 사라진다 (= 한도 리셋) ──")
        import datetime as _dt
        old_key = RateLimitManager._rpd_bucket_key(
            _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=30))
        stale = RateLimitManager()
        stale.import_rpd_state({"rpd": {"gemini": {old_key: 14_400}}})
        check(not stale.is_rpd_exhausted("gemini"),
              "30시간 전 사용분은 한도를 안 잡는다", failures)

        print("\n── 예전 상태 파일도 읽는다 ──")
        old_shape = RateLimitManager()
        old_shape.import_rpd_state({"gemini": {RateLimitManager._rpd_bucket_key(): 100}})
        check(old_shape.rpd_status("gemini")[0] == 100,
              f"평탄한 옛 모양 → {old_shape.rpd_status('gemini')}", failures)

        print("\n── TPD 가 실제로 쌓인다 ──")
        m = fresh()
        m._tpd_limits["gemini"] = 50_000
        m.record_call("gemini", tokens_used=1_234)
        used, limit = m.tpd_status("gemini")
        check((used, limit) == (1_234, 50_000), f"TPD {used:,}/{limit:,}", failures)
        r, t = m.daily_headroom("gemini")
        check(t == 50_000 - 1_234, f"남은 토큰 {t:,}", failures)

        print("\n  ── 한도를 안 정하면 제한 없음으로 다룬다 ──")
        m = fresh()
        r, t = m.daily_headroom("gemini")
        check(t is None, "TPD 미설정 → None (예산을 안 깎는다)", failures)
        check(r == m._rpd_limits["gemini"], f"RPD 는 그대로 {r:,}", failures)

        print("\n── 환경변수로 한도를 바꿀 수 있다 (AI Studio 값을 코드 수정 없이) ──")
        os.environ["ARGUS_TPD_GEMINI"] = "250000"
        os.environ["ARGUS_RPD_GEMINI"] = "1000"
        try:
            m = RateLimitManager()
            check(m._tpd_limits["gemini"] == 250_000, f"TPD {m._tpd_limits['gemini']:,}", failures)
            check(m._rpd_limits["gemini"] == 1_000, f"RPD {m._rpd_limits['gemini']:,}", failures)
            os.environ["ARGUS_RPD_GEMINI"] = "숫자아님"
            m = RateLimitManager()
            check(m._rpd_limits["gemini"] == 14_400, "깨진 값은 기본값으로 되돌아간다", failures)
        finally:
            os.environ.pop("ARGUS_TPD_GEMINI", None)
            os.environ.pop("ARGUS_RPD_GEMINI", None)

        print("\n── 한 회차가 표를 몇 바퀴씩 다시 읽지 않는다 ──")
        src = open(os.path.join(ROOT, "src", "main.py"), encoding="utf-8").read()
        body = src[src.index("def translate_tracked"):src.index("def _translation_exhausted")]
        check("max_windows" in body, "창 순회 횟수에 상한이 있다", failures)
        check("len(candidates) < pool" in body,
              "창을 다 못 채우면 표 끝으로 본다 (count 조회가 실패해도)", failures)
        check("stop_ts" in body and "translation_minutes" in body,
              "이 단계 전용 시간 예산을 쓴다", failures)

        print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
        return 1 if failures else 0
    finally:
        main.rate_limit_manager = real


if __name__ == "__main__":
    sys.exit(main_())
