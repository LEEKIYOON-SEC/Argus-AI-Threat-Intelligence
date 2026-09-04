#!/usr/bin/env python3
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
        for key in ("translation_minutes", "translation_daily_reserve"):
            check(key in config.PERFORMANCE, f"{key} 가 있다", failures)

        print("\n── 한도가 넉넉하면 TPM 이 정하는 만큼 ──")
        m = fresh()
        minutes = config.PERFORMANCE["translation_minutes"]
        cap = (m.minute_token_headroom("gemini") // main._TOKENS_PER_ITEM) * minutes
        check(main._translation_budget() == cap, f"예산 {cap:,}건 (TPM 기준)", failures)

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

        print("\n── 분석 모델 TPM 도 추적한다 ──")
        m = fresh()
        check(m.minute_token_headroom("gemini_analysis") == 225_000,
              f"분석 모델 TPM 여유 {m.minute_token_headroom('gemini_analysis'):,}", failures)

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
        check("gemini" in state, f"저장 키 {sorted(state)}", failures)
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

        print("\n── AI Studio 실측 한도와 코드가 일치한다 ──")
        m = fresh()
        for key, rpm, tpm, rpd in (("gemini", 30, 16_000, 14_400),
                                   ("gemini_fb", 30, 16_000, 14_400),
                                   ("gemini_analysis", 15, 250_000, 500),
                                   ("gemini_analysis_fb", 15, 250_000, 500)):
            got = (m.limits[key].limit, m._tpm_limits[key], m._rpd_limits[key])
            check(got == (rpm, tpm, rpd), f"{key}: RPM {got[0]} · TPM {got[1]:,} · RPD {got[2]:,}",
                  failures)

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
