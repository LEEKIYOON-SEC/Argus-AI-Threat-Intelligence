import datetime as dt
import requests
from typing import Any, Dict, List, Optional, Tuple


def _fmt_int(n: int) -> str:
    try:
        return f"{int(n):,}"
    except Exception:
        return str(n)


def _risk_counts(scored: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in scored.values():
        rb = r.get("risk", "Low")
        counts[rb] = counts.get(rb, 0) + 1
    return counts


def _top_new_highrisk(new_ips: List[str], scored: Dict[str, Dict[str, Any]], topn: int) -> List[Dict[str, Any]]:
    """
    신규 IP 중 Critical/High만 뽑아 점수 내림차순 TOP N.
    """
    rows: List[Dict[str, Any]] = []
    for ip in new_ips:
        r = scored.get(ip)
        if not r:
            continue
        if r.get("risk") in ("Critical", "High"):
            rows.append(r)

    rows.sort(key=lambda x: int(x.get("final_score", 0)), reverse=True)
    return rows[:topn]


def _summarize_abuseipdb(enr: Dict[str, Any]) -> Optional[str]:
    abuse = enr.get("abuseipdb")
    if not isinstance(abuse, dict):
        return None
    c = abuse.get("abuseConfidenceScore")
    rep = abuse.get("totalReports")
    if c is None and rep is None:
        return None
    if rep is None:
        return f"AbuseIPDB {c}%"
    return f"AbuseIPDB {c}% (reports={rep})"


def _summarize_internetdb(enr: Dict[str, Any]) -> Optional[str]:
    inet = enr.get("internetdb")
    if not isinstance(inet, dict):
        return None
    ports = inet.get("ports") or []
    if not isinstance(ports, list) or not ports:
        return None
    # 너무 길어지지 않게 일부만
    ports_sorted = sorted([p for p in ports if isinstance(p, int)])[:12]
    return f"Ports {ports_sorted}"


def _summarize_enrichment(r: Dict[str, Any]) -> str:
    enr = r.get("enrichment") or {}
    if not isinstance(enr, dict) or not enr:
        return "No enrichment"

    parts: List[str] = []
    a = _summarize_abuseipdb(enr)
    if a:
        parts.append(a)
    i = _summarize_internetdb(enr)
    if i:
        parts.append(i)

    if not parts:
        return "No enrichment"
    return ", ".join(parts)


def build_slack_blocks(
    report_date_kst: dt.date,
    scored: Dict[str, Dict[str, Any]],
    new_indicators: List[str],
    removed_indicators: List[str],
    topn: int,
    api_usage: Dict[str, Any],
    feed_failures: Optional[List[Dict[str, Any]]] = None,
    removed_highrisk: Optional[List[Dict[str, Any]]] = None,
    degraded_highrisk: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """
    Slack Block Kit 메시지 구성.

    - removed_highrisk: 어제 고위험 → 오늘 피드에서 완전 제거된 IP (확실한 제거 대상)
    - degraded_highrisk: 어제 고위험 → 오늘 Medium/Low로 등급 하락 (검토 대상)
    """
    total = len(scored)
    new_cnt = len(new_indicators)
    removed_cnt = len(removed_indicators)
    growth = (new_cnt / total * 100.0) if total > 0 else 0.0

    counts = _risk_counts(scored)

    # 신규 중 IP만 (CIDR은 Tier2 대상이 아님)
    new_ips_only = [x for x in new_indicators if "/" not in x]
    top = _top_new_highrisk(new_ips_only, scored, topn)

    blocks: List[Dict[str, Any]] = []

    blocks.append({
        "type": "header",
        "text": {"type": "plain_text", "text": f"📊 The Shield 일일 위협 IP 리포트 ({report_date_kst.isoformat()})"}
    })

    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text":
            f"*총 수집:* {_fmt_int(total)}개\n"
            f"• 신규: {_fmt_int(new_cnt)}개 (+{growth:.1f}%)\n"
            f"• 제거: {_fmt_int(removed_cnt)}개"
        }
    })

    blocks.append({
        "type": "section",
        "fields": [
            {"type": "mrkdwn", "text": f"🔴 *Critical (80+)*\n{_fmt_int(counts['Critical'])}"},
            {"type": "mrkdwn", "text": f"🟠 *High (60-79)*\n{_fmt_int(counts['High'])}"},
            {"type": "mrkdwn", "text": f"🟡 *Medium (40-59)*\n{_fmt_int(counts['Medium'])}"},
            {"type": "mrkdwn", "text": f"⚪ *Low (<40)*\n{_fmt_int(counts['Low'])}"},
        ]
    })

    blocks.append({"type": "divider"})

    if top:
        lines = []
        for i, r in enumerate(top, start=1):
            ip = r.get("indicator")
            score = r.get("final_score")
            cat = r.get("category") or "-"
            summ = _summarize_enrichment(r)
            lines.append(f"{i}. `{ip}` ({score}점) - *{cat}* / {summ}")

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*🆕 신규 고위험 IP TOP 10:*\n" + "\n".join(lines)}
        })
    else:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*🆕 신규 고위험 IP TOP 10:* 해당 없음"}
        })

    # ── 방화벽 관리 섹션 ──
    has_firewall_section = removed_highrisk or degraded_highrisk
    if has_firewall_section:
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*🔥 방화벽 블랙리스트 관리*"}
        })

    # Case 1: 피드에서 완전 제거 (확실한 제거 대상)
    if removed_highrisk:
        rm_lines = []
        for r in removed_highrisk[:10]:
            ip = r.get("indicator", "-")
            score = r.get("final_score", 0)
            risk = r.get("risk", "-")
            cat = r.get("category", "-")
            rm_lines.append(f"• `{ip}` (어제 {score}점/{risk}) - {cat}")

        more = ""
        if len(removed_highrisk) > 10:
            more = f"\n… (+{len(removed_highrisk)-10} more)"

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text":
                f"*🗑️ 제거 대상 ({len(removed_highrisk)}건):*\n"
                "어제 고위험 → 오늘 모든 피드에서 사라짐. 차단 해제하세요.\n\n"
                + "\n".join(rm_lines) + more
            }
        })

    # Case 2: 등급 하락 (검토 대상)
    if degraded_highrisk:
        dg_lines = []
        for r in degraded_highrisk[:10]:
            ip = r.get("indicator", "-")
            y_score = r.get("yesterday_score", 0)
            y_risk = r.get("yesterday_risk", "-")
            t_score = r.get("today_score", 0)
            t_risk = r.get("today_risk", "-")
            cat = r.get("category", "-")
            dg_lines.append(f"• `{ip}` ({y_risk} {y_score}점 → {t_risk} {t_score}점) - {cat}")

        more = ""
        if len(degraded_highrisk) > 10:
            more = f"\n… (+{len(degraded_highrisk)-10} more)"

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text":
                f"*⬇️ 등급 하락 검토 ({len(degraded_highrisk)}건):*\n"
                "어제 고위험 → 오늘 Medium/Low로 하락. 피드에는 남아있으나 차단 해제를 검토하세요.\n\n"
                + "\n".join(dg_lines) + more
            }
        })

    # 피드 실패 요약(운영 가시성)
    if feed_failures:
        shown = feed_failures[:3]
        fail_lines = []
        for f in shown:
            name = f.get("feed", "-")
            err = f.get("error", "-")
            fail_lines.append(f"• {name}: {err}")
        more = ""
        if len(feed_failures) > 3:
            more = f"\n… (+{len(feed_failures)-3} more)"
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*⚠️ Tier1 피드 다운로드 실패:*\n" + "\n".join(fail_lines) + more}
        })

    # API usage(운영 가시성)
    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": (
                f"API usage — AbuseIPDB: {api_usage.get('abuseipdb',0)}, "
                f"InternetDB: {api_usage.get('internetdb',0)}"
            )
        }]
    })

    return blocks


def send_slack(webhook_url: str, blocks: List[Dict[str, Any]]) -> None:
    """Slack 전송 + 재시도 (최대 3회, 지수 백오프)"""
    payload = {"blocks": blocks}
    max_retries = 3
    delays = [2, 5, 10]
    for attempt in range(max_retries):
        try:
            r = requests.post(webhook_url, json=payload, timeout=20)
            r.raise_for_status()
            return
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                delay = delays[attempt]
                print(f"  [!] Slack 전송 실패 (시도 {attempt+1}/{max_retries}): {e}, {delay}s 후 재시도", flush=True)
                import time
                time.sleep(delay)
            else:
                print(f"  [!] Slack 전송 최종 실패: {e}", flush=True)
                raise