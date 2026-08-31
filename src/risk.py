"""위험도 판정 — Argus에서 '무엇을 알릴지'를 정하는 유일한 자리.

예전에는 이 판정이 네 곳에 흩어져 있었다: main._risk_tier(티어), main._should_send_alert
(전이), main._priority_banner(리포트 배너), notifier.is_urgent(즉시 발송). 마지막 것에는
"main._risk_tier의 critical 조건과 동일하게 유지할 것"이라는 주석이 붙어 있었는데,
사람이 지켜야 하는 규칙은 언젠가 깨진다 — 실제로 Metasploit·SSVC active·EPSS 급증 CVE가
리포트에는 '긴급'으로 실리면서 Slack은 조용한 상충이 있었다. 그래서 한 곳으로 모은다.

━━ 판정 모델 ━━

'티어'를 직접 계산하지 않는다. **트리거(trigger)**를 먼저 모으고, 티어는 그 트리거들의
최고 등급으로 유도한다. 이 방향이 중요한 이유는 두 가지다.

 ① 알림 억제가 공짜로 된다. 무엇 때문에 알렸는지를 트리거 이름으로 저장해 두면, 다음
    실행에서는 '새로 켜진 트리거'만 보면 된다. 예전 구조는 EPSS가 0.11 → 0.17 → 0.23으로
    오를 때마다 '급증' 조건이 다시 참이 되어 같은 CVE로 반복 발화할 수 있었다.
 ② 알림에 근거를 적을 수 있다. "왜 지금 이게 왔는가"는 트리거 이름 그 자체다.

━━ 임계값의 근거 ━━

EPSS는 절대 점수 대신 percentile을 쓴다. 점수 0.1은 임의값이었고, EPSS 모델이 갱신되면
같은 점수의 의미가 달라진다. percentile은 분포 기준이라 그 문제가 없다.
2026-08-30 전량 덤프(366,357건) 실측:

    percentile   해당 점수   이상인 CVE
    p99.0        0.571       3,664건 (1.00%)   ← 알림(T1)
    p95.0        0.093      18,318건 (5.00%)   ← 관찰(T2)
    (참고: 기존 임계 score>=0.1 은 17,348건 = 4.74%로 p95와 사실상 같다)

알림 티어를 p99로 올린 이유: 신규 공개 CVE는 EPSS가 낮게 시작하는 게 정상이라(모델에
아직 근거가 없다) p95는 신규분에서 거의 안 걸리고, 대신 '나중에 올라온' 오래된 CVE가
대량으로 걸린다. p99는 "모델이 상위 1%로 본다"는 뜻이라 그 자체로 알릴 값을 한다.

**CVSS는 단독으로 알림을 만들지 않는다.** 2026-08-27~28 실측(3,951건)으로 확인한 값이다.

    알림 조건                                   하루 알림
    악용 신호만 (KEV·MSF·nuclei·EDB·EPSS p99)      15건   ← 채택
    + CVSS>=9 & 원격·무인증                       162건
    + CVSS>=9 & 원격·무인증·무관여·저복잡도            128건
    + 위 + 두 번째 근거                            57건
    + 주요 CNA의 CVSS>=9 사전인증 RCE                53건

점수만 높은 건이 하루 100건 넘게 쏟아지는 이유는 단순하다 — CNA와 CISA ADP가 9.8을
일괄 부여하고, 그중 압도적 다수는 악용 근거가 없다. 그래서 즉시 알림은 **악용이 관측됐거나
공격 도구가 공개된 경우**로 좁히고, 점수 기반 '될 가능성'은 T2로 내려 화면과 시간별 요약에서
본다. 놓치는 게 아니라 방식이 다르다 — 하루 38번의 인터럽트 대신 한 번의 목록으로.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────
# 티어
# ──────────────────────────────────────────────────────────────────────────
T0 = "T0"   # 관측된 악용 — 즉시 알림 + 리포트
T1 = "T1"   # 무기화 임박 — 즉시 알림 + 리포트
T2 = "T2"   # 고위험이 될 가능성 — 대시보드 추적(번역O), Slack은 건수만
T3 = "T3"   # 미저장. 나중에 신호가 붙으면 소스측 diff가 끌어온다

_TIER_ORDER = {T0: 0, T1: 1, T2: 2, T3: 3}

#: 발화하면 즉시 알림이 나가는 티어
ALERTING_TIERS = frozenset({T0, T1})


def tier_rank(tier: str) -> int:
    """정렬·비교용 등급 (낮을수록 위험). 모르는 값은 최하위로."""
    return _TIER_ORDER.get(tier, _TIER_ORDER[T3])


def is_alerting(tier: str) -> bool:
    return tier in ALERTING_TIERS


# ──────────────────────────────────────────────────────────────────────────
# 트리거 사전
# ──────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Trigger:
    key: str
    tier: str
    label: str      # Slack·리포트에 그대로 나가는 한국어 사유
    source: str     # 출처 표기 (라이선스 고지 의무가 있는 소스가 있다)


_TRIGGERS: Tuple[Trigger, ...] = (
    # ── T0: 악용이 관측됐다. 추정이 아니라 보고된 사실이다.
    Trigger("kev_ransomware", T0, "CISA KEV 등재 — 랜섬웨어 캠페인에 사용 확인", "CISA KEV"),
    Trigger("kev", T0, "CISA KEV 등재 — 실제 악용 확인", "CISA KEV"),
    Trigger("vulncheck_kev", T0, "VulnCheck KEV 등재 — 악용 근거 확보", "VulnCheck KEV"),
    Trigger("ssvc_active", T0, "CISA SSVC Exploitation=active — 악용 진행형", "CISA vulnrichment"),
    Trigger("metasploit", T0, "Metasploit 모듈 공개 — 무기화됨", "Metasploit Framework (Rapid7)"),

    # ── T1: 악용 보고는 없지만 공격 도구가 이미 손에 잡힌다.
    Trigger("nuclei", T1, "nuclei 템플릿 공개 — 대량 스캔·검증 가능", "nuclei-templates (ProjectDiscovery)"),
    Trigger("exploitdb", T1, "Exploit-DB 공개 익스플로잇 등재", "Exploit-DB"),
    Trigger("epss_critical", T1, "EPSS 상위 1% (p99+) — 악용 확률 최상위", "EPSS (FIRST.org)"),
    # 출처(provenance) 신호 — 악용 관측이 아니라 '누가 찾았나'다. 공개 시점에 대개 이미
    # 패치돼 있지만(Anthropic 레저 실측 fix_rate 95.3%), 공개되는 순간 상세가 함께
    # 공개되므로 N-day 위험이 실재한다. 물량이 하루 1~2건이라 알림에 얹어도 묻히지 않는다.
    Trigger("ai_discovered", T1, "AI가 발견한 취약점 공개 — 상세가 함께 공개됨",
            "Anthropic CVD / CVE credits"),

    # ── T2: 고위험이 '될' 가능성. 알리지 않고 화면과 시간별 요약에 세워 관측한다.
    Trigger("cvss_critical_remote", T2, "CVSS 9.0+ · 사전인증 원격 · 무기화 쉬운 유형", "CVE/NVD"),
    Trigger("weaponizable_cwe", T2, "사전인증 원격 + 무기화 비율 높은 취약점 유형(CWE)", "CVE/NVD"),
    Trigger("ssvc_automatable", T2, "CISA SSVC Automatable=yes — 자동화 대량 공격 가능", "CISA vulnrichment"),
    Trigger("ssvc_total_impact", T2, "CISA SSVC Technical Impact=total — 완전 장악", "CISA vulnrichment"),
    Trigger("epss_high", T2, "EPSS 상위 5% (p95+)", "EPSS (FIRST.org)"),
    Trigger("poc", T2, "PoC 공개 확인", "nomi-sec / trickest"),
    Trigger("unscored_major_cna", T2, "주요 벤더 신규 CVE · 점수 미부여 — 재평가 대기", "CVE"),
)

TRIGGERS: Dict[str, Trigger] = {t.key: t for t in _TRIGGERS}

#: 이 트리거가 새로 켜지면 알림을 보낸다
ALERTING_TRIGGERS: FrozenSet[str] = frozenset(
    t.key for t in _TRIGGERS if t.tier in ALERTING_TIERS
)


# ──────────────────────────────────────────────────────────────────────────
# CVSS 벡터
# ──────────────────────────────────────────────────────────────────────────
def parse_vector(vector: Optional[str]) -> Dict[str, str]:
    """CVSS 벡터 문자열 → {지표: 값}. 3.0/3.1/4.0을 같은 방식으로 읽는다.

    우리가 보는 AV·AC·AT·PR·UI는 버전 간 이름이 같아서 분기가 필요 없다.
    (4.0의 UI는 N/P/A로 값이 늘었지만 'N = 사용자 관여 없음'은 그대로다.)
    앞머리 'CVSS:3.1'도 같은 규칙으로 파싱돼 {'CVSS': '3.1'}이 되므로 버전 확인에 쓸 수 있다.
    """
    out: Dict[str, str] = {}
    if not vector or vector == "N/A":
        return out
    for part in str(vector).split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        key, val = key.strip(), val.strip()
        if key and val:
            out.setdefault(key, val)
    return out


def is_remote_unauth(vector: Optional[str]) -> bool:
    """네트워크 경유 + 인증 불필요. '누구나 인터넷에서 쏠 수 있다'는 뜻.

    벡터를 모르면 False다 — 모르는 것을 위험하다고 단정하면 CVSS 단독 알림으로 되돌아간다.
    벡터가 없는 CVE는 대개 점수도 없어서 unscored_major_cna 쪽에서 따로 잡힌다.
    """
    m = parse_vector(vector)
    return m.get("AV") == "N" and m.get("PR") == "N"


def is_zero_interaction(vector: Optional[str]) -> bool:
    """원격·무인증에 더해 사용자 관여까지 없음 = 웜처럼 퍼질 수 있는 조건."""
    return is_remote_unauth(vector) and parse_vector(vector).get("UI") == "N"


def is_low_complexity(vector: Optional[str]) -> bool:
    """공격 조건이 까다롭지 않음. 3.x는 AC:L, 4.0은 AT:N이 대응된다."""
    m = parse_vector(vector)
    return m.get("AC") == "L" or m.get("AT") == "N"


# ──────────────────────────────────────────────────────────────────────────
# 고위험 CWE
# ──────────────────────────────────────────────────────────────────────────
# '원격 사전인증 장악'으로 이어지는 유형만 넣는다. 메모리 손상(CWE-787/416)은
# 무기화 사례가 많지만 커널 CVE가 하루 수백 건이라 넣는 순간 T2가 커널로 뒤덮인다 —
# 그쪽은 KEV·Metasploit·EPSS 신호가 붙을 때 T0/T1로 올라오게 둔다.
WEAPONIZABLE_CWE: FrozenSet[str] = frozenset({
    "CWE-77",    # 명령 주입
    "CWE-78",    # OS 명령 주입
    "CWE-89",    # SQL 인젝션
    "CWE-94",    # 코드 주입
    "CWE-98",    # PHP 원격 파일 삽입
    "CWE-22",    # 경로 순회
    "CWE-287",   # 부적절한 인증
    "CWE-306",   # 핵심 기능 인증 누락
    "CWE-434",   # 위험한 형식의 파일 업로드
    "CWE-502",   # 신뢰할 수 없는 데이터 역직렬화
    "CWE-611",   # XXE
    "CWE-798",   # 하드코딩된 자격증명
    "CWE-918",   # SSRF
})

# 점수가 아직 없어도 지켜볼 가치가 있는 CNA. 경계 장비·기업 인프라 벤더라
# '점수가 붙기 전에 KEV로 직행'하는 전례가 반복되는 곳들이다.
# (cveMetadata.assignerShortName 값 기준 — 소문자로 비교한다)
MAJOR_CNAS: FrozenSet[str] = frozenset({
    "microsoft", "cisco", "fortinet", "ivanti", "citrix", "paloaltonetworks",
    "vmware", "broadcom", "oracle", "sap", "adobe", "atlassian", "apache",
    "redhat", "gitlab", "jenkins", "progress", "sonicwall", "zyxel",
    "qnap", "synology", "trendmicro", "zoom", "juniper", "f5", "checkpoint",
    "google", "apple", "mozilla", "jetbrains", "elastic", "hashicorp",
})

# EPSS percentile 임계 (위 모듈 주석의 실측 근거 참조)
EPSS_P_CRITICAL = 0.99
EPSS_P_HIGH = 0.95
# percentile이 없는 과거 저장분을 위한 점수 폴백. 위 실측표의 대응값을 쓴다.
EPSS_SCORE_CRITICAL = 0.571
EPSS_SCORE_HIGH = 0.093


def _epss_at(state: Dict, p_threshold: float, score_threshold: float) -> bool:
    """EPSS가 임계 이상인가. percentile 우선, 없으면 점수로 폴백.

    폴백이 필요한 이유: percentile은 이번 개편에서 새로 저장하기 시작한 값이라
    기존 행에는 없다. 없다고 전부 '미달'로 처리하면 이미 추적 중이던 고EPSS CVE가
    한 번에 티어에서 떨어져 나간다."""
    pct = state.get("epss_percentile")
    if isinstance(pct, (int, float)) and pct > 0:
        return float(pct) >= p_threshold
    return float(state.get("epss") or 0.0) >= score_threshold


# ──────────────────────────────────────────────────────────────────────────
# 판정
# ──────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Verdict:
    tier: str
    triggers: FrozenSet[str] = field(default_factory=frozenset)

    @property
    def alerting_triggers(self) -> FrozenSet[str]:
        return self.triggers & ALERTING_TRIGGERS

    @property
    def tracked(self) -> bool:
        """DB에 남길 대상인가 (T3은 저장하지 않는다)."""
        return self.tier != T3

    def labels(self) -> Tuple[str, ...]:
        """티어 순 · 사전 정의 순서대로 정렬된 사유 문구."""
        return tuple(t.label for t in _TRIGGERS if t.key in self.triggers)


def evaluate(state: Dict) -> Verdict:
    """CVE 상태 dict → 활성 트리거와 티어.

    state는 파이프라인이 쓰는 평평한 dict다(collector가 만들고 DB에 저장하는 그 모양).
    없는 키는 전부 '신호 없음'으로 취급하므로 부분적으로 채워진 상태로도 안전하게 부를 수 있다.
    """
    fired = set()
    vector = state.get("cvss_vector")
    cvss = float(state.get("cvss") or 0.0)
    remote_unauth = is_remote_unauth(vector)
    wide_open = is_zero_interaction(vector) and is_low_complexity(vector)
    weaponizable = _has_weaponizable_cwe(state)

    # ── T0 · 관측된 악용
    if state.get("is_kev"):
        fired.add("kev")
        if state.get("is_kev_ransomware"):
            fired.add("kev_ransomware")
    if state.get("is_vulncheck_kev"):
        fired.add("vulncheck_kev")
    if state.get("ssvc_exploitation") == "active":
        fired.add("ssvc_active")
    if state.get("has_metasploit_module"):
        fired.add("metasploit")

    # ── T1 · 공격 도구 공개
    if state.get("has_nuclei_template"):
        fired.add("nuclei")
    if state.get("has_public_exploit"):
        fired.add("exploitdb")
    epss_hot = _epss_at(state, EPSS_P_CRITICAL, EPSS_SCORE_CRITICAL)
    if epss_hot:
        fired.add("epss_critical")
    if state.get("ai_discovered"):
        fired.add("ai_discovered")

    # ── T2 · 될 가능성
    epss_warm = _epss_at(state, EPSS_P_HIGH, EPSS_SCORE_HIGH)
    automatable = state.get("ssvc_automatable") == "yes"
    total_impact = state.get("ssvc_technical_impact") == "total"
    if epss_warm:
        fired.add("epss_high")
    if automatable:
        fired.add("ssvc_automatable")
    if total_impact:
        fired.add("ssvc_total_impact")
    if state.get("has_poc"):
        fired.add("poc")
    if remote_unauth and weaponizable:
        fired.add("weaponizable_cwe")
    # CVSS는 **단독으로는 아무 티어도 만들지 않는다.** 점수만으로 알리던 시절의 실측이
    # 그 이유다: 'CVSS≥9 + 원격·무인증'만으로 하루 162건, 벡터를 조여도 128건이 나왔다.
    # 대부분은 CNA가 일괄 부여한 9.8이고 악용 근거가 없다. 그래서 점수에는 ① 활짝 열린
    # 벡터(무관여·저복잡도)와 ② 독립적인 두 번째 근거를 모두 요구한다.
    if cvss >= 9.0 and wide_open and (weaponizable or automatable or total_impact
                                      or epss_warm or _is_major_cna(state)):
        fired.add("cvss_critical_remote")
    if cvss <= 0.0 and _is_major_cna(state):
        # 점수가 아직 없다. 대개는 CISA ADP나 NVD가 며칠 안에 채우고, 그 레코드 변경이
        # delta 피드로 다시 들어와 재평가된다 — 그때까지 화면에 세워 둔다.
        fired.add("unscored_major_cna")

    tier = min((TRIGGERS[k].tier for k in fired), key=tier_rank, default=T3)
    return Verdict(tier=tier, triggers=frozenset(fired))


def _has_weaponizable_cwe(state: Dict) -> bool:
    cwes = state.get("cwe") or []
    if not isinstance(cwes, (list, tuple)):
        return False
    for raw in cwes:
        for m in re.findall(r"CWE-\d{1,4}\b", str(raw)):
            if m in WEAPONIZABLE_CWE:
                return True
    return False


def _is_major_cna(state: Dict) -> bool:
    cna = str(state.get("assigner") or "").strip().lower()
    return bool(cna) and cna in MAJOR_CNAS


# ──────────────────────────────────────────────────────────────────────────
# 전이 판정 (알릴 것인가)
# ──────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Decision:
    alert: bool
    tier: str
    triggers: FrozenSet[str]        # 현재 켜져 있는 전체 트리거
    new_triggers: FrozenSet[str]    # 이번에 새로 켜진 알림 트리거
    reason: str                     # 사람이 읽는 사유 (알림 헤드라인)
    full_report: bool               # GitHub Issue 발행 대상인가

    @property
    def tracked(self) -> bool:
        return self.tier != T3


def decide(state: Dict, last: Optional[Dict]) -> Decision:
    """현재 상태와 직전 저장 상태를 비교해 알림 여부를 정한다.

    핵심은 '새로 켜진 알림 트리거가 있는가' 하나다. 값의 증감을 비교하지 않으므로
    EPSS가 계단식으로 오를 때 같은 CVE가 반복 발화하지 않는다.
    """
    verdict = evaluate(state)
    already = _previously_fired(last)
    new = verdict.alerting_triggers - already

    reason = " · ".join(TRIGGERS[k].label for k in _ordered(new)) if new else ""
    return Decision(
        alert=bool(new),
        tier=verdict.tier,
        triggers=verdict.triggers,
        new_triggers=new,
        reason=reason,
        full_report=is_alerting(verdict.tier),
    )


def _ordered(keys) -> Tuple[str, ...]:
    """사전 정의 순서(위험 높은 것 먼저)로 정렬."""
    return tuple(t.key for t in _TRIGGERS if t.key in keys)


def _previously_fired(last: Optional[Dict]) -> FrozenSet[str]:
    """직전 상태에서 '이미 알린' 트리거 집합.

    fired_triggers는 이번 개편에서 도입한 필드다. 없는 과거 행은 직전 상태를 그대로
    재평가해서 유추한다 — 그러지 않으면 전환 첫 실행에서 추적 중이던 CVE 전량이
    '새 트리거'로 보여 알림 폭풍이 난다."""
    if not last:
        return frozenset()
    stored = last.get("fired_triggers")
    if isinstance(stored, (list, tuple, set, frozenset)):
        return frozenset(str(k) for k in stored)
    return evaluate(last).alerting_triggers


def merge_fired(last: Optional[Dict], new_triggers) -> list:
    """저장할 fired_triggers — 과거 발화분에 이번 발화분을 더한다(집합 누적).

    누적이 맞는 이유: 신호는 대개 되돌아가지 않는다(KEV에서 빠지는 일은 드물다).
    되돌아간 신호를 지워버리면 그 신호가 다시 켜질 때 재알림이 나가는데, 그건 우리가
    막으려던 반복 발화 그 자체다."""
    return sorted(_previously_fired(last) | frozenset(new_triggers))
