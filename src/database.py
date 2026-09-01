import os
import re
import time
import copy
import datetime
from supabase import create_client, Client
from typing import Any, Dict, List, Optional, Tuple
from tenacity import (retry, stop_after_attempt, wait_exponential,
                      retry_if_exception, RetryError)
from logger import logger

# PostgREST(Supabase)가 한 응답에 돌려주는 최대 행 수. 이보다 크게 요청해도 잘린다.
_PAGE_MAX = 1000

_ZWSP = "​"  # zero-width space — 화면엔 안 보이지만 WAF 시그니처 문자열은 끊는다


def _describe_error(e: BaseException) -> str:
    """tenacity RetryError를 언랩해 실제 원인(APIError 등)의 메시지를 돌려준다.

    RetryError 그대로 로깅하면 'RetryError[<Future ...>]'만 남아 원인(스키마 오류인지
    일시 장애인지)을 알 수 없다 — 진단 가능한 로그가 되도록 반드시 언랩한다."""
    if isinstance(e, RetryError):
        try:
            e = e.last_attempt.exception() or e
        except Exception:
            pass
    msg = f"{type(e).__name__}: {e}"
    # postgrest.APIError는 message/code/details/hint에 상세가 있다 (str에 빠질 수 있음)
    for attr in ("message", "code", "details", "hint"):
        v = getattr(e, attr, None)
        if v and str(v) not in msg:
            msg += f" | {attr}={v}"
    return msg


def _is_waf_block(e: BaseException) -> bool:
    """Supabase 앞단 Cloudflare WAF의 콘텐츠 차단(403 HTML)인지 판별.

    CVE 본문에는 공격 페이로드성 문자열(디렉터리 트래버설 '../../../../etc/shadow',
    <script>, SQLi 토큰 등)이 흔해, 요청 본문 검사에서 WAF가 악성으로 오탐·차단한다.
    이 차단은 '콘텐츠 결정적' — 동일 본문을 그대로 재전송하면 매번 같은 403이므로
    (일시 장애와 달리) 재시도·대기가 무의미하다. 시그니처로만 구분한다."""
    s = _describe_error(e).lower()
    return ("you have been blocked" in s or "attention required" in s
            or "cloudflare" in s or "<!doctype html" in s
            or ("403" in s and "html" in s))


def _neutralize(s):
    """WAF 시그니처 문자열에 zero-width space를 삽입해 무력화(화면 표시는 동일).

    탐지 룰 원문에는 적용하지 않는다 — '룰 복사'로 붙여넣을 때 ZWSP가 룰을 깨뜨리므로.
    사람이 읽는 표시용 텍스트(제목/설명/영향자산)에만 적용한다."""
    if not isinstance(s, str) or not s:
        return s
    s = re.sub(r'\.\.(?=[/\\])', '.' + _ZWSP + '.', s)                 # ../  ..\
    s = re.sub(r'/(?=(etc|proc|sys|root|windows|boot)\b)', '/' + _ZWSP, s, flags=re.I)  # /etc ...
    s = re.sub(r'<(?=[a-zA-Z/!])', '<' + _ZWSP, s)                     # <script <img ...
    s = re.sub(r'(?i)\b(union|select|insert|drop|delete)(?=\s)',
               lambda m: m.group(1)[0] + _ZWSP + m.group(1)[1:], s)    # 흔한 SQLi 토큰
    return s

class DatabaseError(Exception):
    """데이터베이스 관련 에러"""
    pass

class ArgusDB:
    def __init__(self):
        """데이터베이스 연결 초기화"""
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")

        if not url or not key:
            raise DatabaseError("SUPABASE_URL 또는 SUPABASE_KEY가 설정되지 않음")

        try:
            self.client: Client = create_client(url, key)
            logger.info("Supabase 연결 성공")
        except Exception as e:
            raise DatabaseError(f"Supabase 연결 실패: {e}")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        # WAF 콘텐츠 차단은 결정적이라 재시도해도 매번 같은 403 → 재시도 대상에서 제외(빠른 실패)
        retry=retry_if_exception(lambda e: not _is_waf_block(e))
    )
    def _execute(self, query):
        """Supabase 쿼리 실행 + 일시적 장애 재시도 (지수 백오프). WAF 차단은 즉시 실패."""
        return query.execute()

    def _try_upsert(self, data: Dict) -> Tuple[bool, Optional[BaseException]]:
        try:
            self._execute(self.client.table("cves").upsert(data))
            return True, None
        except Exception as e:
            return False, e

    @staticmethod
    def _waf_neutralized_copy(data: Dict) -> Dict:
        """표시용 자유텍스트에 ZWSP를 넣어 WAF를 우회한 사본 (룰 원문은 건드리지 않음).

        대부분의 WAF 차단은 description의 공격 페이로드성 문자열이 원인이라, 이 사본이면
        원문 손실 없이(화면 동일) 저장된다. 룰 원문은 '룰 복사'가 깨지지 않도록 원본 유지."""
        d = copy.deepcopy(data)
        st = d.get("last_alert_state")
        if isinstance(st, dict):
            for k in ("title", "title_ko", "description", "desc_ko"):
                if k in st:
                    st[k] = _neutralize(st[k])
            for aff in st.get("affected", []) or []:
                if isinstance(aff, dict):
                    for k in ("vendor", "product", "versions"):
                        if k in aff:
                            aff[k] = _neutralize(aff[k])
        return d

    @staticmethod
    def _waf_minimal_copy(data: Dict) -> Dict:
        """최후 안전 저장본 — 공격 페이로드가 담길 수 있는 대용량/원문 필드를 모두 제거.

        스칼라(점수·플래그)와 리포트 링크만 남긴다. 상세 원문은 이미 GitHub Issue에
        보존돼 있고, 대시보드 행은 리포트로 연결되므로 정보 손실이 아니라 '요약 저장'이다.
        목적: 어떤 콘텐츠든 저장을 성사시켜 발화 이력(fired_triggers)을 남기는 것 —
        저장이 실패하면 다음 실행이 같은 CVE를 '처음 보는 것'으로 보고 같은 알림을
        또 보낸다. 표시용 한국어 요약은 ZWSP로 무력화해 함께 보존 시도."""
        st = data.get("last_alert_state") or {}
        safe_state = {
            "title_ko": _neutralize(st.get("title_ko") or st.get("title", "")),
            "desc_ko": _neutralize((st.get("desc_ko") or "")[:300]),
            "cwe": st.get("cwe", []),
            "cvss": st.get("cvss"), "epss": st.get("epss"), "is_kev": st.get("is_kev"),
            "ssvc_exploitation": st.get("ssvc_exploitation"),
            # 자동화 악용 축 — 위험도 판정에 쓰이므로 축소 저장본에서도 반드시 보존한다
            # (빠뜨리면 WAF에 걸린 CVE만 다음 실행에서 티어가 내려앉는다)
            "ssvc_automatable": st.get("ssvc_automatable"),
            "ssvc_technical_impact": st.get("ssvc_technical_impact"),
            "is_kev_ransomware": st.get("is_kev_ransomware", False),
            "is_vulncheck_kev": st.get("is_vulncheck_kev", False),
            "published": st.get("published", ""),
            "has_poc": st.get("has_poc", False),
            "has_public_exploit": st.get("has_public_exploit", False),
            "has_metasploit_module": st.get("has_metasploit_module", False),
            "has_nuclei_template": st.get("has_nuclei_template", False),
            "epss_percentile": st.get("epss_percentile"),
            # 티어와 발화 이력은 축소 저장본에서도 반드시 보존한다 — 빠뜨리면 WAF에 걸린
            # CVE만 다음 실행에서 '처음 보는 것'이 되어 같은 알림이 다시 나간다.
            "tier": st.get("tier"),
            "fired_triggers": st.get("fired_triggers", []),
            "waf_degraded": True,  # 대시보드/모달에서 '원문은 리포트 참조' 안내에 사용 가능
        }
        keep = ("id", "cvss_score", "epss_score", "is_kev", "updated_at",
                "last_alert_at", "report_url",
                "has_official_rules", "last_rule_check_at")
        out = {k: data[k] for k in keep if k in data}
        out["last_alert_state"] = safe_state
        # rules_snapshot(룰 원문)은 최대 WAF 트리거 → 최소 저장본에선 제외 (Issue에 보존)
        return out

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        try:
            response = self._execute(self.client.table("cves").select("*").eq("id", cve_id))

            if response.data:
                logger.debug(f"CVE 발견: {cve_id}")
                return response.data[0]
            else:
                logger.debug(f"신규 CVE: {cve_id}")
                return None

        except Exception as e:
            logger.error(f"CVE 조회 실패 ({cve_id}): {e}")
            return None

    def get_cves(self, cve_ids) -> Tuple[Dict[str, Dict], set]:
        """여러 CVE를 한 번에 조회. → (찾은 행 {id: row}, **조회가 성사된** id 집합)

        두 번째 값이 왜 필요한가: '조회했는데 없다'와 '조회를 못 했다'는 완전히 다르다.
        조회 실패를 '없다'로 처리하면 직전 상태가 없는 것처럼 보여 이미 알린 CVE가
        신규로 판정되고, 같은 알림이 다시 나간다. 그래서 성사된 청크의 id만 담아
        호출부가 나머지는 개별 조회로 폴백하게 한다.

        건별 조회를 없애려고 만들었다. fast-lane 한 회차의 변경분은 대부분 T3이라
        (실측 590건 중 534건 = 90.5%) DB에 있을 리가 없는데도 전부 왕복을 돌았다.
        """
        ids = [str(c) for c in cve_ids if c]
        rows: Dict[str, Dict] = {}
        covered: set = set()
        if not ids:
            return rows, covered

        # PostgREST는 GET 쿼리스트링으로 필터를 보낸다. CVE-2026-12345 가 15~18바이트라
        # 200개면 ~3.5KB — 프록시·게이트웨이의 통상 URL 한도(8KB) 안이다.
        chunk_size = 200
        for i in range(0, len(ids), chunk_size):
            chunk = ids[i:i + chunk_size]
            try:
                r = self._execute(
                    self.client.table("cves").select("*").in_("id", chunk)
                )
                for row in (r.data or []):
                    rid = row.get("id")
                    if rid:
                        rows[rid] = row
                covered.update(chunk)
            except Exception as e:
                # 이 청크는 '모름'으로 남긴다 — covered에 넣지 않으므로 개별 조회로 간다
                logger.warning(f"CVE 일괄 조회 실패 ({len(chunk)}건): {_describe_error(e)} "
                               f"→ 해당 건은 개별 조회로 폴백")
        return rows, covered

    def upsert_cve(self, data: Dict) -> bool:
        """CVE 저장. 실패 유형별로 다르게 대응한다 —

        저장 실패 = Issue는 나갔는데 대시보드 미반영 + 다음 실행 중복 재처리(중복 이슈·
        AI 예산 낭비)로 직결되므로 반드시 성사시킨다.
          1) 성공 → True.
          2) 비-WAF 실패(일시 장애 등) → 25초 후 1회 재시도.
          3) WAF 콘텐츠 차단(결정적) → 재시도 무의미. 표시텍스트를 ZWSP로 무력화한 사본으로
             저장(원문 손실 없음). 그래도 차단되면 스칼라+리포트링크만의 최소 저장본으로.
             → 어떤 콘텐츠든 저장을 성사시켜 poison-pill(매 실행 중복 이슈)을 끊는다.
        """
        cid = data.get('id')
        ok, err = self._try_upsert(data)
        if ok:
            logger.debug(f"CVE 저장 성공: {cid}")
            return True

        if not _is_waf_block(err):
            # 일시 장애 추정 → 짧은 백오프(_execute ~14초)를 넘기는 장애에 대비해 긴 간격 2차 시도
            logger.warning(f"CVE 저장 1차 실패 ({cid}): {_describe_error(err)} → 25초 후 재시도")
            time.sleep(25)
            ok, err = self._try_upsert(data)
            if ok:
                logger.info(f"CVE 저장 재시도 성공: {cid}")
                return True
            if not _is_waf_block(err):
                logger.error(f"CVE 저장 실패 ({cid}): {_describe_error(err)}")
                return False
            # 2차에서 WAF로 판명 → 아래 WAF 경로로 진행

        # WAF 콘텐츠 차단 — 표시텍스트 무력화 사본으로 재시도(원문 보존)
        logger.warning(f"⚠️ CVE 저장 WAF 콘텐츠 차단 ({cid}) — 페이로드성 문자열 무력화 후 재저장 시도")
        ok, err2 = self._try_upsert(self._waf_neutralized_copy(data))
        if ok:
            logger.info(f"CVE 저장 성공 (WAF 우회, 원문 보존): {cid}")
            return True

        # 최후: 스칼라+리포트링크만의 최소 저장본 (원문은 GitHub Issue에 보존)
        ok, err3 = self._try_upsert(self._waf_minimal_copy(data))
        if ok:
            logger.info(f"CVE 저장 성공 (WAF 축소본, 원문은 리포트 참조): {cid}")
            return True

        logger.error(f"CVE 저장 실패 ({cid}) — WAF 축소본까지 실패: {_describe_error(err3)}")
        return False
    
    # 재확인 후보 조회에 필요한 최소 컬럼 — 대용량 JSONB(last_alert_state·rules_snapshot)
    # 제외가 핵심이다. 전체 컬럼(select *)을 끌어오면 고위험 수천 건 × 매시간 실행으로
    # Supabase 무료 egress(5GB/월)를 수백 MB씩 소모한다(불변 원칙 2 위배).
    _RECHECK_COLS = ("id, cvss_score, epss_score, is_kev, has_official_rules, "
                     "last_rule_check_at, last_alert_at, report_url")

    def get_rule_recheck_candidates(self, limit: int = 10) -> List[Dict]:
        """
        공개(공식) 룰 재확인이 필요한 고위험 CVE 조회.

        대상:
        1. 리포트는 됐지만 공개 룰 미확인 CVE (has_official_rules=False, rules_snapshot != null)
           — 이후 공개 룰셋에 룰이 등록됐을 수 있음
        2. rules_snapshot이 없는 고위험 CVE (CVSS >= 7.0) — Issue 생성 실패 등으로
           룰 검색 기록이 없는 케이스 재확인

        쿨다운: 성공 7일 / 실패 1일(last_rule_check_at을 6일 전으로 기록해 구현).
        필터·정렬·상한을 모두 서버(PostgREST)로 밀어 전송량을 최소화한다 — 어차피
        상위 limit건만 쓰므로 전량을 받아 파이썬에서 자르는 것은 순수 낭비였다.
        보존기간(CVSS별 90/180일) 필터는 파이썬에 남으므로 여유분(×3)을 받아 온다.
        """
        try:
            fetch_n = max(limit * 3, 30)
            cutoff_7d = (datetime.datetime.now(datetime.timezone.utc)
                         - datetime.timedelta(days=7)).isoformat()
            # 쿨다운: 미확인(null)이거나 7일 경과분만 — 서버에서 거른다
            cooldown = f"last_rule_check_at.is.null,last_rule_check_at.lt.{cutoff_7d}"

            def _query(base):
                return self._execute(
                    base.or_(cooldown)
                        .order("is_kev", desc=True)
                        .order("cvss_score", desc=True)
                        .order("epss_score", desc=True)
                        .limit(fetch_n)
                )

            # Case 1: 리포트됐지만 공개 룰 미확인 CVE
            norules_response = _query(
                self.client.table("cves")
                .select(self._RECHECK_COLS)
                .eq("has_official_rules", False)
                .not_.is_("rules_snapshot", "null")
            )

            # Case 2: 룰 검색 기록이 없는 고위험 CVE (CVSS >= 7.0)
            norecord_response = _query(
                self.client.table("cves")
                .select(self._RECHECK_COLS)
                .is_("rules_snapshot", "null")
                .gte("cvss_score", 7.0)
            )

            all_records = {}
            for record in (norules_response.data or []):
                all_records[record['id']] = record
            for record in (norecord_response.data or []):
                all_records[record['id']] = record

            if not all_records:
                logger.info("공식 룰 재확인 대상: 0건")
                return []

            now = datetime.datetime.now(datetime.timezone.utc)
            eligible = []

            for cve_id, record in all_records.items():
                cvss = record.get('cvss_score', 0) or 0
                is_kev = record.get('is_kev') or False
                epss = record.get('epss_score', 0) or 0

                # 쿨다운 체크 (성공: 7일, 실패: 1일)
                last_check = record.get('last_rule_check_at') or ''
                if last_check:
                    try:
                        last_check_dt = datetime.datetime.fromisoformat(last_check.replace('Z', '+00:00'))
                        days_since = (now - last_check_dt).days

                        # 공식 룰이 이미 있으면 더 이상 재확인 불필요
                        if record.get('has_official_rules'):
                            continue

                        # 쿨다운: 7일 (실패 시 last_rule_check_at을 6일 전으로 설정하여 1일 후 재시도)
                        if days_since < 7:
                            continue
                    except (ValueError, TypeError):
                        pass

                # KEV 등재 또는 EPSS > 0 → 무기한 (보존 기간 제한 없음)
                if is_kev or epss > 0:
                    eligible.append(record)
                    continue

                # CVSS 7.0 미만 → 재확인 안 함
                if cvss < 7.0:
                    continue

                # CVSS 기반 보존 기간
                max_age_days = 180 if cvss >= 9.0 else 90

                # Supabase는 null 컬럼도 키를 포함해 돌려주므로 .get(k, default)의 기본값이
                # 발동하지 않는다 — None이 그대로 나온다. 예전 코드는 그래서 알림이 나간 적
                # 없는 행(last_alert_at=null)에서 보존기간 검사를 통째로 건너뛰었고, 오래된
                # 행이 재확인 슬롯(회당 10건)을 계속 차지했다. created_at은 _RECHECK_COLS에
                # 없어 어차피 조회되지 않으므로 폴백에서 뺀다.
                created_at = record.get('last_alert_at') or ''
                if created_at:
                    try:
                        created_dt = datetime.datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        if (now - created_dt).days > max_age_days:
                            continue
                    except (ValueError, TypeError):
                        pass

                eligible.append(record)

            # 우선순위: KEV > CVSS 높은 순 > EPSS 높은 순
            eligible.sort(key=lambda r: (
                -(1 if r.get('is_kev') else 0),
                -(r.get('cvss_score', 0) or 0),
                -(r.get('epss_score', 0) or 0),
            ))

            eligible = eligible[:limit]
            total = len(all_records)
            logger.info(f"공개 룰 재확인: 후보 {total}건(서버 필터·상한 적용) → 대상 {len(eligible)}건")
            return eligible

        except Exception as e:
            logger.error(f"룰 재확인 후보 조회 실패: {e}")
            return []
    
    def batch_get_scalar(self, cve_ids: List[str], column: str) -> Dict[str, Any]:
        """CVE별 스칼라 컬럼 1개를 배치 조회. DB에 없는 id는 결과에 포함되지 않는다.

        신호 드리프트 대조 전용이라 last_alert_state(JSONB)를 일부러 제외한다 —
        KEV 전량(1,600여 건)을 매 실행 대조해도 응답이 수십 KB에 그친다.
        마커 행(last_alert_state=null)도 스칼라 컬럼은 있으므로 동일하게 조회된다."""
        result: Dict[str, Any] = {}
        if not cve_ids:
            return result
        try:
            for i in range(0, len(cve_ids), 50):
                chunk = cve_ids[i:i + 50]
                response = self._execute(
                    self.client.table("cves").select(f"id, {column}").in_("id", chunk)
                )
                for row in (response.data or []):
                    result[row['id']] = row.get(column)
            return result
        except Exception as e:
            logger.error(f"배치 스칼라 조회 실패({column}): {e}")
            return result

    def get_translation_backfill_candidates(self, limit: int = 60,
                                            offset: int = 0) -> List[Dict]:
        """한국어 번역이 안 된 채 남은 추적 CVE (대시보드 품질 백필용).

        번역은 Phase B에서 하지만 시간 예산 초과 시 영문 폴백으로 저장된다. 그 행들은
        레코드가 다시 바뀌지 않는 한 영영 영문으로 남아 대시보드 절반이 영문이 된다.
        '영문 여부' 판정은 JSONB 내부 값의 정규식 검사라 서버 필터로 표현할 수 없어
        파이썬에서 거른다 — 그래서 한 번에 볼 수 있는 창이 limit건으로 제한된다.

        offset이 필요한 이유: 창을 항상 '최신순 앞에서부터' 잡으면 영영 못 보는 행이
        생긴다. 매시간 최대 400건이 갱신되므로 최신 200건은 늘 '최근 몇 시간'이고,
        영문으로 굳은 행은 정의상 갱신이 멈춘 과거 행이라 그 창 밖에 있다. 실측으로
        영문 잔존 111건 중 최신 200위 안에 든 건 0건 — 백필이 대상을 한 건도 볼 수
        없었다. 호출부가 매 실행 offset을 밀어 전체를 회전 스캔하게 한다."""
        try:
            response = self._execute(
                self.client.table("cves")
                .select("id, last_alert_state")
                .not_.is_("last_alert_state", "null")
                .order("updated_at", desc=True)
                .range(offset, offset + max(1, min(limit, _PAGE_MAX)) - 1)
            )
            return response.data or []
        except Exception as e:
            logger.error(f"번역 백필 후보 조회 실패: {e}")
            return []

    def count_tracked(self) -> int:
        """추적 행 수만 센다(데이터 전송 없음). 회전 스캔의 한 바퀴 길이 계산용."""
        try:
            r = self._execute(
                self.client.table("cves").select("id", count="exact")
                .not_.is_("last_alert_state", "null").limit(1)
            )
            return r.count or 0
        except Exception as e:
            logger.warning(f"추적 행 수 조회 실패: {e}")
            return 0

    def update_translation(self, cve_id: str, title_ko: str, desc_ko: str) -> bool:
        """기존 last_alert_state의 번역 필드만 갱신 (다른 필드는 보존)."""
        try:
            current = self.get_cve(cve_id)
            if not current or not current.get('last_alert_state'):
                return False
            state = dict(current['last_alert_state'])
            state['title_ko'] = title_ko
            state['desc_ko'] = desc_ko
            return self.upsert_cve({
                "id": cve_id,
                "last_alert_state": state,
                "updated_at": current.get('updated_at') or datetime.datetime.now(
                    datetime.timezone.utc).isoformat(),
            })
        except Exception as e:
            logger.warning(f"{cve_id} 번역 갱신 실패: {e}")
            return False

    def get_tracked_ids(self, page_size: int = 1000, max_rows: int = 50000) -> List[str]:
        """추적 중인(대시보드 노출) CVE의 id만 페이지네이션으로 전량 조회.

        id 하나만 select하므로 전량을 받아도 수백 KB에 그친다 — 패키지 역인덱스를
        만들 대상 목록을 얻는 용도라 다른 컬럼이 필요 없다."""
        ids: List[str] = []
        offset = 0
        try:
            while offset < max_rows:
                response = self._execute(
                    self.client.table("cves")
                    .select("id")
                    .not_.is_("last_alert_state", "null")
                    .order("updated_at", desc=True)
                    .range(offset, offset + page_size - 1)
                )
                batch = response.data or []
                ids.extend(r["id"] for r in batch if r.get("id"))
                if len(batch) < page_size:
                    break
                offset += page_size
        except Exception as e:
            logger.error(f"추적 CVE id 조회 실패: {e}")
        return ids

    def _tracked_states(self, page_size: int = 1000, max_rows: int = 50000) -> List[Dict]:
        """추적 행의 id + last_alert_state 전량. 소급 백필의 공통 입력.

        반드시 range()로 페이지네이션한다. limit(20000)으로 한 번에 요청하면 PostgREST가
        응답을 db-max-rows(Supabase 기본 1,000행)로 조용히 잘라, 최신 1,000건만 보게 된다.
        실제로 그래서 벤더 백필이 대상 198건 중 7건만 보고 "완료"로 끝났다.

        JSONB 내부 조건(키 존재·배열 내부 값)은 서버 필터로 표현하기 번거로워
        호출부가 파이썬에서 거른다. 마커 행은 대시보드에 안 나오므로 제외한다."""
        # 서버가 자르는 한도보다 크게 요청하면 첫 페이지에서 len(batch) < page_size가
        # 되어 루프가 조기 종료된다. 호출부가 무엇을 넘기든 여기서 강제로 맞춘다 —
        # 실제로 이 실수로 페이지네이션이 통째로 무력화됐다(호출부가 20000을 넘김).
        page_size = max(1, min(page_size, _PAGE_MAX))
        rows: List[Dict] = []
        offset = 0
        try:
            while offset < max_rows:
                response = self._execute(
                    self.client.table("cves")
                    .select("id, last_alert_state")
                    .not_.is_("last_alert_state", "null")
                    .order("updated_at", desc=True)
                    .range(offset, offset + page_size - 1)
                )
                batch = response.data or []
                rows.extend(batch)
                if len(batch) < page_size:
                    break
                offset += page_size
        except Exception as e:
            logger.error(f"추적 행 조회 실패(부분 결과 {len(rows):,}건으로 진행): {e}")
        return rows

    def get_rows_missing_published(self) -> List[Dict]:
        """공개일(published)이 아직 없는 추적 행 — 소급 백필 대상 전량."""
        return [r for r in self._tracked_states()
                if not (r.get("last_alert_state") or {}).get("published")]

    def get_rows_missing_vendor(self) -> List[Dict]:
        """영향 벤더가 하나도 없는 추적 행 — NVD CPE 소급 백필 대상.

        원본 CNA 레코드가 'n/a'인 경우가 있는데, 그때도 NVD CPE에는 벤더/제품이
        들어 있곤 한다. 벤더가 비면 대시보드 벤더 필터에서 통째로 빠진다."""
        def has_vendor(state: Dict) -> bool:
            return any(
                str(a.get("vendor") or "").strip().lower() not in ("", "unknown", "n/a", "-")
                for a in (state.get("affected") or []) if isinstance(a, dict)
            )
        return [r for r in self._tracked_states()
                if not has_vendor(r.get("last_alert_state") or {})]

    def get_pipeline_state(self) -> Optional[Dict]:
        """파이프라인 진행 상태(워터마크·실패추적·RPD). 없거나 실패하면 None.

        예전에는 docs/data/pipeline_state.json을 매 실행 커밋해 영속시켰다. 그 방식은
        시간당 커밋 1건을 만들어 저장소를 계속 불렸다(최근 30일 커밋 323건). 상태는
        1행이면 충분하므로 DB로 옮긴다."""
        try:
            response = self._execute(
                self.client.table("pipeline_state").select("state").eq("id", 1).limit(1)
            )
            rows = response.data or []
            state = rows[0].get("state") if rows else None
            return state if isinstance(state, dict) else None
        except Exception as e:
            logger.warning(f"파이프라인 상태 조회 실패: {e}")
            return None

    def set_pipeline_state(self, state: Dict) -> bool:
        """파이프라인 진행 상태 저장. 실패하면 False.

        실패해도 워터마크가 전진하지 않을 뿐이라 다음 실행이 같은 구간을 다시 본다 —
        중복은 dedup이 걸러내므로 '누락 0'(불변 원칙 1)은 유지된다."""
        try:
            self._execute(self.client.table("pipeline_state").upsert({
                "id": 1, "state": state,
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }))
            return True
        except Exception as e:
            logger.error(f"파이프라인 상태 저장 실패: {e}")
            return False

    def request_full_export(self) -> bool:
        """다음 export를 전량으로 돌리도록 표시한다.

        백필은 '확인일'을 보존하려고 updated_at을 일부러 건드리지 않는다. 그런데 증분
        export는 updated_at으로 바뀐 행을 찾으므로, 그대로 두면 백필 결과가 대시보드에
        영영 나타나지 않는다. 한 번만 전량으로 돌려 반영시킨다."""
        state = self.get_pipeline_state() or {}
        state["force_full_export"] = True
        return self.set_pipeline_state(state)

    _STATE_CHUNK = 200

    def bulk_save_states(self, updates: List[Dict], label: str = "상태") -> int:
        """[{id, last_alert_state}, ...]를 묶어 저장. 갱신 성공 건수 반환.

        행마다 저장하면 대상이 1만 건을 넘을 때 왕복이 그만큼 늘어 워크플로
        타임아웃(60분)에 걸리고 Supabase egress도 크게 쓴다(불변 원칙 2).

        payload에 updated_at을 넣지 않는다 — PostgREST는 준 컬럼만 갱신하므로 그 값이
        대시보드의 '확인일'로 그대로 보존된다. 백필 때문에 확인일이 밀리면 안 된다."""
        if not updates:
            return 0
        done = 0
        for i in range(0, len(updates), self._STATE_CHUNK):
            chunk = updates[i:i + self._STATE_CHUNK]
            try:
                self._execute(self.client.table("cves").upsert(chunk))
                done += len(chunk)
            except Exception as e:
                # 묶음이 실패하면 어느 행 탓인지 알 수 없다 → 행 단위로 되돌아간다.
                # WAF 콘텐츠 차단 대응이 upsert_cve에 있으므로 그 경로를 그대로 쓴다.
                logger.warning(f"{label} 배치 저장 실패({len(chunk)}건): {e} → 행 단위 재시도")
                for item in chunk:
                    if self.upsert_cve(item):
                        done += 1
            logger.info(f"  {label} 저장 {min(i + len(chunk), len(updates)):,}/{len(updates):,}")
        return done

    def bulk_set_published(self, rows: List[Dict], published: Dict[str, str]) -> int:
        """이미 조회한 행에 {cve_id: 공개일}을 채워 저장. 갱신 성공 건수 반환.

        rows는 get_rows_missing_published()가 돌려준 그대로 — id와 last_alert_state가
        이미 들어 있어 다시 읽을 필요가 없다."""
        pending = []
        for row in rows:
            cve_id = row.get("id")
            day = published.get(cve_id)
            state = row.get("last_alert_state")
            if not day or not state or state.get("published"):
                continue
            state = dict(state)
            state["published"] = day
            pending.append({"id": cve_id, "last_alert_state": state})
        return self.bulk_save_states(pending, "공개일")

    def get_missing_report_candidates(self, limit: int = 20) -> List[Dict]:
        """알림은 나갔는데 상세 리포트가 없는 CVE (fast-lane이 Slack만 보낸 건).

        정렬은 위험 순이다 — 예산이 모자라 일부만 만들게 되면 T0부터 만들어야 한다.
        last_alert_state를 함께 받는 이유는 리포트 본문이 그 안의 필드를 쓰기 때문이다."""
        try:
            r = self._execute(
                self.client.table("cves")
                .select("id, cvss_score, epss_score, is_kev, last_alert_state, updated_at")
                .not_.is_("last_alert_at", "null")
                .is_("report_url", "null")
                .not_.is_("last_alert_state", "null")
                .order("is_kev", desc=True)
                .order("last_alert_at", desc=True)
                .limit(limit)
            )
            return r.data or []
        except Exception as e:
            logger.error(f"리포트 보강 후보 조회 실패: {e}")
            return []

    # ==================================================================
    # 신호 스냅샷 — 소스측 대조의 '지난번 집합'
    # ==================================================================
    # 왜 별도 테이블인가: cves 테이블은 '우리가 추적하는 CVE'고, 이건 '업스트림이 그때
    # 무엇을 갖고 있었는가'다. 성격이 달라 섞으면 보존정책이 서로를 지운다.
    #
    #   create table if not exists signal_snapshots (
    #     source     text primary key,
    #     digest     text        not null,
    #     cve_ids    jsonb       not null default '[]'::jsonb,
    #     updated_at timestamptz not null default now()
    #   );

    def get_snapshot_digest(self, source: str) -> Optional[str]:
        """스냅샷 지문만 조회 (수십 바이트).

        이게 게이팅의 핵심이다 — 업스트림이 안 바뀐 실행에서는 여기서 끝나므로
        수십만 건짜리 집합을 읽지 않는다(불변 원칙 2)."""
        try:
            r = self._execute(
                self.client.table("signal_snapshots").select("digest")
                .eq("source", source).limit(1)
            )
            rows = r.data or []
            return rows[0].get("digest") if rows else None
        except Exception as e:
            logger.warning(f"스냅샷 지문 조회 실패({source}): {e}")
            return None

    def get_snapshot_ids(self, source: str) -> set:
        """저장된 CVE 집합. 실패하면 빈 집합 — 호출부가 '조회 실패'로 보고 건너뛴다."""
        try:
            r = self._execute(
                self.client.table("signal_snapshots").select("cve_ids")
                .eq("source", source).limit(1)
            )
            rows = r.data or []
            ids = rows[0].get("cve_ids") if rows else None
            return {str(x) for x in ids} if isinstance(ids, list) else set()
        except Exception as e:
            logger.warning(f"스냅샷 집합 조회 실패({source}): {e}")
            return set()

    def save_snapshot(self, source: str, digest: str, ids) -> bool:
        try:
            self._execute(self.client.table("signal_snapshots").upsert({
                "source": source,
                "digest": digest,
                "cve_ids": sorted(ids),
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }))
            return True
        except Exception as e:
            logger.error(f"스냅샷 저장 실패({source}): {e}")
            return False
