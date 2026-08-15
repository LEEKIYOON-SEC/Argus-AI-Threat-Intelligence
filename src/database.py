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
        목적: 어떤 콘텐츠든 저장을 성사시켜 content_hash를 전진 → 매 실행 중복 이슈/재분석
        (poison-pill)을 끊는 것. 표시용 한국어 요약은 ZWSP로 무력화해 함께 보존 시도."""
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
            "published": st.get("published", ""),
            "has_poc": st.get("has_poc", False),
            "has_public_exploit": st.get("has_public_exploit", False),
            "has_metasploit_module": st.get("has_metasploit_module", False),
            "waf_degraded": True,  # 대시보드/모달에서 '원문은 리포트 참조' 안내에 사용 가능
        }
        keep = ("id", "cvss_score", "epss_score", "is_kev", "updated_at",
                "content_hash", "last_alert_at", "report_url",
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
                is_kev = record.get('is_kev', False)
                epss = record.get('epss_score', 0) or 0

                # 쿨다운 체크 (성공: 7일, 실패: 1일)
                last_check = record.get('last_rule_check_at', '')
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

                created_at = record.get('last_alert_at', record.get('created_at', ''))
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
    
    def batch_get_content_hashes(self, cve_ids: List[str]) -> Dict[str, str]:
        """여러 CVE의 콘텐츠 해시를 한번에 조회 (API 호출 최소화)"""
        result = {}
        if not cve_ids:
            return result

        try:
            for i in range(0, len(cve_ids), 50):
                chunk = cve_ids[i:i+50]
                response = self._execute(
                    self.client.table("cves").select("id, content_hash").in_("id", chunk)
                )
                for row in (response.data or []):
                    if row.get('content_hash'):
                        result[row['id']] = row['content_hash']

            logger.debug(f"배치 해시 조회: {len(cve_ids)}건 요청, {len(result)}건 발견")
            return result
        except Exception as e:
            logger.error(f"배치 해시 조회 실패: {e}")
            return result

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

    def get_translation_backfill_candidates(self, limit: int = 60) -> List[Dict]:
        """한국어 번역이 안 된 채 남은 추적 CVE (대시보드 품질 백필용).

        번역은 Phase B에서 하지만 시간 예산 초과 시 영문 폴백으로 저장된다. 그 행들은
        레코드가 다시 바뀌지 않는 한 영영 영문으로 남아 대시보드 절반이 영문이 된다.
        여기서 후보를 받아 재번역한다. '영문 여부' 판정은 JSONB 내부 값 비교라
        서버 필터로 표현하기 어려워 파이썬에서 거른다 — 그래서 최신순 limit건만 받는다.
        """
        try:
            response = self._execute(
                self.client.table("cves")
                .select("id, last_alert_state")
                .not_.is_("last_alert_state", "null")
                .order("updated_at", desc=True)
                .limit(limit)
            )
            return response.data or []
        except Exception as e:
            logger.error(f"번역 백필 후보 조회 실패: {e}")
            return []

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

    def _tracked_states(self, limit: int = 20000) -> List[Dict]:
        """추적 행의 id + last_alert_state. 소급 백필의 공통 입력.

        JSONB 내부 조건(키 존재·배열 내부 값)은 서버 필터로 표현하기 번거로워
        호출부가 파이썬에서 거른다. 마커 행은 대시보드에 안 나오므로 제외한다."""
        try:
            response = self._execute(
                self.client.table("cves")
                .select("id, last_alert_state")
                .not_.is_("last_alert_state", "null")
                .order("updated_at", desc=True)
                .limit(limit)
            )
            return response.data or []
        except Exception as e:
            logger.error(f"추적 행 조회 실패: {e}")
            return []

    def get_rows_missing_published(self, limit: int = 20000) -> List[Dict]:
        """공개일(published)이 아직 없는 추적 행 — 소급 백필 대상."""
        return [r for r in self._tracked_states(limit)
                if not (r.get("last_alert_state") or {}).get("published")]

    def get_rows_missing_vendor(self, limit: int = 20000) -> List[Dict]:
        """영향 벤더가 하나도 없는 추적 행 — NVD CPE 소급 백필 대상.

        원본 CNA 레코드가 'n/a'인 경우가 있는데, 그때도 NVD CPE에는 벤더/제품이
        들어 있곤 한다. 벤더가 비면 대시보드 벤더 필터에서 통째로 빠진다."""
        def has_vendor(state: Dict) -> bool:
            return any(
                str(a.get("vendor") or "").strip().lower() not in ("", "unknown", "n/a", "-")
                for a in (state.get("affected") or []) if isinstance(a, dict)
            )
        return [r for r in self._tracked_states(limit)
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

    def get_escalation_candidates(self, days: int = 30, limit: int = 300) -> List[Dict]:
        """외부 피드(KEV/EPSS/Metasploit) 단독 변화로 고위험 승격 가능성이 있는 '현재 저위험' CVE.

        파이프라인은 cvelistV5 커밋(레코드 변경)을 트리거로 재수집하므로, 레코드는 그대로인데
        외부 피드만 바뀐 CVE는 재수집 큐에 안 올라와 에스컬레이션(재알림)이 누락될 수 있다.
        이 후보들을 주기적으로 재평가하기 위한 읽기 전용 조회다(스키마 변경 없음).

        대상 = is_kev=false 인 추적 행(최근 N일, 최신순 limit건).

        예전에는 여기에 cvss_score < 7 조건이 있었다. '이미 고위험이면 알림이 나갔다'는
        전제였는데, High(7~8.9)는 대시보드 추적만 하고 리포트·즉시 알림이 나가지 않으므로
        전제가 성립하지 않았다. 그 결과 High/Critical 행이 나중에 Metasploit·ExploitDB
        신호를 얻어도 재평가되지 않았다 → 조건을 제거했다.

        KEV·EPSS 전이는 main의 신호 드리프트 대조(_kev_drift_candidates /
        _epss_surge_candidates)가 소스 쪽에서 역방향으로 잡으므로 여기서는 중복되지 않는다.
        이 스윕은 전량 목록이 없는 신호(Metasploit·ExploitDB)를 담당한다.
        last_alert_state(JSONB)에 비교용 필드가 모두 있으므로 그대로 반환한다.
        """
        try:
            cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).isoformat()
            response = self._execute(
                self.client.table("cves")
                .select("id, cvss_score, epss_score, is_kev, last_alert_state, report_url, updated_at")
                .gte("updated_at", cutoff)
                .eq("is_kev", False)
                .not_.is_("last_alert_state", "null")
                .order("updated_at", desc=True)
                .limit(limit)
            )
            return response.data or []
        except Exception as e:
            logger.error(f"에스컬레이션 후보 조회 실패: {e}")
            return []

