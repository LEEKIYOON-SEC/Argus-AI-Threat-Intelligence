import os
import re
import time
import copy
import datetime
from supabase import create_client, Client
from typing import Dict, List, Optional, Set, Tuple
from tenacity import (retry, stop_after_attempt, wait_exponential,
                      retry_if_exception, RetryError)
import risk
from fields import meaningful
from logger import logger
from store.base import Store, StoreError

_PAGE_MAX = 1000

_ZWSP = "​"


def _describe_error(e: BaseException) -> str:
    if isinstance(e, RetryError):
        try:
            e = e.last_attempt.exception() or e
        except Exception:
            pass
    msg = f"{type(e).__name__}: {e}"
    for attr in ("message", "code", "details", "hint"):
        v = getattr(e, attr, None)
        if v and str(v) not in msg:
            msg += f" | {attr}={v}"
    return msg


def _is_waf_block(e: BaseException) -> bool:
    s = _describe_error(e).lower()
    return ("you have been blocked" in s or "attention required" in s
            or "cloudflare" in s or "<!doctype html" in s
            or ("403" in s and "html" in s))


def _neutralize(s):
    if not isinstance(s, str) or not s:
        return s
    s = re.sub(r'\.\.(?=[/\\])', '.' + _ZWSP + '.', s)
    s = re.sub(r'/(?=(etc|proc|sys|root|windows|boot)\b)', '/' + _ZWSP, s, flags=re.I)
    s = re.sub(r'<(?=[a-zA-Z/!])', '<' + _ZWSP, s)
    s = re.sub(r'(?i)\b(union|select|insert|drop|delete)(?=\s)',
               lambda m: m.group(1)[0] + _ZWSP + m.group(1)[1:], s)
    return s


class ArgusDB(Store):
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")

        if not url or not key:
            raise StoreError("SUPABASE_URL 또는 SUPABASE_KEY가 설정되지 않음")

        try:
            self.client: Client = create_client(url, key)
            logger.info("Supabase 연결 성공")
        except Exception as e:
            raise StoreError(f"Supabase 연결 실패: {e}") from e


    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception(lambda e: not _is_waf_block(e))
    )
    def _execute(self, query):
        return query.execute()


    def _try_upsert(self, data: Dict) -> Tuple[bool, Optional[BaseException]]:
        try:
            self._execute(self.client.table("cves").upsert(data))
            return True, None
        except Exception as e:
            return False, e


    @staticmethod
    def _neutralize_deep(value, depth: int = 0):
        if depth > 6:
            return value
        if isinstance(value, str):
            return _neutralize(value)
        if isinstance(value, list):
            return [ArgusDB._neutralize_deep(v, depth + 1) for v in value]
        if isinstance(value, dict):
            return {k: ArgusDB._neutralize_deep(v, depth + 1) for k, v in value.items()}
        return value


    @staticmethod
    def _waf_neutralized_copy(data: Dict) -> Dict:
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


    _WAF_CLIP = (("description", 300), ("desc_ko", 300),
                 ("title", 200), ("title_ko", 200))
    _WAF_LIST_CAP = (("affected", 20), ("references", 5), ("poc_urls", 3),
                     ("metasploit_modules", 3), ("cwe", 10))


    @staticmethod
    def _waf_minimal_copy(data: Dict) -> Dict:
        d = ArgusDB._waf_neutralized_copy(data)
        st = d.get("last_alert_state")
        if not isinstance(st, dict):
            return d
        for key, cap in ArgusDB._WAF_CLIP:
            if isinstance(st.get(key), str) and len(st[key]) > cap:
                st[key] = st[key][:cap]
        for key, cap in ArgusDB._WAF_LIST_CAP:
            if isinstance(st.get(key), list) and len(st[key]) > cap:
                st[key] = st[key][:cap]
        d["last_alert_state"] = ArgusDB._neutralize_deep(st)
        d["last_alert_state"]["waf_degraded"] = True
        return d


    _WAF_TEXT = ("description", "title", "references", "poc_urls",
                 "_exploit_db_url", "_nuclei_url", "ai_detail", "ai_url")


    @staticmethod
    def _waf_text_stripped_copy(data: Dict) -> Dict:
        d = ArgusDB._waf_minimal_copy(data)
        st = d.get("last_alert_state")
        if isinstance(st, dict):
            for key in ArgusDB._WAF_TEXT:
                st.pop(key, None)
        return d


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
            raise StoreError(f"CVE 조회 실패 ({cve_id}): {e}") from e


    def get_cves(self, cve_ids) -> Tuple[Dict[str, Dict], set]:
        ids = [str(c) for c in cve_ids if c]
        rows: Dict[str, Dict] = {}
        covered: set = set()
        if not ids:
            return rows, covered

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
                logger.warning(f"CVE 일괄 조회 실패 ({len(chunk)}건): {_describe_error(e)} "
                               f"→ 해당 건은 개별 조회로 폴백")
        return rows, covered


    def upsert_cve(self, data: Dict) -> bool:
        cid = data.get('id')
        ok, err = self._try_upsert(data)
        if ok:
            logger.debug(f"CVE 저장 성공: {cid}")
            return True

        if not _is_waf_block(err):
            logger.warning(f"CVE 저장 1차 실패 ({cid}): {_describe_error(err)} → 25초 후 재시도")
            time.sleep(25)
            ok, err = self._try_upsert(data)
            if ok:
                logger.info(f"CVE 저장 재시도 성공: {cid}")
                return True
            if not _is_waf_block(err):
                logger.error(f"CVE 저장 실패 ({cid}): {_describe_error(err)}")
                return False

        logger.warning(f"⚠️ CVE 저장 WAF 콘텐츠 차단 ({cid}) — 페이로드성 문자열 무력화 후 재저장 시도")
        ok, err2 = self._try_upsert(self._waf_neutralized_copy(data))
        if ok:
            logger.info(f"CVE 저장 성공 (WAF 우회, 원문 보존): {cid}")
            return True

        ok, err3 = self._try_upsert(self._waf_minimal_copy(data))
        if ok:
            logger.info(f"CVE 저장 성공 (WAF 축소본 — 본문만 줄이고 신호는 전부 보존): {cid}")
            return True

        ok, err4 = self._try_upsert(self._waf_text_stripped_copy(data))
        if ok:
            logger.warning(f"CVE 저장 성공 (WAF 본문 제거 — 원문은 리포트 참조): {cid}")
            return True

        logger.error(f"CVE 저장 실패 ({cid}) — 본문 제거까지 실패: "
                     f"{_describe_error(err4)} (직전 오류: {_describe_error(err3)})")
        return False
    
    _RECHECK_COLS = ("id, cvss_score, epss_score, is_kev, has_official_rules, "
                     "last_rule_check_at, last_alert_at")


    def get_rule_recheck_candidates(self, limit: int = 10) -> List[Dict]:
        try:
            fetch_n = max(limit * 3, 30)
            cutoff_7d = (datetime.datetime.now(datetime.timezone.utc)
                         - datetime.timedelta(days=7)).isoformat()
            cooldown = f"last_rule_check_at.is.null,last_rule_check_at.lt.{cutoff_7d}"


            def _query(base):
                return self._execute(
                    base.or_(cooldown)
                        .order("is_kev", desc=True)
                        .order("cvss_score", desc=True)
                        .order("epss_score", desc=True)
                        .limit(fetch_n)
                )

            norules_response = _query(
                self.client.table("cves")
                .select(self._RECHECK_COLS)
                .eq("has_official_rules", False)
                .not_.is_("rules_snapshot", "null")
            )

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

                last_check = record.get('last_rule_check_at') or ''
                if last_check:
                    try:
                        last_check_dt = datetime.datetime.fromisoformat(last_check.replace('Z', '+00:00'))
                        days_since = (now - last_check_dt).days

                        if record.get('has_official_rules'):
                            continue

                        if days_since < 7:
                            continue
                    except (ValueError, TypeError):
                        pass

                if is_kev or epss > 0:
                    eligible.append(record)
                    continue

                if cvss < 7.0:
                    continue

                max_age_days = 180 if cvss >= 9.0 else 90

                created_at = record.get('last_alert_at') or ''
                if created_at:
                    try:
                        created_dt = datetime.datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        if (now - created_dt).days > max_age_days:
                            continue
                    except (ValueError, TypeError):
                        pass

                eligible.append(record)

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
            raise StoreError(f"룰 재확인 후보 조회 실패: {e}") from e


    def get_translation_backfill_candidates(self, limit: int = 60,
                                            offset: int = 0) -> List[Dict]:
        try:
            response = self._execute(
                self.client.table("cves")
                .select("id, last_alert_state")
                .not_.is_("last_alert_state", "null")
                .order("id")
                .range(offset, offset + max(1, min(limit, _PAGE_MAX)) - 1)
            )
            return response.data or []
        except Exception as e:
            raise StoreError(f"번역 백필 후보 조회 실패: {e}") from e


    def count_tracked(self) -> int:
        try:
            r = self._execute(
                self.client.table("cves").select("id", count="exact")
                .not_.is_("last_alert_state", "null").limit(1)
            )
            return r.count or 0
        except Exception as e:
            raise StoreError(f"추적 행 수 조회 실패: {e}") from e


    def update_translation(self, cve_id: str, title_ko: str, desc_ko: str) -> bool:
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
        page_size = max(1, min(page_size, _PAGE_MAX))
        ids: List[str] = []
        offset = 0
        while offset < max_rows:
            response = self._execute(
                self.client.table("cves")
                .select("id")
                .not_.is_("last_alert_state", "null")
                .order("id")
                .range(offset, offset + page_size - 1)
            )
            batch = response.data or []
            ids.extend(r["id"] for r in batch if r.get("id"))
            if len(batch) < page_size:
                break
            offset += page_size
        return ids


    def tracked_states(self, page_size: int = 1000, max_rows: int = 50000) -> List[Dict]:
        page_size = max(1, min(page_size, _PAGE_MAX))
        rows: List[Dict] = []
        offset = 0
        while offset < max_rows:
            try:
                response = self._execute(
                    self.client.table("cves")
                    .select("id, last_alert_state")
                    .not_.is_("last_alert_state", "null")
                    .order("id")
                    .range(offset, offset + page_size - 1)
                )
            except Exception as e:
                logger.error(f"추적 행 조회 실패 (offset {offset:,}, 여기까지 "
                             f"{len(rows):,}건) — 이 뒤는 '없음'이 아니라 '못 봤음'이다: {e}")
                raise
            batch = response.data or []
            rows.extend(batch)
            if len(batch) < page_size:
                break
            offset += page_size
        return rows


    def get_rows_missing_published(self) -> List[Dict]:
        return [r for r in self.tracked_states()
                if not (r.get("last_alert_state") or {}).get("published")]


    def get_rows_missing_vendor(self) -> List[Dict]:
        def has_vendor(state: Dict) -> bool:
            return any(meaningful(a.get("vendor"))
                       for a in (state.get("affected") or []) if isinstance(a, dict))
        return [r for r in self.tracked_states()
                if not has_vendor(r.get("last_alert_state") or {})]


    def get_rows_needing_cvss(self) -> List[Dict]:
        def needs(state: Dict) -> bool:
            return ("cvss_version" not in state
                    or float(state.get("cvss") or 0.0) <= 0.0)
        return [r for r in self.tracked_states()
                if needs(r.get("last_alert_state") or {})]


    def get_pipeline_state(self) -> Dict:
        try:
            response = self._execute(
                self.client.table("pipeline_state").select("state").eq("id", 1).limit(1)
            )
            rows = response.data or []
            state = rows[0].get("state") if rows else None
            return state if isinstance(state, dict) else {}
        except Exception as e:
            raise StoreError(f"파이프라인 상태 조회 실패: {e}") from e


    def set_pipeline_state(self, state: Dict) -> bool:
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
        state = self.get_pipeline_state() or {}
        state["force_full_export"] = True
        return self.set_pipeline_state(state)


    def take_full_export_flag(self) -> bool:
        state = self.get_pipeline_state()
        if not state.get("force_full_export"):
            return False
        state.pop("force_full_export", None)
        return self.set_pipeline_state(state)

    _EXPORT_COLS = ("id, cvss_score, epss_score, is_kev, has_official_rules, "
                    "last_alert_at, last_alert_state, rules_snapshot, updated_at")
    _PAGE = 1000


    def _paged(self, build, cols: str) -> List[Dict]:
        rows, offset = [], 0
        while True:
            page = self._execute(
                build().select(cols).order("id")
                .range(offset, offset + self._PAGE - 1)).data or []
            rows.extend(page)
            if len(page) < self._PAGE:
                return rows
            offset += self._PAGE


    def export_rows(self, since: Optional[str], days: int = 90) -> List[Dict]:
        cutoff = since or self._days_ago(days)
        try:
            return self._paged(
                lambda: self.client.table("cves")
                .gte("updated_at", cutoff).not_.is_("last_alert_state", "null"),
                self._EXPORT_COLS)
        except Exception as e:
            raise StoreError(f"export 조회 실패: {e}") from e


    def live_ids(self, days: int = 90) -> Set[str]:
        try:
            rows = self._paged(
                lambda: self.client.table("cves")
                .gte("updated_at", self._days_ago(days))
                .not_.is_("last_alert_state", "null"), "id")
        except Exception as e:
            raise StoreError(f"생존 id 조회 실패: {e}") from e
        return {r["id"] for r in rows if r.get("id")}


    def count_rows(self, tracked: bool = False) -> int:
        try:
            q = self.client.table("cves").select("id", count="exact").limit(1)
            if tracked:
                q = q.not_.is_("last_alert_state", "null")
            return self._execute(q).count or 0
        except Exception as e:
            raise StoreError(f"행 수 조회 실패: {e}") from e

    _RETENTION_COLS = "id, is_kev, cvss_score, epss_score, last_alert_state"


    def retention_rows(self, before: str, limit: int, *, tracked: bool = False,
                       unalerted: bool = False, oldest_first: bool = False
                       ) -> List[Dict]:
        try:
            q = self.client.table("cves").select(self._RETENTION_COLS) \
                .lt("updated_at", before)
            if tracked:
                q = q.not_.is_("last_alert_state", "null")
            if unalerted:
                q = q.is_("last_alert_at", "null")
            q = q.order("updated_at" if oldest_first else "id").limit(max(1, limit))
            return self._execute(q).data or []
        except Exception as e:
            raise StoreError(f"보존 대상 조회 실패: {e}") from e


    def delete_markers(self, before: str, limit: int) -> int:
        try:
            victims = self._execute(
                self.client.table("cves").select("id")
                .is_("last_alert_state", "null").is_("last_alert_at", "null")
                .lt("updated_at", before).order("updated_at")
                .limit(max(1, limit))).data or []
        except Exception as e:
            raise StoreError(f"구 마커 조회 실패: {e}") from e
        return self.delete_rows([r["id"] for r in victims if r.get("id")])


    def blank_states(self, ids) -> int:
        return self._chunked(
            ids, lambda chunk: self.client.table("cves")
            .update({"rules_snapshot": None, "last_alert_state": None}).in_("id", chunk),
            "상태 비우기")


    def delete_rows(self, ids) -> int:
        return self._chunked(
            ids, lambda chunk: self.client.table("cves").delete().in_("id", chunk),
            "행 삭제")


    def _chunked(self, ids, build, label: str) -> int:
        todo = [str(i) for i in ids if i]
        done = 0
        for i in range(0, len(todo), self._STATE_CHUNK):
            chunk = todo[i:i + self._STATE_CHUNK]
            try:
                self._execute(build(chunk))
            except Exception as e:
                raise StoreError(f"{label} 실패({len(chunk)}건): {e}") from e
            done += len(chunk)
        return done


    @staticmethod
    def _days_ago(days: int) -> str:
        return (datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=days)).isoformat()

    _STATE_CHUNK = 200


    def bulk_save_states(self, updates: List[Dict], label: str = "상태") -> int:
        if not updates:
            return 0
        done = 0
        for i in range(0, len(updates), self._STATE_CHUNK):
            chunk = updates[i:i + self._STATE_CHUNK]
            try:
                self._execute(self.client.table("cves").upsert(chunk))
                done += len(chunk)
            except Exception as e:
                logger.warning(f"{label} 배치 저장 실패({len(chunk)}건): {e} → 행 단위 재시도")
                for item in chunk:
                    if self.upsert_cve(item):
                        done += 1
            logger.info(f"  {label} 저장 {min(i + len(chunk), len(updates)):,}/{len(updates):,}")
        return done


    def bulk_set_published(self, rows: List[Dict], published: Dict[str, str]) -> int:
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
        try:
            r = self._execute(
                self.client.table("cves")
                .select("id, cvss_score, epss_score, is_kev, last_alert_state, updated_at")
                .not_.is_("last_alert_state", "null")
                .is_("last_alert_state->analysis", "null")
                .in_("last_alert_state->>tier", [risk.T0, risk.T1])
                .order("last_alert_state->>tier")
                .order("is_kev", desc=True)
                .order("cvss_score", desc=True)
                .limit(limit)
            )
            return r.data or []
        except Exception as e:
            raise StoreError(f"리포트 보강 후보 조회 실패: {e}") from e


    def count_missing_reports(self) -> Dict[str, int]:
        out = {}
        for tier in (risk.T0, risk.T1):
            try:
                r = self._execute(
                    self.client.table("cves").select("id", count="exact").limit(1)
                    .not_.is_("last_alert_state", "null")
                    .is_("last_alert_state->analysis", "null")
                    .eq("last_alert_state->>tier", tier))
            except Exception as e:
                raise StoreError(f"분석 잔량 조회 실패({tier}): {e}") from e
            if r.count:
                out[tier] = r.count
        return out


    def get_snapshot_digest(self, source: str) -> Optional[str]:
        r = self._execute(
            self.client.table("signal_snapshots").select("digest")
            .eq("source", source).limit(1)
        )
        rows = r.data or []
        return rows[0].get("digest") if rows else None


    def get_snapshot_ids(self, source: str) -> set:
        r = self._execute(
            self.client.table("signal_snapshots").select("cve_ids")
            .eq("source", source).limit(1)
        )
        rows = r.data or []
        ids = rows[0].get("cve_ids") if rows else None
        return {str(x) for x in ids} if isinstance(ids, list) else set()


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
