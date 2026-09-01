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

class DatabaseError(Exception):
    pass

class ArgusDB:
    def __init__(self):
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

    @staticmethod
    def _waf_minimal_copy(data: Dict) -> Dict:
        st = data.get("last_alert_state") or {}
        safe_state = {
            "title_ko": _neutralize(st.get("title_ko") or st.get("title", "")),
            "desc_ko": _neutralize((st.get("desc_ko") or "")[:300]),
            "cwe": st.get("cwe", []),
            "cvss": st.get("cvss"), "epss": st.get("epss"), "is_kev": st.get("is_kev"),
            "ssvc_exploitation": st.get("ssvc_exploitation"),
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
            "tier": st.get("tier"),
            "fired_triggers": st.get("fired_triggers", []),
            "waf_degraded": True,
        }
        keep = ("id", "cvss_score", "epss_score", "is_kev", "updated_at",
                "last_alert_at", "report_url",
                "has_official_rules", "last_rule_check_at")
        out = {k: data[k] for k in keep if k in data}
        out["last_alert_state"] = safe_state
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
            logger.info(f"CVE 저장 성공 (WAF 축소본, 원문은 리포트 참조): {cid}")
            return True

        logger.error(f"CVE 저장 실패 ({cid}) — WAF 축소본까지 실패: {_describe_error(err3)}")
        return False
    
    _RECHECK_COLS = ("id, cvss_score, epss_score, is_kev, has_official_rules, "
                     "last_rule_check_at, last_alert_at, report_url")

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
            logger.error(f"룰 재확인 후보 조회 실패: {e}")
            return []
    
    def batch_get_scalar(self, cve_ids: List[str], column: str) -> Dict[str, Any]:
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
        try:
            response = self._execute(
                self.client.table("cves")
                .select("id, last_alert_state")
                .not_.is_("last_alert_state", "null")
                # 정렬 키는 id 다. updated_at 으로 정렬하면 순회가 절대 수렴하지 않는다 —
                # fast-lane 이 5분마다 수십 행의 updated_at 을 갱신해 맨 앞으로 올리므로,
                # offset 이 200씩 전진하는 동안 새로 갱신된 행이 그보다 빠르게 앞에 쌓인다.
                # 결과적으로 창은 늘 '최근에 바뀐 것' 근처에 머물고, 조용한 행은 영영
                # 스캔되지 않는다. 번역이 안 되는 CVE가 고정적으로 남던 이유다.
                .order("id")
                .range(offset, offset + max(1, min(limit, _PAGE_MAX)) - 1)
            )
            return response.data or []
        except Exception as e:
            logger.error(f"번역 백필 후보 조회 실패: {e}")
            return []

    def count_tracked(self) -> int:
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
        page_size = max(1, min(page_size, _PAGE_MAX))
        rows: List[Dict] = []
        offset = 0
        try:
            while offset < max_rows:
                response = self._execute(
                    self.client.table("cves")
                    .select("id, last_alert_state")
                    .not_.is_("last_alert_state", "null")
                    # 정렬 키는 id 다. 이건 전수 스캔이고, updated_at 으로 정렬하면
                    # 페이지를 넘기는 동안 fast-lane 이 갱신한 행이 맨 앞으로 올라와
                    # 창을 통째로 밀어낸다 — 어떤 행은 두 번 보이고 어떤 행은 영영
                    # 안 보인다. 백필이 같은 행만 계속 붙잡던 이유다.
                    .order("id")
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
        return [r for r in self._tracked_states()
                if not (r.get("last_alert_state") or {}).get("published")]

    def get_rows_missing_vendor(self) -> List[Dict]:
        def has_vendor(state: Dict) -> bool:
            return any(
                str(a.get("vendor") or "").strip().lower() not in ("", "unknown", "n/a", "-")
                for a in (state.get("affected") or []) if isinstance(a, dict)
            )
        return [r for r in self._tracked_states()
                if not has_vendor(r.get("last_alert_state") or {})]

    def get_rows_missing_cvss_version(self) -> List[Dict]:
        # cvss_version 키의 유무가 곧 "이 행이 어느 코드로 쓰였는지"다. 지금 파이프라인은
        # 점수가 없어도 빈 문자열로 항상 넣는다(collector.parse_record). 키가 아예 없는
        # 행은 버전을 한 개만 읽고 끊던 옛 코드가 남긴 것이다.
        return [r for r in self._tracked_states()
                if "cvss_version" not in (r.get("last_alert_state") or {})]

    def get_pipeline_state(self) -> Optional[Dict]:
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


    def get_snapshot_digest(self, source: str) -> Optional[str]:
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
