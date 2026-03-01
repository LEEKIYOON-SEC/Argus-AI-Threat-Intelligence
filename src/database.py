import os
import datetime
from supabase import create_client, Client
from typing import Dict, List, Optional
from logger import logger

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
    
    def get_cve(self, cve_id: str) -> Optional[Dict]:
        try:
            response = self.client.table("cves").select("*").eq("id", cve_id).execute()
            
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
        try:
            self.client.table("cves").upsert(data).execute()
            logger.debug(f"CVE 저장 성공: {data.get('id')}")
            return True
        except Exception as e:
            logger.error(f"CVE 저장 실패 ({data.get('id')}): {e}")
            return False
    
    def get_ai_generated_cves(self, days: int = 7) -> List[Dict]:
        """
        공식 룰 재확인이 필요한 고위험 CVE 조회.

        대상:
        1. AI 룰만 있는 CVE (has_official_rules=False, rules_snapshot != null) — 공식 룰 교체 필요
        2. 룰이 아예 없는 고위험 CVE (CVSS >= 7.0 or KEV) — 새로 공식 룰 나왔을 수 있음

        쿨다운:
        - 성공 시: 7일 후 재확인
        - 실패 시: 1일 후 재시도 (빠른 복구)
        """
        try:
            # Case 1: AI 룰만 있는 CVE
            ai_response = self.client.table("cves") \
                .select("*") \
                .eq("has_official_rules", False) \
                .not_.is_("rules_snapshot", "null") \
                .execute()

            # Case 2: 룰이 아예 없는 고위험 CVE (CVSS >= 7.0)
            norule_response = self.client.table("cves") \
                .select("*") \
                .is_("rules_snapshot", "null") \
                .gte("cvss_score", 7.0) \
                .execute()

            all_records = {}
            for record in (ai_response.data or []):
                all_records[record['id']] = record
            for record in (norule_response.data or []):
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

            total = len(ai_response.data or []) + len(norule_response.data or [])
            logger.info(f"AI 생성 룰 CVE: {total}건 중 재확인 대상: {len(eligible)}건")
            return eligible

        except Exception as e:
            logger.error(f"AI 생성 CVE 조회 실패: {e}")
            return []
    
    def batch_get_content_hashes(self, cve_ids: List[str]) -> Dict[str, str]:
        """여러 CVE의 콘텐츠 해시를 한번에 조회 (API 호출 최소화)"""
        result = {}
        if not cve_ids:
            return result

        try:
            for i in range(0, len(cve_ids), 50):
                chunk = cve_ids[i:i+50]
                response = self.client.table("cves").select("id, content_hash").in_("id", chunk).execute()
                for row in (response.data or []):
                    if row.get('content_hash'):
                        result[row['id']] = row['content_hash']

            logger.debug(f"배치 해시 조회: {len(cve_ids)}건 요청, {len(result)}건 발견")
            return result
        except Exception as e:
            logger.error(f"배치 해시 조회 실패: {e}")
            return result

    def get_all_cves_for_dashboard(self, days: int = 90) -> List[Dict]:
        """대시보드용 CVE 데이터 조회 (최근 N일)"""
        try:
            cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).isoformat()
            response = self.client.table("cves") \
                .select("id, cvss_score, epss_score, is_kev, last_alert_at, last_alert_state, report_url, updated_at") \
                .gte("updated_at", cutoff) \
                .order("updated_at", desc=True) \
                .execute()
            return response.data or []
        except Exception as e:
            logger.error(f"대시보드 CVE 조회 실패: {e}")
            return []
