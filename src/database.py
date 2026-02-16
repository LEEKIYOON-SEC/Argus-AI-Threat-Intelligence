import os
import datetime
from supabase import create_client, Client
from typing import Dict, List, Optional
from logger import logger

class DatabaseError(Exception):
    """데이터베이스 관련 에러"""
    pass

class ArgusDB:
    """
    Supabase 데이터베이스 인터페이스
    
    역할:
    1. CVE 처리 이력 저장/조회
    2. 룰 이력 추적
    3. 공식 룰 재발견 대상 조회
    
    개선사항:
    - 포괄적 에러 처리
    - 명확한 로깅
    - 타입 힌팅으로 코드 가독성 향상
    
    비유:
    이 클래스는 도서관 사서와 같아요.
    - 책(CVE 정보)을 저장하고
    - 필요할 때 찾아주고
    - 기록을 관리합니다
    """
    
    def __init__(self):
        """
        데이터베이스 연결 초기화
        
        환경 변수에서 Supabase URL과 KEY를 가져와서 연결합니다.
        연결 실패 시 명확한 에러 메시지를 제공해요.
        """
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
        """
        CVE 처리 이력 조회
        
        이전에 이 CVE를 처리한 적이 있는지 확인합니다.
        있으면 그때의 정보를 반환하고, 없으면 None을 반환해요.
        
        Args:
            cve_id: CVE-2024-12345 형식
        
        Returns:
            CVE 레코드 또는 None
        
        왜 필요한가요?
        - 같은 CVE에 대해 매번 알림을 보내면 스팸이 됩니다
        - 이전 상태와 비교해서 변화가 있을 때만 알림을 보내야 해요
        """
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
        """
        CVE 처리 이력 저장/업데이트
        
        Upsert = Update + Insert의 합성어예요.
        - 레코드가 없으면 새로 만들고 (Insert)
        - 있으면 업데이트합니다 (Update)
        
        Args:
            data: 저장할 CVE 데이터
        
        Returns:
            성공 여부
        
        왜 upsert인가요?
        - 레코드가 있는지 먼저 확인하고, 있으면 update, 없으면 insert...
          이렇게 하면 코드가 복잡해져요
        - upsert를 쓰면 한 줄로 해결!
        """
        try:
            self.client.table("cves").upsert(data).execute()
            logger.debug(f"CVE 저장 성공: {data.get('id')}")
            return True
        except Exception as e:
            logger.error(f"CVE 저장 실패 ({data.get('id')}): {e}")
            return False
    
    def get_ai_generated_cves(self, days: int = 7) -> List[Dict]:
        """
        공식 룰 재확인 대상 CVE 조회 (v2.1 - KEV/EPSS 무기한)
        
        보존 기간:
        - KEV 등재 또는 EPSS > 0: 무기한 (공식 룰 발견까지 계속 확인)
        - CVSS 9.0+: 6개월간 재확인
        - CVSS 7.0~8.9: 3개월간 재확인
        - CVSS 7.0 미만: 재확인 안 함
        
        쿨다운: 전체 공통 7일 (마지막 체크 후 7일 미만이면 스킵)
        """
        try:
            response = self.client.table("cves") \
                .select("*") \
                .eq("has_official_rules", False) \
                .not_.is_("rules_snapshot", "null") \
                .execute()
            
            if not response.data:
                logger.info("AI 생성 룰 CVE: 0건")
                return []
            
            now = datetime.datetime.now(datetime.timezone.utc)
            eligible = []
            
            for record in response.data:
                cvss = record.get('cvss_score', 0) or 0
                is_kev = record.get('is_kev', False)
                epss = record.get('epss_score', 0) or 0
                
                # 최근 7일 이내에 이미 체크했으면 스킵 (공통 쿨다운)
                last_check = record.get('last_rule_check_at', '')
                if last_check:
                    try:
                        last_check_dt = datetime.datetime.fromisoformat(last_check.replace('Z', '+00:00'))
                        if (now - last_check_dt).days < 7:
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
            
            logger.info(f"AI 생성 룰 CVE: {len(response.data)}건 중 재확인 대상: {len(eligible)}건")
            return eligible
            
        except Exception as e:
            logger.error(f"AI 생성 CVE 조회 실패: {e}")
            return []
    
    def get_report_url(self, cve_id: str) -> Optional[str]:
        """
        GitHub Issue URL 조회
        
        공식 룰 발견 시 기존 Issue를 업데이트하기 위해
        URL이 필요해요.
        
        Args:
            cve_id: CVE ID
        
        Returns:
            GitHub Issue URL 또는 None
        """
        try:
            record = self.get_cve(cve_id)
            return record.get('report_url') if record else None
        except Exception as e:
            logger.error(f"Report URL 조회 실패: {e}")
            return None