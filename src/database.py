import os
from supabase import create_client, Client

class ArgusDB:
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        self.client: Client = create_client(url, key)

    def get_cve(self, cve_id):
        """CVE의 이전 상태 조회"""
        response = self.client.table("cves").select("*").eq("id", cve_id).execute()
        return response.data[0] if response.data else None

    def upsert_cve(self, data):
        """CVE 상태 업데이트 (Insert or Update)"""
        self.client.table("cves").upsert(data).execute()

    def upload_report(self, cve_id, content):
        """상세 리포트 업로드 및 Signed URL 생성"""
        file_path = f"{cve_id}.md"
        bucket = "reports"
        
        # 파일 업로드 (덮어쓰기 허용)
        self.client.storage.from_(bucket).upload(
            file_path, 
            content.encode('utf-8'), 
            {"content-type": "text/markdown", "x-upsert": "true"}
        )
        
        # 30일 유효한 Signed URL 생성
        return self.client.storage.from_(bucket).create_signed_url(file_path, 60 * 60 * 24 * 30)