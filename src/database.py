import os
from supabase import create_client, Client

class ArgusDB:
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        self.client: Client = create_client(url, key)

    def get_cve(self, cve_id):
        response = self.client.table("cves").select("*").eq("id", cve_id).execute()
        return response.data[0] if response.data else None

    def upsert_cve(self, data):
        self.client.table("cves").upsert(data).execute()

    def upload_report(self, cve_id, content):
        """
        한글 깨짐 방지를 위해 HTML 포맷으로 변환하여 업로드
        """
        file_path = f"{cve_id}.html"
        bucket = "reports"
        
        # HTML 템플릿 적용 (UTF-8 메타태그 포함)
        html_content = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cve_id} Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; padding: 20px; max-width: 800px; margin: 0 auto; color: #333; }}
        h1 {{ border-bottom: 2px solid #eee; padding-bottom: 10px; color: #2c3e50; }}
        h2 {{ margin-top: 30px; color: #34495e; }}
        code {{ background: #f8f9fa; padding: 2px 5px; border-radius: 3px; color: #d63384; }}
        pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #ddd; }}
        blockquote {{ border-left: 4px solid #ccc; margin: 0; padding-left: 10px; color: #666; }}
    </style>
</head>
<body>
    {content.replace(chr(10), '<br>')}
</body>
</html>
        """
        
        try:
            # UTF-8 인코딩 명시
            self.client.storage.from_(bucket).upload(
                file_path, 
                html_content.encode('utf-8'), 
                {
                    "content-type": "text/html; charset=utf-8", 
                    "x-upsert": "true"
                }
            )
        except:
            pass
            
        return self.client.storage.from_(bucket).create_signed_url(file_path, 60 * 60 * 24 * 30)