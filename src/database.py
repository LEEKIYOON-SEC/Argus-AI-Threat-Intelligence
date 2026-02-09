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
        file_path = f"{cve_id}.md"
        bucket = "reports"
        encoded_content = content.encode('utf-8')
        try:
            self.client.storage.from_(bucket).upload(
                file_path, 
                encoded_content, 
                {"content-type": "text/markdown; charset=utf-8", "x-upsert": "true"}
            )
        except:
            pass
        return self.client.storage.from_(bucket).create_signed_url(file_path, 60 * 60 * 24 * 30)