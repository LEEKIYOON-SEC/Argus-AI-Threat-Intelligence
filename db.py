from supabase import create_client
from config import SUPABASE_URL, SUPABASE_KEY

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def upsert(table: str, data: dict):
    supabase.table(table).upsert(data).execute()

def get_one(table: str, key: str, value):
    res = supabase.table(table).select("*").eq(key, value).limit(1).execute()
    return res.data[0] if res.data else None
