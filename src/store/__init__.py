import os

from .base import Store, StoreError


def create_store(kind: str = "") -> Store:
    kind = (kind or os.environ.get("ARGUS_STORE", "supabase")).strip().lower()
    if kind == "turso":
        from .turso_store import TursoStore
        return TursoStore()
    if kind == "supabase":
        from database import ArgusDB
        return ArgusDB()
    raise StoreError(f"알 수 없는 ARGUS_STORE: {kind}")
