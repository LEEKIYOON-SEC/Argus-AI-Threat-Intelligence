import os

from .base import Store, StoreError


def create_store(kind: str = "") -> Store:
    kind = (kind or os.environ.get("ARGUS_STORE", "turso")).strip().lower()
    if kind != "turso":
        raise StoreError(f"알 수 없는 ARGUS_STORE: {kind} (turso 만 지원한다)")
    from .turso_store import TursoStore
    return TursoStore()
