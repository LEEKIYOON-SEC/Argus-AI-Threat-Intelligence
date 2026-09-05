import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import turso_schema
from logger import logger


def _redact(url: str) -> str:
    scheme, _, rest = url.partition("://")
    host = rest.split("/")[0].split("?")[0]
    if "." in host:
        first, _, tail = host.partition(".")
        head = first[:4] + "…" if len(first) > 4 else first
        host = f"{head}.{tail}"
    return f"{scheme}://{host}"


def main() -> int:
    url = (os.environ.get("TURSO_DATABASE_URL") or "").strip()
    token = (os.environ.get("TURSO_AUTH_TOKEN") or "").strip()

    logger.info("=" * 60)
    logger.info("Turso 연결 점검")
    logger.info("=" * 60)

    missing = [n for n, v in (("TURSO_DATABASE_URL", url),
                              ("TURSO_AUTH_TOKEN", token)) if not v]
    if missing:
        logger.error(f"시크릿 누락: {', '.join(missing)}")
        return 1

    logger.info(f"URL: {_redact(url)}")
    logger.info(f"토큰 길이: {len(token)}자")

    scheme = url.split("://", 1)[0]
    if scheme in ("libsql", "wss", "https"):
        logger.info(f"스킴 '{scheme}' — libSQL 경로 (운영 권장)")
    else:
        logger.warning(f"스킴 '{scheme}' — 예상 밖. libsql:// 이 아니면 엔진을 확인해야 한다")

    try:
        import libsql
    except ImportError as e:
        logger.error(f"libsql 패키지 없음: {e}")
        return 1

    try:
        conn = libsql.connect(database=url, auth_token=token)
        version = conn.execute("SELECT sqlite_version()").fetchone()[0]
        logger.info(f"연결 성공 · SQLite 호환 버전 {version}")
    except Exception as e:
        logger.error(f"연결 실패: {type(e).__name__}: {e}")
        return 1

    before = set(turso_schema.indexes(conn))
    try:
        turso_schema.apply(conn)
    except Exception as e:
        logger.error(f"스키마 적용 실패: {type(e).__name__}: {e}")
        return 1

    after = turso_schema.indexes(conn)
    created = [i for i in after if i not in before]
    logger.info(f"스키마 적용 완료 · 인덱스 {len(after)}개"
                + (f" (이번에 생성 {len(created)}개)" if created else " (변경 없음)"))

    for table, n in turso_schema.counts(conn).items():
        logger.info(f"  {table:18s}: {n:,}행")

    logger.info("=" * 60)
    logger.info("점검 통과 — 재시드를 받을 준비가 됐다")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
