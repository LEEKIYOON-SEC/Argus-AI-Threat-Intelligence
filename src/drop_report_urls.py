import sys

from database import ArgusDB
from logger import logger

_PAGE = 500


def run(dry_run: bool) -> int:
    db = ArgusDB()
    cleared = 0
    while True:
        r = db._execute(
            db.client.table("cves").select("id")
            .not_.is_("report_url", "null").order("id").limit(_PAGE)
        )
        ids = [x["id"] for x in (r.data or []) if x.get("id")]
        if not ids:
            break
        logger.info(f"report_url 있는 행 {len(ids)}건 발견")
        if dry_run:
            cleared += len(ids)
            break
        db._execute(
            db.client.table("cves").update({"report_url": None}).in_("id", ids)
        )
        cleared += len(ids)
        logger.info(f"  누적 {cleared:,}건 정리")

    if dry_run:
        logger.info(f"[dry-run] 정리 대상 최소 {cleared:,}건 — 저장하지 않았다")
        return 0

    logger.info(f"report_url 제거 완료: {cleared:,}건")
    if cleared:
        db.request_full_export()
    return 0


def main() -> int:
    return run("--dry-run" in sys.argv)


if __name__ == "__main__":
    sys.exit(main())
