STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS cves (
        id                 TEXT PRIMARY KEY,
        cvss_score         REAL    NOT NULL DEFAULT 0,
        epss_score         REAL    NOT NULL DEFAULT 0,
        is_kev             INTEGER NOT NULL DEFAULT 0,
        last_alert_state   TEXT,
        last_alert_at      TEXT,
        has_official_rules INTEGER NOT NULL DEFAULT 0,
        rules_snapshot     TEXT,
        last_rule_check_at TEXT,
        updated_at         TEXT,
        has_vendor         INTEGER NOT NULL DEFAULT 0,
        tier         TEXT    GENERATED ALWAYS AS
                     (json_extract(last_alert_state, '$.tier')) VIRTUAL,
        published    TEXT    GENERATED ALWAYS AS
                     (json_extract(last_alert_state, '$.published')) VIRTUAL,
        has_analysis INTEGER GENERATED ALWAYS AS
                     (json_extract(last_alert_state, '$.analysis') IS NOT NULL) VIRTUAL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_cves_updated_at    ON cves(updated_at)",
    "CREATE INDEX IF NOT EXISTS idx_cves_last_alert_at ON cves(last_alert_at)",
    "CREATE INDEX IF NOT EXISTS idx_cves_tier          ON cves(tier)",
    "CREATE INDEX IF NOT EXISTS idx_cves_published     ON cves(published)",
    "CREATE INDEX IF NOT EXISTS idx_cves_analysis      ON cves(has_analysis, tier)",
    "CREATE INDEX IF NOT EXISTS idx_cves_vendor        ON cves(has_vendor)",
    "CREATE INDEX IF NOT EXISTS idx_cves_cvss          ON cves(cvss_score)",
    "CREATE INDEX IF NOT EXISTS idx_cves_rule_check    ON cves(last_rule_check_at)",
    """
    CREATE TABLE IF NOT EXISTS signal_snapshots (
        source     TEXT PRIMARY KEY,
        digest     TEXT NOT NULL,
        cve_ids    TEXT NOT NULL,
        updated_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS pipeline_state (
        key        TEXT PRIMARY KEY,
        value      TEXT,
        updated_at TEXT
    )
    """,
)

TABLES = ("cves", "signal_snapshots", "pipeline_state")


def apply(conn) -> None:
    for statement in STATEMENTS:
        conn.execute(statement)
    conn.commit()


def counts(conn) -> dict:
    return {t: conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
            for t in TABLES}


def indexes(conn) -> list:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%' "
        "ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]
