"""
Database helpers: connection, schema creation, CSV ingestion, query execution.
"""

import logging
import time
from pathlib import Path
from typing import Optional

import pandas as pd
import psycopg
from sqlalchemy import create_engine, text

from src.config import (
    DATABASE_URL,
    QUERY_TIMEOUT_MS,
    SCHEMA_COLUMNS,
    TABLE_NAME,
)

logger = logging.getLogger(__name__)


# ── Engine (reused across calls) ──────────────────────────────────────────────

_engine = None


def get_engine():
    """Return a SQLAlchemy engine (lazily created, reused)."""
    global _engine
    if _engine is None:
        _engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    return _engine


# ── Schema ────────────────────────────────────────────────────────────────────

# Build the CREATE TABLE statement cleanly
_col_defs = ",\n".join(f'    "{col}" {dtype}' for col, dtype in SCHEMA_COLUMNS)
CREATE_TABLE_SQL = f"CREATE TABLE IF NOT EXISTS {TABLE_NAME} (\n{_col_defs}\n);"

_INDEXES_SQL = [
    f'CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_eventname  ON {TABLE_NAME} ("eventName");',
    f'CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_eventtime  ON {TABLE_NAME} ("eventTime");',
    f'CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_usertype   ON {TABLE_NAME} ("userIdentitytype");',
    f'CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_errorcode  ON {TABLE_NAME} ("errorCode");',
    f'CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_useragent  ON {TABLE_NAME} ("userAgent");',
    f'CREATE INDEX IF NOT EXISTS idx_{TABLE_NAME}_sourceip   ON {TABLE_NAME} ("sourceIPAddress");',
]


def ensure_schema() -> None:
    """Create the table and indexes if they don't already exist."""
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text(CREATE_TABLE_SQL))
        for idx_sql in _INDEXES_SQL:
            conn.execute(text(idx_sql))
    logger.info("Schema ensured for table %s.", TABLE_NAME)


# ── Ingestion ─────────────────────────────────────────────────────────────────

def _count_rows() -> int:
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT COUNT(*) FROM {TABLE_NAME}"))
        return result.scalar()


def ingest_csv(csv_path: Path, force: bool = False) -> int:
    """
    Load the CloudTrail CSV into Postgres using server-side COPY for speed.

    Idempotent: skips ingestion if the table already contains rows (unless
    force=True).  Returns the final row count.
    """
    ensure_schema()

    existing = _count_rows()
    if existing > 0 and not force:
        logger.info(
            "Table %s already has %d rows — skipping ingestion. "
            "Pass force=True to reload.",
            TABLE_NAME,
            existing,
        )
        return existing

    if not csv_path.exists():
        logger.warning("Dataset not found at %s. Attempting to download from Kaggle...", csv_path)
        try:
            import kagglehub
            import shutil
            # This downloads the dataset to a cache directory
            downloaded_dir = kagglehub.dataset_download("nobukim/aws-cloudtrails-dataset-from-flaws-cloud")
            downloaded_path = Path(downloaded_dir) / "nineteenFeaturesDf.csv"
            if downloaded_path.exists():
                logger.info("Successfully downloaded dataset. Moving to %s", csv_path)
                csv_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(downloaded_path, csv_path)
            else:
                logger.error("Downloaded dataset but could not find nineteenFeaturesDf.csv inside it.")
                raise FileNotFoundError(f"Could not find nineteenFeaturesDf.csv at {downloaded_path}")
        except ImportError:
            logger.error("Dataset not found and kagglehub is not installed. Please `pip install kagglehub` or place the CSV manually.")
            raise FileNotFoundError(f"Dataset missing: {csv_path}")
        except Exception as e:
            logger.error(
                "Failed to download dataset. Kaggle requires authentication. "
                "Ensure KAGGLE_USERNAME and KAGGLE_KEY are set in your environment or .env file. Error: %s", e
            )
            raise FileNotFoundError(f"Dataset missing: {csv_path}") from e

    logger.info("Starting CSV ingestion from %s …", csv_path)
    t0 = time.time()

    # Use psycopg3 COPY for maximum throughput.
    # psycopg3 expects a plain postgresql:// DSN, not the SQLAlchemy dialect prefix.
    dsn = DATABASE_URL.replace("postgresql+psycopg://", "postgresql://", 1)

    csv_abs = str(csv_path.resolve())
    col_list = ", ".join(f'"{c}"' for c, _ in SCHEMA_COLUMNS)

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            # Truncate before reload (only reached when existing==0 or force=True)
            if force and existing > 0:
                cur.execute(f"TRUNCATE TABLE {TABLE_NAME}")

            copy_sql = (
                f"COPY {TABLE_NAME} ({col_list}) "
                f"FROM STDIN WITH (FORMAT CSV, HEADER TRUE, NULL '')"
            )
            with cur.copy(copy_sql) as copy:
                with open(csv_abs, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        copy.write(chunk)

        conn.commit()

    elapsed = time.time() - t0
    final_count = _count_rows()
    logger.info(
        "Ingestion complete: %d rows in %.1f s (%.0f rows/s).",
        final_count,
        elapsed,
        final_count / elapsed if elapsed > 0 else 0,
    )
    return final_count


# ── Query execution ───────────────────────────────────────────────────────────

def run_query(sql: str, timeout_ms: Optional[int] = None) -> pd.DataFrame:
    """
    Execute a read-only SELECT query and return results as a DataFrame.

    Raises on syntax / execution errors (callers should catch and log).
    """
    ms = timeout_ms or QUERY_TIMEOUT_MS
    engine = get_engine()
    with engine.connect() as conn:
        # Set statement timeout to prevent runaway queries
        conn.execute(text(f"SET statement_timeout = {ms}"))
        result = conn.execute(text(sql))
        rows = result.fetchall()
        columns = list(result.keys())
    return pd.DataFrame(rows, columns=columns)


# ── Schema introspection ──────────────────────────────────────────────────────

def get_schema_description() -> str:
    """
    Return a human-readable schema description for use in LLM prompts.
    """
    lines = [f"Table: {TABLE_NAME}", "Columns:"]
    for col, dtype in SCHEMA_COLUMNS:
        lines.append(f"  - {col} ({dtype})")
    return "\n".join(lines)


def get_sample_rows(n: int = 5) -> pd.DataFrame:
    """Return n random sample rows from the table (for prompt context)."""
    return run_query(
        f"SELECT * FROM {TABLE_NAME} TABLESAMPLE SYSTEM(0.01) LIMIT {n}"
    )
