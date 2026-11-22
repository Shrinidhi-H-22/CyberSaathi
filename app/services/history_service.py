
import os
import sqlite3

from flask import current_app


VALID_SCAN_TYPES = {"message", "url"}

VALID_RISK_LEVELS = {"Low", "Medium", "High"}


def get_db_connection():
    """Create a connection to the local SQLite database."""

    database_path = current_app.config["DATABASE"]

    connection = sqlite3.connect(
        database_path,
        timeout=5
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_history_database(app):
    """Create the SQLite database and scan history table."""

    database_path = app.config["DATABASE"]

    os.makedirs(
        os.path.dirname(database_path),
        exist_ok=True
    )

    connection = sqlite3.connect(
        database_path,
        timeout=5
    )

    try:
        with connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    scan_type TEXT NOT NULL
                        CHECK(scan_type IN ('message', 'url')),

                    risk_level TEXT NOT NULL
                        CHECK(risk_level IN ('Low', 'Medium', 'High')),

                    indicator_score INTEGER NOT NULL
                        CHECK(indicator_score >= 0),

                    finding_count INTEGER NOT NULL DEFAULT 0
                        CHECK(finding_count >= 0),

                    link_count INTEGER NOT NULL DEFAULT 0
                        CHECK(link_count >= 0),

                    summary TEXT NOT NULL,

                    created_at TEXT NOT NULL
                        DEFAULT (
                            strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                        )
                )
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_history_created
                ON scan_history(created_at DESC)
            """)

    finally:
        # Important: explicitly close the database connection.
        connection.close()


def save_scan(scan_type, analysis_result):
    """Save non-sensitive scan metadata."""

    if scan_type not in VALID_SCAN_TYPES:
        raise ValueError("Invalid scan type.")

    if not isinstance(analysis_result, dict):
        raise ValueError("Invalid analysis result.")

    risk_level = analysis_result.get("risk_level")

    if risk_level not in VALID_RISK_LEVELS:
        raise ValueError("Invalid risk level.")

    indicator_score = analysis_result.get("indicator_score")

    if (
        isinstance(indicator_score, bool)
        or not isinstance(indicator_score, int)
        or indicator_score < 0
    ):
        raise ValueError("Invalid indicator score.")

    findings = analysis_result.get("findings", [])

    if not isinstance(findings, list):
        raise ValueError("Invalid findings.")

    default_link_count = 1 if scan_type == "url" else 0

    link_count = analysis_result.get(
        "link_count",
        default_link_count
    )

    if (
        isinstance(link_count, bool)
        or not isinstance(link_count, int)
        or link_count < 0
    ):
        raise ValueError("Invalid link count.")

    summary = analysis_result.get("summary", "")

    if not isinstance(summary, str):
        raise ValueError("Invalid summary.")

    summary = summary[:500]

    history_limit = current_app.config["HISTORY_LIMIT"]

    if (
        isinstance(history_limit, bool)
        or not isinstance(history_limit, int)
        or history_limit < 1
    ):
        raise ValueError("Invalid configured history limit.")

    connection = get_db_connection()

    try:

        cursor = connection.execute(
            """
            INSERT INTO scan_history (
                scan_type,
                risk_level,
                indicator_score,
                finding_count,
                link_count,
                summary
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_type,
                risk_level,
                indicator_score,
                len(findings),
                link_count,
                summary
            )
        )

        scan_id = cursor.lastrowid

        # Retain only the latest configured number of scans.
        connection.execute(
            """
            DELETE FROM scan_history
            WHERE id NOT IN (
                SELECT id
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
            )
            """,
            (history_limit,)
        )

        connection.commit()

        return scan_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_recent_scans(limit=None):
    """Return recent scan records without original user content."""

    history_limit = current_app.config["HISTORY_LIMIT"]

    if (
        isinstance(history_limit, bool)
        or not isinstance(history_limit, int)
        or history_limit < 1
    ):
        raise ValueError("Invalid configured history limit.")

    # Default to the smaller of 50 or the configured history limit.
    if limit is None:
        limit = min(50, history_limit)

    elif (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= history_limit
    ):
        raise ValueError("Invalid history limit.")

    connection = get_db_connection()

    try:

        cursor = connection.execute(
            """
            SELECT
                id,
                scan_type,
                risk_level,
                indicator_score,
                finding_count,
                link_count,
                summary,
                created_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )

        return [
            dict(row)
            for row in cursor.fetchall()
        ]

    finally:
        connection.close()


def clear_scan_history():
    """Delete all saved scan records."""

    connection = get_db_connection()

    try:

        cursor = connection.execute(
            "DELETE FROM scan_history"
        )

        deleted_count = cursor.rowcount

        connection.commit()

        return deleted_count

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
