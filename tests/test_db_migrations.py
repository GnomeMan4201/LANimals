from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import nexus_db


class NotesMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "lanimals.db"
        self.db_patch = patch.object(nexus_db, "DB_PATH", self.db_path)
        self.db_patch.start()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.tempdir.cleanup()

    def _create_legacy_hosts_table(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE hosts (ip TEXT PRIMARY KEY, mac TEXT)")
        conn.commit()
        conn.close()

    def _host_columns(self) -> list[str]:
        conn = sqlite3.connect(self.db_path)
        try:
            return [row[1] for row in conn.execute("PRAGMA table_info(hosts)").fetchall()]
        finally:
            conn.close()

    def test_legacy_schema_gains_notes_column(self) -> None:
        self._create_legacy_hosts_table()

        nexus_db.init_db()

        self.assertIn("notes", self._host_columns())

    def test_current_schema_initialization_is_idempotent(self) -> None:
        nexus_db.init_db()
        nexus_db.init_db()

        columns = self._host_columns()
        self.assertEqual(columns.count("notes"), 1)

    def test_real_migration_error_propagates_and_connection_closes(self) -> None:
        self._create_legacy_hosts_table()
        inner = sqlite3.connect(self.db_path, check_same_thread=False)
        inner.row_factory = sqlite3.Row

        class FailingConnection:
            def __init__(self, connection: sqlite3.Connection) -> None:
                self.connection = connection
                self.closed = False

            def executescript(self, sql: str):
                return self.connection.executescript(sql)

            def execute(self, sql: str, parameters=()):
                if sql.startswith("ALTER TABLE hosts ADD COLUMN notes"):
                    raise sqlite3.OperationalError("synthetic migration failure")
                return self.connection.execute(sql, parameters)

            def commit(self) -> None:
                self.connection.commit()

            def rollback(self) -> None:
                self.connection.rollback()

            def close(self) -> None:
                self.closed = True
                self.connection.close()

        failing = FailingConnection(inner)
        with patch.object(nexus_db, "_conn", return_value=failing):
            with self.assertRaisesRegex(sqlite3.OperationalError, "synthetic migration failure"):
                nexus_db.init_db()

        self.assertTrue(failing.closed)


if __name__ == "__main__":
    unittest.main()
