"""Runner de migraciones versionadas: idempotencia, copia de seguridad y atomicidad."""
from __future__ import annotations

import sqlite3

import pytest

from batrade import db


def _v1_database(path):
    """Crea una base con el esquema v1 real (el que tenían las instalaciones previas)."""
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.executescript(db.SCHEMA_V1)
    conn.execute("PRAGMA user_version = 1")
    conn.execute(
        "INSERT INTO identities(key, kind, first_seen, last_seen) VALUES('mac:x','mac',1,1)"
    )
    conn.execute(
        "INSERT INTO devices(mac, ip_actual, first_seen, last_seen, estado_confianza) "
        "VALUES('3c:22:fb:11:22:33','192.168.0.10',1000,1000,'confiable')"
    )
    conn.execute(
        "INSERT INTO events(ts, first_ts, last_ts, severidad, tipo, clave_dedupe) "
        "VALUES(1000, 1000, 1000, 'warn', 'device_new', 'device:new:aa')"
    )
    return conn


def test_new_database_reaches_latest_version(tmp_path):
    conn = db.initialize(tmp_path / "nueva.db")
    try:
        assert db.user_version(conn) == db.SCHEMA_VERSION
        assert db.SCHEMA_VERSION == db.MIGRATIONS[-1][0]
        assert db.migrate(conn) == db.SCHEMA_VERSION
    finally:
        conn.close()


def test_v1_database_migrates_without_losing_data(tmp_path):
    path = tmp_path / "vieja.db"
    _v1_database(path).close()

    conn = db.initialize(path)
    try:
        assert db.user_version(conn) == db.SCHEMA_VERSION
        device = conn.execute("SELECT * FROM devices").fetchone()
        assert device["mac"] == "3c:22:fb:11:22:33"
        assert device["estado_confianza"] == "confiable"
        assert conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"] == 1
        # La migración v2 deja el índice de purga de la cola.
        indexes = {r["name"] for r in conn.execute("PRAGMA index_list(notification_queue)")}
        assert "idx_nq_estado_ts" in indexes
    finally:
        conn.close()


def test_backup_is_created_and_never_overwritten(tmp_path):
    path = tmp_path / "vieja.db"
    _v1_database(path).close()

    conn = db.connect(path)
    try:
        first = db.backup(conn, 1)
        second = db.backup(conn, 1)
        assert first is not None and second is not None
        assert first != second
        assert first.name == "vieja.db.bak-v1"
        assert second.name == "vieja.db.bak-v1-2"
        assert first.stat().st_mode & 0o777 == 0o600
        # La copia contiene los datos, no sólo el esquema.
        copy = sqlite3.connect(str(first))
        try:
            assert copy.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        finally:
            copy.close()
    finally:
        conn.close()


def test_migrate_leaves_backup_of_previous_version(tmp_path):
    path = tmp_path / "vieja.db"
    _v1_database(path).close()
    conn = db.connect(path)
    try:
        db.migrate(conn)
    finally:
        conn.close()
    assert (tmp_path / "vieja.db.bak-v1").exists()


def test_fresh_database_has_no_backup(tmp_path):
    conn = db.initialize(tmp_path / "nueva.db")
    conn.close()
    assert list(tmp_path.glob("*.bak-v*")) == []


def test_second_run_is_a_noop(tmp_path):
    path = tmp_path / "vieja.db"
    _v1_database(path).close()
    conn = db.connect(path)
    try:
        assert db.migrate(conn) == db.SCHEMA_VERSION
        assert db.migrate(conn) == db.SCHEMA_VERSION
    finally:
        conn.close()
    # Sólo la primera pasada hizo copia.
    assert len(list(tmp_path.glob("*.bak-v*"))) == 1


def test_failure_mid_migration_does_not_advance_version(tmp_path, monkeypatch):
    path = tmp_path / "vieja.db"
    _v1_database(path).close()

    def _rota(conn):
        conn.execute("ALTER TABLE devices ADD COLUMN columna_nueva TEXT")
        conn.execute("CREATE TABLE IF NOT EXISTS tabla_nueva(x)")  # aditiva, sí
        raise RuntimeError("fallo simulado a mitad de la migración")

    monkeypatch.setattr(db, "MIGRATIONS",
                        [(1, db.SCHEMA_V1), (2, db._migration_v2_notification_index),
                         (3, _rota)])

    conn = db.connect(path)
    try:
        with pytest.raises(RuntimeError):
            db.migrate(conn)
        # v2 sí se confirmó (cada migración es su propia transacción)…
        assert db.user_version(conn) == 2
        assert not conn.in_transaction
        # …pero los cambios de la v3 fallida no quedaron escritos.
        columnas = {r["name"] for r in conn.execute("PRAGMA table_info(devices)")}
        assert "columna_nueva" not in columnas
        tablas = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "tabla_nueva" not in tablas
    finally:
        conn.close()


def test_database_newer_than_code_is_left_alone(tmp_path):
    path = tmp_path / "futura.db"
    conn = db.initialize(path)
    try:
        conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION + 1}")
    finally:
        conn.close()
    conn = db.initialize(path)
    try:
        assert db.user_version(conn) == db.SCHEMA_VERSION + 1
    finally:
        conn.close()


def test_split_sql_keeps_complete_statements_only():
    statements = db._split_sql(db.SCHEMA_V1)
    assert len(statements) >= 10
    assert all(s.endswith(";") for s in statements)
    assert any(s.startswith("CREATE TABLE IF NOT EXISTS devices") for s in statements)


def _migracion_mixta(version: int, sql: str) -> list:
    return db.MIGRATIONS + [(version, sql)]


def test_migracion_mixta_ddl_y_dml_aplica_todo(tmp_path, monkeypatch):
    """BEGIN IMMEDIATE cubre DDL y DML: o entra todo o no entra nada."""
    conn = db.initialize(tmp_path / "mixta.db")
    try:
        conn.execute(
            "INSERT INTO devices(mac, ip_actual, first_seen, last_seen, "
            "estado_confianza) VALUES('3c:22:fb:11:22:33','10.10.10.50',1,1,'confiable')")
        version = db.SCHEMA_VERSION
        pasos = _migracion_mixta(version + 1, (
            "ALTER TABLE devices ADD COLUMN nota TEXT;\n"
            "UPDATE devices SET nota = 'migrado';\n"
            "INSERT INTO device_history(device_id, ts, evento) "
            "SELECT id, 5, 'migracion' FROM devices;\n"
        ))
        monkeypatch.setattr(db, "MIGRATIONS", pasos)
        monkeypatch.setattr(db, "SCHEMA_VERSION", version + 1)

        assert db.migrate(conn) == version + 1
        assert db.user_version(conn) == version + 1
        fila = conn.execute("SELECT nota FROM devices").fetchone()
        assert fila["nota"] == "migrado"
        assert conn.execute("SELECT COUNT(*) AS n FROM device_history "
                            "WHERE evento = 'migracion'").fetchone()["n"] == 1
    finally:
        conn.close()


def test_migracion_mixta_que_falla_deshace_ddl_y_dml(tmp_path, monkeypatch):
    conn = db.initialize(tmp_path / "mixta-rota.db")
    try:
        conn.execute(
            "INSERT INTO devices(mac, ip_actual, first_seen, last_seen, "
            "estado_confianza) VALUES('3c:22:fb:11:22:33','10.10.10.50',1,1,'confiable')")
        version = db.SCHEMA_VERSION
        pasos = _migracion_mixta(version + 1, (
            "ALTER TABLE devices ADD COLUMN nota TEXT;\n"
            "UPDATE devices SET nota = 'migrado';\n"
            "INSERT INTO tabla_que_no_existe(x) VALUES(1);\n"
        ))
        monkeypatch.setattr(db, "MIGRATIONS", pasos)
        monkeypatch.setattr(db, "SCHEMA_VERSION", version + 1)

        with pytest.raises(sqlite3.Error):
            db.migrate(conn)

        assert db.user_version(conn) == version
        columnas = {r["name"] for r in conn.execute("PRAGMA table_info(devices)")}
        assert "nota" not in columnas
        assert conn.execute("SELECT COUNT(*) AS n FROM device_history").fetchone()["n"] == 0
    finally:
        conn.close()
