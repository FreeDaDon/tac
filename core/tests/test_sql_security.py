import sqlite3

import pytest

from core.security.sql_security import (
    SQLSecurityError,
    analyze_file,
    build_safe_in_clause,
    check_table_exists,
    escape_identifier,
    execute_query_safely,
    find_sql_issues,
    get_safe_table_list,
    sanitize_value_for_like,
    validate_identifier,
    validate_sql_query,
)


@pytest.fixture()
def conn():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'ann'), (2, 'bo')")
    yield c
    c.close()


@pytest.mark.parametrize("name", ["users", "_tmp", "order items", "col1"])
def test_valid_identifiers(name):
    assert validate_identifier(name)


@pytest.mark.parametrize("name", ["", "1abc", "users; DROP", "a-b", "select", "UNION"])
def test_invalid_identifiers(name):
    with pytest.raises(SQLSecurityError):
        validate_identifier(name)


def test_escape_identifier():
    assert escape_identifier("users") == "[users]"


def test_execute_query_safely(conn):
    rows = execute_query_safely(conn, "SELECT name FROM {table} WHERE id = ?", params=(2,),
                                identifier_params={"table": "users"}).fetchall()
    assert rows == [("bo",)]
    with pytest.raises(SQLSecurityError):
        execute_query_safely(conn, "DROP TABLE users")
    with pytest.raises(SQLSecurityError):
        execute_query_safely(conn, "SELECT * FROM {t}", identifier_params={"t": "users; --"})


def test_table_helpers(conn):
    assert get_safe_table_list(conn) == ["users"]
    assert check_table_exists(conn, "users")
    assert not check_table_exists(conn, "nope")
    assert not check_table_exists(conn, "bad;name")


def test_like_and_in_clause():
    assert sanitize_value_for_like("50%_[x]\\") == "50\\%\\_\\[x]\\\\"
    assert build_safe_in_clause("status", ["a", "b"]) == ("[status] IN (?, ?)", ["a", "b"])
    with pytest.raises(SQLSecurityError):
        build_safe_in_clause("status", [])


@pytest.mark.parametrize("query", [
    "SELECT * FROM users WHERE id = 1",
    "SELECT name FROM products UNION SELECT name FROM archived_products",
    "SELECT a FROM t UNION ALL SELECT b FROM u",
])
def test_safe_queries(query):
    assert validate_sql_query(query)


@pytest.mark.parametrize(("query", "rule"), [
    ("SELECT * FROM users WHERE name = '' UNION SELECT username, password FROM admins", "SQL-UNION-INJECTION"),
    ("SELECT * FROM t WHERE id = 1 UNION SELECT NULL, NULL, NULL", "SQL-UNION-INJECTION"),
    ("SELECT * FROM t UNION SELECT name, sql FROM sqlite_master", "SQL-UNION-INJECTION"),
    ("SELECT * FROM users WHERE name = 'x' OR '1'='1'", "SQL-INJECTION"),
    ("SELECT * FROM users -- comment", "SQL-COMMENT"),
    ("DROP TABLE users", "SQL-DANGEROUS-OP"),
    ("SELECT 1; DELETE FROM users", "SQL-DANGEROUS-OP"),
])
def test_dangerous_queries(query, rule):
    assert rule in {r for r, _ in find_sql_issues(query)}
    with pytest.raises(SQLSecurityError):
        validate_sql_query(query)


def test_analyze_file(fixtures):
    report = analyze_file(fixtures / "swe" / "queries.sql")
    assert report.metrics == {"queries": 6, "flagged_queries": 4}
    lines = {f.location.rsplit(":", 1)[1] for f in report.findings}
    assert lines == {"4", "5", "6", "7"}
    assert report.max_severity == "critical"
