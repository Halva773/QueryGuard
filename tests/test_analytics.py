from __future__ import annotations

from app.analytics import BLOCK_SIZE, calculate_toxicity, normalize_query, query_fingerprint
from app.models import Severity


def test_normalize_query_removes_comments_and_literals():
    first = "SELECT * FROM orders -- recent\n WHERE id = 42 AND email = 'a@example.org'"
    second = " select * from orders where id=17 and email='other@example.org' "

    assert normalize_query(first) == "select * from orders where id=? and email=?"
    assert normalize_query(second) == "select * from orders where id=? and email=?"
    assert query_fingerprint(first) == query_fingerprint(second)


def test_fingerprint_is_stable_for_same_normalized_query():
    query = "SELECT count(*) FROM sales WHERE store_id = 10"
    assert query_fingerprint(query) == query_fingerprint(query)
    assert len(query_fingerprint(query)) == 64


def test_toxicity_formula_and_severity():
    row = {
        "mean_exec_time_ms": 2500,
        "total_exec_time_ms": 300000,
        "shared_blks_hit": 750,
        "shared_blks_read": 250,
        "shared_blks_written": 0,
        "temp_blks_written": 32768,
        "wal_bytes": 512 * 1024**2,
    }

    score, severity, parts = calculate_toxicity(row)

    expected = 100 * (
        0.25 * 0.5
        + 0.20 * 0.5
        + 0.20 * ((250 * BLOCK_SIZE) / (2 * 1024**3))
        + 0.15 * 0.5
        + 0.10 * 0.25
        + 0.10 * 0.5
    )
    assert score == round(expected, 2)
    assert severity == Severity.MEDIUM
    assert parts["cache_hit_ratio"] == 0.75
    assert parts["io_bytes"] == 250 * BLOCK_SIZE + 32768 * BLOCK_SIZE


def test_toxicity_is_capped_at_one_hundred():
    score, severity, _ = calculate_toxicity(
        {
            "mean_exec_time_ms": 100000,
            "total_exec_time_ms": 10000000,
            "shared_blks_hit": 0,
            "shared_blks_read": 1000000,
            "shared_blks_written": 1000000,
            "temp_blks_written": 1000000,
            "wal_bytes": 100 * 1024**3,
        }
    )
    assert score == 100
    assert severity == Severity.CRITICAL
