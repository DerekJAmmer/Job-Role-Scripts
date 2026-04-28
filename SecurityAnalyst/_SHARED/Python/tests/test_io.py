from pathlib import Path

from sa_common import io, log


def test_logger_is_reused(tmp_path: Path) -> None:
    a = log.get_logger("sa.test")
    b = log.get_logger("sa.test")
    assert a is b
    assert len(a.handlers) == 1


def test_json_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "x.json"
    io.write_json(path, {"a": 1, "b": [1, 2, 3]})
    assert io.read_json(path) == {"a": 1, "b": [1, 2, 3]}


def test_ndjson_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "x.ndjson"
    written = io.write_ndjson(path, [{"i": 1}, {"i": 2}])
    assert written == 2
    assert list(io.read_ndjson(path)) == [{"i": 1}, {"i": 2}]


def test_csv_union_headers(tmp_path: Path) -> None:
    path = tmp_path / "x.csv"
    n = io.write_csv(path, [{"a": 1, "b": 2}, {"a": 3, "c": 4}])
    assert n == 2
    text = path.read_text(encoding="utf-8")
    assert "a,b,c" in text.splitlines()[0]
