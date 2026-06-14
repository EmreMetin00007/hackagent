"""
XBOW benchmark harness — offline (mock) testleri.
Docker/claude gerektirmez; gömülü fixture seti ile harness mantığını doğrular.
"""
import os
import importlib.util

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(REPO, "scripts", "xbow_benchmark.py")


def _load():
    spec = importlib.util.spec_from_file_location("xbow_benchmark", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_flag_extraction():
    mod = _load()
    assert mod.extract_flag("blah flag{abc_123} blah") == "flag{abc_123}"
    assert mod.extract_flag("XBOW{deadbeef}") == "XBOW{deadbeef}"
    assert mod.extract_flag("no flag here") == ""


def test_discovery_finds_fixtures():
    mod = _load()
    specs = mod.discover_benchmarks(mod.FIXTURES_DIR)
    assert len(specs) == 4
    ids = {s.id for s in specs}
    assert "XBEN-MOCK-001" in ids
    tags = {t for s in specs for t in s.tags}
    assert {"SQLi", "SSRF", "SSTI"} <= tags


def test_mock_run_and_score():
    mod = _load()
    specs = mod.discover_benchmarks(mod.FIXTURES_DIR)
    results = []
    runtime, solver = mod.MockRuntime(), mod.MockSolver()
    for s in specs:
        results.append(mod.run_one(s, runtime, solver))
    score = mod.score_results(results)
    assert score["total"] == 4
    assert score["solved"] == 3            # 3 solvable, 1 negatif
    assert score["success_rate"] == 0.75
    # negatif challenge çözülmemeli
    authz = next(r for r in results if r["id"] == "XBEN-MOCK-004")
    assert authz["solved"] is False
    # çözülenler flag yakalamalı
    sqli = next(r for r in results if r["id"] == "XBEN-MOCK-001")
    assert sqli["solved"] is True and sqli["flag_found"].startswith("flag{")


def test_scorecard_markdown():
    mod = _load()
    specs = mod.discover_benchmarks(mod.FIXTURES_DIR)
    results = [mod.run_one(s, mod.MockRuntime(), mod.MockSolver()) for s in specs]
    md = mod.scorecard_md(mod.score_results(results))
    assert "Benchmark Scorecard" in md
    assert "%75" in md
    assert "XBOW" in md


def test_wrong_flag_not_counted_as_solved():
    mod = _load()
    # beklenen flag biliniyor ama solver farklı flag bulursa → solved False
    spec = mod.BenchmarkSpec(id="X", flag="flag{correct}", target_url="mock://x")

    class WrongSolver:
        name = "wrong"
        def solve(self, spec, target, timeout, budget):
            return {"output": "flag{WRONG}", "flag_found": "flag{WRONG}",
                    "cost_usd": 0, "duration_s": 1}
    rec = mod.run_one(spec, mod.MockRuntime(), WrongSolver())
    assert rec["solved"] is False
    assert rec["flag_match"] is False
