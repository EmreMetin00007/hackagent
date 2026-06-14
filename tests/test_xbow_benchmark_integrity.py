"""
XBOW benchmark harness — bütünlük / kanıt katmanı (v1.1) offline testleri.
Anti-cheat (echo guard), validator-onay sayımı, mock watermark, reprodüksiyon
metadata'sı, resume + bütçe tavanı ve JUnit export'u doğrular. Docker/claude gerektirmez.
"""
import os
import importlib.util

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(REPO, "scripts", "xbow_benchmark.py")


def _load():
    spec = importlib.util.spec_from_file_location("xbow_benchmark", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Solver:
    """Test solver — verilen output/flag/prompt'u aynen döndürür."""
    name = "stub"

    def __init__(self, output="", flag="", prompt=""):
        self._o, self._f, self._p = output, flag, prompt

    def solve(self, spec, target, timeout, budget):
        return {"output": self._o, "flag_found": self._f, "prompt": self._p,
                "cost_usd": 0.0, "duration_s": 1.0}


# ── Anti-cheat: flag girdideyse çözüm sayılmaz ────────────────────────────────
def test_flag_in_input_not_counted_as_solved():
    mod = _load()
    spec = mod.BenchmarkSpec(id="ECHO", target_url="mock://e")  # bilinen flag yok
    solver = _Solver(output="flag{LEAKED}", flag="flag{LEAKED}",
                     prompt="hedefte flag{LEAKED} aramana gerek yok")
    rec = mod.run_one(spec, mod.MockRuntime(), solver)
    assert rec["flag_in_input"] is True
    assert rec["solved"] is False            # echo guard devrede


def test_legit_flag_without_echo_is_solved():
    mod = _load()
    spec = mod.BenchmarkSpec(id="OK", target_url="mock://ok")
    solver = _Solver(output="exploit ok flag{real_from_target}",
                     flag="flag{real_from_target}", prompt="/pwn mock://ok")
    rec = mod.run_one(spec, mod.MockRuntime(), solver)
    assert rec["flag_in_input"] is False
    assert rec["solved"] is True


# ── Validator onayı izi sayılır ───────────────────────────────────────────────
def test_validator_confirmed_detected_and_counted():
    mod = _load()
    spec = mod.BenchmarkSpec(id="VC", target_url="mock://vc")
    solver = _Solver(output="validate_ssti → CONFIRMED (confidence=0.95) flag{x}",
                     flag="flag{x}", prompt="/pwn mock://vc")
    rec = mod.run_one(spec, mod.MockRuntime(), solver)
    assert rec["validator_confirmed"] is True
    sc = mod.score_results([rec])
    assert sc["validator_confirmed_solved"] == 1


def test_no_validator_trace_is_zero():
    mod = _load()
    assert mod._validator_confirmed("sadece düz metin, kanıt yok") is False
    assert mod._validator_confirmed("confidence: 0.3 zayıf") is False
    assert mod._validator_confirmed("confidence=0.75 güçlü") is True


# ── Scorecard: mock watermark + XBOW kıyas ayrımı ─────────────────────────────
def test_mock_scorecard_has_watermark_and_no_delta():
    mod = _load()
    specs = mod.discover_benchmarks(mod.FIXTURES_DIR)
    results = [mod.run_one(s, mod.MockRuntime(), mod.MockSolver()) for s in specs]
    meta = mod.run_metadata("mock", "mock", None, mod.FIXTURES_DIR)
    md = mod.scorecard_md(mod.score_results(results), meta)
    assert "SELF-TEST (MOCK)" in md
    assert "Mod: **mock**" in md
    assert "puan**" not in md                 # mock'ta XBOW delta YOK


def test_docker_scorecard_shows_delta():
    mod = _load()
    specs = mod.discover_benchmarks(mod.FIXTURES_DIR)
    results = [mod.run_one(s, mod.MockRuntime(), mod.MockSolver()) for s in specs]
    meta = mod.run_metadata("docker", "cco", "qwen", "/tmp/repo")
    md = mod.scorecard_md(mod.score_results(results), meta)
    assert "SELF-TEST (MOCK)" not in md
    assert "puan**" in md                     # gerçek modda XBOW delta VAR


# ── Reprodüksiyon metadata ────────────────────────────────────────────────────
def test_run_metadata_fields():
    mod = _load()
    meta = mod.run_metadata("docker", "cco", "qwen3", "/tmp/x")
    for k in ("harness_version", "mode", "is_capability_evidence", "solver",
              "model", "git_commit", "python", "host", "generated"):
        assert k in meta
    assert meta["is_capability_evidence"] is True
    assert mod.run_metadata("mock", "mock", None, "")["is_capability_evidence"] is False


# ── Resume + bütçe tavanı ─────────────────────────────────────────────────────
def test_resume_skips_solved(tmp_path):
    mod = _load()
    out = str(tmp_path / "results.json")
    specs = mod.discover_benchmarks(mod.FIXTURES_DIR)
    # 1. koşu: hepsini çalıştır
    r1 = mod.run_suite(specs, mod.MockRuntime(), mod.MockSolver(), out=out)
    solved1 = sum(1 for r in r1 if r["solved"])
    # 2. koşu (resume): çözülmüşler korunur, yeniden eklenmez (sayı aynı kalmalı)
    r2 = mod.run_suite(specs, mod.MockRuntime(), mod.MockSolver(), out=out, resume=True)
    assert sum(1 for r in r2 if r["solved"]) == solved1
    assert len(r2) == len(specs)             # duplicate yok


def test_max_cost_stops_run(tmp_path):
    mod = _load()
    specs = mod.discover_benchmarks(mod.FIXTURES_DIR)
    # her mock çözüm ~0.4-0.6$; tavanı çok düşük tut → ilk birkaçtan sonra durur
    res = mod.run_suite(specs, mod.MockRuntime(), mod.MockSolver(),
                        max_cost=0.5, out=str(tmp_path / "maxcost.json"))
    assert len(res) < len(specs)             # tavan kalanları kesti


# ── JUnit export ──────────────────────────────────────────────────────────────
def test_junit_xml_structure():
    mod = _load()
    specs = mod.discover_benchmarks(mod.FIXTURES_DIR)
    results = [mod.run_one(s, mod.MockRuntime(), mod.MockSolver()) for s in specs]
    xml = mod.junit_xml(results)
    assert xml.startswith("<testsuite")
    assert 'tests="4"' in xml
    assert 'failures="1"' in xml             # 1 negatif challenge
    assert "<testcase" in xml
