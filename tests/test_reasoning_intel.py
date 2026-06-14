"""
mcp-reasoning — Kill-Chain Intelligence (a) + Payload Evolution (d) +
Exploitability Score (e) offline testleri. Tamamen deterministik, LLM/network yok.
"""
import os
import json
import sqlite3

from conftest import load_server


def _r():
    return load_server("reasoning")


def _seed(mod, target="lab.test"):
    conn = sqlite3.connect(mod.MEM_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, type TEXT, severity TEXT,
        description TEXT, payload TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, url_or_port TEXT, protocol TEXT,
        state TEXT, technologies TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("DELETE FROM findings WHERE target=?", (target,))
    rows = [
        (target, "SSRF", "medium", "url param fetch", "http://169.254.169.254"),
        (target, "Local File Inclusion", "medium", "page param", "../../etc/passwd"),
        (target, "Open Redirect", "low", "next param", "//evil"),
        (target, "SQL Injection", "high", "id param", "1'"),
    ]
    conn.executemany("INSERT INTO findings (target,type,severity,description,payload) VALUES (?,?,?,?,?)", rows)
    conn.commit()
    conn.close()


def _clear_lessons(mod):
    if os.path.exists(mod.LESSONS_DB):
        os.remove(mod.LESSONS_DB)


# ─────────────────────────── (a) Kill-Chain Intelligence ───────────────────────────
def test_compose_chains_builds_multistep_killchains():
    mod = _r()
    _clear_lessons(mod)
    _seed(mod)
    out = json.loads(mod.compose_attack_chains(target="lab.test", max_depth=4, top_n=10))
    assert out["findings_count"] == 4
    assert out["chains_found"] >= 3
    best = out["best_chain"]
    assert best is not None
    assert best["length"] >= 2                      # gerçek çok-adımlı zincir
    assert "→" in best["label"]
    assert 0 < best["ev"] <= 1
    # her adımda yetenek meta'sı var
    assert all("capability" in s for s in best["steps"])


def test_compose_chains_ssrf_reaches_cloud_takeover():
    mod = _r()
    _clear_lessons(mod)
    _seed(mod)
    out = json.loads(mod.compose_attack_chains(target="lab.test", max_depth=4, top_n=20))
    labels = [c["label"] for c in out["ranked_chains"]]
    # SSRF zinciri IMDS → IAM → bulut ele geçirmeye ulaşmalı
    assert any("ssrf" in l and "cloud_account_takeover" in l for l in labels), labels
    # LFI → log_poisoning → RCE zinciri de bulunmalı
    assert any("lfi" in l and "remote_code_execution" in l for l in labels), labels


def test_compose_chains_terminal_high_impact():
    mod = _r()
    _clear_lessons(mod)
    _seed(mod)
    out = json.loads(mod.compose_attack_chains(target="lab.test", top_n=20))
    # en az bir zincir kritik etkiye (impact>=0.9) ulaşmalı
    assert any(c["impact"] >= 0.9 for c in out["ranked_chains"])
    # zincirler EV'ye göre azalan sıralı
    evs = [c["ev"] for c in out["ranked_chains"]]
    assert evs == sorted(evs, reverse=True)


def test_compose_chains_empty_memory_advises():
    mod = _r()
    _clear_lessons(mod)
    out = json.loads(mod.compose_attack_chains(target="no-such-target-xyz"))
    assert out["best_chain"] is None
    assert "advice" in out


def test_kill_chain_report_markdown():
    mod = _r()
    _clear_lessons(mod)
    _seed(mod)
    comp = json.loads(mod.compose_attack_chains(target="lab.test", top_n=5))
    md = mod.kill_chain_report(json.dumps(comp))          # tüm çıktıyı verince best alınır
    assert "Kill-Chain" in md
    assert "## Adımlar" in md
    assert "Doğrula" in md
    # tek zincir nesnesi de kabul edilmeli
    md2 = mod.kill_chain_report(json.dumps(comp["best_chain"]))
    assert "Kill-Chain" in md2


def test_kill_chain_report_bad_input():
    mod = _r()
    assert "HATA" in mod.kill_chain_report("{not json")
    assert "HATA" in mod.kill_chain_report(json.dumps({"foo": "bar"}))


# ─────────────────────────── (d) Payload Evolution ───────────────────────────
def test_evolve_payload_sql_breaks_blocked_token():
    mod = _r()
    _clear_lessons(mod)
    base = "1 UNION SELECT username,password FROM users"
    out = json.loads(mod.evolve_payload(payload=base, technique="sql_injection",
                                        blocked_by="UNION", generations=2, population=10))
    assert out["generated"] > 0
    variants = out["variants"]
    assert variants and all(v["payload"] != base for v in variants)
    # en az bir varyant artık literal 'UNION' içermemeli (signal break)
    assert any("UNION" not in v["payload"] for v in variants)
    # operatörler raporlanmalı
    assert all(v["operators"] for v in variants)


def test_evolve_payload_unsupported_technique():
    mod = _r()
    out = json.loads(mod.evolve_payload(payload="x", technique="subdomain_takeover"))
    assert out["variants"] == []
    assert "supported" in out


def test_payload_learning_records_winrate():
    mod = _r()
    _clear_lessons(mod)
    rate0, n0 = mod._op_winrate("inline_comment", "sql_injection")
    assert n0 == 0
    res = json.loads(mod.record_payload_result(technique="sql_injection",
                                               operators="inline_comment,case_swap",
                                               worked=True, blocked_by="UNION"))
    assert res["stored"] is True
    rate1, n1 = mod._op_winrate("inline_comment", "sql_injection")
    assert n1 == 1 and rate1 == 1.0


def test_payload_learning_biases_fitness():
    mod = _r()
    _clear_lessons(mod)
    base = "1 UNION SELECT 1"
    # öğrenmeden önce
    before = json.loads(mod.evolve_payload(payload=base, technique="sql_injection",
                                           blocked_by="", generations=1, population=20))
    f_before = {v["payload"]: v["fitness"] for v in before["variants"]}
    # inline_comment'i başarılı olarak öğret
    mod.record_payload_result(technique="sql_injection", operators="inline_comment", worked=True)
    after = json.loads(mod.evolve_payload(payload=base, technique="sql_injection",
                                          blocked_by="", generations=1, population=20))
    # inline_comment operatörünü kullanan bir varyantın fitness'ı artmış olmalı
    bumped = [v for v in after["variants"] if "inline_comment" in v["operators"]]
    assert bumped
    v = bumped[0]
    assert v["fitness"] >= f_before.get(v["payload"], 0)


# ─────────────────────────── (e) Exploitability Score ───────────────────────────
def test_exploitability_validator_confirmed():
    mod = _r()
    _clear_lessons(mod)
    out = json.loads(mod.exploitability_score(technique="sql_injection",
                                              validator_confidence=0.95,
                                              reflexion_verdict="APPROVED",
                                              severity="high", evidence="boolean differential CONFIRMED"))
    assert out["band"] == "CONFIRMED"
    assert out["exploitability_score"] >= 0.9
    assert out["false_positive_risk"] <= 0.1
    assert out["recommended_validation"] is None


def test_exploitability_without_validator_capped():
    mod = _r()
    _clear_lessons(mod)
    out = json.loads(mod.exploitability_score(technique="sql_injection",
                                              validator_confidence=-1.0,
                                              reflexion_verdict="APPROVED"))
    assert out["exploitability_score"] <= 0.65       # validator yoksa üst sınır
    assert out["band"] != "CONFIRMED"
    assert out["recommended_validation"]             # doğrulama önerilir


def test_exploitability_revise_lowers_score():
    mod = _r()
    _clear_lessons(mod)
    approved = json.loads(mod.exploitability_score(technique="ssti", validator_confidence=0.8,
                                                   reflexion_verdict="APPROVED"))
    revise = json.loads(mod.exploitability_score(technique="ssti", validator_confidence=0.8,
                                                 reflexion_verdict="REVISE"))
    assert revise["exploitability_score"] < approved["exploitability_score"]
