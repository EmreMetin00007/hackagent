"""
mcp-reasoning — (c) Auto-Skill Router + deep_think orkestratör köprüsü
(recon→zincir→doğrula→skorla) offline testleri. Deterministik, LLM/network yok.
"""
import os
import json
import sqlite3

from conftest import load_server


def _r():
    return load_server("reasoning")


def _seed(mod, target="rtgt"):
    conn = sqlite3.connect(mod.MEM_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, type TEXT, severity TEXT,
        description TEXT, payload TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, url_or_port TEXT, protocol TEXT,
        state TEXT, technologies TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("DELETE FROM findings WHERE target=?", (target,))
    conn.executemany("INSERT INTO findings (target,type,severity,description,payload) VALUES (?,?,?,?,?)",
                     [(target, "SQL Injection", "high", "id param", "1'"),
                      (target, "Open Redirect", "low", "next param", "//evil")])
    conn.commit()
    conn.close()


# ───────────────────────── (c) recommend_skills ─────────────────────────
def test_router_fresh_target_recommends_recon():
    mod = _r()
    out = json.loads(mod.recommend_skills(target="brand-new-xyz-target"))
    assert out["phase"] == "fresh-recon"
    skills = {r["skill"] for r in out["recommended_skills"]}
    assert "attack-surface-mapping" in skills or "recon-enumeration" in skills
    assert out["kickoff"].startswith("/")


def test_router_web_advanced_signals():
    mod = _r()
    out = json.loads(mod.recommend_skills(context="target uses graphql jwt oauth and sso login"))
    skills = [r["skill"] for r in out["recommended_skills"]]
    assert "web-advanced" in skills


def test_router_cloud_top():
    mod = _r()
    out = json.loads(mod.recommend_skills(
        fingerprint="aws s3 bucket imds 169.254.169.254 iam metadata"))
    assert out["recommended_skills"][0]["skill"] == "cloud-exploitation"


def test_router_active_directory_top():
    mod = _r()
    out = json.loads(mod.recommend_skills(context="kerberos ldap domain controller smb ntlm"))
    assert out["recommended_skills"][0]["skill"] == "active-directory"


def test_router_exploitation_phase_with_findings():
    mod = _r()
    _seed(mod)
    out = json.loads(mod.recommend_skills(target="rtgt"))
    assert out["phase"] == "exploitation"
    skills = {r["skill"] for r in out["recommended_skills"]}
    assert "web-exploit" in skills            # sql_injection bulgusu → web-exploit
    assert "exploit-validation" in skills


def test_router_triggers_are_slash_commands():
    mod = _r()
    out = json.loads(mod.recommend_skills(context="nmap port scan service enum"))
    assert all(r["trigger"].startswith("/") for r in out["recommended_skills"])


# ───────────── deep_think köprüsü: recon→zincir→doğrula→skorla ─────────────
def test_deep_think_bridges_chains_skills_and_score():
    mod = _r()
    if os.path.exists(mod.LESSONS_DB):
        os.remove(mod.LESSONS_DB)
    _seed(mod)
    saved = {k: os.environ.pop(k, None)
             for k in ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN", "DEEPSEEK_API_KEY")}
    try:
        out = json.loads(mod.deep_think(task="exploit rtgt", target="rtgt"))
        # step_0: skill router köprüsü
        assert "step_0_recommended_skills" in out
        assert out["step_0_recommended_skills"]["ranked"]
        # step_2b: kill-chain köprüsü
        kc = out["step_2b_kill_chains"]
        assert kc["chains_found"] > 0
        assert kc["best_chain"] is not None
        assert "Kill-Chain" in kc["best_chain_report"]
        # step_5: exploitability ön-skoru (validator yok → CONFIRMED olamaz)
        assert out["step_5_exploitability_preview"]["band"] in ("POSSIBLE", "LIKELY", "UNLIKELY")
        # pipeline + genişletilmiş next_steps
        assert "pipeline" in out
        assert len(out["next_steps"]) == 5
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
