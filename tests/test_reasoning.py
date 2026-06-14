"""
mcp-reasoning (biliş/beyin katmanı) — offline birim testleri.
LLM gerektiren yollar (Reflexion/critic network) test edilmez; deterministik
EV motoru, kalıcı öğrenme (lessons DB), prior karışımı ve plan/öneri doğrulanır.
"""
import os
import json
import sqlite3

import pytest

from conftest import load_server, list_tool_names


def _r():
    return load_server("reasoning")


def _seed_memory(mod, target="lab.test"):
    """agent_memory.db'ye findings/endpoints ekle (izole CCO_HOME içinde)."""
    conn = sqlite3.connect(mod.MEM_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, type TEXT, severity TEXT,
        description TEXT, payload TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, url_or_port TEXT, protocol TEXT,
        state TEXT, technologies TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("INSERT INTO findings (target,type,severity,description,payload) VALUES (?,?,?,?,?)",
                 (target, "SQL Injection", "high", "id param error-based", "1'"))
    conn.execute("INSERT INTO findings (target,type,severity,description,payload) VALUES (?,?,?,?,?)",
                 (target, "Open Redirect", "low", "next param", "//evil"))
    conn.execute("INSERT INTO endpoints (target,url_or_port,protocol,state,technologies) VALUES (?,?,?,?,?)",
                 (target, "http://lab.test/login", "http", "open", "php login form"))
    conn.commit()
    conn.close()


def _clear_lessons(mod):
    if os.path.exists(mod.LESSONS_DB):
        os.remove(mod.LESSONS_DB)


def test_reasoning_imports_and_tool_count():
    mod = _r()
    assert hasattr(mod, "mcp")
    names = list_tool_names(mod)
    assert len(names) == 19, f"reasoning 19 tool sunmalı, {len(names)} bulundu"
    assert "deep_think" in names
    assert "compose_attack_chains" in names
    assert "recommend_skills" in names
    assert "fingerprint_waf" in names
    assert "verify_origin" in names


def test_normalize_tech():
    mod = _r()
    assert mod._normalize_tech("SQL Injection") == "sql_injection"
    assert mod._normalize_tech("Server-Side Template Injection") == "ssti"
    assert mod._normalize_tech("Insecure Direct Object Reference") == "idor"


def test_ev_ranks_high_impact_above_low():
    mod = _r()
    _clear_lessons(mod)
    ev_sqli, *_ = mod._ev("sql_injection", "high")
    ev_redirect, *_ = mod._ev("open_redirect", "low")
    assert ev_sqli > ev_redirect


def test_plan_attack_tree_offline_ranks_actions():
    mod = _r()
    _clear_lessons(mod)
    _seed_memory(mod)
    plan = json.loads(mod.plan_attack_tree(target="lab.test", expand=False))
    assert plan["findings_count"] == 2
    techs = [a["technique"] for a in plan["ranked_actions"]]
    assert "sql_injection" in techs
    # en yüksek EV, open_redirect'ten önce sql_injection olmalı
    assert plan["highest_ev"]["technique"] == "sql_injection"
    # endpoint 'php login' ipucundan çıkarımlı teknikler de gelmeli
    assert any(a["source"] == "inferred-from-endpoint" for a in plan["ranked_actions"])
    # her aksiyon validator hook'una bağlı olmalı
    assert all("validate_with" in a for a in plan["ranked_actions"])


def test_next_best_action_offline():
    mod = _r()
    _clear_lessons(mod)
    _seed_memory(mod)
    nba = json.loads(mod.next_best_action(target="lab.test"))
    assert nba["next_best_action"]["technique"] == "sql_injection"
    assert "validate_with" in nba["next_best_action"]


def test_learning_loop_updates_prior():
    """record_lesson → _blended_prob teknik için öğrenilmiş win-rate'i kullanır."""
    mod = _r()
    _clear_lessons(mod)
    base, src = mod._blended_prob("idor")
    assert src == "prior"
    # 3 başarısız ders ekle → blended prob düşmeli
    for i in range(3):
        mod.record_lesson(context="api idor attempt", technique="idor",
                          action="increment id", outcome="403", worked=False, tags="api")
    blended, src2 = mod._blended_prob("idor")
    assert "blended" in src2
    assert blended < base
    stats = json.loads(mod.lesson_stats())
    assert stats["total_lessons"] == 3
    idor = next(t for t in stats["by_technique"] if t["technique"] == "idor")
    assert idor["winrate"] == 0.0


def test_recall_lessons_relevance_and_tag():
    mod = _r()
    _clear_lessons(mod)
    mod.record_lesson(context="Apache 2.4.49 path traversal", technique="path_traversal",
                      action="..%2f..%2fetc/passwd", outcome="root:x:0:0", worked=True,
                      tags="cve,apache")
    mod.record_lesson(context="random unrelated thing", technique="xss_reflected",
                      action="payload", outcome="encoded", worked=False, tags="web")
    rec = json.loads(mod.recall_lessons(context="Apache path traversal cve", tags="apache", k=1))
    assert rec["returned"] == 1
    assert rec["lessons"][0]["technique"] == "path_traversal"
    assert rec["lessons"][0]["worked"] is True


def test_reflexion_graceful_without_api_key():
    mod = _r()
    # API key'i geçici temizle → graceful fallback (network yok)
    saved = {k: os.environ.pop(k, None) for k in ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
    try:
        out = json.loads(mod.reason_reflexion(task="SQLi exploit for id param", artifact_kind="exploit"))
        assert out["approved"] is False
        assert out["llm_error"] == "no_api_key"
        assert out["static_checklist"]
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


def test_deep_think_offline_combines_pillars():
    mod = _r()
    _clear_lessons(mod)
    _seed_memory(mod)
    saved = {k: os.environ.pop(k, None) for k in ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
    try:
        out = json.loads(mod.deep_think(task="exploit lab.test", target="lab.test"))
        assert "step_1_recalled_lessons" in out
        assert "step_2_attack_plan" in out
        assert out["step_3_chosen_action"]["technique"] == "sql_injection"
        assert out["validator_hook"] == "mcp__validator__validate_sqli"
        assert out["step_4_reflexion"]["skipped"] is True   # LLM yok
        assert "step_0_recommended_skills" in out
        assert out["step_2b_kill_chains"]["chains_found"] >= 1
        assert len(out["next_steps"]) == 5
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


# ───────────────────── DeepSeek sağlayıcı entegrasyonu (offline) ─────────────────────
def _clear_all_keys():
    return {k: os.environ.pop(k, None)
            for k in ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN", "DEEPSEEK_API_KEY",
                      "CCO_REASON_MODEL", "CCO_CRITIC_MODEL")}


def _restore(saved):
    for k, v in saved.items():
        os.environ.pop(k, None)
        if v is not None:
            os.environ[k] = v


def test_provider_routing_by_model_name():
    mod = _r()
    saved = _clear_all_keys()
    try:
        os.environ["DEEPSEEK_API_KEY"] = "sk-test-fake"
        prov, url, key = mod._provider_for("deepseek-reasoner")
        assert prov == "deepseek"
        assert url == mod.DEEPSEEK_URL
        assert "api.deepseek.com" in url
        assert key == "sk-test-fake"
        prov2, url2, _ = mod._provider_for("qwen/qwen3.6-plus")
        assert prov2 == "openrouter" and url2 == mod.OPENROUTER_URL
    finally:
        _restore(saved)


def test_models_auto_switch_to_deepseek_when_key_present():
    mod = _r()
    saved = _clear_all_keys()
    try:
        # key yok → Qwen/Hermes varsayılan
        assert mod.reason_model() == "qwen/qwen3.6-plus"
        assert mod.critic_model() == "nousresearch/hermes-4-405b"
        # DeepSeek key var → beyin DeepSeek'e geçer (reasoner=actor, chat=critic)
        os.environ["DEEPSEEK_API_KEY"] = "sk-test-fake"
        assert mod.reason_model() == "deepseek-reasoner"
        assert mod.critic_model() == "deepseek-chat"
        assert mod._any_llm_key() is True
        # açık override her zaman kazanır
        os.environ["CCO_REASON_MODEL"] = "deepseek-v4-pro"
        assert mod.reason_model() == "deepseek-v4-pro"
    finally:
        _restore(saved)


def test_chat_no_key_returns_no_api_key():
    mod = _r()
    saved = _clear_all_keys()
    try:
        # DeepSeek modeli ama DeepSeek key yok → network'e gitmeden no_api_key
        text, err = mod._chat("deepseek-reasoner", "sys", "user")
        assert text is None and err == "no_api_key"
        assert mod._any_llm_key() is False
    finally:
        _restore(saved)
