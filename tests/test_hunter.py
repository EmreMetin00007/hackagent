"""
mcp-hunter — Bug-Hunting Intelligence offline testleri (deterministik, network/LLM yok).
H1 predict_vulnerabilities · H2 build_authz_matrix + analyze_authz_result ·
H3 generate_abuse_cases · H4 hunt_variants · H5 coverage_report.
"""
import os
import json
import sqlite3

from conftest import load_server


def _h():
    return load_server("hunter")


def _seed(mod, target="htgt"):
    """memory'ye endpoint + finding seed et (izole CCO_HOME)."""
    conn = sqlite3.connect(mod.MEM_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, type TEXT, severity TEXT,
        description TEXT, payload TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, url_or_port TEXT, protocol TEXT,
        state TEXT, technologies TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("DELETE FROM findings WHERE target=?", (target,))
    conn.execute("DELETE FROM endpoints WHERE target=?", (target,))
    conn.executemany(
        "INSERT INTO endpoints (target,url_or_port,protocol,state,technologies) VALUES (?,?,?,?,?)",
        [(target, "https://htgt/api/v1/users/123", "https", "open", "graphql jwt"),
         (target, "https://htgt/admin/export", "https", "open", "nginx"),
         (target, "https://htgt/checkout?price=100&quantity=1&coupon=X", "https", "open", "php")])
    conn.executemany(
        "INSERT INTO findings (target,type,severity,description,payload) VALUES (?,?,?,?,?)",
        [(target, "SQL Injection", "high", "id param on /api/v1/users", "1'")])
    conn.commit()
    conn.close()


def _no_llm():
    for k in ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN", "DEEPSEEK_API_KEY"):
        os.environ.pop(k, None)


# ───────────────────────── H1 predict_vulnerabilities ─────────────────────────
def test_predict_from_fingerprint():
    _no_llm()
    mod = _h()
    out = json.loads(mod.predict_vulnerabilities(fingerprint="Apache 2.4.49 WordPress PHP"))
    assert "wordpress" in out["matched_technologies"]
    assert "apache" in out["matched_technologies"]
    classes = {p["vuln_class"] for p in out["predictions"]}
    # apache path traversal + wordpress sqli/file upload beklenir
    assert "path_traversal" in classes or "sql_injection" in classes
    # cve aileleri dolu
    assert any(p["cve_families"] for p in out["predictions"])
    # ranked by priority_score desc
    scores = [p["priority_score"] for p in out["predictions"]]
    assert scores == sorted(scores, reverse=True)


def test_predict_reads_memory_tech():
    _no_llm()
    mod = _h()
    _seed(mod)
    out = json.loads(mod.predict_vulnerabilities(target="htgt"))
    assert "graphql" in out["matched_technologies"] or "jwt" in out["matched_technologies"]


def test_predict_unknown_stack_advises():
    _no_llm()
    mod = _h()
    out = json.loads(mod.predict_vulnerabilities(fingerprint="zxqw nonsense stack"))
    assert out["matched_technologies"] == []
    assert "advice" in out


# ───────────────────────── H2 build_authz_matrix ─────────────────────────
def test_authz_matrix_classifies_bola_and_bfla():
    _no_llm()
    mod = _h()
    out = json.loads(mod.build_authz_matrix(
        identities="anon,userA,userB,admin",
        resources="https://t/api/users/123,https://t/admin/delete",
        object_ids="123,124"))
    assert out["tests_generated"] > 0
    assert out["by_type"]["bola"] > 0     # users/123 object-level
    assert out["by_type"]["bfla"] > 0     # admin/delete function-level
    assert out["by_type"]["unauth"] > 0   # anon present
    # id substitution gerçekleşti
    assert any("124" in t["resource"] or "123" in t["resource"]
               for t in out["matrix"] if t["test_type"] == "bola")


def test_authz_matrix_pulls_from_memory():
    _no_llm()
    mod = _h()
    _seed(mod)
    out = json.loads(mod.build_authz_matrix(target="htgt", identities="anon,userB"))
    assert out["resources_tested"] >= 1


# ───────────────────────── H2 analyze_authz_result (oracle) ─────────────────────────
def test_authz_oracle_confirms_bola_on_hash_match():
    _no_llm()
    mod = _h()
    out = json.loads(mod.analyze_authz_result(json.dumps({
        "test_type": "bola",
        "authorized": {"identity": "userA", "status": 200, "body_hash": "abc", "markers": ["a@x.com"]},
        "attacker": {"identity": "userB", "status": 200, "body_hash": "abc", "markers": ["a@x.com"]},
    })))
    assert out["verdict"] == "CONFIRMED"
    assert out["confidence"] >= 0.9


def test_authz_oracle_unconfirmed_on_403():
    _no_llm()
    mod = _h()
    out = json.loads(mod.analyze_authz_result(json.dumps({
        "test_type": "bola",
        "authorized": {"identity": "userA", "status": 200, "body_hash": "abc"},
        "attacker": {"identity": "userB", "status": 403},
    })))
    assert out["verdict"] == "UNCONFIRMED"


def test_authz_oracle_bfla_confirmed():
    _no_llm()
    mod = _h()
    out = json.loads(mod.analyze_authz_result(json.dumps({
        "test_type": "bfla",
        "attacker": {"identity": "userB", "status": 200, "method": "DELETE"},
        "authorized": {"identity": "admin", "status": 200},
    })))
    assert out["verdict"] == "CONFIRMED"
    assert out["vuln_class"] == "bfla"


def test_authz_oracle_unauth_confirmed():
    _no_llm()
    mod = _h()
    out = json.loads(mod.analyze_authz_result(json.dumps({
        "test_type": "unauth",
        "attacker": {"identity": "anon", "status": 200},
    })))
    assert out["verdict"] == "CONFIRMED"
    assert out["vuln_class"] == "broken_access_control"


# ───────────────────────── H3 generate_abuse_cases ─────────────────────────
def test_abuse_cases_price_and_role():
    _no_llm()
    mod = _h()
    out = json.loads(mod.generate_abuse_cases(endpoint="/api/checkout",
                                              params="price,quantity,coupon,role,user_id"))
    classes = {c["vuln_class"] for c in out["abuse_cases"]}
    assert "price_manipulation" in classes
    assert "mass_assignment" in classes          # role param
    assert "business_logic" in classes
    # jenerik race condition her zaman eklenir
    assert any(c["vuln_class"] == "race_condition" for c in out["abuse_cases"])
    # impact desc sıralı
    impacts = [c["impact"] for c in out["abuse_cases"]]
    assert impacts == sorted(impacts, reverse=True)


def test_abuse_cases_generic_without_params():
    _no_llm()
    mod = _h()
    out = json.loads(mod.generate_abuse_cases(endpoint="/x"))
    assert "advice" in out
    assert len(out["abuse_cases"]) >= 4          # jenerik saldırılar


# ───────────────────────── H4 hunt_variants ─────────────────────────
def test_hunt_variants_siblings():
    _no_llm()
    mod = _h()
    _seed(mod)
    out = json.loads(mod.hunt_variants(finding_type="sql_injection", target="htgt",
                                       param="id", endpoint="https://htgt/api/v1/users/123"))
    assert out["confirmed_finding"]["vuln_class"] == "sql_injection"
    strategies = {v["strategy"] for v in out["ranked_variants"]}
    assert "sibling_param" in strategies
    assert "method_swap" in strategies
    # EV desc sıralı
    evs = [v["ev"] for v in out["ranked_variants"]]
    assert evs == sorted(evs, reverse=True)


# ───────────────────────── H5 coverage_report ─────────────────────────
def test_coverage_report_gaps_and_blindspots():
    _no_llm()
    mod = _h()
    _seed(mod)
    out = json.loads(mod.coverage_report(target="htgt"))
    assert out["endpoints"] == 3
    assert 0 <= out["coverage_percent"] <= 100
    assert out["top_gaps"]                          # untested cells var
    # access_control / business_logic kör noktası beklenir (sadece sqli denenmiş)
    groups = {b["group"] for b in out["blind_spots"]}
    assert "access_control" in groups or "business_logic" in groups


def test_coverage_empty_advises():
    _no_llm()
    mod = _h()
    out = json.loads(mod.coverage_report(target="no-such-target-xyz"))
    assert "advice" in out


# ───────────────────────── H6 auto_fanout_variants ─────────────────────────
def test_fanout_plan_mode_offline():
    _no_llm()
    mod = _h()
    out = json.loads(mod.auto_fanout_variants(
        finding_type="sql_injection", target="https://t/item?id=1",
        param="id", endpoint="https://t/item?id=1"))
    assert out["mode"] == "PLAN"
    assert out["validator_hook"] == "mcp__validator__validate_sqli"
    assert out["variants"] > 0
    assert out["executed_live"] == 0
    f0 = out["fanout"][0]
    assert f0["curl"].startswith("curl -sk")
    assert "mcp__validator__validate_sqli" in f0["validator_followup"]


def test_fanout_destructive_skipped_live():
    _no_llm()
    mod = _h()
    out = json.loads(mod.auto_fanout_variants(
        finding_type="command_injection", target="https://t/x", endpoint="https://t/x",
        live=True))
    # yıkıcı sınıf → canlı koşum atlanır (network'e gidilmez)
    assert out["executed_live"] == 0
    assert any("skipped_live" in v for v in out["fanout"])


def test_fanout_live_reflection_xss():
    """Loopback yansıtan sunucuya karşı canlı XSS triage (deterministik)."""
    _no_llm()
    mod = _h()
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse as _up, parse_qs

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            q = parse_qs(_up(self.path).query)
            val = (q.get("q") or q.get("search") or [""])[0]
            body = f"<html>echo: {val}</html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{port}/?q=1"
        out = json.loads(mod.auto_fanout_variants(
            finding_type="xss_reflected", target=url, param="q", endpoint=url,
            live=True, max_requests=5))
        assert out["mode"] == "LIVE"
        assert out["executed_live"] > 0
        # yansıyan payload → en az bir LIKELY
        assert len(out["likely_hits"]) >= 1
    finally:
        srv.shutdown()


# ───────────────────────── H7 enrich_with_rag ─────────────────────────
def test_enrich_extracts_cves_and_plan():
    _no_llm()
    mod = _h()
    out = json.loads(mod.enrich_with_rag(fingerprint="Laravel Apache 2.4.49 Struts2 PHP"))
    # Laravel CVE-2021-3129, Apache CVE-2021-41773, Struts CVE-2017-5638
    assert "CVE-2021-3129" in out["cve_ids_found"]
    assert "CVE-2021-41773" in out["cve_ids_found"]
    assert any("rag_ingest_cve" in s for s in out["ingest_plan"])
    assert any("rag_search" in s for s in out["search_plan"])
    assert out["rag_db_ready"] is False           # izole CCO_HOME → henüz ingest yok


def test_enrich_accepts_predictions_json():
    _no_llm()
    mod = _h()
    pred = mod.predict_vulnerabilities(fingerprint="Jenkins")
    out = json.loads(mod.enrich_with_rag(predictions_json=pred))
    assert out["enriched_predictions"]
    assert "CVE-2018-1000861" in out["cve_ids_found"]

