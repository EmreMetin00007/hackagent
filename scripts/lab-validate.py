#!/usr/bin/env python3
"""
CCO Live Lab Validation — mcp-hunter zincirini KASITLI-ZAFİYETLİ loopback hedefe karşı
gerçekten (live=True) doğrular + RAG'ı önce ingest ile doldurup enrich_with_rag inline
hit'leri gösterir.

Kapsam (hepsi yetkili, 127.0.0.1):
  1. VulnLab hedefini başlat (scripts/lab/vuln_lab.py)
  2. memory'ye endpoint seed + RAG'ı writeup ingest ile DOLDUR (chromadb varsa)
  3. enrich_with_rag         → predict→RAG inline PoC hit'leri
  4. predict_vulnerabilities → stack tahmini
  5. coverage_report         → kör nokta tespiti
  6. build_authz_matrix + CANLI koşum + analyze_authz_result → BOLA/BFLA CONFIRMED
  7. generate_abuse_cases    → /checkout iş mantığı
  8. auto_fanout_variants(live=True) → /search XSS + /item SQLi triage (LIKELY)

Kullanım:  python3 scripts/lab-validate.py
Çıkış kodu: tüm kritik kontroller geçerse 0, değilse 1.
"""
import os
import sys
import json
import time
import tempfile
import importlib.util
import threading

import requests

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _hdr(t):
    print("\n" + "═" * 68 + f"\n  {t}\n" + "═" * 68)


def main():
    # izole CCO_HOME (gerçek ~/.cco'ya dokunma)
    os.environ["CCO_HOME"] = tempfile.mkdtemp(prefix="cco_lab_")
    for k in ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN", "DEEPSEEK_API_KEY"):
        os.environ.pop(k, None)  # deterministik (LLM zenginleştirme kapalı)

    lab = _load("vuln_lab", os.path.join(REPO, "scripts", "lab", "vuln_lab.py"))
    hunter = _load("hunter", os.path.join(REPO, "mcp-servers", "mcp-hunter", "server.py"))

    srv = lab.serve(0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    target = base
    time.sleep(0.3)
    print(f"VulnLab hazır → {base}")

    checks = []  # (isim, passed)

    # ── memory seed: endpoint'ler ─────────────────────────────────────────────
    import sqlite3
    conn = sqlite3.connect(hunter.MEM_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS endpoints (id INTEGER PRIMARY KEY, target TEXT, "
                 "url_or_port TEXT, protocol TEXT, state TEXT, technologies TEXT, timestamp TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, target TEXT, "
                 "type TEXT, severity TEXT, description TEXT, payload TEXT, timestamp TEXT)")
    for url, tech in [(f"{base}/search?q=1", "php apache"),
                      (f"{base}/item?id=1", "php mysql"),
                      (f"{base}/api/orders/1001", "rest api jwt"),
                      (f"{base}/admin/export", "admin"),
                      (f"{base}/checkout?price=10&quantity=1", "checkout payment")]:
        conn.execute("INSERT INTO endpoints (target,url_or_port,protocol,state,technologies) "
                     "VALUES (?,?,?,?,?)", (target, url, "http", "open", tech))
    conn.commit()
    conn.close()

    # ── RAG'ı ingest ile DOLDUR (offline writeup ingest; chromadb varsa) ───────
    _hdr("ADIM 2 — RAG'ı ingest ile doldur (rag_ingest_writeup)")
    rag_seeded = False
    try:
        rag = _load("rag_engine", os.path.join(REPO, "mcp-servers", "mcp-rag-engine", "server.py"))
        if getattr(rag, "HAS_CHROMADB", False):
            rag.rag_ingest_writeup(
                title="Apache 2.4.49 Path Traversal RCE (CVE-2021-41773)",
                content="Apache HTTP Server 2.4.49 path traversal via encoded ../ in URL leads to "
                        "source disclosure and, with mod_cgi enabled, remote code execution. PoC: "
                        "curl 'http://t/cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh' --data 'echo;id'.",
                category="web", tags="apache,rce,cve-2021-41773", source="manual")
            rag.rag_ingest_writeup(
                title="MySQL error-based SQL injection cheatsheet",
                content="Error-based SQLi: inject a single quote to trigger 'You have an error in "
                        "your SQL syntax'. Use UNION SELECT and extractvalue/updatexml for data "
                        "exfiltration. Confirm with boolean and time-based payloads.",
                category="web", tags="sqli,mysql,error-based", source="manual")
            rag.rag_ingest_writeup(
                title="BOLA / IDOR exploitation guide (OWASP API #1)",
                content="Broken Object Level Authorization: swap the object id with another user's "
                        "id. If the API returns the victim's object with the attacker's token, BOLA "
                        "is confirmed. Differential: compare owner vs attacker response bodies.",
                category="web", tags="bola,idor,api", source="manual")
            cnt = rag._get_collection("writeups").count()
            rag_seeded = cnt > 0
            print(f"  ✓ RAG writeups koleksiyonu dolduruldu ({cnt} kayıt)")
        else:
            print("  ⚠ chromadb yok → RAG inline atlanır (enrich plan modu doğrulanır)")
    except Exception as e:
        print(f"  ⚠ RAG ingest atlandı: {e}")

    # ── 3) enrich_with_rag ─────────────────────────────────────────────────────
    _hdr("ADIM 3 — enrich_with_rag (predict→RAG, CVE PoC)")
    r = json.loads(hunter.enrich_with_rag(fingerprint="Apache 2.4.49 PHP MySQL REST API"))
    print("  matched:", r["matched_technologies"])
    print("  CVE IDs:", r["cve_ids_found"])
    print("  rag_db_ready:", r["rag_db_ready"])
    has_hits = any(ep.get("rag_hits") for ep in r["enriched_predictions"])
    if rag_seeded:
        for ep in r["enriched_predictions"]:
            if ep.get("rag_hits"):
                print(f"  inline hit [{ep['vuln_class']}]:",
                      ep["rag_hits"][0]["collection"], "rel=", ep["rag_hits"][0]["relevance"],
                      "→", ep["rag_hits"][0]["snippet"][:70])
        checks.append(("enrich_with_rag inline PoC hit", has_hits))
    else:
        checks.append(("enrich_with_rag ingest planı", bool(r["ingest_plan"])))
    checks.append(("enrich CVE çıkarımı (CVE-2021-41773)", "CVE-2021-41773" in r["cve_ids_found"]))

    # ── 4) predict ─────────────────────────────────────────────────────────────
    _hdr("ADIM 4 — predict_vulnerabilities")
    p = json.loads(hunter.predict_vulnerabilities(target=target,
                                                  fingerprint="Apache 2.4.49 PHP MySQL REST API"))
    classes = [x["vuln_class"] for x in p["predictions"]]
    print("  tahmin sınıfları:", classes[:6])
    checks.append(("predict path_traversal/sqli", any(c in classes for c in
                  ("path_traversal", "sql_injection", "rce"))))

    # ── 5) coverage ────────────────────────────────────────────────────────────
    _hdr("ADIM 5 — coverage_report (kör nokta)")
    c = json.loads(hunter.coverage_report(target=target))
    print("  coverage%:", c["coverage_percent"], "| kör noktalar:",
          [b["group"] for b in c["blind_spots"]])
    checks.append(("coverage kör nokta tespiti", len(c["blind_spots"]) > 0))

    # ── 6) ERİŞİM KONTROLÜ: matris + CANLI koşum + oracle ──────────────────────
    _hdr("ADIM 6 — build_authz_matrix + CANLI koşum + analyze_authz_result")
    m = json.loads(hunter.build_authz_matrix(
        target=target, identities="anon,userA,userB,admin",
        resources=f"{base}/api/orders/1001,{base}/admin/export",
        object_ids="1001,1002"))
    print("  matris testleri:", m["tests_generated"], "| by_type:", m["by_type"])

    # 6a) BOLA: userB, userA'nın order'ı 1001'e erişiyor mu? (lab token'ı umursamıyor)
    owner = requests.get(f"{base}/api/orders/1001",
                         headers={"Authorization": "Bearer userA"}, timeout=5)
    attacker = requests.get(f"{base}/api/orders/1001",
                            headers={"Authorization": "Bearer userB"}, timeout=5)
    bola = json.loads(hunter.analyze_authz_result(json.dumps({
        "test_type": "bola",
        "authorized": {"identity": "userA", "status": owner.status_code,
                       "body": owner.text, "markers": ["alice@lab.local"]},
        "attacker": {"identity": "userB", "status": attacker.status_code,
                     "body": attacker.text, "markers": ["alice@lab.local"]},
    })))
    print(f"  [BOLA] /api/orders/1001  userB→{attacker.status_code}  verdict={bola['verdict']} "
          f"(conf={bola['confidence']})")
    checks.append(("BOLA CONFIRMED (canlı)", bola["verdict"] == "CONFIRMED"))

    # 6b) BFLA/unauth: anon → /admin/export
    anon = requests.get(f"{base}/admin/export", timeout=5)
    bfla = json.loads(hunter.analyze_authz_result(json.dumps({
        "test_type": "unauth", "attacker": {"identity": "anon", "status": anon.status_code},
    })))
    print(f"  [UNAUTH] /admin/export  anon→{anon.status_code}  verdict={bfla['verdict']}")
    checks.append(("unauth admin CONFIRMED (canlı)", bfla["verdict"] == "CONFIRMED"))

    # ── 7) iş mantığı: negatif fiyat ───────────────────────────────────────────
    _hdr("ADIM 7 — generate_abuse_cases + iş mantığı canlı doğrulama")
    ab = json.loads(hunter.generate_abuse_cases(endpoint=f"{base}/checkout",
                                               params="price,quantity"))
    neg = requests.get(f"{base}/checkout?price=-100&quantity=2", timeout=5).json()
    print(f"  abuse case sınıfları:", sorted({x['vuln_class'] for x in ab['abuse_cases']}))
    print(f"  [LOGIC] /checkout?price=-100&quantity=2 → charged={neg['charged']} "
          f"(negatif kabul edildi!)")
    checks.append(("iş mantığı: negatif fiyat kabul (canlı)", neg["charged"] < 0))

    # ── 8) auto_fanout_variants LIVE: XSS + SQLi ───────────────────────────────
    _hdr("ADIM 8 — auto_fanout_variants(live=True)")
    fx = json.loads(hunter.auto_fanout_variants(
        finding_type="xss_reflected", target=f"{base}/search?q=1",
        param="q", endpoint=f"{base}/search?q=1", live=True, max_requests=6))
    print(f"  [XSS]  mode={fx['mode']} executed={fx['executed_live']} "
          f"likely={len(fx['likely_hits'])}")
    for h in fx["likely_hits"][:1]:
        print("        LIKELY →", h["evidence"])
    checks.append(("auto_fanout XSS LIKELY (canlı)", len(fx["likely_hits"]) >= 1))

    fs = json.loads(hunter.auto_fanout_variants(
        finding_type="sql_injection", target=f"{base}/item?id=1",
        param="id", endpoint=f"{base}/item?id=1", live=True, max_requests=6))
    print(f"  [SQLi] mode={fs['mode']} executed={fs['executed_live']} "
          f"likely={len(fs['likely_hits'])}")
    for h in fs["likely_hits"][:1]:
        print("        LIKELY →", h["evidence"])
    checks.append(("auto_fanout SQLi LIKELY (canlı)", len(fs["likely_hits"]) >= 1))

    # ── ÖZET ───────────────────────────────────────────────────────────────────
    _hdr("SONUÇ")
    ok = sum(1 for _, p in checks if p)
    for name, passed in checks:
        print(f"  {'✓ PASS' if passed else '✗ FAIL'}  {name}")
    print(f"\n  {ok}/{len(checks)} kontrol geçti.")
    srv.shutdown()
    return 0 if ok == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
