#!/usr/bin/env python3
"""
mcp-reasoning: CCO Biliş / Beyin Katmanı (güçlü LLM çekirdeği)
==============================================================
CCO'nun "düşünme" gücünü üç pilarla üst seviyeye taşır. Pilarlar birbirini besler:
öğrenilen dersler → planlayıcının Bayesçi olasılık önceliklerini günceller →
Reflexion, deterministik validator ile doğrular → sonuç tekrar derse döner.

  1a. REFLEXION  — actor→critic→(validator)→retry: ajan kendi exploit/plan'ını
      eleştirir, başarısızsa öğrenip revize eder → halüsinasyonsuz, kendini düzelten
      akıl yürütme. (`reason_reflexion`, `critic_review`)
  1d. SALDIRI PLANLAMA MOTORU — tree-of-thought + Bayesçi beklenen değer (EV):
      memory knowledge-graph'i okur, en yüksek getirili saldırı yolunu seçer.
      (`plan_attack_tree`, `next_best_action`)
  1e. KALICI ÖĞRENME — oturumlar arası "neyin işe yaradığı" dersleri; planlayıcının
      önceliklerini günceller → zamanla akıllanır. (`record_lesson`, `recall_lessons`,
      `lesson_stats`)

  ⚡ deep_think — bayrak gemisi: recall_lessons → plan_attack_tree → seçilen yola
      Reflexion/critique → deneyimle beslenmiş, kendini eleştirmiş somut aksiyon planı.

LLM servisi: DeepSeek (DEEPSEEK_API_KEY varsa otomatik) veya OpenRouter. Modeller
env ile değiştirilebilir: CCO_REASON_MODEL (actor/planner), CCO_CRITIC_MODEL (critic).
DeepSeek seçildiğinde varsayılan actor=deepseek-reasoner, critic=deepseek-chat.
API key yoksa deterministik kısımlar (EV, dersler, graph) yine çalışır; LLM kısımları
graceful fallback verir.
"""
import os
import re
import json
import time
import sqlite3
import difflib
from datetime import datetime, timezone

import requests
from mcp.server.fastmcp import FastMCP

CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
os.makedirs(CCO_HOME, exist_ok=True)
MEM_DB = os.path.join(CCO_HOME, "agent_memory.db")
LESSONS_DB = os.path.join(CCO_HOME, "lessons.db")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
# DeepSeek OpenAI-uyumlu endpoint (api-docs.deepseek.com). base: https://api.deepseek.com
DEEPSEEK_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/") + "/chat/completions"
# DeepSeek model adları (legacy ad → v4-flash non-thinking/thinking; env ile override).
DEEPSEEK_REASONER = os.environ.get("CCO_DEEPSEEK_REASON_MODEL", "deepseek-reasoner")
DEEPSEEK_CHAT = os.environ.get("CCO_DEEPSEEK_CHAT_MODEL", "deepseek-chat")

mcp = FastMCP(
    "reasoning",
    instructions="CCO biliş katmanı — Reflexion (kendini düzelten akıl yürütme), "
                 "Bayesçi saldırı planlama (EV) ve kalıcı öğrenme. Kompleks/belirsiz "
                 "görevlerde önce deep_think çağır."
)


# ─────────────────────── Sağlayıcı (provider) yardımcıları ───────────────────────
def _config_value(*keys):
    """~/.cco/config.yaml veya settings.json içinden iç içe anahtar okur."""
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


def _openrouter_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
    if key:
        return key
    try:
        import keyring
        key = keyring.get_password("cco", "openrouter")
        if key:
            return key
    except Exception:
        pass
    return _config_value("openrouter_api_key")


def _deepseek_key() -> str:
    """DeepSeek API anahtarı — env > keyring > config. Asla koda gömülmez."""
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    if key:
        return key
    try:
        import keyring
        key = keyring.get_password("cco", "deepseek")
        if key:
            return key
    except Exception:
        pass
    return _config_value("deepseek_api_key")


# Geriye uyumluluk
def _api_key() -> str:
    return _openrouter_key()


def _any_llm_key() -> bool:
    return bool(_deepseek_key() or _openrouter_key())


def _provider_for(model: str):
    """Model adına göre (provider, url, key) seç. 'deepseek*' → DeepSeek; aksi → OpenRouter."""
    if (model or "").lower().startswith("deepseek"):
        return "deepseek", DEEPSEEK_URL, _deepseek_key()
    return "openrouter", OPENROUTER_URL, _openrouter_key()


def reason_model() -> str:
    """Actor/planner modeli — açık override > DeepSeek (key varsa) > Qwen."""
    return os.environ.get("CCO_REASON_MODEL") or (DEEPSEEK_REASONER if _deepseek_key() else "qwen/qwen3.6-plus")


def critic_model() -> str:
    """Critic modeli — actor'dan farklı tutulur (çeşitlilik = daha sert eleştiri)."""
    return os.environ.get("CCO_CRITIC_MODEL") or (DEEPSEEK_CHAT if _deepseek_key() else "nousresearch/hermes-4-405b")


def _chat(model: str, system: str, user: str, temperature: float = 0.4,
          max_tokens: int = 1300, timeout: int = 120):
    """Sağlayıcı-agnostik chat completion (OpenRouter veya DeepSeek). (text, error) döner.
    DeepSeek reasoning yanıtındaki 'reasoning_content' yok sayılır; yalnızca final
    'content' kullanılır (reasoning_content'i mesaj geçmişine geri koymak 400 verir)."""
    provider, url, key = _provider_for(model)
    if not key:
        return None, "no_api_key"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    if provider == "openrouter":
        headers.update({"HTTP-Referer": "https://cco.local", "X-Title": "CCO Reasoning"})
    data = {"model": model, "temperature": temperature, "max_tokens": max_tokens,
            "stream": False,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]}
    try:
        r = requests.post(url, headers=headers, json=data, timeout=timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"], None
    except Exception as e:
        return None, f"{provider}: {e}"


# ═══════════════════════════ Bayesçi teknik kataloğu ═══════════════════════════
TECHNIQUE_SUCCESS_PROBS = {
    "sql_injection": 0.85, "sql_injection_blind": 0.65, "xss_stored": 0.90,
    "xss_reflected": 0.80, "xss_dom": 0.70, "rce": 0.95, "command_injection": 0.90,
    "ssrf": 0.70, "ssrf_blind": 0.50, "idor": 0.80, "lfi": 0.75, "rfi": 0.60,
    "file_upload": 0.65, "ssti": 0.75, "xxe": 0.70, "deserialization": 0.60,
    "buffer_overflow": 0.55, "authentication_bypass": 0.70, "privilege_escalation": 0.65,
    "default_credentials": 0.90, "weak_credentials": 0.80, "credential_reuse": 0.75,
    "subdomain_takeover": 0.85, "cors_misconfiguration": 0.60, "open_redirect": 0.50,
    "csrf": 0.55, "jwt_attack": 0.65, "path_traversal": 0.70,
}
TECH_IMPACT = {
    "rce": 1.0, "command_injection": 1.0, "deserialization": 0.95, "ssti": 0.95,
    "sql_injection": 0.9, "default_credentials": 0.9, "authentication_bypass": 0.85,
    "file_upload": 0.85, "lfi": 0.75, "path_traversal": 0.75, "ssrf": 0.7, "xxe": 0.7,
    "idor": 0.7, "jwt_attack": 0.7, "xss_stored": 0.7, "subdomain_takeover": 0.6,
    "privilege_escalation": 0.8, "xss_reflected": 0.5, "cors_misconfiguration": 0.4,
    "csrf": 0.4, "open_redirect": 0.3,
}
TECH_EFFORT = {  # 0..1 (yüksek = daha çok efor → EV'yi düşürür)
    "default_credentials": 0.1, "open_redirect": 0.15, "idor": 0.25, "sql_injection": 0.3,
    "xss_reflected": 0.3, "ssti": 0.35, "lfi": 0.35, "path_traversal": 0.35,
    "command_injection": 0.4, "ssrf": 0.45, "xxe": 0.45, "authentication_bypass": 0.4,
    "rce": 0.5, "file_upload": 0.5, "jwt_attack": 0.5, "deserialization": 0.75,
    "buffer_overflow": 0.85,
}
RECOMMENDED_TOOL = {
    "sql_injection": "mcp__kali-tools__sqlmap_test_structured",
    "command_injection": "mcp__kali-tools__generate_exploit_poc",
    "rce": "mcp__kali-tools__generate_exploit_poc",
    "ssti": "mcp__kali-tools__generate_exploit_poc",
    "ssrf": "mcp__kali-tools__interactsh_start (OOB)",
    "xxe": "mcp__kali-tools__interactsh_start (OOB)",
    "idor": "mcp__web-advanced__idor_matrix",
    "lfi": "mcp__kali-tools__ffuf_fuzz + manuel payload",
    "path_traversal": "mcp__kali-tools__ffuf_fuzz",
    "jwt_attack": "mcp__web-advanced__jwt_attack",
    "default_credentials": "mcp__kali-tools__hydra_attack",
    "open_redirect": "manuel curl",
    "authentication_bypass": "mcp__web-advanced__*",
}
VALIDATE_WITH = {
    "sql_injection": "mcp__validator__validate_sqli",
    "sql_injection_blind": "mcp__validator__validate_sqli",
    "ssti": "mcp__validator__validate_ssti",
    "command_injection": "mcp__validator__validate_command_injection",
    "rce": "mcp__validator__validate_command_injection",
    "lfi": "mcp__validator__validate_path_traversal",
    "path_traversal": "mcp__validator__validate_path_traversal",
    "xss_reflected": "mcp__validator__validate_xss_reflection",
    "xss_stored": "mcp__validator__validate_xss_reflection",
    "open_redirect": "mcp__validator__validate_open_redirect",
    "ssrf": "mcp__validator__validate_ssrf_oob",
    "ssrf_blind": "mcp__validator__validate_ssrf_oob",
    "xxe": "mcp__validator__validate_xxe",
    "idor": "mcp__validator__validate_idor",
    "authentication_bypass": "mcp__validator__validate_auth_bypass",
}
SEVERITY_IMPACT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}

_SYN = [
    ("sql injection", "sql_injection"), ("sqli", "sql_injection"),
    ("blind sql", "sql_injection_blind"), ("os command", "command_injection"),
    ("command injection", "command_injection"), ("remote code", "rce"),
    ("server-side template", "ssti"), ("template injection", "ssti"),
    ("path traversal", "path_traversal"), ("directory traversal", "path_traversal"),
    ("file inclusion", "lfi"), ("local file", "lfi"), ("cross-site scripting", "xss_reflected"),
    ("reflected xss", "xss_reflected"), ("stored xss", "xss_stored"), ("dom xss", "xss_dom"),
    ("insecure direct object", "idor"), ("server-side request", "ssrf"),
    ("xml external", "xxe"), ("open redirect", "open_redirect"),
    ("auth bypass", "authentication_bypass"), ("authentication bypass", "authentication_bypass"),
    ("default cred", "default_credentials"), ("weak cred", "weak_credentials"),
    ("jwt", "jwt_attack"), ("deserial", "deserialization"), ("file upload", "file_upload"),
    ("subdomain takeover", "subdomain_takeover"), ("cors", "cors_misconfiguration"),
    ("privilege escal", "privilege_escalation"), ("priv esc", "privilege_escalation"),
]


def _normalize_tech(s: str) -> str:
    low = (s or "").strip().lower()
    for needle, key in _SYN:
        if needle in low:
            return key
    norm = re.sub(r"[^a-z0-9]+", "_", low).strip("_")
    return norm or "unknown"


# ─────────────────────────── Lessons DB (1e) ───────────────────────────
def _lessons_conn():
    conn = sqlite3.connect(LESSONS_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS lessons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, context TEXT, technique TEXT, target_tech TEXT,
        action TEXT, outcome TEXT, worked INTEGER, tags TEXT)""")
    return conn


def _learned_winrate(technique: str):
    """(rate, n) — bu teknik için öğrenilmiş başarı oranı ve örnek sayısı."""
    try:
        conn = _lessons_conn()
        row = conn.execute(
            "SELECT AVG(worked), COUNT(*) FROM lessons WHERE technique=?",
            (technique,)).fetchone()
        conn.close()
        if row and row[1]:
            return float(row[0]), int(row[1])
    except Exception:
        pass
    return None, 0


def _blended_prob(technique: str):
    """Bayesçi karışım: statik prior + öğrenilmiş win-rate (örnek sayısıyla ağırlıklı)."""
    base = TECHNIQUE_SUCCESS_PROBS.get(technique, 0.5)
    rate, n = _learned_winrate(technique)
    if rate is None or n == 0:
        return base, "prior"
    # n büyüdükçe öğrenilen veri ağır basar (pseudo-count 4)
    w = n / (n + 4.0)
    blended = round((1 - w) * base + w * rate, 4)
    return blended, f"blended(n={n})"


# ─────────────────────────── Memory okuma ───────────────────────────
def _read_findings(target: str):
    out = []
    try:
        conn = sqlite3.connect(MEM_DB)
        q = "SELECT type, severity, description, payload FROM findings"
        params = ()
        if target:
            q += " WHERE target=?"
            params = (target,)
        for typ, sev, desc, pl in conn.execute(q, params).fetchall():
            out.append({"type": typ, "severity": (sev or "info").lower(),
                        "description": desc or "", "payload": pl or ""})
        conn.close()
    except Exception:
        pass
    return out


def _read_endpoints(target: str):
    out = []
    try:
        conn = sqlite3.connect(MEM_DB)
        q = "SELECT url_or_port, protocol, state, technologies FROM endpoints"
        params = ()
        if target:
            q += " WHERE target=?"
            params = (target,)
        for url, proto, state, tech in conn.execute(q, params).fetchall():
            out.append({"url_or_port": url, "protocol": proto or "",
                        "state": state or "", "technologies": tech or ""})
        conn.close()
    except Exception:
        pass
    return out


def _ev(technique: str, severity: str = "info"):
    """Beklenen değer = blended_prob * impact * (1 - 0.4*effort)."""
    prob, src = _blended_prob(technique)
    impact = max(TECH_IMPACT.get(technique, 0.0), SEVERITY_IMPACT.get(severity, 0.1))
    effort = TECH_EFFORT.get(technique, 0.5)
    ev = round(prob * impact * (1 - 0.4 * effort), 4)
    return ev, prob, impact, effort, src


def _candidate_actions(target: str):
    """Findings + endpoints → puanlanmış aday saldırı aksiyonları (deterministik)."""
    findings = _read_findings(target)
    endpoints = _read_endpoints(target)
    actions = []

    for f in findings:
        tech = _normalize_tech(f["type"])
        ev, prob, impact, effort, src = _ev(tech, f["severity"])
        actions.append({
            "technique": tech, "source": "finding", "severity": f["severity"],
            "ev": ev, "prob": prob, "impact": impact, "effort": effort, "prior_source": src,
            "recommended_tool": RECOMMENDED_TOOL.get(tech, "mcp__kali-tools__generate_exploit_poc"),
            "validate_with": VALIDATE_WITH.get(tech, "mcp__validator__validate_finding"),
            "rationale": f"Bulgu: {f['type']} ({f['severity']}) — {f['description'][:80]}",
        })

    # endpoint teknolojilerinden çıkarımlı teknikler
    tech_hints = {
        "php": ["lfi"], "wordpress": ["sql_injection", "file_upload"],
        "graphql": ["sql_injection", "idor"], "jwt": ["jwt_attack"],
        "node": ["ssti", "deserialization"], "express": ["ssti"],
        "java": ["deserialization"], "spring": ["ssti"],
        "flask": ["ssti"], "jinja": ["ssti"], "login": ["authentication_bypass", "sql_injection"],
        "upload": ["file_upload"], "redirect": ["open_redirect"], "api": ["idor", "ssrf"],
        "xml": ["xxe"], "soap": ["xxe"],
    }
    seen = {a["technique"] for a in actions}
    for ep in endpoints:
        blob = f"{ep['url_or_port']} {ep['technologies']}".lower()
        for hint, techs in tech_hints.items():
            if hint in blob:
                for tech in techs:
                    if tech in seen:
                        continue
                    seen.add(tech)
                    ev, prob, impact, effort, src = _ev(tech, "medium")
                    actions.append({
                        "technique": tech, "source": "inferred-from-endpoint", "severity": "medium",
                        "ev": ev, "prob": prob, "impact": impact, "effort": effort, "prior_source": src,
                        "recommended_tool": RECOMMENDED_TOOL.get(tech, "mcp__kali-tools__generate_exploit_poc"),
                        "validate_with": VALIDATE_WITH.get(tech, "mcp__validator__validate_finding"),
                        "rationale": f"Endpoint ipucu '{hint}' → {tech} dene ({ep['url_or_port']})",
                    })
    actions.sort(key=lambda a: a["ev"], reverse=True)
    return actions, findings, endpoints


def _static_critique(kind: str):
    base = ["Scope/izin doğrulandı mı?", "False-positive: deterministik validator ile teyit edildi mi?"]
    by = {
        "exploit": ["Payload hedef stack'e uygun mu (DB/OS/template engine)?",
                    "WAF/encoding bypass gerekiyor mu?", "İdempotent ve geri-dönüşsüz hasar yok mu?",
                    "PoC reproducible mı (tek komutla)?"],
        "plan": ["En yüksek EV yolu mu seçildi?", "Önkoşullar (auth/erişim) sağlandı mı?",
                 "Alternatif vektör hazır mı (başarısızlık halinde)?"],
        "finding": ["Severity/CVSS doğru mu?", "Impact net mi?", "Kanıt yeterli mi?"],
        "code": ["Sömürülebilir sink doğrulandı mı?", "Girdi gerçekten kullanıcı-kontrollü mü?"],
    }
    return base + by.get(kind, [])


# ════════════════════════════════ TOOLS ════════════════════════════════

@mcp.tool()
def plan_attack_tree(target: str = "", scope: str = "", expand: bool = True) -> str:
    """1d — Bayesçi saldırı planlama motoru. memory'deki bulgu/endpoint'leri okur,
    her saldırı vektörünü beklenen-değer (EV = blended_prob × impact × effort) ile
    puanlar ve sıralar. expand=True ise (LLM varsa) tree-of-thought ile çok-adımlı
    zincirler üretir. Öğrenilen dersler önceliklere otomatik karışır (1e ile bağlı).

    Args:
        target: Hedef (memory'de bu hedefin bulgularını okur; boşsa tümü)
        scope: Scope notu (rapor için)
        expand: LLM ile tree-of-thought genişletmesi yap (varsa)
    """
    actions, findings, endpoints = _candidate_actions(target)
    result = {
        "engine": "bayesian-ev + tree-of-thought",
        "target": target or "(tümü)", "scope": scope,
        "findings_count": len(findings), "endpoints_count": len(endpoints),
        "ranked_actions": actions[:12],
        "highest_ev": actions[0] if actions else None,
        "note": "EV = blended_prob × impact × (1 - 0.4·effort). blended_prob = statik "
                "prior + öğrenilmiş win-rate (record_lesson ile büyür).",
    }
    if not actions:
        result["advice"] = ("memory boş — önce recon/enumeration yap ve store_finding/"
                            "store_endpoint ile kaydet, sonra tekrar planla.")
    if expand and actions:
        top = actions[:5]
        sys = ("You are an elite offensive-security planner in an authorized lab. Given "
               "ranked single-step vectors, produce a concise multi-step attack TREE "
               "(chains, preconditions, pivots) toward maximum impact. Be concrete and "
               "technical. Output short bullet chains.")
        usr = (f"Target: {target}\nScope: {scope}\nTop EV vectors:\n" +
               "\n".join(f"- {a['technique']} (EV={a['ev']}, {a['rationale']})" for a in top))
        narrative, err = _chat(reason_model(), sys, usr, temperature=0.5, max_tokens=900)
        result["tot_narrative"] = narrative
        result["tot_model"] = reason_model() if narrative else None
        if err:
            result["tot_note"] = f"LLM genişletme yok ({err}); deterministik sıralama geçerli."
    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def next_best_action(target: str = "") -> str:
    """1d (hızlı) — Mevcut memory durumuna göre EN YÜKSEK beklenen-değerli TEK sonraki
    aksiyonu döndürür (deterministik, LLM gerekmez). OODA 'Decide' adımı için.

    Args:
        target: Hedef (boşsa tüm bulgular)
    """
    actions, findings, _ = _candidate_actions(target)
    if not actions:
        return json.dumps({"action": None,
                           "advice": "memory boş — önce recon yap + store_finding/store_endpoint."},
                          indent=2, ensure_ascii=False)
    top = actions[0]
    return json.dumps({
        "next_best_action": top,
        "alternatives": actions[1:4],
        "decide_rationale": f"{top['technique']} en yüksek EV ({top['ev']}); "
                            f"önce {top['validate_with']} ile doğrula, sonra {top['recommended_tool']}.",
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def critic_review(artifact: str, kind: str = "exploit", context: str = "") -> str:
    """1a — Bağımsız 'critic'. Bir exploit/PoC/bulgu/plan/kod parçasını DOĞRULUK,
    false-positive riski ve OPSEC açısından eleştirir; revizyon önerir. Critic modeli
    actor'dan FARKLI tutulur (çeşitlilik daha sert eleştiri verir).

    Args:
        artifact: İncelenecek içerik (exploit kodu, PoC, bulgu açıklaması, plan)
        kind: 'exploit' | 'plan' | 'finding' | 'code'
        context: Hedef/stack bağlamı
    """
    sys = ("You are a ruthless senior red-team reviewer in an authorized lab. Critique "
           "the artifact for correctness, false-positive risk, target-fit, WAF/encoding "
           "needs, OPSEC and reproducibility. Be specific. End with a line "
           "'VERDICT: APPROVED' or 'VERDICT: REVISE' and a confidence 0-1.")
    usr = f"Kind: {kind}\nContext: {context}\n\nARTIFACT:\n{artifact}"
    out, err = _chat(critic_model(), sys, usr, temperature=0.3, max_tokens=900)
    if out is None:
        return json.dumps({
            "critic_model": None, "verdict": "REVIEW_MANUALLY",
            "llm_error": err, "static_checklist": _static_critique(kind),
            "note": "LLM yok — statik kontrol listesiyle elle değerlendir.",
        }, indent=2, ensure_ascii=False)
    verdict = "APPROVED" if re.search(r"VERDICT:\s*APPROVED", out, re.I) else "REVISE"
    mconf = re.search(r"([01](?:\.\d+)?)\s*$", out.strip())
    return json.dumps({
        "critic_model": critic_model(), "kind": kind, "verdict": verdict,
        "confidence": float(mconf.group(1)) if mconf else None,
        "critique": out,
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def reason_reflexion(task: str, target: str = "", context: str = "",
                     artifact_kind: str = "exploit", max_iters: int = 3) -> str:
    """1a — REFLEXION döngüsü: actor bir artifact üretir → critic eleştirir →
    actor revize eder → critic onaylayana veya max_iters'a kadar. Halüsinasyonu
    düşürür; çıktı + tüm yansıma izi döner. Sonunda deterministik doğrulama önerir.

    Args:
        task: Üretilecek şey ('SQLi exploit for id param', 'attack plan for X'...)
        target: Hedef/stack
        context: Ek bağlam (recon çıktısı, parametreler, WAF notu)
        artifact_kind: 'exploit' | 'plan' | 'finding' | 'code'
        max_iters: Maksimum actor↔critic turu (1-5)
    """
    max_iters = max(1, min(int(max_iters), 5))
    if not _any_llm_key():
        return json.dumps({
            "approved": False, "llm_error": "no_api_key",
            "static_checklist": _static_critique(artifact_kind),
            "note": "LLM yok — DEEPSEEK_API_KEY veya OPENROUTER_API_KEY ayarla. "
                    "Statik kontrol listesiyle elle yürüt.",
        }, indent=2, ensure_ascii=False)

    actor_sys = ("You are an elite exploit developer in an authorized lab. Produce a "
                 "concrete, technically correct, reproducible artifact for the task. "
                 "If given prior critique, FIX every issue. Output only the artifact.")
    critic_sys = ("You are a ruthless reviewer. Find every flaw, false-positive risk, "
                  "target-mismatch, missing step. End with 'VERDICT: APPROVED' or "
                  "'VERDICT: REVISE'.")
    actor_m, critic_m = reason_model(), critic_model()
    iterations, draft, critique = [], "", ""
    approved = False
    for i in range(max_iters):
        actor_usr = (f"Task: {task}\nTarget: {target}\nContext: {context}\n" +
                     (f"\nPrior critique to fix:\n{critique}" if critique else ""))
        draft, err = _chat(actor_m, actor_sys, actor_usr, temperature=0.5, max_tokens=1100)
        if draft is None:
            iterations.append({"iter": i + 1, "error": err})
            break
        critique, cerr = _chat(critic_m, critic_sys,
                               f"Task: {task}\nTarget: {target}\n\nARTIFACT:\n{draft}",
                               temperature=0.3, max_tokens=700)
        approved = bool(critique) and bool(re.search(r"VERDICT:\s*APPROVED", critique, re.I))
        iterations.append({"iter": i + 1, "draft": draft,
                           "critique": critique or f"(critic hata: {cerr})",
                           "verdict": "APPROVED" if approved else "REVISE"})
        if approved:
            break
    tech = _normalize_tech(task)
    return json.dumps({
        "task": task, "approved": approved, "rounds": len(iterations),
        "final_artifact": draft, "iterations": iterations,
        "recommended_validation": VALIDATE_WITH.get(tech, "mcp__validator__validate_finding"),
        "actor_model": actor_m, "critic_model": critic_m,
        "note": "Onaylandıysa bile mcp__validator ile deterministik doğrula, sonra record_lesson.",
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def record_lesson(context: str, technique: str, action: str, outcome: str,
                  worked: bool, target_tech: str = "", tags: str = "") -> str:
    """1e — Kalıcı ders kaydı. Ne denendi, hangi bağlamda, işe yaradı mı? Bu veri
    planlayıcının olasılık önceliklerini günceller (zamanla akıllanır). BAŞARI ve
    BAŞARISIZLIK eşit değerlidir — ikisi de kaydedilmeli.

    Args:
        context: Durum ('Apache 2.4.49 + login form', 'GraphQL API behind Cloudflare')
        technique: Teknik (sql_injection, ssti, idor, command_injection, ...)
        action: Yapılan somut aksiyon/payload
        outcome: Sonuç açıklaması (kanıt/hata)
        worked: İşe yaradı mı (True/False)
        target_tech: Hedef teknoloji/stack (opsiyonel)
        tags: Virgülle etiketler (opsiyonel)
    """
    tech = _normalize_tech(technique)
    try:
        conn = _lessons_conn()
        conn.execute(
            "INSERT INTO lessons (ts, context, technique, target_tech, action, outcome, worked, tags) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), context, tech, target_tech,
             action, outcome, 1 if worked else 0, tags))
        conn.commit()
        lid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        rate, n = _learned_winrate(tech)
        return json.dumps({
            "stored": True, "lesson_id": lid, "technique": tech, "worked": worked,
            "updated_winrate": {"technique": tech, "rate": rate, "samples": n},
            "effect": f"plan_attack_tree artık '{tech}' için öğrenilmiş win-rate'i kullanacak.",
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"stored": False, "error": str(e)}, ensure_ascii=False)


@mcp.tool()
def recall_lessons(context: str = "", technique: str = "", tags: str = "", k: int = 5) -> str:
    """1e — Mevcut duruma EN İLGİLİ geçmiş dersleri getirir (bağlam benzerliği +
    teknik/etiket eşleşmesi). Yeni bir göreve başlarken 'daha önce ne işe yaradı?'
    bilgisini enjekte eder.

    Args:
        context: Mevcut durum metni
        technique: Filtre tekniği (opsiyonel)
        tags: Virgülle etiket filtresi (opsiyonel)
        k: Döndürülecek ders sayısı
    """
    want_tags = {t.strip().lower() for t in tags.split(",") if t.strip()}
    tech = _normalize_tech(technique) if technique else ""
    try:
        conn = _lessons_conn()
        rows = conn.execute(
            "SELECT id, ts, context, technique, target_tech, action, outcome, worked, tags "
            "FROM lessons").fetchall()
        conn.close()
    except Exception as e:
        return json.dumps({"lessons": [], "error": str(e)}, ensure_ascii=False)

    scored = []
    for r in rows:
        lid, ts, ctx, ltech, ttech, action, outcome, worked, ltags = r
        sim = difflib.SequenceMatcher(None, (context or "").lower(), (ctx or "").lower()).ratio()
        score = 0.6 * sim
        if tech and ltech == tech:
            score += 0.3
        ltagset = {t.strip().lower() for t in (ltags or "").split(",") if t.strip()}
        if want_tags and (want_tags & ltagset):
            score += 0.2 * len(want_tags & ltagset)
        scored.append((score, {
            "id": lid, "context": ctx, "technique": ltech, "target_tech": ttech,
            "action": action, "outcome": outcome, "worked": bool(worked), "tags": ltags,
            "relevance": round(score, 3)}))
    scored.sort(key=lambda x: x[0], reverse=True)
    top = [d for s, d in scored[:max(1, int(k))]]
    return json.dumps({
        "query": {"context": context, "technique": tech, "tags": list(want_tags)},
        "total_lessons": len(rows), "returned": len(top), "lessons": top,
        "hint": "İşe yarayanları (worked=true) önceliklendir; yaramayan vektörleri tekrar etme.",
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def lesson_stats() -> str:
    """1e — Birikmiş öğrenme özeti: toplam ders, teknik bazında win-rate, etiket
    dağılımı. Hangi tekniklerin bu ajanın elinde gerçekte işe yaradığını gösterir.
    """
    try:
        conn = _lessons_conn()
        total = conn.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
        overall = conn.execute("SELECT AVG(worked) FROM lessons").fetchone()[0]
        per = conn.execute(
            "SELECT technique, AVG(worked), COUNT(*) FROM lessons GROUP BY technique "
            "ORDER BY COUNT(*) DESC").fetchall()
        conn.close()
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    return json.dumps({
        "total_lessons": total,
        "overall_winrate": round(overall, 3) if overall is not None else None,
        "by_technique": [{"technique": t, "winrate": round(w, 3), "samples": n} for t, w, n in per],
        "note": "Bu win-rate'ler plan_attack_tree EV hesabına otomatik karışır.",
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def deep_think(task: str, target: str = "", scope: str = "", context: str = "",
               reflexion: bool = True) -> str:
    """⚡ BAYRAK GEMİSİ — CCO'nun 'güçlü beyni'. Üç piları tek çağrıda birleştirir:
    (1e) ilgili geçmiş dersleri hatırla → (1d) Bayesçi saldırı planı kur →
    (1a) seçilen yola Reflexion/critique uygula. Deneyimle beslenmiş, kendini
    eleştirmiş, validator-bağlı somut bir aksiyon planı döndürür. Kompleks/belirsiz
    görevlerde İLK çağrı bu olmalı.

    Args:
        task: Görev ('X hedefini exploit et', 'bu API'de en yüksek impact'i bul')
        target: Hedef (memory anahtarı)
        scope: Scope
        context: Recon/stack bağlamı
        reflexion: Seçilen aksiyona Reflexion uygula (LLM varsa)
    """
    recalled = json.loads(recall_lessons(context=f"{task} {context}", k=5))
    plan = json.loads(plan_attack_tree(target=target, scope=scope, expand=True))
    chosen = plan.get("highest_ev")

    out = {
        "task": task, "target": target, "scope": scope,
        "step_1_recalled_lessons": recalled.get("lessons", []),
        "step_2_attack_plan": {
            "ranked_actions": plan.get("ranked_actions", []),
            "tot_narrative": plan.get("tot_narrative"),
            "findings_count": plan.get("findings_count"),
            "endpoints_count": plan.get("endpoints_count"),
        },
        "step_3_chosen_action": chosen,
    }
    if chosen:
        out["validator_hook"] = chosen.get("validate_with")
        out["recommended_tool"] = chosen.get("recommended_tool")
        if reflexion and _any_llm_key():
            refl = json.loads(reason_reflexion(
                task=f"{task} — primary vector: {chosen['technique']}",
                target=target,
                context=(context + "\nRecalled lessons: " +
                         "; ".join(l["action"] for l in recalled.get("lessons", [])[:3])),
                artifact_kind="plan", max_iters=2))
            out["step_4_reflexion"] = {
                "approved": refl.get("approved"), "rounds": refl.get("rounds"),
                "final_artifact": refl.get("final_artifact"),
                "recommended_validation": refl.get("recommended_validation"),
            }
        else:
            out["step_4_reflexion"] = {"skipped": True,
                                       "reason": "reflexion kapalı veya LLM yok",
                                       "static_checklist": _static_critique("plan")}
    else:
        out["advice"] = ("memory boş — önce recon/enumeration yap, store_finding/"
                         "store_endpoint ile kaydet, sonra deep_think tekrar çağır.")

    out["next_steps"] = [
        "1) chosen_action.validate_with ile deterministik DOĞRULA (false-positive guard)",
        "2) CONFIRMED ise recommended_tool ile exploit et + store_finding",
        "3) Sonucu record_lesson ile kaydet (worked=true/false) → beyin akıllanır",
    ]
    return json.dumps(out, indent=2, ensure_ascii=False)


# ═══════════ Kill-Chain Intelligence — saldırı zinciri kompozisyonu (a) ═══════════
# Yetenek grafiği: kaynak yetenek → (hedef yetenek, fizibilite, pivot notu). Bulgular
# giriş yetenekleridir; DFS ile yüksek-impact terminal yeteneklere zincir kurulur.
CAPABILITY_IMPACT = {
    "remote_code_execution": 1.0, "webshell": 0.95, "cloud_account_takeover": 1.0,
    "iam_credentials": 0.9, "data_breach": 0.9, "account_takeover": 0.9,
    "admin_access": 0.85, "internal_network_access": 0.8, "credential_dump": 0.8,
    "session_hijack": 0.7, "oauth_token_theft": 0.7, "cloud_metadata_access": 0.6,
    "authentication_bypass": 0.6, "log_poisoning": 0.5, "ssrf": 0.5,
}
CHAIN_RULES = {
    "ssrf": [("cloud_metadata_access", 0.7, "169.254.169.254 IMDS sorgusu"),
             ("internal_network_access", 0.5, "iç ağ port taraması / pivot")],
    "cloud_metadata_access": [("iam_credentials", 0.8, "IMDS role kimlik bilgisi sızıntısı")],
    "iam_credentials": [("cloud_account_takeover", 0.7, "AWS/GCP API ile kaynak ele geçirme"),
                        ("data_breach", 0.7, "S3/bucket / storage okuma")],
    "lfi": [("log_poisoning", 0.6, "access.log'a PHP payload enjeksiyonu"),
            ("credential_dump", 0.6, "config/.env/secrets okuma")],
    "log_poisoning": [("remote_code_execution", 0.7, "poisoned log include → kod yürütme")],
    "path_traversal": [("credential_dump", 0.55, "hassas dosya okuma")],
    "rfi": [("remote_code_execution", 0.8, "uzak shell include")],
    "file_upload": [("webshell", 0.7, "yürütülebilir dosya yükleme")],
    "webshell": [("remote_code_execution", 0.95, "yüklenen shell çağrısı")],
    "sql_injection": [("credential_dump", 0.8, "users tablosu / hash dump"),
                      ("authentication_bypass", 0.5, "' OR 1=1 login bypass")],
    "sql_injection_blind": [("credential_dump", 0.6, "boolean/time-based veri çıkarımı")],
    "credential_dump": [("admin_access", 0.7, "kırılan hash ile admin login")],
    "authentication_bypass": [("admin_access", 0.7, "yetkili panel erişimi")],
    "default_credentials": [("admin_access", 0.85, "varsayılan admin login")],
    "weak_credentials": [("admin_access", 0.7, "zayıf parola brute/guess")],
    "admin_access": [("remote_code_execution", 0.6, "admin paneli → dosya/komut yürütme"),
                     ("data_breach", 0.7, "tüm veriye erişim")],
    "idor": [("account_takeover", 0.6, "başka kullanıcı kaynağı → ATO"),
             ("data_breach", 0.6, "yetkisiz veri okuma")],
    "open_redirect": [("oauth_token_theft", 0.5, "OAuth redirect_uri ile token sızdırma")],
    "oauth_token_theft": [("account_takeover", 0.8, "çalınan token ile hesap ele geçirme")],
    "xss_stored": [("session_hijack", 0.7, "kalıcı cookie/oturum çalma")],
    "xss_reflected": [("session_hijack", 0.5, "kurban cookie çalma")],
    "xss_dom": [("session_hijack", 0.5, "DOM tabanlı oturum çalma")],
    "session_hijack": [("account_takeover", 0.8, "çalınan oturumla ATO")],
    "jwt_attack": [("authentication_bypass", 0.6, "alg=none / zayıf imza → kimlik sahteciliği")],
    "ssti": [("remote_code_execution", 0.8, "template engine RCE")],
    "command_injection": [("remote_code_execution", 0.95, "doğrudan komut yürütme")],
    "rce": [("remote_code_execution", 0.99, "doğrudan kod yürütme")],
    "xxe": [("ssrf", 0.6, "XXE → iç istek (SSRF pivot)"),
            ("credential_dump", 0.6, "dosya okuma via XXE")],
    "deserialization": [("remote_code_execution", 0.7, "gadget chain RCE")],
    "subdomain_takeover": [("account_takeover", 0.6, "cookie/oauth domain trust kötüye kullanımı")],
    "cors_misconfiguration": [("data_breach", 0.5, "kimlikli cross-origin veri okuma")],
}
CAPABILITY_TOOL = {
    "cloud_metadata_access": "mcp__kali-tools__interactsh_start (OOB) / curl IMDS",
    "iam_credentials": "aws/gcloud CLI ile çalınan token doğrulama",
    "cloud_account_takeover": "bulut API enumeration",
    "log_poisoning": "manuel curl (User-Agent/log injection)",
    "webshell": "mcp__kali-tools__generate_exploit_poc",
    "credential_dump": "mcp__kali-tools__sqlmap_test_structured --dump",
    "admin_access": "mcp__kali-tools__hydra_attack / manuel login",
    "session_hijack": "mcp__browser__browser_cookie_audit",
    "oauth_token_theft": "manuel OAuth akış analizi",
    "account_takeover": "manuel doğrulama (giriş)",
    "remote_code_execution": "mcp__kali-tools__generate_exploit_poc",
    "data_breach": "manuel veri erişim kanıtı",
    "internal_network_access": "mcp__kali-tools__nmap_scan_structured (pivot)",
    "ssrf": "mcp__validator__validate_ssrf_oob",
    "authentication_bypass": "mcp__validator__validate_auth_bypass",
}


def _cap_impact(node: str) -> float:
    return CAPABILITY_IMPACT.get(node, TECH_IMPACT.get(node, 0.0))


def _step_meta(node: str) -> dict:
    return {
        "capability": node,
        "validate_with": VALIDATE_WITH.get(node, ""),
        "recommended_tool": CAPABILITY_TOOL.get(node, RECOMMENDED_TOOL.get(node, "")),
        "impact": _cap_impact(node),
    }


def _build_chain(path, edge_feas, notes):
    entry = path[0]
    entry_prob, prior_src = _blended_prob(entry)
    comp = entry_prob
    for f in edge_feas:
        comp *= f
    terminal = path[-1]
    impact = _cap_impact(terminal)
    num_edges = len(path) - 1
    effort = min(0.95, TECH_EFFORT.get(entry, 0.5) + 0.12 * num_edges)
    ev = round(comp * impact * (1 - 0.4 * effort), 4)
    steps = []
    for i, node in enumerate(path):
        m = _step_meta(node)
        if i > 0:
            m["feasibility"] = edge_feas[i - 1]
            m["pivot_note"] = notes[i - 1]
        steps.append(m)
    return {
        "label": " → ".join(path), "entry": entry, "terminal": terminal,
        "length": len(path), "composite_prob": round(comp, 4), "impact": impact,
        "effort": round(effort, 3), "ev": ev, "entry_prior_source": prior_src, "steps": steps,
    }


def _compose_from(entry, max_depth):
    chains, seen = [], set()

    def dfs(node, path, feas, notes, depth, visited):
        if len(path) >= 2 and _cap_impact(node) >= 0.6:
            ch = _build_chain(path, feas, notes)
            if ch["label"] not in seen:
                seen.add(ch["label"])
                chains.append(ch)
        if depth >= max_depth:
            return
        for (tgt, f, note) in CHAIN_RULES.get(node, []):
            if tgt in visited:
                continue
            dfs(tgt, path + [tgt], feas + [f], notes + [note], depth + 1, visited | {tgt})

    dfs(entry, [entry], [], [], 0, {entry})
    return chains


# ═══════════ WAF-aware Payload Evolution — guided mutation (d) ═══════════
import base64 as _b64
from urllib.parse import quote as _urlq


def _op_case_swap(p): return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p))
def _op_url_encode(p): return _urlq(p, safe="")
def _op_double_url_encode(p): return _urlq(_urlq(p, safe=""), safe="")
def _op_inline_comment(p): return p.replace(" ", "/**/")
def _op_versioned_comment(p): return re.sub(r"(?i)\b(union|select|from|where)\b", r"/*!50000\1*/", p)
def _op_whitespace_alt(p): return p.replace(" ", "%0a")
def _op_keyword_split(p): return re.sub(r"(?i)union", "UNI/**/ON", re.sub(r"(?i)select", "SEL/**/ECT", p))
def _op_html_entity(p): return p.replace("<", "&lt;").replace(">", "&gt;")
def _op_js_unicode(p): return "".join("\\u%04x" % ord(c) if c.isalpha() else c for c in p)
def _op_tag_breakup(p): return p.replace("script", "scr<x>ipt").replace("alert", "al<x>ert")
def _op_svg_alt(p): return p.replace("<script>", "<svg/onload=").replace("</script>", ">")
def _op_ifs(p): return p.replace(" ", "${IFS}")
def _op_quote_insert(p): return re.sub(r"([a-z]{2,})", lambda m: m.group(1)[0] + "''" + m.group(1)[1:], p, count=1)
def _op_b64_wrap(p): return f"echo {_b64.b64encode(p.encode()).decode()}|base64 -d|sh"
def _op_dot_alt(p): return p.replace("../", "....//")
def _op_unicode_slash(p): return p.replace("/", "%c0%af")
def _op_null_byte(p): return p + "%00"

OPERATORS = {
    "case_swap": _op_case_swap, "url_encode": _op_url_encode,
    "double_url_encode": _op_double_url_encode, "inline_comment": _op_inline_comment,
    "versioned_comment": _op_versioned_comment, "whitespace_alt": _op_whitespace_alt,
    "keyword_split": _op_keyword_split, "html_entity": _op_html_entity,
    "js_unicode": _op_js_unicode, "tag_breakup": _op_tag_breakup, "svg_alt": _op_svg_alt,
    "ifs_sub": _op_ifs, "quote_insert": _op_quote_insert, "b64_wrap": _op_b64_wrap,
    "dot_alt": _op_dot_alt, "unicode_slash": _op_unicode_slash, "null_byte": _op_null_byte,
}
FAMILY_OPS = {
    "sql_injection": ["inline_comment", "versioned_comment", "keyword_split", "case_swap",
                      "whitespace_alt", "url_encode", "double_url_encode"],
    "xss_reflected": ["case_swap", "tag_breakup", "svg_alt", "js_unicode", "html_entity", "url_encode"],
    "xss_stored": ["case_swap", "tag_breakup", "svg_alt", "js_unicode", "url_encode"],
    "command_injection": ["ifs_sub", "quote_insert", "b64_wrap", "case_swap", "url_encode"],
    "path_traversal": ["dot_alt", "url_encode", "double_url_encode", "unicode_slash", "null_byte"],
    "ssti": ["whitespace_alt", "case_swap", "url_encode"],
}
_FAMILY_ALIAS = {
    "sql_injection_blind": "sql_injection", "rce": "command_injection",
    "lfi": "path_traversal", "rfi": "path_traversal", "xss_dom": "xss_reflected",
}


def _payload_family(tech): return _FAMILY_ALIAS.get(tech, tech)


def _payload_ops_conn():
    conn = sqlite3.connect(LESSONS_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS payload_ops (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, technique TEXT, operators TEXT,
        blocked_by TEXT, worked INTEGER)""")
    return conn


def _op_winrate(op, technique):
    try:
        conn = _payload_ops_conn()
        row = conn.execute(
            "SELECT AVG(worked), COUNT(*) FROM payload_ops WHERE technique=? AND operators LIKE ?",
            (technique, f"%{op}%")).fetchone()
        conn.close()
        if row and row[1]:
            return float(row[0]), int(row[1])
    except Exception:
        pass
    return None, 0


def _fitness(base, variant, ops, technique, blocked_by):
    if not variant or variant == base:
        return 0.0
    diversity = min(1.0, len(ops) / 3.0)
    signal_break = 0.0
    toks = [t for t in re.split(r"[^A-Za-z0-9]+", (blocked_by or "")) if len(t) >= 3]
    if toks:
        broken = sum(1 for t in toks if t.lower() in base.lower() and t.lower() not in variant.lower())
        signal_break = min(1.0, broken / len(toks))
    rates = [r for r in (_op_winrate(o, technique)[0] for o in ops) if r is not None]
    learned = sum(rates) / len(rates) if rates else 0.0
    return round(0.45 * diversity + 0.35 * signal_break + 0.20 * learned, 4)


# ════════════════════════════ YENİ TOOLS (a + d + e) ════════════════════════════

@mcp.tool()
def compose_attack_chains(target: str = "", scope: str = "", max_depth: int = 4, top_n: int = 8) -> str:
    """(a) KILL-CHAIN INTELLIGENCE — memory'deki bulguları deterministik ÇOK-ADIMLI
    saldırı zincirlerine bağlar (SSRF→IMDS→IAM→bulut ele geçirme, LFI→log poisoning→RCE,
    open-redirect→OAuth token→hesap ele geçirme...). Her zinciri bileşik olasılık ×
    yükseltilmiş impact × EV ile sıralar — tek tek orta-seviye bulguları KRİTİK etkiye
    dönüştürür (büyük ödülleri kazandıran şey). Her adım validator hook'una bağlıdır.

    Args:
        target: Hedef (memory anahtarı; boşsa tüm bulgular)
        scope: Scope notu
        max_depth: Maksimum zincir derinliği (adım)
        top_n: Döndürülecek en iyi zincir sayısı
    """
    actions, findings, endpoints = _candidate_actions(target)
    entries, seen = [], set()
    for a in actions:
        t = a["technique"]
        if t not in seen:
            seen.add(t)
            entries.append(t)
    all_chains = []
    for e in entries:
        all_chains.extend(_compose_from(e, max_depth))
    all_chains.sort(key=lambda c: c["ev"], reverse=True)
    top = all_chains[:max(1, int(top_n))]
    result = {
        "engine": "deterministic kill-chain composer (capability graph + Bayesian EV)",
        "target": target or "(tümü)", "scope": scope,
        "findings_count": len(findings), "entry_techniques": entries,
        "chains_found": len(all_chains), "ranked_chains": top,
        "best_chain": top[0] if top else None,
        "note": "EV = composite_prob × terminal_impact × (1−0.4·effort). composite_prob = "
                "entry blended_prob × Π(edge feasibility). Tek bulgular zincirlenerek impact yükseltilir.",
    }
    if not entries:
        result["advice"] = ("memory boş — önce recon/exploit yap, store_finding ile kaydet, "
                            "sonra compose_attack_chains tekrar çağır.")
    elif not all_chains:
        result["advice"] = ("Bulgular için bilinen pivot kuralı yok (zaten terminal olabilirler). "
                            "next_best_action ile devam et.")
    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def kill_chain_report(chain_json: str) -> str:
    """(a) Tek bir kill-chain'i (compose_attack_chains'in bir 'ranked_chains' öğesi veya
    tüm çıktısı) reprodüklenebilir Markdown saldırı anlatısına çevirir: adım adım pivot,
    her adımın validator komutu, bileşik olasılık/impact/EV. XBOW-tarzı 'validated trace'.

    Args:
        chain_json: Tek zincir nesnesi veya compose_attack_chains tüm çıktısı (JSON)
    """
    try:
        ch = json.loads(chain_json) if isinstance(chain_json, str) else chain_json
        if isinstance(ch, dict) and "ranked_chains" in ch:
            ch = ch.get("best_chain") or (ch.get("ranked_chains") or [{}])[0]
    except Exception as e:
        return f"HATA: chain_json parse edilemedi: {e}"
    if not ch or "steps" not in ch:
        return "HATA: geçerli bir zincir nesnesi gerekli (steps alanı yok)."
    L = [f"# 🔗 Kill-Chain: {ch.get('label','?')}", "",
         f"- **Bileşik başarı olasılığı:** {round(ch.get('composite_prob',0)*100,1)}%",
         f"- **Terminal impact:** {ch.get('impact')} | **Efor:** {ch.get('effort')} | **EV:** {ch.get('ev')}",
         f"- **Uzunluk:** {ch.get('length')} adım | **Giriş:** `{ch.get('entry')}` → **Hedef:** `{ch.get('terminal')}`",
         "", "## Adımlar", "",
         "| # | Yetenek | Pivot | Fizibilite | Doğrula (validator) | Araç |",
         "|---|---|---|---|---|---|"]
    for i, s in enumerate(ch["steps"], 1):
        pivot = s.get("pivot_note", "— (giriş bulgusu)")
        feas = f"{int(s.get('feasibility',1.0)*100)}%" if "feasibility" in s else "—"
        L.append(f"| {i} | `{s['capability']}` | {pivot} | {feas} | "
                 f"{s.get('validate_with') or '—'} | {s.get('recommended_tool') or '—'} |")
    L += ["", "## Reprodüksiyon / Doğrulama Sırası", ""]
    for i, s in enumerate(ch["steps"], 1):
        vw = s.get("validate_with")
        L.append(f"{i}. `{s['capability']}` → " +
                 (f"deterministik doğrula: **{vw}**" if vw
                  else f"manuel kanıtla ({s.get('recommended_tool') or 'manuel'})"))
    L += ["", "> Her adımı önce validator ile CONFIRMED yap, sonra bir sonraki pivota geç. "
          "Zincir = düşük-seviye bulguların KRİTİK etkiye yükseltilmiş, doğrulanabilir kanıtı.", ""]
    return "\n".join(L)


@mcp.tool()
def evolve_payload(payload: str, technique: str, blocked_by: str = "",
                   generations: int = 2, population: int = 8) -> str:
    """(d) WAF-AWARE PAYLOAD EVOLUTION — gözlemlenen bloklara (blocked_by) göre bir
    payload'ı guided/genetik mutasyonla evrimleştirir (encoding, yorum enjeksiyonu, case,
    ${IFS}, tag-breakup...). Operatörler tekniğe göre seçilir; record_payload_result ile
    öğrenilen başarı oranları fitness'a karışır → WAF'a karşı zamanla daha iyi bypass üretir.

    Args:
        payload: Bloklanan/temel payload
        technique: Teknik (sql_injection, xss_reflected, command_injection, path_traversal, ssti...)
        blocked_by: Gözlemlenen blok sinyali (WAF mesajı, filtrelenen token...)
        generations: Maksimum ardışık dönüşüm derinliği (1-3)
        population: Döndürülecek en iyi varyant sayısı
    """
    tech = _normalize_tech(technique)
    fam = _payload_family(tech)
    ops = FAMILY_OPS.get(fam)
    if not payload or not ops:
        return json.dumps({
            "variants": [], "technique": tech, "family": fam,
            "error": "payload boş veya bu teknik için operatör ailesi yok",
            "supported": list(FAMILY_OPS.keys()),
        }, indent=2, ensure_ascii=False)
    generations = max(1, min(int(generations), 3))
    candidates, expanded = {}, set()

    def expand(cur, cur_ops, depth):
        if cur in expanded or len(candidates) >= 1500:
            return
        expanded.add(cur)
        for name in ops:
            try:
                nxt = OPERATORS[name](cur)
            except Exception:
                continue
            if not nxt or nxt == cur:
                continue
            new_ops = cur_ops + [name]
            if nxt not in candidates:
                candidates[nxt] = new_ops
            if depth + 1 < generations:
                expand(nxt, new_ops, depth + 1)

    expand(payload, [], 0)
    scored = [{"payload": v, "operators": o, "fitness": _fitness(payload, v, o, tech, blocked_by)}
              for v, o in candidates.items()]
    scored.sort(key=lambda x: x["fitness"], reverse=True)
    return json.dumps({
        "engine": "guided mutation (lessons-weighted fitness)",
        "base_payload": payload, "technique": tech, "family": fam,
        "blocked_by": blocked_by, "operators_available": ops,
        "generated": len(scored), "variants": scored[:max(1, int(population))],
        "note": "Bir varyant işe yarar/yaramazsa record_payload_result ile kaydet → "
                "operatör win-rate'leri sonraki evrimi yönlendirir.",
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def record_payload_result(technique: str, operators: str, worked: bool, blocked_by: str = "") -> str:
    """(d) Bir evrimleşmiş payload'ın sonucunu kaydet → operatör başarı oranlarını öğren.
    evolve_payload bunları fitness'a karıştırır (WAF'a karşı zamanla akıllanır).

    Args:
        technique: Teknik
        operators: Uygulanan operatör adları (virgülle ayrılmış veya JSON liste)
        worked: Bypass çalıştı mı (True/False)
        blocked_by: Blok sinyali bağlamı (opsiyonel)
    """
    tech = _normalize_tech(technique)
    if operators.strip().startswith("["):
        try:
            ops = ",".join(json.loads(operators))
        except Exception:
            ops = operators
    else:
        ops = operators
    try:
        conn = _payload_ops_conn()
        conn.execute("INSERT INTO payload_ops (ts, technique, operators, blocked_by, worked) "
                     "VALUES (?,?,?,?,?)",
                     (datetime.now(timezone.utc).isoformat(), tech, ops, blocked_by, 1 if worked else 0))
        conn.commit()
        conn.close()
        return json.dumps({"stored": True, "technique": tech, "operators": ops, "worked": worked,
                           "effect": "evolve_payload bu operatörleri fitness'ta ağırlıklandıracak."},
                          indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"stored": False, "error": str(e)}, ensure_ascii=False)


@mcp.tool()
def exploitability_score(technique: str, validator_confidence: float = -1.0,
                         reflexion_verdict: str = "", severity: str = "info",
                         evidence: str = "") -> str:
    """(e) KALİBRE SÖMÜRÜLEBİLİRLİK SKORU — validator confidence + reflexion verdict +
    öğrenilmiş win-rate + kanıt bütünlüğünü TEK kalibre skora (0-1) ve banda
    (CONFIRMED/LIKELY/POSSIBLE/UNLIKELY) birleştirir. False-positive riskini ve kanıt
    anlatısını döndürür → 'güven' ticari moat. Deterministik validator varsa o baskındır.

    Args:
        technique: Zafiyet tekniği
        validator_confidence: Deterministik validator güveni 0-1 (yoksa -1 bırak)
        reflexion_verdict: 'APPROVED' | 'REVISE' | '' (reason_reflexion çıktısı)
        severity: Bulgu severity'si (critical/high/medium/low/info)
        evidence: Kanıt metni (PoC/yansıma/oracle çıktısı)
    """
    tech = _normalize_tech(technique)
    learned, prior_src = _blended_prob(tech)
    has_validator = validator_confidence is not None and validator_confidence >= 0
    verdict = (reflexion_verdict or "").strip().upper()
    evidence_completeness = min(1.0, len((evidence or "").strip()) / 120.0)
    signals = {
        "validator_confidence": validator_confidence if has_validator else None,
        "reflexion_verdict": verdict or None, "learned_winrate": learned,
        "prior_source": prior_src, "severity": severity,
        "evidence_completeness": round(evidence_completeness, 2),
    }
    if has_validator:
        score = float(validator_confidence)
        score += 0.05 if verdict == "APPROVED" else (-0.10 if verdict == "REVISE" else 0.0)
        score += 0.05 * (learned - 0.5)
        score += 0.05 * (evidence_completeness - 0.5)
        basis = "deterministic-validator-dominant"
    else:
        score = 0.55 * learned + 0.15 * (1 if verdict == "APPROVED" else 0) + 0.20 * evidence_completeness
        score = min(score, 0.65)
        basis = "no-validator (deterministik doğrulama yok → üst sınır 0.65)"
    score = round(max(0.0, min(1.0, score)), 3)
    band = ("CONFIRMED" if score >= 0.9 else "LIKELY" if score >= 0.7
            else "POSSIBLE" if score >= 0.4 else "UNLIKELY")
    fp_risk = round(1 - score, 3) if has_validator else round(min(1.0, (1 - score) + 0.15), 3)
    recommend = (VALIDATE_WITH.get(tech, "mcp__validator__validate_finding")
                 if (not has_validator or band != "CONFIRMED") else None)
    narrative = (
        f"{tech}: skor {score} ({band}). "
        + (f"Validator güveni {validator_confidence}. " if has_validator
           else "Deterministik validator YOK → kanıt zayıf, üst sınır LIKELY. ")
        + (f"Reflexion {verdict}. " if verdict else "")
        + f"Öğrenilmiş win-rate {learned} ({prior_src}). FP riski {fp_risk}. "
        + (f"ÖNERİ: {recommend} ile deterministik doğrula." if recommend else "Yayınlanabilir kanıt."))
    return json.dumps({
        "technique": tech, "exploitability_score": score, "band": band,
        "false_positive_risk": fp_risk, "basis": basis, "signals": signals,
        "recommended_validation": recommend, "evidence_narrative": narrative,
    }, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()
