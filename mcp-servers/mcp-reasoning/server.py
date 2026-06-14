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


if __name__ == "__main__":
    mcp.run()
