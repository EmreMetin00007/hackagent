#!/usr/bin/env python3
"""MCP Browser Server — Playwright tabanlı web tarayıcı + ekran görüntüsü.

HackerAgent'ın görsel (vision) yeteneği için: web sayfasını render edip
screenshot alır, OCR için metin çıkarır, form alanlarını keşfeder.

Tools:
  • browser_screenshot(url, full_page=True) → base64 PNG + metadata
  • browser_extract_text(url) → görünen metin
  • browser_get_forms(url) → form alanları, input'lar, CSRF token'ları

Playwright gereksinimi — opsiyonel dependency:
    pip install playwright
    playwright install chromium

Playwright kurulu değilse her tool net hata mesajı döner.
"""

from __future__ import annotations

import base64
import os
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from mcp.server.fastmcp import FastMCP

try:
    from playwright.sync_api import sync_playwright  # type: ignore
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
SCREENSHOT_DIR = os.path.join(CCO_HOME, "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

mcp = FastMCP(
    "browser",
    instructions=(
        "Playwright tabanlı web tarayıcı — screenshot, DOM analizi, form keşfi. "
        "Vision-capable LLM'ler bu screenshot'ı base64 image olarak yorumlayabilir."
    ),
)

DEFAULT_VIEWPORT = {"width": 1366, "height": 800}
DEFAULT_TIMEOUT = 30_000  # 30s
MAX_IMAGE_B64_CHARS = 4_000_000  # ~3MB base64 (LLM limit'lerini aşma)


def _missing_playwright_msg() -> str:
    return (
        "HATA: playwright kurulu değil. Kurulum:\n"
        "  pip install playwright\n"
        "  playwright install chromium\n"
    )


@mcp.tool()
def browser_screenshot(
    url: str,
    full_page: bool = True,
    wait_seconds: float = 2.0,
    return_base64: bool = True,
) -> str:
    """Bir URL'nin ekran görüntüsünü alır.

    Vision-capable LLM'ler için base64-encoded PNG döndürür. Agent bu
    sonucu `{"type": "image_url", "image_url": {"url": "data:image/png;base64,<b64>"}}`
    biçimine dönüştürerek multimodal LLM'e gönderebilir.

    Args:
        url: Ziyaret edilecek URL (http/https)
        full_page: Tüm sayfayı mı yoksa sadece viewport'u mu yakala
        wait_seconds: Sayfa yüklendikten sonra render için bekleme süresi
        return_base64: True → JSON'da base64 dön, False → sadece dosya yolu

    Returns: JSON-like string — path, base64 (opsiyonel), boyutlar, title
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    ts = int(__import__("time").time())
    safe = re.sub(r"[^a-z0-9]+", "_", url.lower())[:80]
    path = os.path.join(SCREENSHOT_DIR, f"{ts}_{safe}.png")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport=DEFAULT_VIEWPORT)
            page = ctx.new_page()
            page.set_default_timeout(DEFAULT_TIMEOUT)
            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(int(wait_seconds * 1000))
            title = page.title()
            page.screenshot(path=path, full_page=full_page)
            ctx.close()
            browser.close()
    except Exception as e:
        return f"HATA: Screenshot alınamadı: {e}"

    size = os.path.getsize(path)
    out = {
        "url": url,
        "title": title[:200],
        "path": path,
        "size_bytes": size,
        "full_page": full_page,
    }
    if return_base64:
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        if len(b64) > MAX_IMAGE_B64_CHARS:
            out["base64"] = None
            out["base64_skipped_reason"] = f"size>{MAX_IMAGE_B64_CHARS}"
        else:
            out["base64"] = b64
            out["data_url"] = f"data:image/png;base64,{b64}"
    import json as _json
    return _json.dumps(out, ensure_ascii=False)


@mcp.tool()
def browser_extract_text(url: str, wait_seconds: float = 2.0) -> str:
    """Bir URL'den görünen text içeriğini çıkarır (JS render sonrası).

    Args:
        url: URL (http/https)
        wait_seconds: Sayfa yüklendikten sonra bekleme

    Returns: Temizlenmiş düz metin (max 15000 karakter)
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport=DEFAULT_VIEWPORT)
            page = ctx.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
            page.wait_for_timeout(int(wait_seconds * 1000))
            text = page.evaluate("() => document.body.innerText")
            ctx.close()
            browser.close()
    except Exception as e:
        return f"HATA: Metin çıkarılamadı: {e}"

    text = (text or "").strip()
    if len(text) > 15_000:
        text = text[:15_000] + "\n…[kırpıldı]"
    return text or "(boş sayfa)"


@mcp.tool()
def browser_get_forms(url: str, wait_seconds: float = 2.0) -> str:
    """Sayfadaki tüm form'ları, input'ları, CSRF token'larını keşfeder.

    Web exploit vektörleri için ilk adım (SQLi, XSS, CSRF analizi).

    Args:
        url: URL
        wait_seconds: Render bekleme

    Returns: JSON — form listesi (action, method, inputs, tokens)
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    script = """
    () => {
        const forms = Array.from(document.querySelectorAll('form')).map(f => {
            const inputs = Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({
                name: i.name || i.id || '',
                type: i.type || i.tagName.toLowerCase(),
                value_sample: (i.value || '').slice(0, 100),
                required: i.required,
                placeholder: i.placeholder || '',
            }));
            return {
                action: f.action || '',
                method: (f.method || 'get').toUpperCase(),
                id: f.id || '',
                inputs: inputs,
            };
        });
        const metaTokens = Array.from(document.querySelectorAll('meta[name*="token" i], meta[name*="csrf" i]'))
            .map(m => ({ name: m.name, content: m.content }));
        return { forms, meta_tokens: metaTokens, url: location.href };
    }
    """

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport=DEFAULT_VIEWPORT)
            page = ctx.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
            page.wait_for_timeout(int(wait_seconds * 1000))
            data = page.evaluate(script)
            ctx.close()
            browser.close()
    except Exception as e:
        return f"HATA: Form analizi başarısız: {e}"

    import json as _json
    return _json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def browser_extract_links(url: str, wait_seconds: float = 2.0) -> str:
    """Sayfadaki tüm linkleri, script kaynaklarını ve form action'larını çıkarır.

    Saldırı yüzeyi haritalaması için ilk adım — internal/external link ayrımı,
    JS dosyaları (secret/endpoint analizi için), parametreli URL'ler.

    Args:
        url: URL (http/https)
        wait_seconds: JS render bekleme
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    script = """
    () => {
        const origin = location.origin;
        const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
        const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
        const forms = Array.from(document.querySelectorAll('form')).map(f => f.action || location.href);
        const internal = [], external = [];
        [...new Set(links)].forEach(h => {
            try { (new URL(h).origin === origin ? internal : external).push(h); } catch(e) {}
        });
        const withParams = [...new Set(links)].filter(h => h.includes('?') && h.includes('='));
        return {
            internal_links: internal.slice(0, 300),
            external_links: external.slice(0, 200),
            js_files: [...new Set(scripts)].slice(0, 100),
            form_actions: [...new Set(forms)],
            urls_with_params: withParams.slice(0, 150),
        };
    }
    """
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport=DEFAULT_VIEWPORT)
            page = ctx.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
            page.wait_for_timeout(int(wait_seconds * 1000))
            data = page.evaluate(script)
            ctx.close()
            browser.close()
    except Exception as e:
        return f"HATA: Link çıkarma başarısız: {e}"

    import json as _json
    data["url"] = url
    return _json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def browser_security_headers(url: str) -> str:
    """HTTP yanıt güvenlik başlıklarını analiz eder ve eksik olanları raporlar.

    CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy kontrolü — clickjacking, MIME sniffing, downgrade riskleri.

    Args:
        url: URL (http/https)
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    important = {
        "content-security-policy": "XSS/injection azaltma (CSP)",
        "strict-transport-security": "HTTPS downgrade koruması (HSTS)",
        "x-frame-options": "Clickjacking koruması",
        "x-content-type-options": "MIME sniffing koruması",
        "referrer-policy": "Referrer bilgi sızıntısı koruması",
        "permissions-policy": "Tarayıcı özellik kısıtlama",
    }
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport=DEFAULT_VIEWPORT)
            page = ctx.new_page()
            resp = page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
            headers = {k.lower(): v for k, v in (resp.headers if resp else {}).items()}
            status = resp.status if resp else None
            ctx.close()
            browser.close()
    except Exception as e:
        return f"HATA: Header analizi başarısız: {e}"

    present, missing = {}, []
    for h, desc in important.items():
        if h in headers:
            present[h] = headers[h][:300]
        else:
            missing.append({"header": h, "risk": desc})

    leaky = {h: headers[h] for h in ("server", "x-powered-by", "x-aspnet-version") if h in headers}

    import json as _json
    return _json.dumps(
        {
            "url": url,
            "status": status,
            "present_security_headers": present,
            "missing_security_headers": missing,
            "information_disclosure": leaky,
            "severity": "medium" if missing else "info",
        },
        ensure_ascii=False, indent=2,
    )


@mcp.tool()
def browser_cookie_audit(url: str, wait_seconds: float = 2.0) -> str:
    """Sayfanın set ettiği cookie'lerin güvenlik flag'lerini denetler.

    HttpOnly, Secure, SameSite eksikliği → session hijacking / CSRF riski.

    Args:
        url: URL (http/https)
        wait_seconds: Render bekleme
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport=DEFAULT_VIEWPORT)
            page = ctx.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
            page.wait_for_timeout(int(wait_seconds * 1000))
            cookies = ctx.cookies()
            ctx.close()
            browser.close()
    except Exception as e:
        return f"HATA: Cookie denetimi başarısız: {e}"

    audited = []
    for c in cookies:
        issues = []
        if not c.get("httpOnly"):
            issues.append("HttpOnly eksik (XSS ile çalınabilir)")
        if not c.get("secure"):
            issues.append("Secure eksik (HTTP üzerinden sızabilir)")
        if not c.get("sameSite") or c.get("sameSite") == "None":
            issues.append("SameSite zayıf/eksik (CSRF riski)")
        audited.append({
            "name": c.get("name"),
            "domain": c.get("domain"),
            "httpOnly": c.get("httpOnly"),
            "secure": c.get("secure"),
            "sameSite": c.get("sameSite"),
            "issues": issues,
        })

    import json as _json
    return _json.dumps(
        {"url": url, "cookie_count": len(audited), "cookies": audited},
        ensure_ascii=False, indent=2,
    )


@mcp.tool()
def browser_capture_requests(url: str, wait_seconds: float = 4.0) -> str:
    """Sayfa yüklenirken yapılan tüm XHR/fetch/API isteklerini yakalar.

    SPA'larda gizli API endpoint keşfi için kritik — JS'in arka planda
    konuştuğu backend route'larını ortaya çıkarır.

    Args:
        url: URL (http/https)
        wait_seconds: İstekleri toplamak için bekleme süresi
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    captured = []

    def _on_request(req):
        try:
            if req.resource_type in ("xhr", "fetch", "websocket"):
                captured.append({
                    "method": req.method,
                    "url": req.url,
                    "resource_type": req.resource_type,
                })
        except Exception:
            pass

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport=DEFAULT_VIEWPORT)
            page = ctx.new_page()
            page.on("request", _on_request)
            page.goto(url, wait_until="networkidle", timeout=DEFAULT_TIMEOUT)
            page.wait_for_timeout(int(wait_seconds * 1000))
            ctx.close()
            browser.close()
    except Exception as e:
        return f"HATA: İstek yakalama başarısız: {e} (yakalanan: {len(captured)})"

    # Dedup
    seen, unique = set(), []
    for c in captured:
        key = (c["method"], c["url"])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    import json as _json
    return _json.dumps(
        {"url": url, "api_requests": unique, "total": len(unique)},
        ensure_ascii=False, indent=2,
    )


@mcp.tool()
def browser_console_logs(url: str, wait_seconds: float = 3.0) -> str:
    """Sayfanın JavaScript console mesajlarını ve hatalarını yakalar.

    Console error/warning'ler bilgi sızıntısı (stack trace, API key, debug log)
    ve DOM XSS ipuçları içerebilir.

    Args:
        url: URL (http/https)
        wait_seconds: Mesaj toplama süresi
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    logs, errors = [], []

    def _on_console(msg):
        try:
            logs.append({"type": msg.type, "text": msg.text[:500]})
        except Exception:
            pass

    def _on_pageerror(exc):
        errors.append(str(exc)[:500])

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport=DEFAULT_VIEWPORT)
            page = ctx.new_page()
            page.on("console", _on_console)
            page.on("pageerror", _on_pageerror)
            page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
            page.wait_for_timeout(int(wait_seconds * 1000))
            ctx.close()
            browser.close()
    except Exception as e:
        return f"HATA: Console yakalama başarısız: {e}"

    import json as _json
    return _json.dumps(
        {
            "url": url,
            "console_messages": logs[:100],
            "page_errors": errors[:50],
            "error_count": len([m for m in logs if m["type"] == "error"]) + len(errors),
        },
        ensure_ascii=False, indent=2,
    )


@mcp.tool()
def browser_dom_xss_probe(url: str, param: str = "q", wait_seconds: float = 2.0) -> str:
    """DOM-based XSS için reflection probe — benzersiz canary enjekte eder.

    Belirtilen query parametresine eşsiz bir işaretçi + zararsız XSS payload'u
    enjekte eder; payload'un DOM'a yansıyıp yansımadığını ve alert()/dialog
    tetiklenip tetiklenmediğini gözlemler. (Doğrulama amaçlı, non-destructive.)

    Args:
        url: Hedef URL (http/https)
        param: Test edilecek query parametresi adı
        wait_seconds: Render bekleme
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    import time as _t
    canary = f"cco{int(_t.time())}xss"
    payload = f'{canary}"><img src=x onerror=window.__ccoXss=1>'

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))

    dialog_fired = {"v": False}

    def _on_dialog(d):
        dialog_fired["v"] = True
        try:
            d.dismiss()
        except Exception:
            pass

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport=DEFAULT_VIEWPORT)
            page = ctx.new_page()
            page.on("dialog", _on_dialog)
            page.goto(test_url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
            page.wait_for_timeout(int(wait_seconds * 1000))
            html = page.content()
            xss_marker = page.evaluate("() => window.__ccoXss === 1")
            ctx.close()
            browser.close()
    except Exception as e:
        return f"HATA: XSS probe başarısız: {e}"

    reflected_raw = canary in html and '"><img' in html
    reflected_any = canary in html
    verdict = "LIKELY VULNERABLE" if (xss_marker or dialog_fired["v"] or reflected_raw) else \
              ("REFLECTED (escaped?)" if reflected_any else "no reflection")

    import json as _json
    return _json.dumps(
        {
            "tested_url": test_url,
            "param": param,
            "canary": canary,
            "reflected": reflected_any,
            "reflected_unescaped": reflected_raw,
            "js_executed": bool(xss_marker),
            "dialog_triggered": dialog_fired["v"],
            "verdict": verdict,
            "severity": "high" if (xss_marker or reflected_raw) else "info",
        },
        ensure_ascii=False, indent=2,
    )


if __name__ == "__main__":
    mcp.run()
