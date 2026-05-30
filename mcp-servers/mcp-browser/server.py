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


if __name__ == "__main__":
    mcp.run()
