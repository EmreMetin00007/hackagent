#!/usr/bin/env python3
"""
MCP CTF Platform Server — CTF platformlarına (CTFd, HackTheBox, TryHackMe) 
API erişimi sağlayan MCP server.

Desteklenen platformlar:
- CTFd (self-hosted veya third-party)
- HackTheBox API
- TryHackMe API

Kullanım:
    python server.py
"""

import os
import json
import requests
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "ctf-platform",
    instructions="CTF platform API entegrasyonu — challenge yönetimi ve flag submission"
)

# ============================================================
# YAPILANDIRMA
# ============================================================

# Ortam değişkenlerinden platform bilgileri
CTFD_URL = os.environ.get("CTFD_URL", "")
CTFD_TOKEN = os.environ.get("CTFD_TOKEN", "")
HTB_TOKEN = os.environ.get("HTB_TOKEN", "")
THM_TOKEN = os.environ.get("THM_TOKEN", "")

def get_headers(platform: str) -> dict:
    """Platform için auth headerlerini döndür."""
    if platform == "ctfd":
        return {
            "Authorization": f"Token {CTFD_TOKEN}",
            "Content-Type": "application/json"
        }
    elif platform == "htb":
        return {
            "Authorization": f"Bearer {HTB_TOKEN}",
            "Content-Type": "application/json"
        }
    elif platform == "thm":
        return {
            "Authorization": f"Bearer {THM_TOKEN}",
            "Content-Type": "application/json"
        }
    return {}

# ============================================================
# CTFd ARAÇLARI
# ============================================================

@mcp.tool()
def ctfd_list_challenges(
    ctfd_url: str = "",
    token: str = ""
) -> str:
    """
    CTFd platformunda challenge'ları listele.
    
    Args:
        ctfd_url: CTFd URL'si (ör: https://ctf.example.com)
        token: CTFd API token
    """
    url = ctfd_url or CTFD_URL
    auth_token = token or CTFD_TOKEN
    
    if not url:
        return "HATA: CTFd URL belirtilmedi. ctfd_url parametresi veya CTFD_URL env var gerekli."
    
    try:
        headers = {"Authorization": f"Token {auth_token}", "Content-Type": "application/json"}
        response = requests.get(f"{url.rstrip('/')}/api/v1/challenges", headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        if data.get("success"):
            challenges = data.get("data", [])
            output = f"Toplam {len(challenges)} challenge bulundu:\n\n"
            for c in challenges:
                solved = "✅" if c.get("solved_by_me") else "⬜"
                output += f"{solved} [{c.get('category', 'N/A')}] {c.get('name')} — {c.get('value', 0)} puan\n"
            return output
        else:
            return f"API hatası: {data}"
    except Exception as e:
        return f"HATA: {str(e)}"


@mcp.tool()
def ctfd_get_challenge(
    challenge_id: int,
    ctfd_url: str = "",
    token: str = ""
) -> str:
    """
    CTFd'de belirli bir challenge'ın detaylarını getir.
    
    Args:
        challenge_id: Challenge ID
        ctfd_url: CTFd URL'si
        token: CTFd API token
    """
    url = ctfd_url or CTFD_URL
    auth_token = token or CTFD_TOKEN
    
    if not url:
        return "HATA: CTFd URL belirtilmedi."
    
    try:
        headers = {"Authorization": f"Token {auth_token}", "Content-Type": "application/json"}
        response = requests.get(
            f"{url.rstrip('/')}/api/v1/challenges/{challenge_id}",
            headers=headers, timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        if data.get("success"):
            c = data.get("data", {})
            output = f"""
Challenge: {c.get('name')}
Kategori: {c.get('category')}
Puan: {c.get('value')}
Çözülme sayısı: {c.get('solves', 0)}
Açıklama: {c.get('description')}

Dosyalar: {json.dumps(c.get('files', []), indent=2)}
Tags: {c.get('tags', [])}
Hints: {c.get('hints', [])}
"""
            return output
        else:
            return f"API hatası: {data}"
    except Exception as e:
        return f"HATA: {str(e)}"


@mcp.tool()
def ctfd_submit_flag(
    challenge_id: int,
    flag: str,
    ctfd_url: str = "",
    token: str = ""
) -> str:
    """
    CTFd'de flag gönder.
    
    Args:
        challenge_id: Challenge ID
        flag: Gönderilecek flag
        ctfd_url: CTFd URL'si
        token: CTFd API token
    """
    url = ctfd_url or CTFD_URL
    auth_token = token or CTFD_TOKEN
    
    if not url:
        return "HATA: CTFd URL belirtilmedi."
    
    try:
        headers = {"Authorization": f"Token {auth_token}", "Content-Type": "application/json"}
        response = requests.post(
            f"{url.rstrip('/')}/api/v1/challenges/attempt",
            headers=headers,
            json={"challenge_id": challenge_id, "submission": flag},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        if data.get("success"):
            status = data.get("data", {}).get("status", "")
            if status == "correct":
                return "🎉 DOĞRU FLAG! Challenge çözüldü!"
            elif status == "already_solved":
                return "✅ Bu challenge zaten çözülmüş."
            else:
                return f"❌ Yanlış flag: {flag}"
        else:
            return f"API hatası: {data}"
    except Exception as e:
        return f"HATA: {str(e)}"


@mcp.tool()
def ctfd_download_files(
    challenge_id: int,
    output_dir: str = "./challenge_files",
    ctfd_url: str = "",
    token: str = ""
) -> str:
    """
    CTFd'den challenge dosyalarını indir.
    
    Args:
        challenge_id: Challenge ID
        output_dir: İndirme dizini
        ctfd_url: CTFd URL'si
        token: CTFd API token
    """
    url = ctfd_url or CTFD_URL
    auth_token = token or CTFD_TOKEN
    
    if not url:
        return "HATA: CTFd URL belirtilmedi."
    
    try:
        headers = {"Authorization": f"Token {auth_token}", "Content-Type": "application/json"}
        
        # Challenge bilgisini al
        response = requests.get(
            f"{url.rstrip('/')}/api/v1/challenges/{challenge_id}",
            headers=headers, timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        files = data.get("data", {}).get("files", [])
        if not files:
            return "Bu challenge'da dosya bulunmuyor."
        
        os.makedirs(output_dir, exist_ok=True)
        downloaded = []
        
        for file_url in files:
            if not file_url.startswith("http"):
                file_url = f"{url.rstrip('/')}{file_url}"
            
            filename = file_url.split("/")[-1].split("?")[0]
            filepath = os.path.join(output_dir, filename)
            
            r = requests.get(file_url, headers=headers, timeout=60)
            with open(filepath, "wb") as f:
                f.write(r.content)
            downloaded.append(filepath)
        
        return "İndirilen dosyalar:\n" + "\n".join(f"  - {f}" for f in downloaded)
    except Exception as e:
        return f"HATA: {str(e)}"

# ============================================================
# HACKTHEBOX ARAÇLARI
# ============================================================

@mcp.tool()
def htb_list_machines(
    token: str = "",
    retired: bool = False
) -> str:
    """
    HackTheBox'ta makine listesi al.
    
    Args:
        token: HTB API token
        retired: Emekli makineleri dahil et
    """
    auth_token = token or HTB_TOKEN
    if not auth_token:
        return "HATA: HTB_TOKEN belirtilmedi."
    
    try:
        headers = {"Authorization": f"Bearer {auth_token}"}
        endpoint = "https://labs.hackthebox.com/api/v4/machine/list"
        if retired:
            endpoint = "https://labs.hackthebox.com/api/v4/machine/list/retired"
        
        response = requests.get(endpoint, headers=headers, timeout=30)
        response.raise_for_status()
        machines = response.json().get("data", [])
        
        output = f"Toplam {len(machines)} makine:\n\n"
        for m in machines[:30]:
            diff = m.get("difficultyText", "?")
            os_type = m.get("os", "?")
            name = m.get("name", "?")
            output += f"  [{os_type}] {name} — {diff}\n"
        
        return output
    except Exception as e:
        return f"HATA: {str(e)}"


@mcp.tool()
def htb_submit_flag(
    machine_id: int,
    flag: str,
    difficulty: int = 50,
    token: str = ""
) -> str:
    """
    HackTheBox'ta flag gönder.
    
    Args:
        machine_id: Makine ID
        flag: Flag
        difficulty: Zorluk puanı (1-100)
        token: HTB API token
    """
    auth_token = token or HTB_TOKEN
    if not auth_token:
        return "HATA: HTB_TOKEN belirtilmedi."
    
    try:
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            "https://labs.hackthebox.com/api/v4/flag/own",
            headers=headers,
            json={"id": machine_id, "flag": flag, "difficulty": difficulty},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        if data.get("success"):
            return "🎉 FLAG DOĞRU! Makine pwned!"
        else:
            return "❌ Yanlış flag veya makine."
    except Exception as e:
        return f"HATA: {str(e)}"

# ============================================================
# GENEL CTF YARDIMCI ARAÇLAR
# ============================================================

@mcp.tool()
def ctf_decode(
    text: str,
    encoding: str = "auto"
) -> str:
    """
    Metni çeşitli encoding'lerden decode et.
    
    Args:
        text: Decode edilecek metin
        encoding: 'auto', 'base64', 'base32', 'hex', 'rot13', 'url', 'binary', 'decimal'
    """
    import base64
    import codecs
    import urllib.parse
    
    results = []
    
    if encoding == "auto" or encoding == "base64":
        try:
            decoded = base64.b64decode(text).decode('utf-8', errors='replace')
            results.append(f"Base64: {decoded}")
        except Exception:
            if encoding == "base64":
                results.append("Base64 decode başarısız")
    
    if encoding == "auto" or encoding == "base32":
        try:
            decoded = base64.b32decode(text).decode('utf-8', errors='replace')
            results.append(f"Base32: {decoded}")
        except Exception:
            if encoding == "base32":
                results.append("Base32 decode başarısız")
    
    if encoding == "auto" or encoding == "hex":
        try:
            decoded = bytes.fromhex(text.replace(" ", "").replace("0x", "")).decode('utf-8', errors='replace')
            results.append(f"Hex: {decoded}")
        except Exception:
            if encoding == "hex":
                results.append("Hex decode başarısız")
    
    if encoding == "auto" or encoding == "rot13":
        decoded = codecs.decode(text, 'rot_13')
        results.append(f"ROT13: {decoded}")
    
    if encoding == "auto" or encoding == "url":
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                results.append(f"URL: {decoded}")
        except Exception:
            pass
    
    if encoding == "auto" or encoding == "binary":
        try:
            bits = text.replace(" ", "")
            if all(c in '01' for c in bits) and len(bits) % 8 == 0:
                decoded = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
                results.append(f"Binary: {decoded}")
        except Exception:
            pass
    
    if encoding == "auto" or encoding == "decimal":
        try:
            nums = text.split()
            if all(n.isdigit() and int(n) < 128 for n in nums):
                decoded = ''.join(chr(int(n)) for n in nums)
                results.append(f"Decimal: {decoded}")
        except Exception:
            pass
    
    return "\n".join(results) if results else "Decode edilemedi"


@mcp.tool()
def ctf_hash_identify(hash_value: str) -> str:
    """
    Hash tipini tanımla.
    
    Args:
        hash_value: Hash değeri
    """
    length = len(hash_value)
    
    identifications = []
    
    if length == 32:
        identifications.extend(["MD5", "NTLM", "MD4"])
    elif length == 40:
        identifications.extend(["SHA-1", "MySQL5"])
    elif length == 56:
        identifications.append("SHA-224")
    elif length == 64:
        identifications.extend(["SHA-256", "Keccak-256"])
    elif length == 96:
        identifications.append("SHA-384")
    elif length == 128:
        identifications.extend(["SHA-512", "Whirlpool"])
    elif hash_value.startswith("$1$"):
        identifications.append("MD5crypt")
    elif hash_value.startswith("$2"):
        identifications.append("bcrypt")
    elif hash_value.startswith("$5$"):
        identifications.append("SHA-256crypt")
    elif hash_value.startswith("$6$"):
        identifications.append("SHA-512crypt")
    elif hash_value.startswith("$apr1$"):
        identifications.append("Apache MD5")
    elif ":" in hash_value and length > 32:
        identifications.append("Muhtemelen Hash:Salt formatı")
    
    if identifications:
        return f"Hash: {hash_value}\nUzunluk: {length}\nOlası tipler:\n" + "\n".join(f"  - {h}" for h in identifications)
    else:
        return f"Hash: {hash_value}\nUzunluk: {length}\nTip tanımlanamadı. hashid veya hash-identifier aracını deneyin."


# ============================================================
# BUG BOUNTY SPESİFİK MODÜLLER (v2.0 — Phase 4)
# ============================================================

@mcp.tool()
def bb_parse_scope(
    program_url: str,
    platform: str = "hackerone"
) -> str:
    """Bug bounty programının scope'unu otomatik çek ve parse et.

    Args:
        program_url: Program URL'si veya adı (ör: 'security' for hackerone.com/security)
        platform: Platform ('hackerone', 'bugcrowd', 'intigriti')
    """
    try:
        if platform == "hackerone":
            # HackerOne API (public program info)
            program_name = program_url.split("/")[-1] if "/" in program_url else program_url
            # Basit scope çekme (public API)
            resp = requests.get(
                f"https://hackerone.com/{program_name}",
                headers={"Accept": "application/json"},
                timeout=15
            )
            if resp.status_code == 200:
                return f"✓ {program_name} scope bilgisi:\n{resp.text[:2000]}"
            else:
                return f"Program bilgisi çekilemedi (HTTP {resp.status_code}). Manuel scope kontrolü yapın."

        elif platform == "bugcrowd":
            return f"Bugcrowd scope parser henüz implemente edilmedi. Manuel kontrol edin: {program_url}"
        elif platform == "intigriti":
            return f"Intigriti scope parser henüz implemente edilmedi. Manuel kontrol edin: {program_url}"
        else:
            return f"Bilinmeyen platform: {platform}"
    except Exception as e:
        return f"HATA: Scope çekilemedi: {e}"


@mcp.tool()
def bb_check_duplicate(
    vulnerability_type: str,
    target: str,
    description: str = ""
) -> str:
    """Bulunan bug'ı public disclosure'larla karşılaştır.
    HackerOne Hacktivity üzerinde benzer raporları arar.

    Args:
        vulnerability_type: Zafiyet tipi (ör: 'XSS', 'SSRF', 'IDOR')
        target: Hedef domain/asset
        description: Zafiyetin kısa açıklaması
    """
    try:
        search_query = f"{vulnerability_type} {target}"
        # HackerOne Hacktivity search
        resp = requests.get(
            "https://hackerone.com/hacktivity",
            params={"querystring": search_query, "order_direction": "DESC", "order_field": "popular"},
            headers={"Accept": "application/json"},
            timeout=15
        )

        if resp.status_code == 200:
            output = f"🔍 Duplicate Check: {vulnerability_type} on {target}\n{'='*50}\n"
            output += f"HackerOne Hacktivity araması: '{search_query}'\n"
            output += f"HTTP {resp.status_code} — Sonuçlar:\n{resp.text[:1500]}\n\n"
            output += "⚠️ Sonuçları dikkatle inceleyin. Benzer rapor varsa duplicate olabilir.\n"
            output += "💡 İpucu: Farklı bir endpoint, parametre veya impact gösterebilirseniz duplicate değildir."
            return output
        else:
            return f"Hacktivity araması başarısız (HTTP {resp.status_code}). Manuel kontrol edin."
    except Exception as e:
        return f"HATA: Duplicate check başarısız: {e}"


@mcp.tool()
def bb_estimate_bounty(
    severity: str,
    vulnerability_type: str = "",
    platform: str = "hackerone",
    asset_type: str = "web"
) -> str:
    """Severity × Platform ortalama payout hesabı.

    Args:
        severity: CVSS severity (critical, high, medium, low)
        vulnerability_type: Zafiyet tipi (opsiyonel, daha doğru tahmin için)
        platform: Platform ('hackerone', 'bugcrowd')
        asset_type: Asset tipi ('web', 'api', 'mobile', 'infrastructure')
    """
    # Platform bazlı ortalama payout'lar (USD)
    avg_payouts = {
        "hackerone": {
            "critical": {"min": 2000, "avg": 5000, "max": 25000},
            "high": {"min": 750, "avg": 2000, "max": 10000},
            "medium": {"min": 250, "avg": 750, "max": 3000},
            "low": {"min": 50, "avg": 200, "max": 1000},
        },
        "bugcrowd": {
            "critical": {"min": 1500, "avg": 4000, "max": 20000},
            "high": {"min": 500, "avg": 1500, "max": 8000},
            "medium": {"min": 150, "avg": 500, "max": 2000},
            "low": {"min": 50, "avg": 150, "max": 750},
        },
    }

    # Vulnerability type bazlı bonuslar
    vuln_multipliers = {
        "rce": 2.0, "command_injection": 1.8, "sql_injection": 1.5,
        "ssrf": 1.3, "xxe": 1.2, "idor": 1.0, "xss": 0.8,
        "csrf": 0.6, "open_redirect": 0.4, "information_disclosure": 0.5,
    }

    sev = severity.lower()
    plat = platform.lower()

    payouts = avg_payouts.get(plat, avg_payouts["hackerone"])
    if sev not in payouts:
        return f"HATA: Geçersiz severity: {severity}. Kullanın: critical, high, medium, low"

    p = payouts[sev]
    multiplier = vuln_multipliers.get(vulnerability_type.lower().replace(" ", "_"), 1.0)

    est_min = int(p["min"] * multiplier)
    est_avg = int(p["avg"] * multiplier)
    est_max = int(p["max"] * multiplier)

    output = f"""💰 Bounty Tahmini
{'='*40}
  Platform: {platform.upper()}
  Severity: {severity.upper()}
  Zafiyet: {vulnerability_type or 'Genel'}
  Asset: {asset_type}

  💵 Tahmini Ödeme:
     Min:  ${est_min:,}
     Ort:  ${est_avg:,}
     Max:  ${est_max:,}

  {'📈 Multiplier: ' + str(multiplier) + 'x' if multiplier != 1.0 else ''}

  💡 İpuçları:
  - Impact'i net gösterin (admin erişimi, veri sızıntısı vb.)
  - PoC'yi çalışır durumda verin
  - Remediation önerisi ekleyin
  - Scope dışı asset'lere dikkat
"""
    return output


# ============================================================
# CTF SPESİFİK MODÜLLER (v2.0 — Phase 4)
# ============================================================

@mcp.tool()
def ctf_scoreboard_monitor(
    ctfd_url: str = ""
) -> str:
    """Live CTF scoreboard'u çek — rakip takımların çözdüğü challenge'ları göster.

    Args:
        ctfd_url: CTFd URL (boş: env'den al)
    """
    url = ctfd_url or os.environ.get("CTFD_URL", "")
    token = os.environ.get("CTFD_TOKEN", "")

    if not url:
        return "HATA: CTFd URL belirtilmedi. ctfd_url parametresi veya CTFD_URL env var kullanın."

    url = url.rstrip("/")
    headers = {"Authorization": f"Token {token}"} if token else {}

    try:
        # Scoreboard
        resp = requests.get(f"{url}/api/v1/scoreboard", headers=headers, timeout=10)
        resp.raise_for_status()
        scoreboard = resp.json().get("data", [])

        output = f"🏆 CTF Scoreboard: {url}\n{'='*50}\n"
        output += f"{'Sıra':<5} {'Takım':<25} {'Puan':>8}\n"
        output += "-" * 40 + "\n"
        for i, team in enumerate(scoreboard[:20], 1):
            name = team.get("name", "?")
            score = team.get("score", 0)
            output += f"#{i:<4} {name:<25} {score:>8}\n"

        return output
    except Exception as e:
        return f"HATA: Scoreboard çekilemedi: {e}"


@mcp.tool()
def ctf_auto_writeup(
    challenge_name: str,
    category: str,
    flag: str,
    steps: str,
    tools_used: str = "",
    difficulty: str = "medium"
) -> str:
    """Çözüm sonrası otomatik writeup oluştur (markdown formatında).

    Args:
        challenge_name: Challenge adı
        category: Kategori (Web, Pwn, Reverse, Crypto, Forensics, Misc)
        flag: Bulunan flag
        steps: Çözüm adımları (her adım yeni satırda)
        tools_used: Kullanılan araçlar (virgülle ayrılmış)
        difficulty: Zorluk (easy, medium, hard)
    """
    tools_list = [t.strip() for t in tools_used.split(",") if t.strip()] if tools_used else []

    writeup = f"""# {challenge_name}

## Bilgi
| Alan | Değer |
|------|-------|
| **Kategori** | {category} |
| **Zorluk** | {difficulty} |
| **Flag** | `{flag}` |
| **Araçlar** | {', '.join(tools_list) if tools_list else 'N/A'} |

## Çözüm

{steps}

## Flag
```
{flag}
```

---
*Otomatik oluşturuldu — HackerAgent v2.0*
*Tarih: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*
"""

    # Dosyaya kaydet
    safe_name = "".join(c if c.isalnum() or c in "-_ " else "" for c in challenge_name).replace(" ", "_")
    writeup_path = f"/tmp/writeup_{safe_name}.md"
    try:
        with open(writeup_path, "w") as f:
            f.write(writeup)
    except Exception:
        writeup_path = None

    output = f"📝 Writeup oluşturuldu: {challenge_name}\n"
    if writeup_path:
        output += f"📁 Dosya: {writeup_path}\n"
    output += f"\n{writeup}"
    return output


@mcp.tool()
def ctf_difficulty_ranking(
    ctfd_url: str = ""
) -> str:
    """Challenge'ları çözülme oranına göre kolay→zor sırala.

    Args:
        ctfd_url: CTFd URL (boş: env'den al)
    """
    url = ctfd_url or os.environ.get("CTFD_URL", "")
    token = os.environ.get("CTFD_TOKEN", "")

    if not url:
        return "HATA: CTFd URL belirtilmedi."

    url = url.rstrip("/")
    headers = {"Authorization": f"Token {token}"} if token else {}

    try:
        resp = requests.get(f"{url}/api/v1/challenges", headers=headers, timeout=10)
        resp.raise_for_status()
        challenges = resp.json().get("data", [])

        if not challenges:
            return "Challenge bulunamadı."

        # Çözülme oranına göre sırala
        sorted_challenges = sorted(challenges, key=lambda x: x.get("solves", 0), reverse=True)

        output = f"📊 Challenge Zorluk Sıralaması\n{'='*60}\n"
        output += f"{'#':<4} {'Ad':<30} {'Kategori':<12} {'Çözüm':>6} {'Puan':>6}\n"
        output += "-" * 60 + "\n"

        for i, ch in enumerate(sorted_challenges, 1):
            name = ch.get("name", "?")[:28]
            cat = ch.get("category", "?")[:10]
            solves = ch.get("solves", 0)
            value = ch.get("value", 0)

            # Zorluk emoji
            if solves > 50:
                diff = "🟢"
            elif solves > 20:
                diff = "🟡"
            elif solves > 5:
                diff = "🟠"
            else:
                diff = "🔴"

            output += f"{diff}{i:<3} {name:<30} {cat:<12} {solves:>6} {value:>6}\n"

        return output
    except Exception as e:
        return f"HATA: Challenge listesi çekilemedi: {e}"


# ============================================================
# SERVER BAŞLAT
# ============================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")
