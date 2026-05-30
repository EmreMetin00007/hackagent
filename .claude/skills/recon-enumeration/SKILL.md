---
name: recon-enumeration
description: "Keşif ve numaralandırma skill'i. Hedef sistemlerin kapsamlı keşfi, port tarama, subdomain enumeration, dizin brute-force, servis tespiti ve OSINT. Bu skill'i şu durumlarda kullan: kullanıcı 'hedefi tara', 'keşif yap', 'port scan', 'subdomain bul', 'dizin tara', 'recon', 'enumeration', 'bilgi topla', 'fingerprint', 'OSINT', 'asset discovery', 'attack surface' dediğinde veya bir IP/domain/URL verip analiz istediğinde. Ağ keşfi, servis tanıma, web dizin keşfi veya herhangi bir bilgi toplama görevi olduğunda mutlaka bu skill'i kullan."
---

# 🔍 Keşif & Numaralandırma (Recon & Enumeration)

Hedef sistem hakkında mümkün olan en fazla bilgiyi toplamak için kullanılan kapsamlı keşif skill'i. Her pentest/bug bounty/CTF görevi bu adımla başlar.

## Temel İlke

**"Ne kadar çok bilirsen, o kadar çok saldırı vektörün olur."**

Keşif asla tek bir araçla yapılmaz. Katmanlı, çoklu araç kullanarak yüzey alanını maksimize et.

## Faz 1: Pasif Keşif (Hedefle Doğrudan Temas Yok)

### DNS & Domain Intelligence
```bash
# DNS Kayıtları — Tüm tipleri sorgula
dig +short A target.com
dig +short AAAA target.com
dig +short MX target.com
dig +short TXT target.com
dig +short NS target.com
dig +short CNAME target.com
dig +short SOA target.com
dig ANY target.com @8.8.8.8

# Zone Transfer Denemesi (çoğu yerde kapalı ama dene)
dig axfr target.com @ns1.target.com

# WHOIS
whois target.com

# Reverse DNS
host IP_ADRESI

# DNS History
# crt.sh üzerinden subdomain keşfi
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u
```

### Subdomain Enumeration
```bash
# subfinder — pasif subdomain keşfi
subfinder -d target.com -all -o subdomains.txt

# amass — kapsamlı OSINT
amass enum -passive -d target.com -o amass_subs.txt

# assetfinder
assetfinder --subs-only target.com >> subdomains.txt

# Sonuçları birleştir ve canlılık kontrolü
cat subdomains.txt | sort -u | httpx -silent -o alive_subs.txt
```

### OSINT & Bilgi Toplama
```bash
# theHarvester — email, subdomain, IP toplama
theHarvester -d target.com -b all -f harvester_results

# Google Dorks
# site:target.com filetype:pdf
# site:target.com inurl:admin
# site:target.com intext:"password"
# site:target.com ext:sql | ext:env | ext:log
# "target.com" site:github.com password|secret|api_key

# Shodan CLI
shodan search hostname:target.com
shodan host IP_ADRESI

# Wayback Machine — eski URL'ler
waybackurls target.com | sort -u > wayback_urls.txt
```

### SSL/TLS Analizi
```bash
# SSL sertifika bilgisi
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -text -noout

# testssl.sh — kapsamlı SSL testi
testssl.sh target.com
```

## Faz 2: Aktif Keşif (Hedefle Doğrudan Temas)

### Port Tarama
```bash
# Hızlı Tarama — En yaygın portlar
nmap -sC -sV -O target.com -oA nmap_initial

# Tam Port Tarama — Tüm 65535 port
nmap -p- -T4 --min-rate=1000 target.com -oA nmap_allports

# Bulunan portları detaylı tara
nmap -sC -sV -O -A -p PORTLAR target.com -oA nmap_detailed

# UDP Tarama — Üst 100 port
nmap -sU --top-ports 100 -T4 target.com -oA nmap_udp

# NSE Script Tarama — Zafiyet scriptleri
nmap --script=vuln target.com -oA nmap_vuln
nmap --script=default,discovery,vuln target.com

# Agresif servis tespiti
nmap -sV --version-intensity 5 -p PORTLAR target.com
```

### Alternatif Port Tarama
```bash
# masscan — çok hızlı port tarama
masscan -p1-65535 --rate=1000 -e tun0 TARGET_IP --router-ip GATEWAY

# rustscan — otomatik nmap entegrasyonu
rustscan -a TARGET_IP -- -sC -sV
```

## Faz 3: Web Enumeration

### Dizin & Dosya Keşfi
```bash
# ffuf — hızlı dizin brute-force
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -mc 200,301,302,403 -o dirs.json

# gobuster — klasik dizin tarama
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt,js,bak,old,conf -o gobuster.txt

# feroxbuster — recursive dizin tarama
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --depth 3

# Hassas dosya arama
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -e .bak,.old,.conf,.env,.git,.svn,.DS_Store,Dockerfile,docker-compose.yml,.htaccess,.htpasswd,web.config
```

### VHost & Subdomain Brute-Force
```bash
# VHost keşfi
ffuf -u http://TARGET_IP -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs SIZE_TO_FILTER

# gobuster vhost
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Teknoloji Fingerprinting
```bash
# whatweb
whatweb -a 3 http://target.com

# curl ile header inceleme
curl -I http://target.com
curl -v http://target.com 2>&1 | grep -i 'server\|x-powered\|x-aspnet\|x-generator'

# wafw00f — WAF tespiti
wafw00f http://target.com
```

### Parameter & API Discovery
```bash
# arjun — parameter keşfi
arjun -u http://target.com/endpoint

# API endpoint keşfi
ffuf -u http://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# JavaScript dosyalarından endpoint çıkarma
# linkfinder.py -i http://target.com/main.js -o cli
```

## Faz 4: Servis Enumeration

### SMB (Port 139/445)
```bash
enum4linux -a TARGET_IP
smbclient -L \\\\TARGET_IP -N
crackmapexec smb TARGET_IP --shares
smbmap -H TARGET_IP
```

### LDAP (Port 389/636)
```bash
ldapsearch -x -H ldap://TARGET_IP -b "dc=target,dc=com"
nmap -p 389 --script=ldap-search TARGET_IP
```

### SNMP (Port 161)
```bash
snmpwalk -v2c -c public TARGET_IP
snmp-check TARGET_IP
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt TARGET_IP
```

### FTP (Port 21)
```bash
ftp TARGET_IP  # anonymous login dene
nmap -p 21 --script=ftp-anon,ftp-bounce TARGET_IP
```

### SMTP (Port 25)
```bash
smtp-user-enum -M VRFY -u users.txt -t TARGET_IP
nmap -p 25 --script=smtp-enum-users TARGET_IP
```

### MySQL (Port 3306)
```bash
mysql -h TARGET_IP -u root -p
nmap -p 3306 --script=mysql-* TARGET_IP
```

### Redis (Port 6379)
```bash
redis-cli -h TARGET_IP
nmap -p 6379 --script=redis-info TARGET_IP
```

## Çıktı Organizasyonu

Tüm keşif sonuçları aşağıdaki yapıda organize edilmeli:

```
recon/
├── passive/
│   ├── whois.txt
│   ├── dns_records.txt
│   ├── subdomains.txt
│   ├── alive_subs.txt
│   └── osint_results.txt
├── active/
│   ├── nmap_initial.nmap
│   ├── nmap_allports.nmap
│   ├── nmap_detailed.nmap
│   └── nmap_udp.nmap
├── web/
│   ├── directories.txt
│   ├── vhosts.txt
│   ├── tech_stack.txt
│   └── parameters.txt
└── services/
    ├── smb_enum.txt
    ├── ldap_enum.txt
    └── other_services.txt
```

## Karar Ağacı

```
Hedef alındı
├── Domain mi? → DNS + Subdomain + WHOIS + OSINT
├── IP mi? → Port scan + Servis enum
└── URL mi? → Web enum + Tech fingerprint + Dir bruteforce

Port sonuçlarına göre:
├── 80/443 → Web Enumeration skill'ine geç
├── 21 → FTP enum
├── 22 → SSH versiyon + key enum
├── 25 → SMTP user enum
├── 139/445 → SMB enum
├── 3306 → MySQL enum
├── 6379 → Redis enum
└── Bilinmeyen → Banner grab + NSE script
```

## Önemli Wordlist'ler

| Amaç | Wordlist Yolu |
|------|--------------|
| Dizin tarama | `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` |
| Dosya tarama | `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt` |
| Subdomain | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| API endpoints | `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt` |
| Kullanıcı adları | `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` |
| Şifreler | `/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt` |
| SNMP community | `/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt` |
| Backup dosyaları | Uzantılar: `.bak, .old, .backup, .save, .orig, .copy, .tmp, .swp, ~` |
