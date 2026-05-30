# Nmap Cheatsheet — Hızlı Referans

## Temel Tarama Türleri

| Komut | Açıklama |
|-------|----------|
| `nmap target` | Top 1000 port, SYN scan |
| `nmap -sC -sV target` | Default script + version detection |
| `nmap -A target` | Aggressive: OS, version, script, traceroute |
| `nmap -p- target` | Tüm 65535 port |
| `nmap -sU target` | UDP scan |
| `nmap -sS target` | SYN (stealth) scan |
| `nmap -sT target` | TCP connect scan |
| `nmap -sN target` | NULL scan (firewall evasion) |
| `nmap -sF target` | FIN scan |
| `nmap -sX target` | Xmas scan |
| `nmap -sP target` | Ping sweep (host discovery) |

## Hız ve Zamanlama

| Flag | Açıklama |
|------|----------|
| `-T0` | Paranoid — çok yavaş, IDS evasion |
| `-T1` | Sneaky — yavaş, IDS evasion |
| `-T2` | Polite — yavaş |
| `-T3` | Normal — varsayılan |
| `-T4` | Aggressive — hızlı |
| `-T5` | Insane — çok hızlı |
| `--min-rate 1000` | Minimum paket hızı |
| `--max-retries 1` | Retry limitini düşür |

## Port Belirtimi

| Komut | Açıklama |
|-------|----------|
| `-p 80` | Tek port |
| `-p 80,443,8080` | Birden fazla port |
| `-p 1-1000` | Port aralığı |
| `-p-` | Tüm portlar (1-65535) |
| `--top-ports 100` | En yaygın 100 port |
| `-p U:53,T:80` | UDP 53 + TCP 80 |

## Çıktı Formatları

| Flag | Format |
|------|--------|
| `-oN file.txt` | Normal text |
| `-oX file.xml` | XML |
| `-oG file.gnmap` | Grepable |
| `-oA basename` | Tüm formatlar |
| `-oS file.txt` | Script kiddie (lol) |

## NSE Script Kategorileri

| Kategori | Açıklama |
|----------|----------|
| `--script=default` | Varsayılan scriptler (sC) |
| `--script=vuln` | Zafiyet scriptleri |
| `--script=discovery` | Keşif scriptleri |
| `--script=auth` | Authentication scriptleri |
| `--script=brute` | Brute force scriptleri |
| `--script=exploit` | Exploit scriptleri |
| `--script=malware` | Malware tespiti |
| `--script=safe` | Güvenli (non-intrusive) scriptler |

## Popüler NSE Scriptleri

```bash
# HTTP
--script=http-enum              # Dizin ve dosya enumeration
--script=http-headers            # HTTP headerları
--script=http-methods            # İzin verilen HTTP metotları
--script=http-shellshock         # Shellshock testi
--script=http-sql-injection      # SQLi testi
--script=http-title              # Sayfa başlıkları
--script=http-robots.txt         # robots.txt
--script=http-git                # .git klasörü
--script=http-backup-finder      # Backup dosyaları
--script=http-config-backup      # Config backup'ları
--script=http-wordpress-enum     # WordPress enum

# SMB
--script=smb-enum-shares         # Paylaşım listesi
--script=smb-enum-users          # Kullanıcı listesi
--script=smb-vuln-ms17-010       # EternalBlue testi
--script=smb-os-discovery        # OS tespiti

# DNS
--script=dns-zone-transfer       # Zone transfer
--script=dns-brute               # DNS brute force

# FTP
--script=ftp-anon                # Anonymous login
--script=ftp-bounce              # FTP bounce

# SSH
--script=ssh-brute               # SSH brute force
--script=ssh2-enum-algos         # Algoritma listesi

# MySQL
--script=mysql-brute             # MySQL brute force
--script=mysql-databases         # Veritabanı listesi
--script=mysql-empty-password    # Boş şifre kontrolü

# Genel
--script=banner                  # Banner grabbing
--script=ssl-enum-ciphers        # SSL cipher listesi
--script=ssl-heartbleed          # Heartbleed testi
```

## Yaygın Kullanım Senaryoları

```bash
# İlk keşif
nmap -sC -sV -O -oA initial TARGET

# Tam port taraması
nmap -p- -T4 --min-rate=1000 -oA allports TARGET

# Bulunan portları detaylı tara
nmap -sC -sV -O -A -p 22,80,443,8080 -oA detailed TARGET

# Zafiyet taraması
nmap --script=vuln -p PORTS -oA vuln TARGET

# UDP tarama
nmap -sU --top-ports 50 -T4 -oA udp TARGET

# Stealth tarama (IDS bypass)
nmap -sS -T2 -Pn -f --data-length 100 TARGET

# Ağ keşfi (subnet tarama)
nmap -sn 192.168.1.0/24 -oA sweep

# OS fingerprinting
nmap -O --osscan-guess TARGET

# Specific CVE check
nmap --script=smb-vuln-ms17-010 -p 445 TARGET
nmap --script=http-shellshock --script-args uri=/cgi-bin/test -p 80 TARGET
```

## Firewall / IDS Evasion

```bash
# Paket fragmantasyonu
nmap -f TARGET
nmap --mtu 24 TARGET

# Decoy scan (sahte IP'lerle gizlen)
nmap -D RND:5 TARGET
nmap -D decoy1,decoy2,ME TARGET

# Kaynak port belirle (53=DNS bypass)
nmap --source-port 53 TARGET

# Data padding
nmap --data-length 200 TARGET

# MAC spoofing
nmap --spoof-mac 0 TARGET

# Idle scan (zombie)
nmap -sI zombie_host TARGET
```
