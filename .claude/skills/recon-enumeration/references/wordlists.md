# Wordlist Rehberi — Hangi Durumda Hangi Wordlist

## SecLists Konumları (Kali Linux)

Ana dizin: `/usr/share/seclists/`

### Dizin ve Dosya Keşfi
```
/usr/share/seclists/Discovery/Web-Content/
├── directory-list-2.3-small.txt      (87,650)   — Hızlı tarama
├── directory-list-2.3-medium.txt     (220,546)  — Standart tarama ⭐
├── directory-list-2.3-big.txt        (1,273,819) — Kapsamlı tarama
├── raft-medium-directories.txt       (30,000)   — Alternatif dizin listesi
├── raft-medium-files.txt             (17,000)   — Dosya keşfi
├── raft-large-directories.txt        (62,274)   — Büyük dizin listesi
├── common.txt                        (4,712)    — En yaygın yollar ⭐
├── big.txt                           (20,469)   — Büyük ortak liste
└── common-and-french.txt             — Fransızca eklentili

/usr/share/seclists/Discovery/Web-Content/api/
├── api-endpoints.txt                 — REST API endpoint'leri ⭐
└── api-seen-in-wild.txt              — Gerçek dünyada görülen API'ler
```

### Subdomain Keşfi
```
/usr/share/seclists/Discovery/DNS/
├── subdomains-top1million-5000.txt   (4,997)    — Hızlı ⭐
├── subdomains-top1million-20000.txt  (19,997)   — Orta
├── subdomains-top1million-110000.txt (114,441)  — Kapsamlı
├── namelist.txt                      (151,000)  — Geniş
└── fierce-hostlist.txt               (2,280)    — Fierce uyumlu
```

### Kullanıcı Adları
```
/usr/share/seclists/Usernames/
├── top-usernames-shortlist.txt       (17)       — En yaygın ⭐
├── Names/names.txt                   (10,177)   — İsim listesi
├── cirt-default-usernames.txt        (827)      — Default kullanıcılar
└── xato-net-10-million-usernames.txt — Dev liste
```

### Şifreler
```
/usr/share/wordlists/
├── rockyou.txt                       (14,344,392) — Ana şifre listesi ⭐⭐⭐

/usr/share/seclists/Passwords/
├── Common-Credentials/
│   ├── top-passwords-shortlist.txt   (36)       — Hızlı deneme ⭐
│   ├── 10-million-password-list-top-100.txt
│   ├── 10-million-password-list-top-1000.txt
│   └── best1050.txt                  (1,050)
├── Default-Credentials/
│   ├── default-passwords.csv         — Default şifreler
│   └── ftp-betterdefaultpasslist.txt
├── Leaked-Databases/                  — Sızdırılmış DB'ler
└── darkweb2017-top10000.txt
```

### SNMP
```
/usr/share/seclists/Discovery/SNMP/
├── common-snmp-community-strings.txt (122)      — SNMP community ⭐
└── snmp-onesixtyone.txt              (3,217)    — Geniş SNMP listesi
```

### Fuzzing
```
/usr/share/seclists/Fuzzing/
├── special-chars.txt                  — Özel karakterler
├── command-injection-commix.txt       — Command injection
├── LDAP-injection.txt                 — LDAP injection
├── XSS/                              — XSS payload'ları
├── SQLi/                             — SQLi payload'ları
└── LFI/
    ├── LFI-Jhaddix.txt               — LFI yolları ⭐
    └── LFI-gracefulsecurity-linux.txt
```

## Duruma Göre Wordlist Seçimi

| Durum | Wordlist | Boyut |
|-------|----------|-------|
| İlk hızlı tarama | `common.txt` | ~5K |
| Standart dizin tara | `directory-list-2.3-medium.txt` | ~220K |
| Kapsamlı dizin tara | `directory-list-2.3-big.txt` | ~1.3M |
| Subdomain hızlı | `subdomains-top1million-5000.txt` | ~5K |
| Subdomain kapsamlı | `subdomains-top1million-110000.txt` | ~114K |
| Şifre cracking | `rockyou.txt` | ~14M |
| Hızlı brute force | `top-passwords-shortlist.txt` | 36 |
| Default credential | `default-passwords.csv` | ~300 |
| API endpoint | `api-endpoints.txt` | ~600 |
| LFI yolları | `LFI-Jhaddix.txt` | ~900 |

## Özel Wordlist Oluşturma

```bash
# CeWL — Web sitesinden wordlist oluştur
cewl -d 3 -m 5 http://target.com -w custom_wordlist.txt

# crunch — Pattern tabanlı wordlist
crunch 6 8 abcdefghijklmnop -o wordlist.txt
crunch 8 8 -t pass%%%% -o pin_wordlist.txt  # pass0000 - pass9999

# Kullanıcı adı formatlama
# john.doe, jdoe, j.doe, johnd formatları
# username-anarchy aracı ile otomatik oluştur

# Wordlist birleştirme ve tekil yapma
sort -u wordlist1.txt wordlist2.txt > combined.txt

# Belirli uzunlukta filtrele
awk 'length >= 6 && length <= 12' rockyou.txt > filtered.txt
```

## Uzantı Listesi — Duruma Göre

```bash
# PHP uygulaması
-e php,php3,php4,php5,phtml,phar,inc,bak,old,conf,txt,html

# ASP/.NET uygulaması
-e asp,aspx,ashx,asmx,config,bak,old,txt

# Java uygulaması
-e jsp,jspx,do,action,xml,properties,yaml,yml,conf

# Node.js uygulaması
-e js,json,env,config,yml,yaml,bak,old

# Python uygulaması
-e py,pyc,wsgi,cfg,conf,ini,env,yml,yaml

# Genel backup/hassas dosyalar
-e bak,old,backup,save,orig,copy,tmp,swp,conf,config,env,log,sql,db,sqlite,git
```
