---
name: source-code-review
description: "Sızdırılmış, açık kaynaklı veya ele geçirilmiş kaynak kodlar üzerinde (SAST) Statik Analiz yaparak RCE, SQLi ve hardcoded secret tespit etme metodolojisi."
---

# Kaynak Kod İnceleme ve SAST Metodolojisi

Hedefin kaynak kodlarına erişim sağlandığında (Github sızıntısı, klasör sızıntısı veya decompile edilmiş bir binary), körlemesine testler yapmak yerine doğrudan koda odaklanmalısın. Bu, zafiyetleri %100 kesinlikle ve sıfır gürültüyle bulmanın en etkili yoludur.

## 1. Hızlı Haritalama ve Teknolojiyi Anlama
Kodu analiz etmeye başlamadan önce yapıyı anla.
- **Eylem:** `grep_search` kullanarak `pom.xml`, `package.json`, `requirements.txt`, `go.mod`, `docker-compose.yml` gibi dosyaları bul ve içeriklerini incele.
- **Neden:** Hedefin framework'ünü (Spring, Express, Django vb.) anlamak, nereye bakman gerektiğini (Controller, Route, Model) gösterir. Zayıf bağımlılıkları (vulnerable dependencies) buradan tespit edebilirsin.

## 2. Hardcoded Secrets (T1552: Unsecured Credentials)
Geliştiriciler kod içine API key, veritabanı şifresi veya AWS key unutmayı severler.
- **Eylem:** `grep_search` aracıyla (IsRegex: true) aşağıdaki regex pattern'lerini veya anahtar kelimeleri tüm kod bazında ara:
  - `password|secret|apikey|token|aws_access_key|api_key|auth_token`
  - Özel regex: `(?i)(password|secret|key).*?['"][A-Za-z0-9+/=]{10,}['"]`
- **Konumlar:** Özellikle `config/`, `.env.example`, `constants.py`, `settings.json` gibi dosyalara dikkat et.

## 3. Tehlikeli Fonksiyon ve Sink Noktaları (T1190: Exploit Public-Facing Application)
Kullanıcıdan alınan verinin (Source), tehlikeli fonksiyonlara (Sink) gidip gitmediğini manuel olarak izle. (Taint Analysis)
- **Komut Çalıştırma (RCE):**
  - Python: `os.system`, `subprocess.Popen`, `eval(`, `exec(`
  - PHP: `shell_exec(`, `system(`, `passthru(`, `eval(`
  - Node.js: `child_process.exec(`, `eval(`
  - **Uygulama:** Bu fonksiyonları `grep_search` ile ara. Çıkan satırları `view_file` ile inceleyerek kullanıcı girdisinin (`$_GET`, `req.body`, `request.args`) doğrudan buralara ulaşıp ulaşmadığını doğrula.

- **SQL Injection (SQLi):**
  - Güvenli olan ORM kullanımları yerine raw SQL yazılan yerleri ara:
  - `SELECT * FROM`, `executeQuery(`, `db.query(`
  - Eğer `SELECT * FROM users WHERE username = '` + `req.body.user` + `'` şeklinde string birleştirme (concatenation) görüyorsan, %100 SQLi buldun demektir.

- **Deserialization Hataları:**
  - Python: `pickle.loads(`, `yaml.load(` (Safe olmayan)
  - Java: `ObjectInputStream.readObject(`
  - PHP: `unserialize(`
  - Node.js: `node-serialize` kütüphanesi kullanımı.

## 4. LLM Doğrulama (Akıllı Analiz)
Yüzlerce satırlık bir kod bloğu bulduğunda ve zafiyetten emin olamadığında:
- **Eylem:** Sorunlu Controller veya Route dosyasının tam içeriğini `view_file` ile oku.
- **Analiz:** Kendine (Agent) kodun iş akışını (User Input -> Sanitization -> Sink) sor. Eksik kontrol (Missing Authorization) veya hatalı sanitization (örneğin sadece tek bir `'` tırnağın replace edilmesi) var mı kontrol et.

## 5. Exploit Geliştirme ve Test (PoC)
Bulduğun zafiyeti teoride bırakma.
- **Eylem:** Zafiyetin nasıl tetikleneceğine dair bir `curl` komutu veya kısa bir Python PoC betiği yaz.
- **Test:** Eğer kod lokalde koşuyorsa veya hedef sistem aktifse, PoC'ni çalıştırarak zafiyeti kanıtla.
