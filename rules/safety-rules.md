# Safety Rules — Operasyonel Güvenlik

## Credential Yönetimi
- Bulunan şifreleri/token'ları ASLA loglama veya üçüncü partiye gönderme
- Session token'ları scope dışında kullanma
- API key'leri düz metin olarak saklamaktan kaçın

## Destruktif Operasyonlar
- DELETE/DROP/TRUNCATE komutları için kullanıcı onayı gerekli
- Dosya silme, veritabanı değiştirme operasyonları onay ister
- DDoS veya servis kesintisi yaratabilecek testler yasak (aksi belirtilmedikçe)

## Operasyonel Güvenlik
- Exploit çalıştırmadan önce reversibility kontrolü yap
- Her kritik adımda checkpoint oluştur
- Hata durumunda güvenli durma (graceful stop)
