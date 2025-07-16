FitKodlar.com, fitness, sağlıklı yaşam ve supplement konularında güvenilir içerikler sunan; kullanıcıların kayıt olup içerikleri okuyabileceği, yorum yapabileceği ve yöneticilerin içerik yönetimi gerçekleştirebildiği bir web platformudur. Bu proje, web güvenliği odaklı olarak geliştirilmiştir.

🚀 Özellikler
🔐 Kullanıcı Kayıt / Giriş Sistemi

🧩 İki Faktörlü Doğrulama (2FA) – Normal kullanıcılar için e-posta kodlu giriş

🚫 Hesap Kilitleme – 3 yanlış girişte geçici bloklama (10 dakika)

🧠 Admin Paneli

Kullanıcı yönetimi (admin yapma, silme)

Gönderi ekleme, düzenleme, silme

Kategori yönetimi

📝 Gönderilere Yorum Ekleme

🖼️ Görsel Yükleme ve Gösterimi

🧹 Şifre Sıfırlama Sistemi – E-posta bağlantısıyla

🔒 CSRF koruması – Flask-WTF ile tüm formlarda güvenlik

🧪 SQLite ile veritabanı desteği

⚙️ Kullanılan Teknolojiler
Katman	Teknoloji
Backend	Python (Flask)
Veritabanı	SQLite
Frontend	HTML, CSS, Bootstrap
Mail	Flask-Mail (Gmail SMTP)
Güvenlik	Werkzeug, Flask-WTF, CSRFProtect, Hashing
2FA / Şifre Sıfırlama	itsdangerous, Flask-Mail

✅ Güvenlik Özellikleri
Şifreler bcrypt ile hashlenir

CSRF koruması tüm formlarda aktiftir

Kullanıcı oturumları session üzerinden takip edilir

3 kez yanlış girişte hesap geçici olarak kilitlenir

Normal kullanıcılar için 2FA (e-posta doğrulama) zorunludur

🔧 Projeyi Çalıştırmak ve Test Etmek
Projeyi çalıştırmak için aşağıdaki adımları izleyebilirsiniz:

Visual Studio Code üzerinde projeyi açın.

Gerekli Python kütüphaneleri yüklü değilse, terminalde aşağıdaki komutla yükleyin:

bash
pip install -r requirements.txt
Sağ üst köşedeki “Run” (Çalıştır) sekmesine tıklayın veya terminalde aşağıdaki komutu çalıştırın:

bash
python app.py
Terminalde şu bağlantıyı göreceksiniz:

arduino
http://localhost:5000
Bu bağlantıyı tarayıcıda açarak sistemi test edebilirsiniz.

👨‍💻 Geliştirici
Ad: Kadir LUPU

Program: Doğuş Üniversitesi – Bilişim Güvenliği Teknolojisi

İletişim: kadirlupu00@gmail.com

Not: Bu proje büyük oranda tamamlanmıştır ancak hâlâ geliştirme aşamasındadır. Yeni özellikler eklenmekte ve mevcut yapılar iyileştirilmektedir.

