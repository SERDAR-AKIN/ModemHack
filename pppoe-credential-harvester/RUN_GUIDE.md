# PPPoE Credential Harvester - Kullanım ve Akış Rehberi

Bu döküman, projenin nasıl çalıştırılacağını ve arkasındaki "Otomatik Yönlendiren Kodlama Akışı"nı açıklamaktadır.

## 📋 Çalıştırma Adımları

### 1. Hazırlık
- Bilgisayarınızın Ethernet portu ile modemin **WAN** portunu bir ethernet kablosuyla bağlayın.
- Bilgisayarınızda internet bağlantısı olmasına gerek yoktur (ancak bağımlılıklar için gereklidir).

### 2. Tek Komutla Çalıştırma
Proje dizinine gidin ve aşağıdaki komutu verin:
```bash
sudo chmod +x run.sh
sudo ./run.sh                  # Varsayılan arayüz (enp8s0)
sudo ./run.sh eth0             # Farklı arayüz belirtin
```

Veya doğrudan Python ile:
```bash
sudo python3 src/harvester.py                      # Varsayılan
sudo python3 src/harvester.py -i eth0              # Farklı arayüz
sudo python3 src/harvester.py -i enp8s0 -t 120     # 2 dakika timeout
sudo python3 src/harvester.py -t 0                 # Sınırsız bekleme
```

### 3. Tetikleme
Ekranda `[!] HAZIR! Modemi şimdi yeniden başlatın.` mesajını gördüğünüzde:
- Modemin güç kablosunu çıkarıp 10 saniye bekleyin.
- Kabloyu geri takın ve yaklaşık 1 dakika içinde şifrenin ekrana düşmesini bekleyin.

### 4. Sonuçlar
- Şifre ekrana basılır.
- Ayrıca `logs/` dizinine JSON formatında kaydedilir.

---

## 🏗️ Otomatik Yönlendiren Kodlama Akışı (Logic Flow)

Proje, modemin "internete çıkma isteğini" sömüren şu akışı takip eder:

1.  **Arayüz Hazırlığı:** `run.sh` NetworkManager'ı devreden çıkarır ve arayüzü `UP` yapar.
2.  **PADI (Keşif) Yakalama:** Modem "Kimse var mı?" dediğinde, `harvester.py` bu paketi (VLAN 0 olsa bile) yakalar.
3.  **PADO (Teklif) Gönderimi:** Bilgisayar modeme "Ben bir Telekom Santraliyim (BRAS), şifreni bana gönder" der.
4.  **PADS (Oturum) Onayı:** Modem bilgisayarı onaylar ve bir oturum açılır.
5.  **LCP (Anlaşma) Fazı:** Modem ile bağlantı protokolleri üzerinde anlaşılır.
6.  **PAP (Ele Geçirme) Fazı:** Araç, modemi şifreyi **açık metin** (Clear-text) göndermeye zorlar.
7.  **Sonuç:** Şifre yakalanır, ekrana ve dosyaya yazılır, program kendini kapatır.

---

## 🛠️ Sorun Giderme
- **PADI yakalanmıyor:** Ethernet kablosunun WAN portuna takılı olduğundan ve modemin yeniden başladığından emin olun.
- **VLAN hatası:** Arayüz isminin doğru olduğundan emin olun (`ip link` komutuyla bakabilirsiniz).
- **Zaman aşımı:** `-t 0` parametresiyle sınırsız bekleme modunda çalıştırın.
