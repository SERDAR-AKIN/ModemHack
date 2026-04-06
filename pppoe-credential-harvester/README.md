# PPPoE Credential Harvester

Bu proje, modemlerin internete bağlanırken kullandığı PPPoE kullanıcı adı ve şifresini ele geçirmek için tasarlanmış bir ağ güvenlik aracıdır.

## 🚀 Hızlı Başlangıç

1. **Bağımlılıkları Kurun:**
   ```bash
   pip install scapy
   ```

2. **Kablo Bağlantısı:**
   Bilgisayarınızın ethernet portunu modemin **WAN** portuna bağlayın.

3. **Aracı Çalıştırın:**
   ```bash
   sudo ./run.sh                # Varsayılan arayüz (enp8s0)
   sudo ./run.sh eth0           # Farklı arayüz
   ```

   Veya doğrudan Python ile:
   ```bash
   sudo python3 src/harvester.py
   sudo python3 src/harvester.py -i eth0 -t 120
   ```

4. **Tetikleme:**
   Modemi yeniden başlatın. Şifre saniyeler içinde ekrana düşecektir.

## 🧠 Teknik Özet
Standart PPPoE sunucularının (rp-pppoe gibi) başarısız olduğu durumlarda bu araç şu teknikleri kullanarak sonuca ulaşır:
- **VLAN 0 Awareness:** Modemlerin gönderdiği Priority Tagged (802.1Q VLAN 0) paketlerini ham Ethernet seviyesinde yakalar.
- **LCP Handshake Simulation:** Modem ile bağlantı parametrelerini (MRU, Magic Number) konuşarak PAP aşamasına geçmesini sağlar.
- **PAP Forced Authentication:** Güvenli yöntemleri reddedip modemi şifreyi açık metin (Clear-text) göndermeye zorlar.

## 📁 Proje Yapısı
```
pppoe-credential-harvester/
├── src/
│   └── harvester.py          # Ana araç (VLAN-Aware PPPoE Harvester)
├── docs/
│   └── TECH_JOURNEY.md       # Teknik yolculuk ve karşılaşılan engeller
├── logs/                     # Yakalanan kimlik bilgileri (otomatik oluşur)
├── run.sh                    # Kolay başlatma betiği
├── README.md                 # Bu dosya
├── RUN_GUIDE.md              # Detaylı kullanım rehberi
└── .gitignore
```

## ⚙️ Parametreler
| Parametre | Varsayılan | Açıklama |
|-----------|-----------|----------|
| `-i`, `--interface` | `enp8s0` | Ethernet arayüzü |
| `-t`, `--timeout` | `180` | Zaman aşımı (saniye, 0=sınırsız) |

## ⚠️ Uyarı
Bu araç sadece eğitim ve kendi cihazlarınızda şifre kurtarma amacıyla kullanılmalıdır. Etik dışı kullanımı kesinlikle önerilmez.
