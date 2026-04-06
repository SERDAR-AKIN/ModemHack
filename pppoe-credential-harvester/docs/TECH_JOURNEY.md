# Teknik Yolculuk: PPPoE Şifre Yakalama Zorlukları

Bu projenin geliştirilme sürecinde karşılaşılan engeller ve bu engellerin çözüm yolları:

## 1. Engel: Görünmez Paketler (VLAN 0 / Priority Tagging)
**Sorun:** Modem (`zte_2d:bd:ad`), gönderdiği PADI paketlerini `802.1Q (VLAN)` başlığıyla (`VLAN 0`) sarmalıyordu. Standart Linux PPPoE sunucuları (`pppoe-server`) bu paketleri "ham ethernet" paketi olarak görmediği için hiç cevap vermiyordu.
**Çözüm:** `scapy` kütüphanesi ile paketleri Ethernet katmanında (Layer 2) ham olarak yakaladık ve VLAN başlıklarını manuel olarak ayıklayıp cevapları da aynı VLAN başlığıyla geri gönderdik.

## 2. Engel: Paket Uzunluk (Length) Hatası
**Sorun:** `scapy` ile manuel paket oluştururken `PPPoED` katmanındaki `len` (uzunluk) değeri `0` kalıyordu. Modem, uzunluğu hatalı paketleri geçersiz sayıp çöpe atıyordu.
**Çözüm:** Gönderilen etiketlerin (Tags) uzunluğunu dinamik olarak hesaplayıp `PPPoED(len=...)` parametresine ekledik.

## 3. Engel: LCP Handshake Döngüsü
**Sorun:** Modem, internete çıkmadan önce "LCP (Link Control Protocol)" el sıkışması yapmak ister. Eğer bu aşamada doğru Configure-Ack paketleri gitmezse modem şifre aşamasına (PAP) hiç geçmez.
**Çözüm:** Modemin gönderdiği LCP isteklerini (ID'leri takip ederek) onayladık (ACK) ve aynı zamanda "Hadi PAP protokolüyle kimlik doğrulaması yapalım" diyen kendi LCP isteğimizi (`proto=0xc021`) gönderdik.

## Sonuç
Bu süreç, standart ağ araçlarının sınırlamalarını aşmak için ham soket programlamanın ve protokol seviyesinde analiz yapmanın önemini bir kez daha kanıtlamıştır.
