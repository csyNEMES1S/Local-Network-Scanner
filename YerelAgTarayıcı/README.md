# 🛡️ Local Vulnerability Scanner (Yerel Ağ Zafiyet Tarayıcısı)

Bu proje, Python ve Nmap kütüphaneleri kullanılarak geliştirilmiş, yerel ağ üzerindeki cihazları analiz eden ve potansiyel güvenlik risklerini raporlayan bir siber güvenlik aracıdır.

## 🚀 Özellikler
- **IP Tarama:** Hedef IP üzerindeki aktif cihazları tespit eder.
- **Port Analizi:** 1-1024 arasındaki TCP portlarını tarar.
- **Versiyon Tespiti (Banner Grabbing):** Çalışan servislerin (Apache, OpenSSH, vb.) versiyonlarını çeker.
- **Risk Analizi:** Kritik portlar (Telnet, FTP, SMB) tespit edildiğinde güvenlik uyarısı verir.

## 🛠️ Kurulum

1. Projeyi bilgisayarınıza klonlayın:
   ```bash
   git clone [https://github.com/kullaniciadin/Local-Vuln-Scanner.git](https://github.com/kullaniciadin/Local-Vuln-Scanner.git)