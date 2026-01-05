import nmap

scanner = nmap.PortScanner()

print("****************************************************")
print("   GELİŞMİŞ YEREL AĞ VE ZAFİYET TARAYICISI v1.0   ")
print("****************************************************")

ip_addr = input("Taramak istediğiniz IP adresini girin: ")

print(f"\n{ip_addr} üzerinde detaylı analiz yapılıyor... Bu işlem biraz sürebilir.")
print("Versiyon tespiti ve servis analizi çalıştırılıyor...\n")

# -sV: Versiyon tespiti yapar (Hangi programın çalıştığını bulur)
scanner.scan(ip_addr, '1-1024', arguments='-sV -v')

if ip_addr in scanner.all_hosts():
    print(f"IP Durumu: {scanner[ip_addr].state().upper()}")

    if 'tcp' in scanner[ip_addr]:
        acik_portlar = scanner[ip_addr]['tcp'].keys()

        print(f"\n{'PORT':<10} {'SERVİS':<15} {'VERSİYON':<20} {'RİSK DURUMU'}")
        print("-" * 60)

        for port in acik_portlar:
            servis_info = scanner[ip_addr]['tcp'][port]
            servis_adi = servis_info['name']
            versiyon = servis_info['product'] + " " + servis_info['version']

            # Basit Risk Analizi (Rules Engine)
            risk = "Düşük/Bilgi"

            # Kural 1: Telnet (23) güvensizdir
            if port == 23:
                risk = "!!! YÜKSEK (Şifrelenmemiş Bağlantı)"

            # Kural 2: FTP (21) bazen tehlikeli olabilir
            elif port == 21:
                risk = "ORTA (Anonim giriş kontrol edilmeli)"

            # Kural 3: SMB (445) Windows için kritik
            elif port == 445:
                risk = "ORTA/YÜKSEK (SMB Versiyonuna dikkat)"

            print(f"{port:<10} {servis_adi:<15} {versiyon:<20} {risk}")

    else:
        print("Açık TCP portu bulunamadı.")
else:
    print("HATA: Cihaza ulaşılamadı.")