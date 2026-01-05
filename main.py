import nmap
import argparse
from datetime import datetime
import os
import sys


class VulnerabilityScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.version = "3.0"

    def banner(self):
        print(r"""
    ____  ___  ____  ___    __    
   / __ \/   |/_  / /   |  / /    
  / / / / /| | / / / /| | / /     
 / /_/ / ___ |/ /_/ ___ |/ /___   
/_____/_/  |_/___/_/  |_/_____/   
        Local Vulnerability Scanner v3.0
        Developer: csyNEMES1S
        """)

    def scan_target(self, ip_address, ports):
        """Belirtilen IP ve portları tarar."""
        print(f"[*] Hedef IP: {ip_address}")
        print(f"[*] Tarama başlatıldı... Lütfen bekleyin.")
        print("-" * 50)

        try:
            # -sS: SYN Scan, -sV: Version Detection, -O: OS Detection (Root gerekebilir)
            # Hata almamak için şimdilik -sV kullanıyoruz.
            self.scanner.scan(ip_address, ports, arguments='-sV -v --version-light')

            if ip_address not in self.scanner.all_hosts():
                print("[-] Hedef anaikine ulaşılamadı (Host down).")
                return None

            return self.scanner[ip_address]

        except Exception as e:
            print(f"[!] Tarama sırasında hata oluştu: {e}")
            return None

    def analyze_risks(self, scan_result):
        """Tarama sonuçlarını analiz eder ve yapılandırılmış veri döndürür."""
        analyzed_data = []

        if 'tcp' in scan_result:
            for port, info in scan_result['tcp'].items():
                service = info.get('name', 'Unknown')
                version = info.get('product', '') + " " + info.get('version', '')

                # Risk Analiz Motoru
                risk_level = "Düşük"
                risk_desc = "Bilgi"

                if port == 21:  # FTP
                    risk_level = "ORTA"
                    risk_desc = "FTP (Dosya Transferi) - Anonim giriş kapalı olmalı."
                elif port == 23:  # Telnet
                    risk_level = "KRİTİK"
                    risk_desc = "Telnet trafiği şifrelenmez. Man-in-the-Middle saldırısına açıktır."
                elif port == 80 and "Apache" in version:
                    risk_level = "BİLGİ"
                    risk_desc = "Web Sunucusu. Versiyon güncelliğini kontrol et."
                elif port == 445:  # SMB
                    risk_level = "YÜKSEK"
                    risk_desc = "SMB Servisi. EternalBlue gibi exploitlere karşı kontrol edilmeli."
                elif port == 3389:  # RDP
                    risk_level = "ORTA"
                    risk_desc = "Uzak Masaüstü açık. Brute-force saldırılarına dikkat."

                analyzed_data.append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "risk_level": risk_level,
                    "risk_desc": risk_desc
                })
        return analyzed_data

    def generate_html_report(self, ip, data, filename):
        """Sonuçları HTML raporu olarak kaydeder."""
        html = f"""
        <html>
        <head>
            <title>Security Scan - {ip}</title>
            <style>
                body {{ background: #1a1a1a; color: #ddd; font-family: monospace; padding: 20px; }}
                h1 {{ color: #00ff00; border-bottom: 1px solid #444; padding-bottom: 10px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #444; padding: 10px; text-align: left; }}
                th {{ background: #333; }}
                .KRİTİK {{ color: #ff0000; font-weight: bold; }}
                .YÜKSEK {{ color: #ff6600; font-weight: bold; }}
                .ORTA {{ color: #ffcc00; }}
                .Düşük {{ color: #00cc00; }}
            </style>
        </head>
        <body>
            <h1>DAZAL - Scanner Report (v3.0)</h1>
            <p><strong>Target:</strong> {ip}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <table>
                <tr>
                    <th>PORT</th>
                    <th>SERVICE</th>
                    <th>VERSION</th>
                    <th>RISK LEVEL</th>
                    <th>DESCRIPTION</th>
                </tr>
        """

        for item in data:
            html += f"""
            <tr>
                <td>{item['port']}</td>
                <td>{item['service']}</td>
                <td>{item['version']}</td>
                <td class="{item['risk_level']}">{item['risk_level']}</td>
                <td>{item['risk_desc']}</td>
            </tr>
            """

        html += "</table></body></html>"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n[+] Rapor oluşturuldu: {os.path.abspath(filename)}")


def main():
    # CLI Argümanlarını Ayarlama
    parser = argparse.ArgumentParser(description="Profesyonel Ağ Zafiyet Tarayıcısı")
    parser.add_argument("-t", "--target", help="Hedef IP Adresi (Örn: 192.168.1.1)", required=True)
    parser.add_argument("-p", "--ports", help="Taranacak Port Aralığı (Varsayılan: 1-1000)", default="1-1000")
    parser.add_argument("-o", "--output", help="Rapor Dosya Adı (Varsayılan: report.html)", default="report.html")

    args = parser.parse_args()

    # Program Akışı
    app = VulnerabilityScanner()
    app.banner()

    scan_result = app.scan_target(args.target, args.ports)

    if scan_result:
        risks = app.analyze_risks(scan_result)

        # Sonuçları ekrana da basalım
        print("\n{:<10} {:<15} {:<30} {:<10}".format("PORT", "SERVİS", "VERSİYON", "RİSK"))
        print("-" * 70)
        for r in risks:
            print("{:<10} {:<15} {:<30} {:<10}".format(r['port'], r['service'], r['version'][:25], r['risk_level']))

        app.generate_html_report(args.target, risks, args.output)
    else:
        print("[-] Tarama başarısız oldu veya sonuç bulunamadı.")


if __name__ == "__main__":
    main()