# Love U N Vulnerability Scanner
Vulnerability Scanner Amatir yang menggabungkan kecerdasan **CVE Correlation (NVD)** dengan **Active Hunter Engine (DAST)** untuk deteksi celah keamanan yang akurat, stealthy, dan berbasis bukti.

---

## INSTALLATION

Pastikan Anda sudah menginstal Python 3.9+.

1. **Clone & Setup**
   ```bash
   git clone https://github.com/hafourenai/Test.git
   cd Test
   pip install -r requirements.txt
   ```

2. **Konfigurasi API Key**
   Dapatkan API Key di [NVD NIST](https://nvd.nist.gov/developers/request-an-api-key) dan masukkan ke file `.env` di root folder:
   ```env
   NVD_API_KEY=your_key_here
   ```

---

## CARA PENGGUNAAN 

`unified_scanner.py` adalah entry point tunggal untuk semua fitur.

```bash
# Scan standar (Interactive atau CLI)
python python/unified_scanner.py target.com --ports 80,443 --stealth ninja

# Scan melalui Jaringan Tor (Anonimitas Maksimal)
python python/unified_scanner.py target.com --ports 80 --tor

# Scan dengan Rotasi Proxy dari proxies.txt
python python/unified_scanner.py target.com --ports 80 --proxies
```

> [!TIP]
> Fitur `--tor` memerlukan layanan **Tor** berjalan di port 9050.  
> Fitur `--proxies` akan otomatis membaca list di file `proxies.txt` (satu proxy per baris).

### Alur Kerja Scanner (4-Step Process)
1. **[Step 1/4] Service Fingerprinting**: Identifikasi software & versi aktif.
2. **[Step 2/4] Web Discovery**: Mencari path sensitif & parameter serangan secara otomatis.
3. **[Step 3/4] CVE Correlation**: Pencocokan versi terhadap database kerentanan NVD.
4. **[Step 4/4] Targeted Injection**: Eksekusi payload cerdas pada parameter yang ditemukan.

---

## STRUKTUR PROYEK (CLEAN)
- `python/unified_scanner.py`: Script utama (The Hunter).
- `python/modules/`: Engine inti untuk fingerprinting & NVD matching.
- `python/stealth_engine.py`: Logika penyamaran & bypass.
- `Payloads/`: Database pusat untuk ribuan payload XSS, SQLi, LFI.

---

## PAYLOAD MANAGEMENT
Anda dapat menambah atau memperbarui payload dengan sangat mudah:
1. Navigasi ke folder `Payloads/[XSS|SQLI|LFI]`.
2. Masukkan file `.txt` baru atau tambahkan baris payload ke file yang sudah ada.
3. Scanner akan **otomatis mendeteksi** dan memuat payload tersebut saat dijalankan tanpa perlu mengubah kode.

---



---

## TROUBLESHOOTING & TIPS
- **High Failed Requests?** Target memiliki WAF kuat. Gunakan `--stealth ninja` atau `--stealth ghost`.
- **0 Vulnerabilities?** Cek bagian **Potential Issues** di akhir laporan untuk analisa korelasi versi.
- **WAF Detected: True?** Scanner mendeteksi proteksi aktif, pertimbangkan untuk memperlambat scan.

---

## ⚖️ DISCLAIMER
Alat ini dibuat untuk tujuan edukasi dan pengujian keamanan yang sah. Penggunaan tanpa izin pada infrastruktur pihak ketiga dapat berakibat hukum.