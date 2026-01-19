# Love U N - Vulnerability Scanner

Pemindai kerentanan profesional dengan anonimitas tinggi, terintegrasi Tor, rotasi proxy, dan intelijen NVD real-time.

## Instalasi

### Prasyarat

* Python 3.9+
* Go 1.18+
* Tor (sudah terpasang dan berjalan)

### Langkah-langkah

1. **Clone repositori:**

   ```bash
   git clone https://github.com/hafourenai/Test.git
   cd Test
   ```

2. **Instal dependensi Python:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Build scanner Go:**

   ```bash
   cd go
   go build -o scanner.exe main.go
   cd ..
   ```

4. **Konfigurasi Environment:**
   Buat file `.env` di direktori root:

   ```env
   NVD_API_KEY=your_api_key_here (opsional)
   ```

## Penggunaan

### Verifikasi Koneksi Tor

Pastikan Tor berjalan di `127.0.0.1:9050`, lalu jalankan:

```bash
python python/test_tor.py
```

### Menjalankan Stealth Scan

Memindai target secara anonim melalui jaringan Tor:

```bash
python python/main.py <target> --use-tor --accept-disclaimer
```

### Menjalankan dengan Rotasi Proxy

```bash
python python/main.py <target> --use-proxies --proxies-file proxies.txt --accept-disclaimer
```

### Membersihkan Proyek

Menghapus cache Python dan file sementara:

```bash
python clean.py
```

### Opsi

* `--target <target>`: IP atau domain yang akan dipindai
* `--use-tor`: Mengarahkan seluruh trafik melalui Tor
* `--use-proxies`: Menggunakan rotasi proxy dari file
* `--no-cve`: Menonaktifkan korelasi kerentanan NVD
* `--output <dir>`: Direktori output laporan (default: ./reports)

[DISCLAIMER!]
Alat ini hanya untuk tujuan edukasi dan riset etis. Pemindaian tanpa izin adalah tindakan ilegal.
