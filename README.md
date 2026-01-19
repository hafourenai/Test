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

1.  **Clone repositori:**

    ```bash
    git clone https://github.com/hafourenai/Test.git
    cd Test
    ```

2.  **Instal dependensi Python:**

    ```bash
    pip install -r requirements.txt
    ```

## Komponen Go Scanner (`go/`)

Go berfungsi sebagai mesin pemindaian berperforma tinggi (high-performance scanning engine).

### 🛠️ Membangun (Build) Scanner

Jika Anda belum memiliki `scanner.exe` atau ingin membangun ulang dari source:

```bash
cd go
go build -o scanner.exe main.go
```

### 🚀 Cara Menggunakan Go Scanner

#### 1. Mode CLI (Standalone)
Gunakan ini untuk pemindaian cepat langsung dari terminal:

```bash
# Pindah ke direktori go
cd go

# Jalankan scan dasar
./scanner.exe --target google.com --start 80 --end 443 --threads 50

# Opsi CLI:
# --target  : IP atau Domain target (Wajib)
# --start   : Port awal (Default: 1)
# --end     : Port akhir (Default: 1000)
# --timeout : Timeout koneksi dalam detik (Default: 2)
# --threads : Jumlah thread concurrent (Default: 100)
# --db      : Path ke database SQLite (Default: vulnerabilities.db)
```

#### 2. Mode API (Server)
Gunakan ini jika ingin mengintegrasikan scanner dengan aplikasi lain melalui REST API:

```bash
cd go
./scanner.exe --api --apiport 8000
```
Setelah server berjalan, Anda bisa mengirim request:
```bash
# Contoh request menggunakan curl
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","start_port":1,"end_port":100}'
```

---

4.  **Konfigurasi Environment:**
    Buat file `.env` di direktori root:

    ```env
    NVD_API_KEY=your_api_key_here (opsional)
    ```

## 🐍 Komponen Python Orchestrator (`python/`)

Python bertugas sebagai pengatur strategi (stealth orchestration) dan analisis kerentanan (CVE correlation).

### Penggunaan Utama
Jalankan scanner menggunakan sintaks module (WAJIB):
```bash
# Scan dengan anonimitas Tor
python -m python.main <target> --use-tor --accept-disclaimer

# Scan dengan rotasi Proxy
python -m python.main <target> --use-proxies --proxies-file proxies.txt --accept-disclaimer
```

---

## 🧹 Pembersihan Proyek

Gunakan `clean.py` untuk menghapus file sementara dan log:

```bash
python clean.py
```

---

### Opsi

*   `--target <target>`: IP atau domain yang akan dipindai
*   `--use-tor`: Mengarahkan seluruh trafik melalui Tor
*   `--use-proxies`: Menggunakan rotasi proxy dari file
*   `--no-cve`: Menonaktifkan korelasi kerentanan NVD
*   `--output <dir>`: Direktori output laporan (default: ./reports)

---

**DISCLAIMER!**
Alat ini hanya untuk tujuan edukasi dan riset etis. Pemindaian tanpa izin adalah tindakan ilegal.
