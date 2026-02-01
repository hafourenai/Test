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

### Membangun (Build) Scanner

```bash
cd go
go build -o scanner.exe main.go
```

### Cara Menggunakan Go Scanner

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
   
    ```
    touch .env
    nano .env
    ```

    ```env
    NVD_API_KEY=your_api_key_here 
    ```

5.  **Proxies:**
    Buat file `proxies.txt ` di direktori root:

    ```
    touch proxies.txt
    nano proxies.txt
    ```

    ```proxies
    dapatkan proxy rotation kamu sendiri yhh
    ```

##  Komponen Python Orchestrator (`python/`)

Python bertugas sebagai pengatur strategi (stealth orchestration) dan analisis kerentanan (CVE correlation).

### Penggunaan Utama
Jalankan scanner menggunakan sintaks module (WAJIB):
```bash
# Scan dengan anonimitas Tor
python -m python.main <target> --use-tor --accept-disclaimer

# Scan dengan rotasi Proxy
python -m python.main <target> --use-proxies --proxies-file proxies.txt --accept-disclaimer
```

### Pemindai Port Stealth (Budgeted)

Gunakan flag `--stealth` untuk pemindaian port yang berfokus pada kerahasiaan dan kepatuhan anggaran (budget compliance). Mode ini menggunakan mesin pemindaian Python internal yang lebih lambat namun lebih sulit dideteksi.

####  Cara Penggunaan

```bash
# Mode Stealth (Sangat Direkomendasikan):
# - Mengaktifkan delay acak (0.5s - 2.0s) antar percobaan.
# - Membatasi hanya 10 port acak dari daftar umum.
# - Memprioritaskan port web (80, 443).
# - Budget ketat: Maksimal 20 percobaan atau 60 detik.
python -m python.main <target> --stealth --accept-disclaimer
```

####  Ketentuan Teknis
* **Single-threaded**: Menghindari anomali trafik yang mencurigakan.
* **Deterministic Randomness**: Pemilihan port acak namun terkendali dalam mode stealth.
* **Budget Guards**: Otomatis berhenti jika mencapai batas waktu atau jumlah percobaan untuk menghindari deteksi IDS.

---

## Manajemen Data (SQLite)

Hasil pemindaian disimpan secara otomatis dalam database SQLite (`go/vulnerabilities.db`).

### Cara Membuka Database:

1.  **Menggunakan Interface Grafis (GUI) [REKOMENDASI]:**
    - Unduh [DB Browser for SQLite](https://sqlitebrowser.org/).
    - Buka aplikasi dan pilih **Open Database**.
    - Pilih file `go/vulnerabilities.db`.

2.  **Menggunakan VS Code:**
    - Instal ekstensi **"SQLite Viewer"**.
    - Klik kanan pada file `vulnerabilities.db` -> **Open with SQLite Viewer**.

3.  **Menggunakan CLI (sqlite3):**
    ```bash
    cd go
    sqlite3 vulnerabilities.db
    # Query contoh:
    SELECT * FROM scans ORDER BY timestamp DESC LIMIT 5;
    ```

### Struktur Tabel:
- `scans`: Target dan waktu pemindaian.
- `services`: Port, versi aplikasi, dan banner service.
- `http_findings`: Header keamanan yang hilang dan metode HTTP yang diizinkan.

---

## Pembersihan Proyek

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
Alat ini hanya dibuat oleh amatir. Tidak bermaksud merugikan siapapun
