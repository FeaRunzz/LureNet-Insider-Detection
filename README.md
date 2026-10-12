# LureNet — Insider Threat Detection System menggunakan Deception Technology
<p align="center">
  <img src="img/lurenet_logo_hook_folder_1x1.png" alt="Logo LureNet" width="200">
</p>
LureNet adalah sistem deteksi **insider threat** (ancaman dari dalam organisasi) berbasis **deception technology**. Sistem ini memasang "umpan" (decoy) berupa file dokumen palsu, kredensial palsu, database palsu, serta layanan SSH/HTTP palsu. Karena umpan tersebut tidak pernah dipakai untuk pekerjaan yang sah, **setiap interaksi dengannya otomatis dianggap mencurigakan**. Seluruh aktivitas dicatat, diproses lewat ELK Stack, dan ditampilkan secara visual di dashboard Kibana.
## Latar Belakang

Ancaman siber tidak hanya datang dari luar. Insider sulit dideteksi karena memiliki akses yang sah secara teknis. Firewall dan antivirus bersifat **reaktif** (bertindak setelah ada kejadian), sedangkan deception technology bersifat **proaktif**: memancing pelaku sebelum kerusakan terjadi.

## Fitur
- **Decoy file dokumen** dan **database palsu** di lokasi yang tampak wajar
- **Honeytoken kredensial** (contoh: `aws_credentials.txt`) yang dipantau perubahannya
- **Honeypot SSH** (fake SSH service) yang mencatat koneksi dan percobaan login
- **Honeypot HTTP** (fake admin panel) yang mencatat akses halaman dan percobaan login
- Pengiriman alert terstruktur (JSON) ke **Logstash → Elasticsearch**
- **Dashboard Kibana** dengan panel total alert, distribusi severity, distribusi sumber sensor, tren waktu, dan tabel log
- **Data persisten** lewat Docker volume, sehingga data tidak hilang saat container dibuat ulang
- **Script simulasi serangan** yang mengukur _time-to-detection_ secara otomatis

## Arsitektur
Sistem terdiri dari 3 lapisan:
1. **Decoy Layer**: file, kredensial, dan database palsu
2. **Detection & Logging Layer**: honeypot/honeytoken (Python) → Logstash → Elasticsearch
3. **Visualization Layer**: dashboard Kibana

**Pembagian lokasi komponen:**

| Komponen              | Dijalankan sebagai      | Port |
| --------------------- | ----------------------- | ---- |
| Elasticsearch         | Container Docker        | 9200 |
| Logstash (HTTP input) | Container Docker        | 8080 |
| Kibana                | Container Docker        | 5601 |
| Honeypot SSH          | Script Python (di host) | 2222 |
| Honeypot HTTP         | Script Python (di host) | 9090 |
## Teknologi
- **ELK Stack 8.15.0**: Elasticsearch, Logstash, Kibana
- **Python 3**: `watchdog` (monitoring file), `requests` (kirim data ke Logstash), library standar (`socket`, `http.server`)
- **Docker & Docker Compose**

## Cara Menjalankan
**Urutan penting:** nyalakan penerima data (Docker) lebih dulu, baru pengirim data (honeypot). Jika Logstash belum hidup, pengiriman alert gagal secara diam-diam dan data hanya tersimpan di log lokal.

### 1. Clone repository

bash

```bash
git clone https://github.com/FeaRunzz/LureNet-Insider-Detection.git
cd LureNet-Insider-Detection
```

### 2. Nyalakan ELK Stack

bash

```bash
docker compose up -d
docker ps
```

Pastikan 3 container (`lurenet-elasticsearch`, `lurenet-logstash`, `lurenet-kibana`) berstatus `Up`. Kibana butuh beberapa menit untuk siap pada start pertama. Buka `http://localhost:5601`; pesan `Kibana server is not ready yet` berarti masih proses inisialisasi.

Cek Elasticsearch:

bash

```bash
curl http://localhost:9200
```

### 3. Install dependency Python

bash

```bash
cd LureNet_Deception_Prototype/ids_deception
pip install -r requirements.txt
pip install requests
```

Jika muncul error `externally-managed-environment` di Ubuntu versi baru, gunakan virtual environment (`python3 -m venv venv && source venv/bin/activate`) atau tambahkan flag `--break-system-packages`.

### 4. Jalankan sensor (Terminal 1)

bash

```bash
python3 main.py
```

Biarkan terus berjalan. Sensor akan memasang decoy, mengaktifkan honeypot SSH (2222) dan HTTP (9090), serta memantau folder honeytoken.

### 5. Simulasikan serangan (Terminal 2)

bash

```bash
cd LureNet_Deception_Prototype/ids_deception
python3 simulate_attack.py
```

Biarkan sampai selesai sendiri (jangan `Ctrl+C` di tengah proses). Hasil pengukuran disimpan di `metrics_results.json`.

### 6. Lihat hasil di Kibana

1. Buka `http://localhost:5601` → **Stack Management → Data Views → Create data view**
2. Name: `decoy-logs`, index pattern: `decoy-logs*`, timestamp field: `@timestamp`
3. Buka **Discover** dan perluas rentang waktu jika data belum terlihat (default hanya "Last 15 minutes")
4. Buat dashboard lewat menu **Dashboard → Create dashboard**

> **Tip pencarian:** untuk field kategori (`severity`, `source`, `action`), gunakan `.keyword` agar hasil persis. Contoh: `source.keyword:honeypot-http`. Tanpa `.keyword`, pencarian dipecah per kata dan bisa memberi hasil yang keliru.

### Menghentikan sistem

bash

```bash
docker compose stop
```

Gunakan `stop` atau `down`. **Jangan** gunakan `docker compose down -v` karena akan menghapus volume dan seluruh data Elasticsearch 

## Format Data Alert

Setiap alert dikirim ke Logstash sebagai JSON dengan field berikut:

| Field       | Keterangan                                                                                     |
| ----------- | ---------------------------------------------------------------------------------------------- |
| `timestamp` | Waktu kejadian (ISO 8601, presisi milidetik)                                                   |
| `severity`  | `LOW`, `MEDIUM`, `HIGH`, atau `CRITICAL` (otomatis diubah ke huruf besar oleh Logstash)        |
| `source`    | Nama sensor, misalnya `honeypot-ssh`, `honeypot-http`, `honeytoken-credential`                 |
| `action`    | Jenis kejadian, misalnya `CONNECTION`, `LOGIN_ATTEMPT`, `PAGE_ACCESS`, `FILE_MOVED_OR_RENAMED` |
| `source_ip` | IP sumber (bisa kosong untuk akses file lokal)                                                 |
| `file_name` | Nama file decoy yang tersentuh (jika relevan)                                                  |
| `detail`    | Deskripsi bebas                                                                                |
## Lisensi

Proyek ini dilindungi di bawah **MIT License**. Lihat file [LICENSE](LICENSE) untuk informasi selengkapnya.
