import os
import shutil
import socket
import time
import json
from datetime import datetime

import urllib.request

from alert_manager import LOG_FILE, TS_FORMAT

SSH_PORT = 2222
HTTP_PORT = 8080
TARGET_HOST = "127.0.0.1"

BASE_DIR = os.path.dirname(__file__)
HONEYTOKEN_DIR = os.path.join(BASE_DIR, "honeytokens")
METRICS_FILE = os.path.join(BASE_DIR, "metrics_results.json")
METRICS_RUNS_DIR = os.path.join(BASE_DIR, "metrics_runs")
METRICS_HISTORY_FILE = os.path.join(BASE_DIR, "metrics_history.jsonl")


def simulate_ssh_bruteforce():
    print("\n[attacker] Mencoba login ke fake SSH service...")
    creds = [("admin", "admin123"), ("root", "toor")]
    for user, pwd in creds:
        try:
            s = socket.create_connection((TARGET_HOST, SSH_PORT), timeout=3)
            s.recv(1024)  
            s.sendall((user + "\n").encode())
            s.recv(1024)  
            s.sendall((pwd + "\n").encode())
            s.recv(1024)
            s.close()
            print(f"[attacker]  -> mencoba {user}:{pwd}")
            time.sleep(0.5)
        except (ConnectionRefusedError, socket.timeout):
            print("[attacker] Gagal connect ke honeypot SSH. Pastikan main.py sudah jalan.")
            return


def simulate_http_probe():
    print("\n[attacker] Mengakses fake admin panel via HTTP...")
    try:
        urllib.request.urlopen(f"http://{TARGET_HOST}:{HTTP_PORT}/", timeout=3)
        data = b"user=admin&pass=letmein123"
        req = urllib.request.Request(
            f"http://{TARGET_HOST}:{HTTP_PORT}/login", data=data, method="POST"
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        print(f"[attacker]  -> request terkirim (server merespon: {e})")


def simulate_honeytoken_theft():
    print("\n[attacker] Menemukan file kredensial mencurigakan, mencoba mengambilnya...")
    src = os.path.join(HONEYTOKEN_DIR, "aws_credentials.txt")
    dst = os.path.join(HONEYTOKEN_DIR, "aws_credentials_stolen.txt")
    if os.path.exists(src):
        shutil.move(src, dst)
        print(f"[attacker]  -> file dipindahkan ke {dst}")
        time.sleep(1)
        shutil.move(dst, src)
    else:
        print("[attacker] Honeytoken kredensial tidak ditemukan. Pastikan main.py sudah jalan.")


def simulate_document_theft():
    print("\n[attacker] Menemukan dokumen mencurigakan (Data_Gaji_Karyawan_2026.csv)...")
    src = os.path.join(HONEYTOKEN_DIR, "Data_Gaji_Karyawan_2026.csv")
    dst = os.path.join(HONEYTOKEN_DIR, "Data_Gaji_Karyawan_2026_stolen.csv")
    if os.path.exists(src):
        shutil.move(src, dst)
        print(f"[attacker]  -> dokumen dipindahkan ke {dst}")
        time.sleep(1)
        shutil.move(dst, src)
    else:
        print("[attacker] Decoy dokumen tidak ditemukan. Jalankan generate_decoys.py dulu.")


def simulate_database_theft():
    print("\n[attacker] Menemukan file database mencurigakan (customers_backup.db)...")
    src = os.path.join(HONEYTOKEN_DIR, "customers_backup.db")
    dst = os.path.join(HONEYTOKEN_DIR, "customers_backup_stolen.db")
    if os.path.exists(src):
        shutil.move(src, dst)
        print(f"[attacker]  -> database dipindahkan ke {dst}")
        time.sleep(1)
        shutil.move(dst, src)
    else:
        print("[attacker] Decoy database tidak ditemukan. Jalankan generate_decoys.py dulu.")


# ---------------------------------------------------------------------------
# Time-to-detection metrics
# ---------------------------------------------------------------------------

def _read_log_lines():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()


def _parse_ts(line):
    try:
        ts_str = line.split("]")[0].lstrip("[")
        return datetime.strptime(ts_str, TS_FORMAT)
    except Exception:
        return None


def measure_detection(label, action_fn, match_keywords, timeout=5):
    baseline = len(_read_log_lines())
    t_attack = datetime.now()

    action_fn()

    deadline = time.time() + timeout
    detected_at = None
    matched_line = None
    while time.time() < deadline:
        lines = _read_log_lines()
        for line in lines[baseline:]:
            if any(kw.lower() in line.lower() for kw in match_keywords):
                ts = _parse_ts(line)
                if ts:
                    detected_at = ts
                    matched_line = line.strip()
                    break
        if detected_at:
            break
        time.sleep(0.05)

    delta = (detected_at - t_attack).total_seconds() if detected_at else None

    return {
        "action": label,
        "t_attack": t_attack.strftime(TS_FORMAT)[:-3],
        "t_detect": detected_at.strftime(TS_FORMAT)[:-3] if detected_at else None,
        "delta_seconds": round(delta, 3) if delta is not None else None,
        "matched_log_line": matched_line,
    }

#penambahan yang baru dibawah inii
def print_summary(results):
    print("\n" + "=" * 70)
    print(" RINGKASAN TIME-TO-DETECTION")
    print("=" * 70)
    print(f"{'Aksi':<28} {'Delta (detik)':<16} {'Status'}")
    print("-" * 70)
    for r in results:
        if r["delta_seconds"] is not None:
            status = "TERDETEKSI"
            delta_str = f"{r['delta_seconds']}s"
        else:
            status = "TIDAK TERDETEKSI"
            delta_str = "-"
        print(f"{r['action']:<28} {delta_str:<16} {status}")

    detected = [r for r in results if r["delta_seconds"] is not None]
    avg = None
    if detected:
        avg = sum(r["delta_seconds"] for r in detected) / len(detected)
        print("-" * 70)
        print(
            f"Rata-rata time-to-detection: {avg:.3f} detik "
            f"({len(detected)}/{len(results)} aksi terdeteksi)"
        )

    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 1. Simpan hasil lengkap run ini ke file TERPISAH -- tidak ketimpa run lain
    os.makedirs(METRICS_RUNS_DIR, exist_ok=True)
    run_file = os.path.join(METRICS_RUNS_DIR, f"run_{run_timestamp}.json")
    with open(run_file, "w") as f:
        json.dump(results, f, indent=2)

    # 2. Tetap simpan salinan "hasil terakhir" di lokasi lama (kompatibel)
    with open(METRICS_FILE, "w") as f:
        json.dump(results, f, indent=2)

    # 3. Tambahkan (append) 1 baris ringkasan ke riwayat semua run
    summary_line = {
        "run_timestamp": run_timestamp,
        "avg_delta_seconds": round(avg, 3) if avg is not None else None,
        "detected_count": len(detected),
        "total_count": len(results),
        "per_action": {r["action"]: r["delta_seconds"] for r in results},
    }
    with open(METRICS_HISTORY_FILE, "a") as f:
        f.write(json.dumps(summary_line) + "\n")

    print(f"\n[metrics] Detail run ini disimpan di: {run_file}")
    print(f"[metrics] Ringkasan run ditambahkan ke riwayat: {METRICS_HISTORY_FILE}")


if __name__ == "__main__":
    print("=" * 70)
    print(" SIMULASI SERANGAN (untuk demo & evaluasi deception-based IDS)")
    print("=" * 70)

    results = []
    results.append(measure_detection(
        "SSH Bruteforce", simulate_ssh_bruteforce, ["honeypot-ssh"]
    ))
    results.append(measure_detection(
        "HTTP Admin Probe", simulate_http_probe, ["honeypot-http"]
    ))
    results.append(measure_detection(
        "Honeytoken Kredensial Theft", simulate_honeytoken_theft, ["honeytoken-credential"]
    ))
    results.append(measure_detection(
        "Decoy Dokumen Access", simulate_document_theft, ["honeytoken-document"]
    ))
    results.append(measure_detection(
        "Decoy Database Access", simulate_database_theft, ["honeytoken-database"]
    ))

    print("\n[attacker] Simulasi selesai. Cek terminal main.py untuk lihat alert real-time.")
    print_summary(results)