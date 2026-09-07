import logging
import os
from datetime import datetime
from enum import Enum

import requests


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Warna ANSI biar output di terminal gampang dibaca saat demo
_COLOR = {
    Severity.LOW: "\033[94m",       # biru
    Severity.MEDIUM: "\033[93m",    # kuning
    Severity.HIGH: "\033[91m",      # merah
    Severity.CRITICAL: "\033[95m",  # magenta
}
_RESET = "\033[0m"

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")

# Format ISO 8601 dengan presisi milidetik, contoh: 2026-09-07T14:23:03.456
# Disepakati bareng Infra Engineer supaya Elasticsearch/Logstash bisa parse
# timestamp otomatis tanpa konfigurasi tambahan.
TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

# --- Konfigurasi pengiriman ke Logstash (Opsi A) ---
# Endpoint hasil kesepakatan dengan Infra Engineer. Bisa di-override tanpa
# ubah kode lewat environment variable LOGSTASH_URL -- PENTING kalau kalian
# ternyata run di mesin/laptop yang beda (localhost cuma valid kalau
# script ini & Docker Logstash jalan di mesin yang sama).
LOGSTASH_URL = os.environ.get("LOGSTASH_URL", "http://localhost:8080")
LOGSTASH_TIMEOUT = 1  # detik -- sengaja pendek biar IDS gak nge-freeze kalau Logstash lagi mati

# Logger file (plain text, tanpa warna, biar gampang diparse/dianalisis, dan
# tetap jadi sumber data buat simulate_attack.py yang polling alerts.log)
_file_logger = logging.getLogger("ids_deception.alerts")
_file_logger.setLevel(logging.INFO)
_fh = logging.FileHandler(LOG_FILE)
_fh.setFormatter(logging.Formatter("%(message)s"))
if not _file_logger.handlers:
    _file_logger.addHandler(_fh)


def _send_to_logstash(payload: dict):

    try:
        requests.post(LOGSTASH_URL, json=payload, timeout=LOGSTASH_TIMEOUT)
    except requests.exceptions.RequestException:
        # Sengaja di-silent-kan: kegagalan kirim ke Logstash bukan alasan
        # buat gagalin deteksi/alert lokal. Buka komentar di bawah kalau
        # butuh debug kenapa gagal kirim.
        # print(f"[alert_manager] Gagal kirim ke Logstash: {e}")
        pass


def raise_alert(source: str, event_type: str, detail: str,
                 severity: Severity = Severity.MEDIUM,
                 src_ip: str | None = None,
                 file_name: str | None = None):
    timestamp = datetime.now().strftime(TS_FORMAT)[:-3]  # potong ke milidetik

    # --- 1. Tetap tulis ke alerts.log kayak sebelumnya (plain text) ---
    ip_part = f" | src={src_ip}" if src_ip else ""
    line = f"[{timestamp}] [{severity.value}] [{source}] {event_type}{ip_part} -> {detail}"
    _file_logger.info(line)
    color = _COLOR.get(severity, "")
    print(f"{color}{line}{_RESET}")

    # --- 2. Kirim juga versi JSON-nya ke Logstash (Opsi A) ---
    # Nama field di sini sudah disesuaikan hasil kesepakatan dengan Infra
    # Engineer, supaya cocok dengan logstash.conf & Data View Kibana yang
    # sudah lebih dulu mereka buat -- jadi mereka tidak perlu ubah config lagi:
    #   event_type (kode)  -> "action"     (JSON, key final)
    #   src_ip     (kode)  -> "source_ip"  (JSON, key final)
    #   source     (kode)  -> "source"     (JSON, key final -- tetap dipakai apa adanya)
    payload = {
        "timestamp": timestamp,
        "severity": severity.value,
        "source": source,
        "action": event_type,
        "source_ip": src_ip,
        "file_name": file_name,
        "detail": detail,
    }
    _send_to_logstash(payload)


def read_recent_alerts(n: int = 20):
    """Ambil n alert terakhir dari file log, buat ditampilin di dashboard/CLI."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    return [l.strip() for l in lines[-n:]]