import time

from alert_manager import raise_alert, Severity
from honeypot import FakeSSHHoneypot, FakeAdminPanel
from honeytoken_monitor import deploy_honeytokens, HoneytokenMonitor
from generate_decoys import deploy_all_document_decoys


SSH_PORT = 2222

HTTP_PORT = 8083

HTTP_PORT = 9090



def main():
    print("=" * 60)
    print(" Deception-based Intrusion Detection - Prototype")
    print("=" * 60)

    # 1. Siapkan honeytoken (file umpan)
    deploy_honeytokens()
    deploy_all_document_decoys()
    token_monitor = HoneytokenMonitor()
    token_monitor.start()

    # 2. Nyalakan honeypot service
    ssh_honeypot = FakeSSHHoneypot(port=SSH_PORT)
    http_honeypot = FakeAdminPanel(port=HTTP_PORT)
    ssh_honeypot.start()
    http_honeypot.start()

    raise_alert(
        source="system",
        event_type="STARTUP",
        detail=f"Semua sensor aktif (SSH umpan:{SSH_PORT}, HTTP umpan:{HTTP_PORT})",
        severity=Severity.LOW,
    )

    print("\nSensor aktif. Tekan Ctrl+C untuk berhenti.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nMenghentikan semua sensor...")
        ssh_honeypot.stop()
        http_honeypot.stop()
        token_monitor.stop()


if __name__ == "__main__":
    main()
