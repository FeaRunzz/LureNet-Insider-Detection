import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from alert_manager import raise_alert, Severity


class FakeSSHHoneypot(threading.Thread):
    """Honeypot TCP sederhana yang meniru prompt login SSH."""

    def __init__(self, host="0.0.0.0", port=2222):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self._sock = None
        self._running = False

    def run(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._running = True
        print(f"[honeypot-ssh] Listening on {self.host}:{self.port} (fake SSH)")

        while self._running:
            try:
                client, addr = self._sock.accept()
                threading.Thread(
                    target=self._handle_client, args=(client, addr), daemon=True
                ).start()
            except OSError:
                break

    def _handle_client(self, client, addr):
        src_ip = addr[0]
        raise_alert(
            source="honeypot-ssh",
            event_type="CONNECTION",
            detail="Ada koneksi masuk ke port SSH umpan",
            severity=Severity.MEDIUM,
            src_ip=src_ip,
        )
        try:
            # Pakai file-like reader (readline) supaya baris username & password
            # tidak ketuker/nyampur walau dikirim client secara cepat berurutan.
            reader = client.makefile("rb")

            client.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
            client.sendall(b"login: ")
            username = reader.readline().decode(errors="ignore").strip()

            client.sendall(b"password: ")
            password = reader.readline().decode(errors="ignore").strip()

            raise_alert(
                source="honeypot-ssh",
                event_type="LOGIN_ATTEMPT",
                detail=f"username='{username}' password='{password}'",
                severity=Severity.HIGH,
                src_ip=src_ip,
            )

            client.sendall(b"Access denied\r\n")
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            client.close()

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()


class _FakeAdminHandler(BaseHTTPRequestHandler):
    """Handler HTTP yang berpura-pura jadi halaman login admin panel."""

    def log_message(self, format, *args):
        # Matikan default logging bawaan http.server, kita pakai alert_manager
        pass

    def do_GET(self):
        raise_alert(
            source="honeypot-http",
            event_type="PAGE_ACCESS",
            detail=f"GET {self.path}",
            severity=Severity.MEDIUM,
            src_ip=self.client_address[0],
        )
        body = b"<html><body><h2>Admin Login</h2><form method='POST'>" \
               b"User: <input name='user'><br>Pass: <input name='pass' type='password'>" \
               b"<input type='submit'></form></body></html>"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Client sudah menutup koneksi lebih dulu -- alert sudah tercatat
            # di atas, jadi kegagalan kirim response ini aman diabaikan.
            pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="ignore")
        raise_alert(
            source="honeypot-http",
            event_type="LOGIN_ATTEMPT",
            detail=f"POST {self.path} body='{body}'",
            severity=Severity.HIGH,
            src_ip=self.client_address[0],
        )
        try:
            self.send_response(401)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h3>401 Unauthorized</h3>")
        except (BrokenPipeError, ConnectionResetError):
            # Client sudah menutup koneksi lebih dulu -- alert sudah tercatat
            # di atas, jadi kegagalan kirim response ini aman diabaikan.
            pass


class FakeAdminPanel(threading.Thread):
    """Honeypot HTTP sederhana (fake admin login page)."""

    def __init__(self, host="0.0.0.0", port=8080):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self._server = None

    def run(self):
        self._server = HTTPServer((self.host, self.port), _FakeAdminHandler)
        print(f"[honeypot-http] Listening on {self.host}:{self.port} (fake admin panel)")
        self._server.serve_forever()

    def stop(self):
        if self._server:
            self._server.shutdown()