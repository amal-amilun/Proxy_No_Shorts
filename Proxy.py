import socket
import ssl
import threading
import select
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os

# ==================== CONFIG ====================
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 8081
CA_CERT_FILE = "mitm_ca.crt"
CA_KEY_FILE = "mitm_ca.key"
CERT_DIR = "certs"

# Domain yang mau di-intercept (sisanya akan di-bypass secara transparan)
TARGET_DOMAINS = ["youtube.com", "instagram.com", "tiktok.com", "tiktokcdn.com"]

# Keyword URL yang mau diblokir
BLOCKED_KEYWORDS = [b"/shorts", b"/reels", b"/video/"]
# ================================================

os.makedirs(CERT_DIR, exist_ok=True)

class FastMITMProxy:
    def __init__(self):
        self.ca_cert, self.ca_key = self.load_or_create_ca()
        self.cert_cache = {} # Optimasi: Cache cert di RAM

    def load_or_create_ca(self):
        if os.path.exists(CA_CERT_FILE) and os.path.exists(CA_KEY_FILE):
            print("[*] Loaded existing Root CA")
            with open(CA_CERT_FILE, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            with open(CA_KEY_FILE, "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)
            return ca_cert, ca_key

        print("[*] Generating new Root CA...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Fast MITM Root CA"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, True, True, False, False), critical=True)
            .sign(private_key, hashes.SHA256())
        )

        with open(CA_CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(CA_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return cert, private_key

    def get_cert_for_domain(self, hostname):
        # Gunakan Cache untuk menghindari disk I/O yang lambat
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]

        cert_path = os.path.join(CERT_DIR, f"{hostname}.crt")
        key_path = os.path.join(CERT_DIR, f"{hostname}.key")

        if os.path.exists(cert_path) and os.path.exists(key_path):
            self.cert_cache[hostname] = (cert_path, key_path)
            return cert_path, key_path

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

        with open(cert_path, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f: f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
        ))
        
        self.cert_cache[hostname] = (cert_path, key_path)
        return cert_path, key_path

    def relay_stream(self, src, dst, is_client, is_mitm):
        """Memompa data secara paralel dan memfilter stream jika sedang MITM"""
        try:
            while True:
                data = src.recv(65535)
                if not data:
                    break
                
                # Cepat & efisien: Scan byte stream langsung saat mengalir
                if is_client and is_mitm:
                    if any(kw in data for kw in BLOCKED_KEYWORDS):
                        print("\n[BLOCKED] Terdeteksi akses short content!")
                        src.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n<h1>Content Blocked by Proxy</h1>")
                        break
                
                dst.sendall(data)
        except Exception:
            pass
        finally:
            src.close()
            dst.close()

    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(65535)
            if not request:
                return

            if request.startswith(b"CONNECT"):
                self.handle_https(client_socket, request)
            else:
                self.handle_http(client_socket, request)
        except Exception:
            pass

    def handle_http(self, client_socket, request):
        try:
            lines = request.split(b"\r\n")
            host_line = next((l for l in lines if l.lower().startswith(b"host:")), None)
            if not host_line: return
            host = host_line.split(b":")[1].strip().decode()

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((host, 80))
            
            # Cek blokir untuk HTTP biasa
            if any(kw in request for kw in BLOCKED_KEYWORDS):
                client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n<h1>Blocked</h1>")
                client_socket.close()
                return

            server_socket.sendall(request)
            threading.Thread(target=self.relay_stream, args=(client_socket, server_socket, True, False)).start()
            threading.Thread(target=self.relay_stream, args=(server_socket, client_socket, False, False)).start()
        except Exception:
            client_socket.close()

    def handle_https(self, client_socket, connect_request):
        try:
            host_port = connect_request.split(b" ")[1].decode()
            hostname = host_port.split(":")[0]

            # Kirim 200 Connection Established ke browser
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Cek apakah domain ini perlu di-MITM
            needs_mitm = any(target in hostname for target in TARGET_DOMAINS)

            server_socket = socket.create_connection((hostname, 443))

            if needs_mitm:
                # ====== TLS INTERCEPTION (Lambat, tapi perlu untuk inspeksi URL) ======
                cert_path, key_path = self.get_cert_for_domain(hostname)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=cert_path, keyfile=key_path)
                
                ssl_client = context.wrap_socket(client_socket, server_side=True)
                
                server_context = ssl.create_default_context()
                ssl_server = server_context.wrap_socket(server_socket, server_hostname=hostname)

                # Jalankan stream relay dengan mode is_mitm=True agar di-filter
                threading.Thread(target=self.relay_stream, args=(ssl_client, ssl_server, True, True)).start()
                threading.Thread(target=self.relay_stream, args=(ssl_server, ssl_client, False, True)).start()
            else:
                # ====== RAW TCP TUNNEL (Sangat Cepat, langsung bypass) ======
                threading.Thread(target=self.relay_stream, args=(client_socket, server_socket, True, False)).start()
                threading.Thread(target=self.relay_stream, args=(server_socket, client_socket, False, False)).start()

        except Exception:
            client_socket.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((PROXY_HOST, PROXY_PORT))
        server.listen(500)
        print(f"[*] Fast MITM Proxy running on http://{PROXY_HOST}:{PROXY_PORT}")
        print("[*] Mode: Block Shorts (YouTube, IG, TikTok)")

        while True:
            client, _ = server.accept()
            threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    proxy = FastMITMProxy()
    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\n[*] Proxy stopped.")