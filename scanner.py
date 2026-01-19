"""
scanner.py - Modul untuk melakukan vulnerability scanning sederhana

Modul ini berisi class-class untuk melakukan pengecekan keamanan dasar:
1. SecurityHeaderScanner - Mengecek HTTP security headers
2. SSLScanner - Mengecek sertifikat SSL/TLS
3. PortScanner - Mengecek port yang terbuka
4. VulnerabilityScanner - Class utama yang menggabungkan semua scanner
"""

import requests
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Tuple


class SecurityHeaderScanner:
    """
    Class untuk mengecek keberadaan HTTP Security Headers.

    Security headers adalah header HTTP yang membantu melindungi website
    dari berbagai serangan seperti XSS, clickjacking, dll.
    """

    # Daftar security headers yang penting beserta penjelasannya
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'Memaksa browser menggunakan HTTPS',
        'X-Content-Type-Options': 'Mencegah MIME type sniffing',
        'X-Frame-Options': 'Melindungi dari clickjacking',
        'X-XSS-Protection': 'Filter XSS bawaan browser',
        'Content-Security-Policy': 'Mengontrol sumber konten yang diizinkan',
        'Referrer-Policy': 'Mengontrol informasi referrer',
        'Permissions-Policy': 'Mengontrol fitur browser yang diizinkan'
    }

    def __init__(self, url: str):
        """
        Constructor - Inisialisasi scanner dengan URL target.

        Args:
            url: URL website yang akan di-scan
        """
        self.url = url
        self.headers = {}  # Menyimpan headers yang ditemukan

    def scan(self) -> Dict[str, dict]:
        """
        Melakukan scanning security headers.

        Returns:
            Dictionary berisi hasil scan untuk setiap header
        """
        results = {}

        try:
            # Kirim HTTP GET request ke website
            # timeout=10 artinya tunggu maksimal 10 detik
            response = requests.get(self.url, timeout=10, verify=True)
            self.headers = response.headers

            # Cek setiap security header
            for header, description in self.SECURITY_HEADERS.items():
                if header in self.headers:
                    # Header ditemukan - AMAN
                    results[header] = {
                        'status': 'FOUND',
                        'value': self.headers[header],
                        'description': description
                    }
                else:
                    # Header tidak ditemukan - POTENSI MASALAH
                    results[header] = {
                        'status': 'MISSING',
                        'value': None,
                        'description': description
                    }

        except requests.exceptions.RequestException as e:
            # Terjadi error saat request
            results['error'] = str(e)

        return results


class SSLScanner:
    """
    Class untuk mengecek sertifikat SSL/TLS website.

    SSL/TLS adalah protokol keamanan yang mengenkripsi komunikasi
    antara browser dan server website.
    """

    def __init__(self, url: str):
        """
        Constructor - Inisialisasi scanner dengan URL target.

        Args:
            url: URL website yang akan di-scan
        """
        # Parse URL untuk mendapatkan hostname
        parsed = urlparse(url)
        self.hostname = parsed.netloc or parsed.path
        # Hapus port jika ada (contoh: example.com:8080 -> example.com)
        self.hostname = self.hostname.split(':')[0]

    def scan(self) -> Dict[str, any]:
        """
        Melakukan scanning sertifikat SSL.

        Returns:
            Dictionary berisi informasi sertifikat SSL
        """
        results = {}

        try:
            # Buat SSL context untuk koneksi aman
            context = ssl.create_default_context()

            # Buat koneksi socket ke server
            with socket.create_connection((self.hostname, 443), timeout=10) as sock:
                # Bungkus socket dengan SSL
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Ambil informasi sertifikat
                    cert = ssock.getpeercert()

                    # Parse tanggal expired sertifikat
                    expire_date = datetime.strptime(
                        cert['notAfter'],
                        '%b %d %H:%M:%S %Y %Z'
                    )

                    # Hitung sisa hari sebelum expired
                    days_left = (expire_date - datetime.now()).days

                    results = {
                        'status': 'VALID',
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expire_date': cert['notAfter'],
                        'days_until_expire': days_left,
                        'version': ssock.version()  # Versi TLS yang digunakan
                    }

                    # Warning jika sertifikat akan expired dalam 30 hari
                    if days_left < 30:
                        results['warning'] = f'Sertifikat akan expired dalam {days_left} hari!'

        except ssl.SSLError as e:
            results = {'status': 'SSL_ERROR', 'error': str(e)}
        except socket.error as e:
            results = {'status': 'CONNECTION_ERROR', 'error': str(e)}
        except Exception as e:
            results = {'status': 'ERROR', 'error': str(e)}

        return results


class PortScanner:
    """
    Class untuk mengecek port yang terbuka pada server.

    Port adalah "pintu" virtual yang digunakan untuk komunikasi jaringan.
    Port yang terbuka bisa menjadi celah keamanan jika tidak dikonfigurasi dengan benar.
    """

    # Daftar port umum yang sering menjadi target
    COMMON_PORTS = {
        21: 'FTP (File Transfer)',
        22: 'SSH (Secure Shell)',
        23: 'Telnet (Tidak Aman!)',
        25: 'SMTP (Email)',
        53: 'DNS',
        80: 'HTTP (Web)',
        110: 'POP3 (Email)',
        143: 'IMAP (Email)',
        443: 'HTTPS (Web Secure)',
        445: 'SMB (File Sharing)',
        3306: 'MySQL Database',
        3389: 'RDP (Remote Desktop)',
        5432: 'PostgreSQL Database',
        8080: 'HTTP Alternatif',
        8443: 'HTTPS Alternatif'
    }

    def __init__(self, url: str):
        """
        Constructor - Inisialisasi scanner dengan URL target.

        Args:
            url: URL website yang akan di-scan
        """
        parsed = urlparse(url)
        self.hostname = parsed.netloc or parsed.path
        self.hostname = self.hostname.split(':')[0]

    def scan_port(self, port: int) -> bool:
        """
        Cek apakah satu port terbuka.

        Args:
            port: Nomor port yang akan dicek

        Returns:
            True jika port terbuka, False jika tertutup
        """
        try:
            # Buat socket dan coba koneksi
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Timeout 2 detik per port
            result = sock.connect_ex((self.hostname, port))
            sock.close()

            # result == 0 berarti koneksi berhasil (port terbuka)
            return result == 0

        except socket.error:
            return False

    def scan(self) -> Dict[str, any]:
        """
        Scan semua port umum.

        Returns:
            Dictionary berisi daftar port terbuka
        """
        results = {
            'hostname': self.hostname,
            'open_ports': [],
            'closed_ports': []
        }

        # Scan setiap port dalam daftar
        for port, service in self.COMMON_PORTS.items():
            if self.scan_port(port):
                results['open_ports'].append({
                    'port': port,
                    'service': service
                })
            else:
                results['closed_ports'].append(port)

        return results


class VulnerabilityScanner:
    """
    Class utama yang menggabungkan semua scanner.

    Class ini menggunakan pola Facade - menyederhanakan penggunaan
    beberapa class scanner menjadi satu interface yang mudah digunakan.
    """

    def __init__(self, url: str):
        """
        Constructor - Inisialisasi semua scanner.

        Args:
            url: URL website yang akan di-scan
        """
        # Pastikan URL memiliki schema (http:// atau https://)
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        self.url = url

        # Inisialisasi semua scanner
        self.header_scanner = SecurityHeaderScanner(url)
        self.ssl_scanner = SSLScanner(url)
        self.port_scanner = PortScanner(url)

    def scan_headers(self) -> Dict:
        """Jalankan scan security headers saja."""
        return self.header_scanner.scan()

    def scan_ssl(self) -> Dict:
        """Jalankan scan SSL saja."""
        return self.ssl_scanner.scan()

    def scan_ports(self) -> Dict:
        """Jalankan scan ports saja."""
        return self.port_scanner.scan()

    def full_scan(self) -> Dict:
        """
        Jalankan semua scan sekaligus.

        Returns:
            Dictionary berisi hasil semua scan
        """
        return {
            'url': self.url,
            'timestamp': datetime.now().isoformat(),
            'security_headers': self.scan_headers(),
            'ssl_certificate': self.scan_ssl(),
            'port_scan': self.scan_ports()
        }


# Kode untuk testing jika file ini dijalankan langsung
if __name__ == '__main__':
    # Contoh penggunaan
    scanner = VulnerabilityScanner('https://example.com')
    results = scanner.full_scan()
    print(results)
