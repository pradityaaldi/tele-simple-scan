# Simple Vulnerability Scanner - Telegram Bot

Bot Telegram sederhana untuk melakukan scanning keamanan dasar pada website.

## Fitur

- **Security Headers Scan** - Mengecek HTTP security headers
- **SSL Certificate Scan** - Mengecek validitas sertifikat SSL/TLS
- **Port Scan** - Mengecek port umum yang terbuka

## Cara Membuat Bot Telegram

1. Buka Telegram dan cari **@BotFather**
2. Kirim command `/newbot`
3. Ikuti instruksi untuk memberi nama bot
4. Setelah selesai, BotFather akan memberikan **Bot Token**
5. Simpan token tersebut (jangan share ke siapapun!)

## Instalasi

```bash
# 1. Clone atau masuk ke folder project
cd tele-simple-scan

# 2. Buat virtual environment (opsional tapi recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# atau
venv\Scripts\activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variable untuk bot token
export TELEGRAM_BOT_TOKEN='token_dari_botfather'  # Linux/Mac
# atau
set TELEGRAM_BOT_TOKEN=token_dari_botfather  # Windows

# 5. Jalankan bot
python bot.py
```

## Commands Bot

| Command | Deskripsi |
|---------|-----------|
| `/start` | Memulai bot dan menampilkan bantuan |
| `/scan <url>` | Full scan (headers + SSL + ports) |
| `/headers <url>` | Scan security headers saja |
| `/ssl <url>` | Scan sertifikat SSL saja |
| `/ports <url>` | Scan port terbuka saja |
| `/help` | Menampilkan bantuan |

## Contoh Penggunaan

```
/scan google.com
/headers https://example.com
/ssl github.com
/ports 192.168.1.1
```

## Struktur Project

```
tele-simple-scan/
├── bot.py              # Bot Telegram utama
├── scanner.py          # Modul scanner (OOP)
├── requirements.txt    # Dependencies Python
├── .env.example        # Contoh environment variable
└── README.md           # Dokumentasi
```

## Penjelasan Kode (untuk Tugas Kuliah)

### scanner.py
- `SecurityHeaderScanner` - Class untuk mengecek HTTP security headers
- `SSLScanner` - Class untuk mengecek sertifikat SSL
- `PortScanner` - Class untuk scan port
- `VulnerabilityScanner` - Facade class yang menggabungkan semua scanner

### bot.py
- `TelegramScannerBot` - Class utama yang menangani interaksi Telegram
- Menggunakan library `python-telegram-bot` untuk komunikasi dengan Telegram API
- Setiap command (`/scan`, `/headers`, dll) memiliki handler masing-masing

## Disclaimer

Bot ini dibuat untuk tujuan edukasi. Hanya gunakan untuk scanning website yang kamu miliki atau memiliki izin untuk di-scan.
