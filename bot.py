"""
bot.py - Bot Telegram untuk Simple Vulnerability Scanner

Bot ini menyediakan interface Telegram untuk melakukan scanning
keamanan sederhana pada website.

Commands yang tersedia:
- /start - Memulai bot dan menampilkan bantuan
- /scan <url> - Melakukan full scan pada website
- /headers <url> - Scan security headers saja
- /ssl <url> - Scan sertifikat SSL saja
- /ports <url> - Scan port terbuka saja
- /help - Menampilkan bantuan
"""

import os
import asyncio
import logging
from dotenv import load_dotenv
from telegram import Update

# Load environment variables dari file .env
load_dotenv()
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes
)

# Import class scanner dari modul scanner.py
from scanner import VulnerabilityScanner

# Setup logging untuk debugging
# Level INFO akan menampilkan informasi penting saat bot berjalan
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


class TelegramScannerBot:
    """
    Class utama untuk Telegram Bot.

    Class ini menangani semua interaksi dengan Telegram API
    dan menghubungkannya dengan VulnerabilityScanner.
    """

    def __init__(self, token: str):
        """
        Constructor - Inisialisasi bot dengan token.

        Args:
            token: Bot token dari BotFather
        """
        self.token = token
        # Application adalah class utama dari python-telegram-bot
        self.app = Application.builder().token(token).build()

        # Daftarkan semua command handlers
        self._register_handlers()

    def _register_handlers(self):
        """
        Mendaftarkan semua command handlers ke bot.

        Handler adalah fungsi yang dipanggil ketika user
        mengirim command tertentu.
        """
        # Setiap CommandHandler menghubungkan command dengan fungsi
        self.app.add_handler(CommandHandler("start", self.start_command))
        self.app.add_handler(CommandHandler("help", self.help_command))
        self.app.add_handler(CommandHandler("scan", self.scan_command))
        self.app.add_handler(CommandHandler("headers", self.headers_command))
        self.app.add_handler(CommandHandler("ssl", self.ssl_command))
        self.app.add_handler(CommandHandler("ports", self.ports_command))

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """
        Handler untuk command /start.

        Dipanggil ketika user pertama kali memulai bot
        atau mengirim command /start.
        """
        welcome_message = """
🔍 *Simple Vulnerability Scanner Bot*

Selamat datang! Bot ini dapat membantu kamu melakukan scanning keamanan sederhana pada website.

*Commands yang tersedia:*
• /scan <url> - Full scan (headers + SSL + ports)
• /headers <url> - Scan security headers
• /ssl <url> - Scan sertifikat SSL
• /ports <url> - Scan port terbuka

*Contoh:*
`/scan example.com`
`/headers https://google.com`

⚠️ *Disclaimer:* Gunakan bot ini hanya untuk website yang kamu miliki atau memiliki izin untuk di-scan.
        """
        # parse_mode='Markdown' memungkinkan formatting teks
        await update.message.reply_text(welcome_message, parse_mode='Markdown')

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /help."""
        # Sama dengan start untuk kesederhanaan
        await self.start_command(update, context)

    def _get_url_from_args(self, context: ContextTypes.DEFAULT_TYPE) -> str | None:
        """
        Helper method untuk mengambil URL dari argumen command.

        Args:
            context: Context dari telegram yang berisi argumen

        Returns:
            URL jika ada, None jika tidak ada
        """
        # context.args berisi list kata setelah command
        # Contoh: "/scan example.com" -> args = ["example.com"]
        if context.args and len(context.args) > 0:
            return context.args[0]
        return None

    def _format_header_results(self, results: dict) -> str:
        """
        Format hasil scan headers menjadi pesan yang mudah dibaca.

        Args:
            results: Dictionary hasil scan headers

        Returns:
            String pesan terformat
        """
        if 'error' in results:
            return f"❌ Error: {results['error']}"

        message = "🔒 *Security Headers Scan*\n\n"

        for header, data in results.items():
            if data['status'] == 'FOUND':
                # ✅ Header ditemukan
                message += f"✅ *{header}*\n"
                message += f"   └ {data['description']}\n\n"
            else:
                # ❌ Header tidak ditemukan
                message += f"❌ *{header}* (MISSING)\n"
                message += f"   └ {data['description']}\n\n"

        return message

    def _format_ssl_results(self, results: dict) -> str:
        """
        Format hasil scan SSL menjadi pesan yang mudah dibaca.
        """
        if results.get('status') in ['SSL_ERROR', 'CONNECTION_ERROR', 'ERROR']:
            return f"❌ SSL Error: {results.get('error', 'Unknown error')}"

        message = "🔐 *SSL Certificate Scan*\n\n"

        if results.get('status') == 'VALID':
            message += f"✅ Status: Valid\n"
            message += f"📜 Issuer: {results['issuer'].get('organizationName', 'N/A')}\n"
            message += f"🌐 Subject: {results['subject'].get('commonName', 'N/A')}\n"
            message += f"📅 Expires: {results['expire_date']}\n"
            message += f"⏳ Days Left: {results['days_until_expire']} hari\n"
            message += f"🔒 TLS Version: {results['version']}\n"

            if 'warning' in results:
                message += f"\n⚠️ {results['warning']}"

        return message

    def _format_port_results(self, results: dict) -> str:
        """
        Format hasil scan ports menjadi pesan yang mudah dibaca.
        """
        message = f"🔌 *Port Scan - {results['hostname']}*\n\n"

        if results['open_ports']:
            message += "*Port Terbuka:*\n"
            for port_info in results['open_ports']:
                message += f"  🟢 {port_info['port']} - {port_info['service']}\n"
        else:
            message += "✅ Tidak ada port umum yang terbuka\n"

        message += f"\n📊 Total: {len(results['open_ports'])} port terbuka"

        return message

    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """
        Handler untuk command /scan - Full scan.

        Melakukan scan lengkap: headers, SSL, dan ports.
        """
        url = self._get_url_from_args(context)

        if not url:
            await update.message.reply_text(
                "❌ Mohon masukkan URL.\nContoh: `/scan example.com`",
                parse_mode='Markdown'
            )
            return

        # Kirim pesan "sedang scanning" karena proses bisa memakan waktu
        status_msg = await update.message.reply_text(
            f"🔍 Scanning {url}...\nMohon tunggu, ini mungkin memakan waktu beberapa detik."
        )

        try:
            # Buat instance scanner dan jalankan full scan
            scanner = VulnerabilityScanner(url)
            results = scanner.full_scan()

            # Format dan kirim hasil
            header_msg = self._format_header_results(results['security_headers'])
            ssl_msg = self._format_ssl_results(results['ssl_certificate'])
            port_msg = self._format_port_results(results['port_scan'])

            # Hapus pesan status
            await status_msg.delete()

            # Kirim hasil dalam beberapa pesan terpisah
            await update.message.reply_text(header_msg, parse_mode='Markdown')
            await update.message.reply_text(ssl_msg, parse_mode='Markdown')
            await update.message.reply_text(port_msg, parse_mode='Markdown')

        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
            await status_msg.edit_text(f"❌ Error: {str(e)}")

    async def headers_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /headers - Scan headers saja."""
        url = self._get_url_from_args(context)

        if not url:
            await update.message.reply_text(
                "❌ Mohon masukkan URL.\nContoh: `/headers example.com`",
                parse_mode='Markdown'
            )
            return

        status_msg = await update.message.reply_text(f"🔍 Scanning headers {url}...")

        try:
            scanner = VulnerabilityScanner(url)
            results = scanner.scan_headers()
            message = self._format_header_results(results)

            await status_msg.delete()
            await update.message.reply_text(message, parse_mode='Markdown')

        except Exception as e:
            await status_msg.edit_text(f"❌ Error: {str(e)}")

    async def ssl_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /ssl - Scan SSL saja."""
        url = self._get_url_from_args(context)

        if not url:
            await update.message.reply_text(
                "❌ Mohon masukkan URL.\nContoh: `/ssl example.com`",
                parse_mode='Markdown'
            )
            return

        status_msg = await update.message.reply_text(f"🔍 Scanning SSL {url}...")

        try:
            scanner = VulnerabilityScanner(url)
            results = scanner.scan_ssl()
            message = self._format_ssl_results(results)

            await status_msg.delete()
            await update.message.reply_text(message, parse_mode='Markdown')

        except Exception as e:
            await status_msg.edit_text(f"❌ Error: {str(e)}")

    async def ports_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /ports - Scan ports saja."""
        url = self._get_url_from_args(context)

        if not url:
            await update.message.reply_text(
                "❌ Mohon masukkan URL.\nContoh: `/ports example.com`",
                parse_mode='Markdown'
            )
            return

        status_msg = await update.message.reply_text(
            f"🔍 Scanning ports {url}...\nIni mungkin memakan waktu agak lama."
        )

        try:
            scanner = VulnerabilityScanner(url)
            results = scanner.scan_ports()
            message = self._format_port_results(results)

            await status_msg.delete()
            await update.message.reply_text(message, parse_mode='Markdown')

        except Exception as e:
            await status_msg.edit_text(f"❌ Error: {str(e)}")

    async def start(self):
        """
        Menjalankan bot secara async.

        Method ini akan terus berjalan dan mendengarkan
        pesan dari Telegram sampai dihentikan (Ctrl+C).
        """
        logger.info("Bot starting...")
        # Initialize dan start polling
        await self.app.initialize()
        await self.app.start()
        await self.app.updater.start_polling(allowed_updates=Update.ALL_TYPES)

        # Keep running sampai dihentikan
        logger.info("Bot is running. Press Ctrl+C to stop.")
        try:
            # Buat event yang tidak pernah selesai untuk keep alive
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            pass
        finally:
            # Cleanup saat bot dihentikan
            await self.app.updater.stop()
            await self.app.stop()
            await self.app.shutdown()

    def run(self):
        """Wrapper untuk menjalankan bot dengan asyncio."""
        asyncio.run(self.start())


# Entry point - kode yang dijalankan saat file ini dieksekusi
if __name__ == '__main__':
    # Ambil token dari environment variable
    # Ini lebih aman daripada hardcode token di kode
    BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

    if not BOT_TOKEN:
        print("❌ Error: TELEGRAM_BOT_TOKEN tidak ditemukan!")
        print("Silakan set environment variable TELEGRAM_BOT_TOKEN")
        print("Contoh: export TELEGRAM_BOT_TOKEN='your_token_here'")
        exit(1)

    # Buat instance bot dan jalankan
    bot = TelegramScannerBot(BOT_TOKEN)
    bot.run()
