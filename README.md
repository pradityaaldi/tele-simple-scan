# Simple Vulnerability Scanner — Telegram Bot

A lightweight Telegram bot that performs basic security scans against any website, directly from a chat. Built with an object-oriented scanner core and the `python-telegram-bot` library.

## Features

- **Security Headers Scan** — inspects HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- **SSL Certificate Scan** — validates the SSL/TLS certificate and its expiry
- **Port Scan** — checks for commonly open ports

## Creating a Telegram Bot

1. Open Telegram and search for **@BotFather**
2. Send the `/newbot` command
3. Follow the prompts to name your bot
4. BotFather returns a **Bot Token**
5. Store the token securely (never share it)

## Installation

```bash
# 1. Clone or enter the project folder
cd tele-simple-scan

# 2. Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate   # Linux/Mac
# or
venv\Scripts\activate      # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set the bot token environment variable
export TELEGRAM_BOT_TOKEN='token_from_botfather'   # Linux/Mac
# or
set TELEGRAM_BOT_TOKEN=token_from_botfather         # Windows

# 5. Run the bot
python bot.py
```

## Bot Commands

| Command          | Description                       |
| ---------------- | -------------------------------- |
| `/start`         | Start the bot and show help      |
| `/scan <url>`    | Full scan (headers + SSL + ports) |
| `/headers <url>` | Scan security headers only       |
| `/ssl <url>`     | Scan the SSL certificate only    |
| `/ports <url>`   | Scan for open ports only         |
| `/help`          | Show help                        |

## Usage Examples

```
/scan google.com
/headers https://example.com
/ssl github.com
/ports 192.168.1.1
```

## Project Structure

```
tele-simple-scan/
├── bot.py              # Main Telegram bot
├── scanner.py          # Scanner modules (OOP)
├── requirements.txt    # Python dependencies
├── .env.example        # Example environment variables
└── README.md           # Documentation
```

## Code Overview

### scanner.py

- `SecurityHeaderScanner` — checks HTTP security headers
- `SSLScanner` — validates the SSL certificate
- `PortScanner` — scans for open ports
- `VulnerabilityScanner` — facade that combines all scanners

### bot.py

- `TelegramScannerBot` — main class handling Telegram interaction
- Uses the `python-telegram-bot` library to talk to the Telegram API
- Each command (`/scan`, `/headers`, …) has its own dedicated handler

## Disclaimer

This bot is built for educational purposes. Only scan websites you own or have explicit permission to test.
