# Pardus Antivirus Project

This is a Python-based antivirus project developed for **Teknofest 2025 – Pardus / Bug-Fix and Development** category. Our goal is to create an open-source, modular, and customizable antivirus engine designed to run on Pardus Linux systems.

## 🚀 Features

- File hash scanning (MD5 / SHA256)
- YARA rule-based signature scanning
- Real-time filesystem monitoring (via Watchdog)
- API integration (e.g., VirusTotal)
- Command-line interface (CLI)
- Modular and extensible architecture

## 🛠 Installation

Requires Python 3.10+ and `pip`.

```bash
# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
