LANGUAGES = {
    "tr": {
        "title": "Pardus Antivirüs",
        "start_realtime": "Gerçek Zamanlı Koruma Başlat",
        "manual_scan": "Manuel Dosya Tara",
        "quit": "Çıkış",
        "threat_count": "Tehdit Sayısı: {}",
        "select_file": "Bir dosya seç",
        "file_clean": "Dosya temiz.",
        "threat_found": "Tehdit bulundu: {}",
        "scanning": "{} taranıyor...",
        "theme_label": "Tema:",
        "language_label": "Dil:",
        "new_file": "Yeni dosya: {}",
        "modified_file": "Değiştirilen dosya: {}",
        "realtime_started": "Gerçek zamanlı koruma başlatıldı.",
        "error_scanning": "Hata taramada: {}",
        "monitoring": "İzleniyor: {}",
        "error_monitoring": "Hata ({}): {}",
        "please_select_file": "Lütfen bir dosya seçin.",
        "theme_changed": "Tema değiştirildi: {}",
        "language_changed": "Dil değiştirildi: {}",
    },
    "en": {
        "title": "Pardus Antivirus",
        "start_realtime": "Start Real-Time Protection",
        "manual_scan": "Manual File Scan",
        "quit": "Quit",
        "threat_count": "Threat Count: {}",
        "select_file": "Select a file",
        "file_clean": "File is clean.",
        "threat_found": "Threat found: {}",
        "scanning": "Scanning {}...",
        "theme_label": "Theme:",
        "language_label": "Language:",
        "new_file": "New file: {}",
        "modified_file": "Modified file: {}",
        "realtime_started": "Real-time protection started.",
        "error_scanning": "Error scanning: {}",
        "monitoring": "Monitoring: {}",
        "error_monitoring": "Error ({}): {}",
        "please_select_file": "Please select a file.",
        "theme_changed": "Theme changed to: {}",
        "language_changed": "Language changed to: {}",
    }
}

current_lang = "en"

def t(key, *args):
    text = LANGUAGES.get(current_lang, {}).get(key, key)
    if args:
        return text.format(*args)
    return text

def set_language(lang_code):
    global current_lang
    if lang_code in LANGUAGES:
        current_lang = lang_code
