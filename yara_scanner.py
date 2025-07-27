import yara
import os
RULES_PATH = os.path.join(os.path.dirname(__file__), 'home/mert/Desktop/antivirus/signatures/yara_rules.yar')

def load_yara_rules(rule_path):
    try:
        rules = yara.compile(filepath=rule_path)
        return rules
    except yara.SyntaxError as e:
        print(f"[!] YARA kural hatası: {e}")
        return None

def scan_yara(filepath):
    try:
        rules = yara.compile(filepath=RULES_PATH)
        matches = rules.match(filepath)
        print(f"Yara matches: {matches}")
        return len(matches) > 0
    except Exception as e:
        print(f"Hata scan_yara fonksiyonunda: {e}")
        return False

def scan_file_with_yara(file_path, rules):
    try:
        matches = rules.match(filepath=file_path)
        if matches:
            print(f"[!] {file_path} dosyası YARA ile eşleşti:")
            for match in matches:
                print(f"    - Kural: {match.rule}")
        else:
            print(f"[+] {file_path} temiz.")
    except Exception as e:
        print(f"[!] Dosya taranamadı: {file_path} - {e}")

def scan_directory_with_yara(directory_path, rules):
    for root, _, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            scan_file_with_yara(full_path, rules)

if __name__ == "__main__":
    RULE_PATH = "../signatures/yara_rules.yar"
    TARGET_PATH = input("Tarama yapılacak dosya/dizin yolu: ").strip()

    if not os.path.exists(TARGET_PATH):
        print("[!] Belirtilen dosya ya da dizin yok.")
        exit(1)

    rules = load_yara_rules(RULE_PATH)
    if rules:
        if os.path.isfile(TARGET_PATH):
            scan_file_with_yara(TARGET_PATH, rules)
        elif os.path.isdir(TARGET_PATH):
            scan_directory_with_yara(TARGET_PATH, rules)
