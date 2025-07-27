import os
import hashlib

def scan_hash(filepath):
    virus_hashes = set()
    try:
        with open("../signatures/virus_hashes.txt", "r") as f:
            for line in f:
                virus_hashes.add(line.strip())
    except FileNotFoundError:
        print("virus_hashes.txt dosyası bulunamadı.")
        return False

    try:
        with open(filepath, "rb") as file:
            file_hash = hashlib.sha256(file.read()).hexdigest()
        return file_hash in virus_hashes
    except Exception as e:
        print(f"Hata scan_hash fonksiyonunda: {e}")
        return False

def calculate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            return hashlib.sha256(content).hexdigest()
    except Exception as e:
        print(f"[ERROR] Cannot hash {file_path}: {e}")
        return None

def load_known_hashes(file_path):
    known_hashes = set()
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    known_hashes.add(line)
    except Exception as e:
        print(f"[ERROR] Could not load known hashes: {e}")
    return known_hashes

def scan_directory(directory, known_hashes):
    print(f"[INFO] Scanning directory: {directory}\n")
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            file_hash = calculate_hash(full_path)
            if file_hash:
                print(f"[SCAN] {file} -> {file_hash}")
                if file_hash in known_hashes:
                    print(f"[ALERT] Virus detected: {file}\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python hash_scanner.py <directory_to_scan>")
        sys.exit(1)
    path = sys.argv[1]
    hashes_path = os.path.join(os.path.dirname(__file__), "..", "signatures", "virus_hashes.txt")
    known_hashes = load_known_hashes(hashes_path)
    if os.path.isdir(path):
        scan_directory(path, known_hashes)
    else:
        print("[ERROR] Invalid directory.")
