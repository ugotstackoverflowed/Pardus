import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanner.hash_scanner import scan_hash
from scanner.yara_scanner import scan_yara

class RealtimeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"Yeni dosya oluşturuldu: {event.src_path}")
            self.scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"Dosya değişti: {event.src_path}")
            self.scan_file(event.src_path)

    def scan_file(self, filepath):
        try:
            if scan_hash(filepath):
                print(f"[HASH] Tehdit bulundu: {filepath}")
            if scan_yara(filepath):
                print(f"[YARA] Tehdit bulundu: {filepath}")
        except Exception as e:
            print(f"Hata taramada: {e}")

def monitor_multiple(paths):
    event_handler = RealtimeHandler()
    observer = Observer()
    for path in paths:
        print(f"İzleme başlatıldı: {path}")
        observer.schedule(event_handler, path=path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("İzleme durduruldu.")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    paths_to_watch = ["/home", "/root", "/tmp", "/var/tmp"]
    monitor_multiple(paths_to_watch)
