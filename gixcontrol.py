import os
import queue
import time
from datetime import datetime
import threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class MyHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_modification_times = {}
        self.packet_queue = queue.Queue()

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if os.path.exists(file_path):
                try:
                    modification_time = os.path.getmtime(file_path)
                    self.last_modification_times[file_path] = modification_time
                    print(f'{datetime.now().strftime("%H:%M:%S")} | Modified: {file_path} [Modified]')
                except FileNotFoundError:
                    pass
            else:
                print(f'{datetime.now().strftime("%H:%M:%S")} | File not found: {file_path}')

    def on_moved(self, event):
        if not event.is_directory:
            print(f'{datetime.now().strftime("%H:%M:%S")} | Moved: {event.src_path} to {event.dest_path} [Moved]')

    def on_deleted(self, event):
        if not event.is_directory:
            print(f'{datetime.now().strftime("%H:%M:%S")} | Deleted: {event.src_path} [Deleted]')

    def on_created(self, event):
        if not event.is_directory:
            print(f'{datetime.now().strftime("%H:%M:%S")} | Downloaded: {event.src_path} [Downloaded]')

    @staticmethod
    def display_new_cpu_processes():
        prev_processes = set(psutil.pids())

        while True:
            time.sleep(1)

            new_processes = set(psutil.pids()) - prev_processes
            prev_processes |= new_processes

            for pid in new_processes:
                try:
                    process = psutil.Process(pid)
                    print(f'{datetime.now().strftime("%H:%M:%S")} | NEW CPU Process: {process.name()} ({process.cpu_percent()}%) [PID: {pid}]')
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

    @staticmethod
    def display_new_ram_processes():
        prev_processes = set(psutil.pids())

        while True:
            time.sleep(1)

            new_processes = set(psutil.pids()) - prev_processes
            prev_processes |= new_processes

            for pid in new_processes:
                try:
                    process = psutil.Process(pid)
                    print(f'{datetime.now().strftime("%H:%M:%S")} | NEW RAM Process: {process.name()} ({process.memory_info().rss / (1024 * 1024)} MB) [PID: {pid}]')
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

    @staticmethod
    def track_open_files():
        prev_open_files = {}

        while True:
            time.sleep(1)
            current_open_files = {}

            for process in psutil.process_iter(['pid', 'name']):
                try:
                    for file_info in process.open_files():
                        current_open_files[file_info.path] = process.info['name']
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            new_open_files = set(current_open_files.keys()) - set(prev_open_files.keys())
            closed_files = set(prev_open_files.keys()) - set(current_open_files.keys())

            for file in new_open_files:
                print(f'{datetime.now().strftime("%H:%M:%S")} | Opened: {file} [by: {current_open_files[file]}]')

            for file in closed_files:
                print(f'{datetime.now().strftime("%H:%M:%S")} | Closed: {file} [by: {prev_open_files[file]}]')

            prev_open_files = current_open_files


def monitor_directory(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"The directory '{path}' does not exist.")

    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    cpu_processes_thread = threading.Thread(target=event_handler.display_new_cpu_processes)
    cpu_processes_thread.start()

    ram_processes_thread = threading.Thread(target=event_handler.display_new_ram_processes)
    ram_processes_thread.start()

    open_files_thread = threading.Thread(target=event_handler.track_open_files)
    open_files_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        cpu_processes_thread.join()
        ram_processes_thread.join()
        open_files_thread.join()
    observer.join()


if __name__ == "__main__":
    path_to_monitor = '/home'
    monitor_directory(path_to_monitor)
