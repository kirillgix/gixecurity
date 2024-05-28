import os
import shutil
import subprocess
from typing import Set
import yara
import send2trash
import psutil



whitelist_file = "log/whitelist.txt"


def create_whitelist_file():
    os.makedirs(os.path.dirname(whitelist_file), exist_ok=True)
    if not os.path.exists(whitelist_file):
        with open(whitelist_file, 'w'):
            pass


def write_to_whitelist(file_path):
    create_whitelist_file()
    with open(whitelist_file, 'a') as f:
        f.write(file_path + '\n')
    print(f"File added to whitelist: {file_path}")


def load_whitelist() -> Set[str]:
    whitelist = set()
    if os.path.exists(whitelist_file):
        with open(whitelist_file, 'r') as f:
            for line in f:
                whitelist.add(line.strip())
    return whitelist


def scan_file(file_path, yara_rules):
    try:
        matches = yara_rules.match(file_path)
        if matches:
            print(f"POSSIBLE MALWARE DETECTED: {matches} in {file_path}")
            return True
    except yara.Error as e:
        print(f"SOURCE FILE ERROR {file_path}: {e}")
    return False


def terminate_processes(file_path):
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.exe() == file_path:
                print(f"Terminating process: {proc.name()} (PID: {proc.pid})")
                proc.terminate()
                proc.wait(timeout=3)
                if proc.is_running():
                    print(f"Forcefully killing process: {proc.name()} (PID: {proc.pid})")
                    proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def delete_malicious_file(file_path):
    user_input = input(f"Do you want to remove the malicious file {file_path}? [y/n] ")
    if user_input.lower() == 'y':
        try:
            terminate_processes(file_path)

            if os.path.isdir(file_path):
                shutil.rmtree(file_path, ignore_errors=True)
            else:
                os.remove(file_path)

            print(f"Malicious file removed: {file_path}")
        except Exception as e:
            print(f"ERROR REMOVING MALICIOUS FILE {file_path}: {e}")
    else:
        print("Malicious file was not removed.")


def scan_directory(directory_to_scan, yara_rules):
    print(f"Start scanning directory: {directory_to_scan}")
    whitelist = load_whitelist()
    for root, dirs, files in os.walk(directory_to_scan):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning: {file_path}")
            if file_path in whitelist:
                print(f"File {file_path} is in whitelist. [SKIPPING]")
                continue
            if scan_file(file_path, yara_rules):
                delete_malicious_file(file_path)
    print("Scanning is complete.")


def empty_recycle_bin():
    try:
        subprocess.run(['gio', 'trash', '--empty'], check=True)
        print("The recycle bin has been emptied.")
    except subprocess.CalledProcessError as e:
        print(f"ERROR EMPTYING RECYCLE BIN: {e}")



def main():
    print("Welcome to gixecurity!\nTo the world of control and security, scan your system for malware, trackers and vulnerabilities\nWe will make your device more secure and anonymous\n\noptions:\n{./path/to/directory} - specify the path to the directory you want to scan.")
    try:
        scan_path = 'rules/scan_rules.yar'
        yara_rules = yara.compile(filepath=scan_path)
        while True:
            directory_to_scan = input("\nEnter directory to scan: ")
            print("\nStart scanning...\n")
            create_whitelist_file()
            scan_directory(directory_to_scan, yara_rules)
            empty_recycle_bin()
            print("\n\nScanning is complete.")
    except yara.SyntaxError as e:
       print(f"YARA Syntax Error: {e}")
    except yara.WarningError as e:
        print(f"YARA Warning Error: {e}")
    except yara.Error as e:
        print(f"YARA General Error: {e}")



if __name__ == "__main__":
    main()

