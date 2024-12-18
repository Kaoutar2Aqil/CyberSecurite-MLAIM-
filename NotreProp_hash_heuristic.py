import os
import re
import hashlib
import magic
import csv
import time
from concurrent.futures import ThreadPoolExecutor

# Variables globales
total_files = 0
infected_files = 0
infected_file_paths = []

# Liste des chaînes suspectes
SUSPICIOUS_STRINGS = [
    "os.system", "subprocess", "shutil", "chmod", "chown", "sudo", 
    "setuid", "setgid", "privilege escalation", "delete", "write", "open", 
    "os.remove", "os.rename", "shutil.rmtree",
    "socket", "requests", "urllib", "ftplib", "paramiko", "telnetlib", 
    "ftp", "http", "dns", "reverse shell", "bind shell", "payload", "callback",
    "base64", "binascii", "encode", "decode", "marshal", "rot13", "hex", 
    "hashlib", "md5", "sha1", "sha256", "cryptography", "rsa", "aes", "fernet",
    "psutil", "threading", "multiprocessing", "os.kill", "signal", 
    "getpid", "process", "threads", "memory", "cpu", "disk",
    "trojan", "virus", "malware", "worm", "botnet", "exploit", "backdoor", 
    "keylogger", "spyware", "ransomware", "ddos", "phishing", "inject", 
    "dump", "bind", "scan", "attack", "bypass", "breach",
    "autorun", "startup", "registry", "schedule task", "cron", "boot",
    "password", "login", "credential", "session", "cookie", "token", 
    "key", "send", "upload", "exfil", "post", "curl", "wget"
]

# Fonction pour analyser un fichier pour les chaînes suspectes
def check_suspicious_strings(file_path):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            for s in SUSPICIOUS_STRINGS:
                if re.search(s, content, re.IGNORECASE):
                    return True
    except Exception as e:
        print(f"Erreur lors de l'ouverture du fichier {file_path}: {e}")
    return False

# Fonction pour calculer le hash MD5 d'un fichier
def compute_md5(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            data = f.read(4194304)  # Lire par morceaux (4 Mo)
            while data:
                hasher.update(data)
                data = f.read(4194304)
    except (PermissionError, FileNotFoundError):
        pass
    return hasher.hexdigest()

# Fonction pour charger la base de données de signatures
def load_dataset(dataset_file):
    dataset = set()
    try:
        if dataset_file.endswith('.csv'):
            with open(dataset_file, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if 'hash' in row:
                        dataset.add(row['hash'])
                    elif 'md5' in row:
                        dataset.add(row['md5'])
        elif dataset_file.endswith('.txt'):
            with open(dataset_file, 'r') as file:
                for line in file:
                    signature = line.strip()
                    if signature:
                        dataset.add(signature)
        else:
            print(f"Error: Unsupported file format '{dataset_file}'. Only CSV and TXT files are supported.")
            return None
    except FileNotFoundError:
        print(f"Error: The signature file '{dataset_file}' was not found.")
        return None
    return dataset

# Fonction pour comparer un hash MD5 avec la base de données
def compare_md5_with_dataset(file_md5, dataset):
    return file_md5 in dataset

# Fonction pour vérifier la taille du fichier (taille anormale pouvant signaler une menace)
def check_file_size(file_path, max_size=10 * 1024 * 1024):
    """Vérifie si la taille du fichier est anormalement grande."""
    try:
        file_size = os.path.getsize(file_path)
        return file_size > max_size 
    except Exception as e:
        print(f"Erreur lors de la récupération de la taille du fichier {file_path}: {e}")
        return False

# Fonction pour vérifier les extensions suspectes
def load_suspicious_extensions(file_path):
    """Charge les extensions suspectes à partir d'un fichier texte."""
    try:
        with open(file_path, 'r') as f:
            extensions = [f".{line.strip().lower()}" for line in f.readlines() if line.strip()]
        return extensions
    except Exception as e:
        print(f"Erreur lors du chargement des extensions depuis le fichier {file_path}: {e}")
        return []

def check_file_extension(file_path, suspicious_extensions_file="extensions.txt"):
    """Vérifie si l'extension du fichier est suspecte."""
    suspicious_extensions = load_suspicious_extensions(suspicious_extensions_file)
    _, extension = os.path.splitext(file_path)
    return extension.lower() in suspicious_extensions

# Fonction pour vérifier le type MIME réel d'un fichier
def get_file_type(file_path):
    """Retourne le type MIME réel d'un fichier en utilisant la bibliothèque python-magic."""
    try:
        file_type = magic.from_file(file_path, mime=True)
        return file_type
    except Exception as e:
        print(f"Erreur lors de la détection du type de fichier {file_path}: {e}")
        return None

# Fonction principale d'analyse heuristique et par hash
def analyze_file(file_path, dataset):
    print(f"Analyse du fichier : {file_path}")

    # Vérification des chaînes suspectes
    if check_suspicious_strings(file_path):
        print(f"Suspicion: Chaînes suspectes trouvées dans {file_path}")

    # Vérification du hash MD5 avec la base de données
    file_md5 = compute_md5(file_path)
    if compare_md5_with_dataset(file_md5, dataset):
        global infected_files
        infected_files += 1
        infected_file_paths.append(file_path)
        print(f"Suspicion: Fichier infecté détecté (MD5 match) : {file_path}")

    # Vérification de la taille du fichier
    if check_file_size(file_path):
        print(f"Suspicion: Taille du fichier anormalement grande pour {file_path}")

    # Vérification de l'extension du fichier
    if check_file_extension(file_path):
        print(f"Suspicion: Extension suspecte pour {file_path}")

    # Vérification du type MIME du fichier
    file_type = get_file_type(file_path)
    if file_type and file_type not in ["text/plain", "image/jpeg", "image/png", "application/pdf"]:
        print(f"Suspicion: Type MIME suspect pour {file_path}")

# Fonction pour scanner un répertoire avec la détection par hash et heuristique
def scan_directory(directory, dataset_file):
    global total_files, infected_files, infected_file_paths

    dataset = load_dataset(dataset_file)
    if dataset is None:
        return

    file_list = []
    for root_dir, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root_dir, file)
            file_list.append(file_path)

    total_files = len(file_list)

    num_threads = os.cpu_count() * 2
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        executor.map(lambda f: analyze_file(f, dataset), file_list)

# Fonction pour afficher et sauvegarder les résultats
def save_scan_results(start_time, output_file="scan_report.txt"):
    duration = time.time() - start_time
    results = [
        "\nScan terminé !",
        f"Total de fichiers scannés : {total_files}",
        f"Fichiers infectés : {infected_files}",
    ]
    if infected_file_paths:
        results.append("Fichiers infectés trouvés :")
        results.extend([f" - {path}" for path in infected_file_paths])
    results.append(f"Durée du scan : {duration:.2f} secondes")

    # Affichage des résultats
    print("\n".join(results))

    # Sauvegarde des résultats dans un fichier
    with open(output_file, 'w') as f:
        f.write("\n".join(results))
    print(f"\nRapport sauvegardé dans : {output_file}")

# Exemple d'utilisation
if __name__ == "__main__":
    start_time = time.time()

    directory_to_scan = r"C:\Users\kaout\Documents\CyberS"
    dataset_file = r"C:\Users\kaout\Documents\CyberS\activite\signature.txt"

    print("Démarrage du scan...")
    scan_directory(directory_to_scan, dataset_file)
    save_scan_results(start_time)
