import os
import hashlib
import csv
import time
from concurrent.futures import ThreadPoolExecutor
import sys

# Variables globales
total_files = 0
infected_files = 0
infected_file_paths = []

# Liste des chaînes suspectes pour l'analyse heuristique
SUSPICIOUS_STRINGS = [ "virus", "vers", "trojan", "malware", "hack", "payload", "exploit", 
    "ransomware", "ddos", "botnet", "attack", "inject", "backdoor"]
SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".vbs", ".scr", ".com"]
SAFE_EXTENSIONS = [".txt", ".pdf", ".jpg", ".png", ".docx", ".xlsx"]


# Fonction pour calculer le hash MD5 d'un fichier
def compute_md5(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            data = f.read(4096)  # Lire par morceaux (4 Ko)
            while data:
                hasher.update(data)
                data = f.read(4096)
    except (PermissionError, FileNotFoundError):
        pass  # Ignorer les fichiers auxquels l'accès est refusé ou qui n'existent pas
    return hasher.hexdigest()

def load_dataset(dataset_file):
    dataset = set()
    
    try:
        # Handle CSV files with 'hash' or 'md5' columns
        if dataset_file.endswith('.csv'):
            with open(dataset_file, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                # Check if the CSV file has a 'hash' or 'md5' column
                for row in reader:
                    if 'hash' in row:
                        dataset.add(row['hash'])  # Add hash from 'hash' column
                    elif 'md5' in row:
                        dataset.add(row['md5'])  # Add hash from 'md5' column
                    else:
                        print("Warning: Neither 'hash' nor 'md5' column found.")
        # Handle plain text files with raw signatures
        elif dataset_file.endswith('.txt'):
            with open(dataset_file, 'r') as file:
                for line in file:
                    signature = line.strip()  # Remove extra spaces or newline characters
                    if signature:  # Ensure the line isn't empty
                        dataset.add(signature)
        else:
            print(f"Error: Unsupported file format '{dataset_file}'. Only CSV and TXT files are supported.")
            sys.exit(1)
        
    except FileNotFoundError:
        print(f"Error: The signature file '{dataset_file}' was not found.")
        sys.exit(1)

    return dataset

# Fonction pour comparer un hash MD5 avec la base de données de signatures
def compare_md5_with_dataset(file_md5, dataset):
    return file_md5 in dataset


# Fonction pour l'analyse heuristique (extensions, chaînes suspectes)
def check_suspicious(file_path):
    # Vérification de l'extension
    _, extension = os.path.splitext(file_path)
    if extension.lower() in SUSPICIOUS_EXTENSIONS:
        return True

    # Vérification des chaînes suspectes dans le contenu du fichier
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            if any(s in content for s in SUSPICIOUS_STRINGS):
                return True
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier {file_path}: {e}")

    return False


# Fonction pour scanner un fichier en utilisant à la fois les signatures (MD5) et l'analyse heuristique
def scan_single_file(file_path, dataset):
    global infected_files

    # Calcul du hachage MD5 du fichier
    file_md5 = compute_md5(file_path)

    # Vérification des signatures de malwares
    if compare_md5_with_dataset(file_md5, dataset):
        infected_files += 1
        infected_file_paths.append(file_path)
        return

    # Analyse heuristique
    if check_suspicious(file_path):
        infected_files += 1
        infected_file_paths.append(file_path)


# Fonction pour scanner un répertoire
def scan_directory(directory, dataset_file):
    global total_files, infected_files, infected_file_paths

    dataset = load_dataset(dataset_file)
    file_list = []

    # Collecte des fichiers à scanner
    for root_dir, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root_dir, file)
            file_list.append(file_path)

    total_files = len(file_list)

    # Scanner les fichiers avec multi-threading
    num_threads = os.cpu_count() * 2
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        executor.map(lambda f: scan_single_file(f, dataset), file_list)


# Fonction pour afficher et sauvegarder les résultats du scan
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

    # Afficher les résultats
    print("\n".join(results))
    
    # Sauvegarder les résultats dans un fichier
    with open(output_file, 'w') as f:
        f.write("\n".join(results))
    print(f"\nRapport sauvegardé dans : {output_file}")


# Exemple d'utilisation
if __name__ == "__main__":
    start_time = time.time()

    directory_to_scan = r"C:\Users\kaout\Documents\CyberS\tp5"
    dataset_file = r"C:\Users\kaout\Downloads\malware.csv"

    print("Démarrage du scan...")
    scan_directory(directory_to_scan, dataset_file)
    save_scan_results(start_time)
