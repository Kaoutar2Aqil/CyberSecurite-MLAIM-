import os
import hashlib
import csv
from concurrent.futures import ThreadPoolExecutor
import time
import sys

# Variables globales
total_files = 0
infected_files = 0
infected_file_paths = []

# Fonction pour calculer le hash MD5 d'un fichier
def compute_md5(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            data = f.read(4194304)  # Lire le fichier par morceaux (4 Mo)
            while data:
                hasher.update(data)
                data = f.read(4194304)
    except (PermissionError, FileNotFoundError):
        pass  # Ignorer les fichiers auxquels l'accès est refusé ou qui n'existent pas
    return hasher.hexdigest()

# Fonction pour charger la base de données de signatures
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

# Fonction pour comparer un hash MD5 avec la base de données
def compare_md5_with_dataset(file_md5, dataset):
    return file_md5 in dataset

# Fonction pour scanner un fichier
def scan_single_file(file_path, dataset):
    global infected_files

    file_md5 = compute_md5(file_path)
    if compare_md5_with_dataset(file_md5, dataset):
        infected_files += 1
        infected_file_paths.append(file_path)

# Fonction pour scanner un répertoire
def scan_directory(directory, dataset_file):
    global total_files, infected_files, infected_file_paths

    dataset = load_dataset(dataset_file)
    file_list = []

    # Collecte des fichiers
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
def save_scan_results(start_time, output_file=r"C:\Users\kaout\Documents\CyberS\Mini-projet\scan_report.txt"):
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

    directory_to_scan = r"C:\Users\kaout\Documents\CyberS"
    dataset_file = r"C:\Users\kaout\Documents\CyberS\activite\signature.txt"

    print("Démarrage du scan...")
    scan_directory(directory_to_scan, dataset_file)
    save_scan_results(start_time)
