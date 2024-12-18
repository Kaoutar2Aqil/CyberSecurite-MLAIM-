import os
import re

# Liste des chaînes suspectes à rechercher dans les fichiers
SUSPICIOUS_STRINGS = [
    "virus", "vers", "trojan", "malware", "hack", "payload", "exploit", 
    "ransomware", "ddos", "botnet", "attack", "inject", "backdoor"
]
# Fonction pour analyser le contenu d'un fichier
def check_suspicious_strings(file_path, suspicious_strings=None):
    """Vérifie la présence de chaînes suspectes dans le contenu du fichier."""
    if suspicious_strings is None:
        suspicious_strings = SUSPICIOUS_STRINGS
    
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            # Recherche de chaque chaîne suspecte dans le fichier
            for s in suspicious_strings:
                if re.search(s, content, re.IGNORECASE):
                    return True
    except Exception as e:
        print(f"Erreur lors de l'ouverture du fichier {file_path}: {e}")
    return False

# Fonction pour analyser la taille du fichier (taille anormale pouvant signaler une menace)
def check_file_size(file_path, max_size=10 * 1024 * 1024):
    """Vérifie si la taille du fichier est anormalement grande."""
    try:
        file_size = os.path.getsize(file_path)
        return file_size > max_size
    except Exception as e:
        print(f"Erreur lors de la récupération de la taille du fichier {file_path}: {e}")
        return False

# Fonction pour vérifier les extensions suspectes
def check_file_extension(file_path):
    """Vérifie si l'extension du fichier est suspecte."""
    suspicious_extensions = [".exe", ".bat", ".vbs", ".com", ".scr", ".js", ".dll"]
    _, extension = os.path.splitext(file_path)
    return extension.lower() in suspicious_extensions

# Fonction pour vérifier le type MIME réel d'un fichier
import magic  # Installer python-magic: pip install python-magic
def get_file_type(file_path):
    """Retourne le type MIME réel d'un fichier en utilisant la bibliothèque python-magic."""
    try:
        file_type = magic.from_file(file_path, mime=True)
        return file_type
    except Exception as e:
        print(f"Erreur lors de la détection du type de fichier {file_path}: {e}")
        return None

# Fonction principale d'analyse heuristique
def analyze_file(file_path):
    """Effectue une analyse heuristique d'un fichier."""
    print(f"Analyse du fichier : {file_path}")

    # Vérification de l'extension suspecte
    if check_file_extension(file_path):
        print(f"Suspicion: Extension suspecte pour {file_path}")

    # Vérification de la taille du fichier
    if check_file_size(file_path):
        print(f"Suspicion: Taille du fichier anormalement grande pour {file_path}")

    # Vérification de chaînes suspectes dans le contenu du fichier
    if check_suspicious_strings(file_path):
        print(f"Suspicion: Chaînes suspectes trouvées dans {file_path}")

    # Vérification du type MIME du fichier
    file_type = get_file_type(file_path)
    if file_type and file_type not in ["text/plain", "image/jpeg", "image/png", "application/pdf"]:
        print(f"Suspicion: suspect détecté ")
    else:
        print(f"Le fichier semble inoffensif d'un point de vue heuristique.")

# Fonction pour analyser un répertoire
def scan_directory(directory_path):
    """Scanner un répertoire et analyser tous les fichiers qu'il contient."""
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            analyze_file(file_path)

# Exemple d'utilisation
if __name__ == "__main__":
    directory_to_scan = r"C:\Users\kaout\Documents\CyberS\tp5"  # Remplacer par votre répertoire
    scan_directory(directory_to_scan)