from scapy.all import *
import time
from collections import defaultdict
import os

# Dictionnaire pour suivre le nombre de paquets par adresse IP source
ip_count = defaultdict(int)
threshold = 50 # Seuil de paquets autorisés par adresse IP
blocked_ips = set()  # JHEW- Ensemble des IPs bloquées

# Fonction de traitement des paquets
def packet_callback(packet):
    # Vérifier si le paquet est un paquet IP
    if packet.haslayer(IP):
        ip_src = packet[IP].src  # Adresse IP source
        ip_dst = packet[IP].dst  # Adresse IP destination
        protocol = packet[IP].proto  # Protocole (TCP, UDP, etc.)

        # Si l'adresse IP source est déjà bloquée, ignorer ce paquet
        if ip_src in blocked_ips:
            print(f"Paquet de {ip_src} ignoré (bloqué).")
            return

        # Afficher les informations sur le paquet
        print(f"Packet capturé: {time.ctime()} | {ip_src} -> {ip_dst} | Protocole: {protocol}")
        
        # Vérifier le nombre de paquets venant de l'adresse IP source
        ip_count[ip_src] += 1
        if ip_count[ip_src] > threshold:
            print(f"ALERTE: Adresse IP {ip_src} a dépassé le seuil de {threshold} paquets!")
            # Ajouter l'adresse IP à la liste des IPs bloquées
            blocked_ips.add(ip_src)
            # Optionnel : Vous pouvez aussi exécuter une commande pour bloquer l'IP via un pare-feu (ex. iptables)
            block_ip(ip_src)

        # Si c'est un paquet TCP, afficher des informations supplémentaires
        if packet.haslayer(TCP):
            sport = packet[TCP].sport  # Port source
            dport = packet[TCP].dport  # Port destination
            print(f"  [TCP] Source port: {sport}, Destination port: {dport}")
        
        # Si c'est un paquet UDP, afficher des informations supplémentaires
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport  # Port source
            dport = packet[UDP].dport  # Port destination
            print(f"  [UDP] Source port: {sport}, Destination port: {dport}")

# Fonction pour bloquer une adresse IP (utilisation de `iptables` sous Linux)
def block_ip(ip_address):
    # Exécuter une commande système pour bloquer l'IP via iptables (exclusivement sur un système Linux)
    print(f"Blocage de l'IP: {ip_address}...")
    os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
    # Assurez-vous d'avoir les droits d'administrateur pour exécuter cette commande.

# Fonction de démarrage de la surveillance du trafic
def start_traffic_monitoring(interface="eth0"):
    print(f"Surveillance du trafic réseau sur l'interface {interface}...")
    
    # Commence à écouter les paquets sur l'interface spécifiée
    sniff(iface=interface, prn=packet_callback, store=0)

# Exemple d'utilisation
if __name__ == "__main__":
    # Remplacer 'eth0' par l'interface réseau que vous souhaitez surveiller
    start_traffic_monitoring("eth0")  # Remplacer par "wlan0" pour Wi-Fi, selon votre configuration
