import time
import sqlite3
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from netaddr import IPAddress, IPNetwork
from telegram_alert import enviar_alerta

# --- Parámetros ---
LIMITE_CONEXIONES = 500
TIEMPO_ANALISIS = 5
LIMITE_PUERTOS = 50
LIMITE_DDOS = 1000
LIMITE_IPS_DDOS = 50

# --- IPs y puertos permitidos ---
IPs_ignoradas = ["192.168.0.13", "192.168.0.1", "8.8.8.8","192.168.80.55"]
PUERTOS_PERMITIDOS = {80, 443, 53, 22, 3389}

# --- Contadores independientes ---
conexiones_syn = defaultdict(list)
conexiones_ddos = defaultdict(list)
puertos_por_ip = defaultdict(set)
ddos_por_destino = defaultdict(set)
advertencias = defaultdict(int)

# --- Base de datos ---
conn = sqlite3.connect('ataques_detectados.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS ataques (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    tipo_ataque TEXT,
    ip_src TEXT,
    protocolo TEXT,
    puerto INTEGER
)
''')
conn.commit()

# --- Funciones auxiliares ---
def es_ip_confiable(ip_src):
    return any(IPAddress(ip_src) in IPNetwork(cidr) for cidr in IPs_ignoradas)

def guardar_ataque(ip_src, tipo_ataque, protocolo, puerto):
    advertencias[ip_src] += 1
    if advertencias[ip_src] >= 3:
        timestamp = time.ctime()
        print(f"🚨 [ALERTA] {tipo_ataque} desde {ip_src} | Protocolo: {protocolo}, Puerto: {puerto}")
        
        mensaje = f"🚨 [IDS] {tipo_ataque} detectado\n🧑‍💻 IP: {ip_src}\n📦 Protocolo: {protocolo}\n🔌 Puerto: {puerto}"
        enviar_alerta(mensaje)

        cursor.execute('''
        INSERT INTO ataques (timestamp, tipo_ataque, ip_src, protocolo, puerto)
        VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, tipo_ataque, ip_src, protocolo, puerto))
        conn.commit()
        advertencias[ip_src] = 0

# --- Detectores específicos ---
def detectar_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        ip_src = packet[IP].src
        tiempo = time.time()
        conexiones_syn[ip_src].append(tiempo)
        conexiones_syn[ip_src] = [t for t in conexiones_syn[ip_src] if tiempo - t < TIEMPO_ANALISIS]

        if len(conexiones_syn[ip_src]) > LIMITE_CONEXIONES:
            guardar_ataque(ip_src, "SYN Flood", "TCP", packet[TCP].dport)
            conexiones_syn[ip_src] = []

def detectar_ddos_distribuido(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tiempo = time.time()

        if es_ip_confiable(ip_src):
            return

        conexiones_ddos[ip_src].append(tiempo)
        conexiones_ddos[ip_src] = [t for t in conexiones_ddos[ip_src] if tiempo - t < TIEMPO_ANALISIS]
        ddos_por_destino[ip_dst].add(ip_src)

        total_conexiones = sum(len(conexiones_ddos[ip]) for ip in ddos_por_destino[ip_dst])
        if len(ddos_por_destino[ip_dst]) > LIMITE_IPS_DDOS and total_conexiones > LIMITE_DDOS:
            guardar_ataque(ip_dst, "DDoS Distribuido", "TCP/UDP", 0)
            ddos_por_destino[ip_dst].clear()

def detectar_escaneo_puertos(packet):
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        ip_src = packet[IP].src
        dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        tiempo = time.time()

        if dport in PUERTOS_PERMITIDOS:
            return

        puertos_por_ip[ip_src].add(dport)
        if len(puertos_por_ip[ip_src]) > LIMITE_PUERTOS:
            guardar_ataque(ip_src, "Escaneo de Puertos", "TCP/UDP", dport)
            puertos_por_ip[ip_src].clear()

# --- Análisis de paquetes ---
def analizar_paquete(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocolo = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Otro"
        print(f"📡 {ip_src} ➝ {ip_dst} | Protocolo: {protocolo}")

        if es_ip_confiable(ip_src):
            return

        detectar_syn_flood(packet)
        detectar_ddos_distribuido(packet)
        detectar_escaneo_puertos(packet)

def iniciar_monitoreo():
    print("🛡️ IDS-UNIPAZ escuchando tráfico en tiempo real...")
    sniff(prn=analizar_paquete, store=0)

if __name__ == "__main__":
    iniciar_monitoreo()
