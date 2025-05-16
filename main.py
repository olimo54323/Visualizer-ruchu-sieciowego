from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, make_response
from werkzeug.utils import secure_filename
from scapy.all import rdpcap, IP, TCP, UDP, Ether
import os
import json
import datetime
import ipaddress
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Ustawienie backendu dla matplotlib bez GUI
from io import BytesIO
import base64
import collections
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
import networkx as nx
from reportlab.platypus import PageBreak

# Konfiguracja aplikacji
app = Flask(__name__)
app.config['SECRET_KEY'] = 'klucz_tajny_aplikacji'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['JSON_FOLDER'] = 'json_files'
app.config['STATIC_FOLDER'] = 'static'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Limit 100MB

# Tworzenie katalogów, jeśli nie istnieją
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['JSON_FOLDER'], exist_ok=True)
os.makedirs(os.path.join('static', 'img'), exist_ok=True)

# Dozwolone rozszerzenia plików
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Funkcja do serializacji obiektów sieciowych (np. adresy IP)
def json_serial(obj):
    if isinstance(obj, ipaddress.IPv4Address) or isinstance(obj, ipaddress.IPv6Address):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable")

# Słownik popularnych OUI (Organizationally Unique Identifier) dla adresów MAC
MAC_OUI_VENDORS = {
    '000000': 'Officially Xerox',
    '000001': 'SuperLAN',
    '000002': 'BBN Internal',
    '000003': 'XEROX CORPORATION',
    '000004': 'XEROX CORPORATION',
    '000005': 'XEROX CORPORATION',
    '00000C': 'Cisco',
    '00000E': 'Fujitsu',
    '000010': 'Sytek',
    '000020': 'DIAB',
    '000021': 'SC&C',
    '000022': 'Visual Technology',
    '000023': 'ABB Automation',
    '000024': 'Oki Electric Industry',
    '000029': 'IMC Networks',
    '00002A': 'TRW',
    '00002F': 'COMDESIGN',
    '000032': 'GPT Limited',
    '000050': 'NETWORK SYSTEMS',
    '000055': 'AT&T',
    '000077': 'INTERPHASE',
    '00007A': 'Ardent',
    '00007B': 'Research Machines',
    '0000A7': 'NCD',
    '0000A9': 'NETWORK SYSTEMS',
    '0000AA': 'XEROX CORPORATION',
    '0000B3': 'CIMLINC',
    '0000B7': 'DOVE',
    '0000BC': 'Allen-Bradley',
    '0000C0': 'WESTERN DIGITAL',
    '0000C5': 'FARALLON',
    '0000C6': 'HP',
    '0000C8': 'ALTOS',
    '0000C9': 'Emulex',
    '0000D7': 'DARTMOUTH',
    '0000D8': 'NOVELL',
    '0000DD': 'Gould',
    '0000DE': 'UNISYS',
    '0000E2': 'ACER',
    '0000EF': 'Alantec',
    '0000F0': 'Samsung',
    '0000F2': 'SPIDER SYSTEMS',
    '0000F3': 'GANDALF DATA',
    '0000F4': 'Allied Telesis',
    '0000F5': 'DIAMOND SALES',
    '0000F6': 'Applied Microsystems',
    '0000F8': 'DEC',
    '0000FB': 'RECHNER',
    '001000': 'Cable Television Laboratories',
    '001007': 'Cisco',
    '00100D': 'Cisco',
    '001011': 'Cisco',
    '001014': 'Cisco',
    '00102F': 'Cisco',
    '001054': 'Cisco',
    '00105A': '3COM',
    '0010E7': 'Breezecom',
    '0010F6': 'Cisco',
    '0020C2': 'TEXAS INSTRUMENTS',
    '0020D2': 'RAD Data Communications',
    '00400B': 'Cisco',
    '00601D': 'LUCENT TECHNOLOGIES',
    '00809F': 'ALE International',
    '00E018': 'ASUSTek',
    '010203': 'Techsan',
    '010CCC': 'Apple',
    '043695': 'Apple',
    '081196': 'Intel',
    '087045': 'Intel',
    '0C8112': 'Intel',
    '103047': 'Apple',
    '14FEB5': 'Dell',
    '182032': 'Apple',
    '1C6F65': 'Intel',
    '28633E': 'Siemens',
    '3C5AB4': 'Google',
    '3CA9F4': 'Intel',
    '4044F5': 'Samsung',
    '4860BC': 'Apple',
    '506B8D': 'Apple',
    '58CB52': 'Google',
    '5C969D': 'Apple',
    '609084': 'Apple',
    '68AB1E': 'Apple',
    '70106F': 'HP',
    '7CEBAE': 'Hewlett Packard',
    'A42983': 'Apple',
    'A860B6': 'Apple',
    'AC87A3': 'Apple',
    'B8C111': 'Apple',
    'C0A53E': 'Apple',
    'C88550': 'Apple',
    'D89695': 'Apple',
    'D8F883': 'Oracle',
    'E4E0C5': 'Samsung',
    'F0766F': 'Apple'
}

# Funkcja do uzyskania nazwy producenta z adresu MAC
def get_mac_vendor(mac_address):
    # Normalizacja adresu MAC 
    mac = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()
    oui = mac[:6]
    
    return MAC_OUI_VENDORS.get(oui, "Unknown")

# Funkcja do przetwarzania pliku PCAP na JSON
def pcap_to_json(pcap_file):
    try:
        packets = rdpcap(pcap_file)
        result = []
        
        for i, packet in enumerate(packets):
            packet_data = {
                'packet_number': i + 1,
                'time': str(datetime.datetime.fromtimestamp(float(packet.time))),
                'length': len(packet),
            }
            
            # Analiza warstwy Ethernet
            if Ether in packet:
                packet_data['ethernet'] = {
                    'src': packet[Ether].src,
                    'dst': packet[Ether].dst,
                    'type': hex(packet[Ether].type),
                    'src_vendor': get_mac_vendor(packet[Ether].src),
                    'dst_vendor': get_mac_vendor(packet[Ether].dst)
                }
            
            # Analiza warstwy IP
            if IP in packet:
                packet_data['ip'] = {
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'proto': packet[IP].proto,
                    'ttl': packet[IP].ttl
                }
                
                # Analiza warstwy TCP
                if TCP in packet:
                    packet_data['tcp'] = {
                        'sport': packet[TCP].sport,
                        'dport': packet[TCP].dport,
                        'flags': str(packet[TCP].flags),
                        'seq': packet[TCP].seq,
                        'ack': packet[TCP].ack
                    }
                
                # Analiza warstwy UDP
                elif UDP in packet:
                    packet_data['udp'] = {
                        'sport': packet[UDP].sport,
                        'dport': packet[UDP].dport,
                        'len': packet[UDP].len
                    }
            
            # Dodanie ładunku (payload) jeśli istnieje
            if hasattr(packet, 'load') and packet.load:
                try:
                    # Próba dekodowania ładunku jako UTF-8
                    payload = packet.load.decode('utf-8', errors='replace')
                    packet_data['payload'] = payload
                except:
                    # Jeśli nie można zdekodować, zapisz jako hex
                    packet_data['payload_hex'] = packet.load.hex()
            
            result.append(packet_data)
        
        return result
    except Exception as e:
        print(f"Błąd podczas przetwarzania pliku PCAP: {e}")
        return {'error': str(e)}

# Funkcja do generowania rozszerzonych statystyk
def generate_extended_stats(data):
    stats = {
        'total_packets': len(data),
        'protocols': {},
        'top_ips': {},
        'top_ports': {},
        'top_mac_addresses': {},
        'top_mac_vendors': {},
        'mac_communication': [],  # Połączenia między adresami MAC
        'packet_sizes': [],
        'time_distribution': {}
    }
    
    # Dane do network graph
    network_graph = {
        'nodes': [],
        'edges': []
    }
    
    # Dane do grafu MAC
    mac_graph = {
        'nodes': [],
        'edges': []
    }
    
    # Obsługa geolokalizacji (bardzo podstawowa - można rozszerzyć)
    geo_data = []
    
    # Znajdowanie zakresu czasowego wszystkich pakietów
    all_times = []
    for packet in data:
        try:
            packet_time = datetime.datetime.fromisoformat(packet['time'])
            all_times.append(packet_time)
        except:
            pass
    
    # Jeśli są dane czasowe, utwórz równomiernie rozłożone buckety
    if all_times:
        min_time = min(all_times)
        max_time = max(all_times)
        time_range = (max_time - min_time).total_seconds()
        
        # Stała liczba punktów na wykresie (np. 60)
        num_points = 60
        
        # Tworzenie równomiernie rozłożonych bucketów
        time_buckets = {}
        if time_range > 0:
            interval_seconds = time_range / num_points
            
            # Inicjalizacja pustych bucketów
            for i in range(num_points + 1):
                bucket_time = min_time + datetime.timedelta(seconds=i * interval_seconds)
                bucket_key = bucket_time.strftime('%Y-%m-%d %H:%M:%S')
                time_buckets[bucket_key] = 0
            
            # Przypisanie pakietów do bucketów
            for packet_time in all_times:
                # Obliczenie indeksu bucketu dla tego czasu
                time_diff = (packet_time - min_time).total_seconds()
                bucket_index = int(time_diff / interval_seconds)
                if bucket_index >= num_points:
                    bucket_index = num_points - 1
                
                # Dodanie pakietu do odpowiedniego bucketu
                bucket_time = min_time + datetime.timedelta(seconds=bucket_index * interval_seconds)
                bucket_key = bucket_time.strftime('%Y-%m-%d %H:%M:%S')
                time_buckets[bucket_key] = time_buckets.get(bucket_key, 0) + 1
        else:
            # Jeśli wszystkie pakiety mają ten sam czas
            time_buckets[min_time.strftime('%Y-%m-%d %H:%M:%S')] = len(all_times)
    
    # Sortowanie czasowych bucketów
    sorted_time_buckets = dict(sorted(time_buckets.items()))
    stats['time_distribution'] = {
        'labels': list(sorted_time_buckets.keys()),
        'values': list(sorted_time_buckets.values())
    }
    
    # Zbieranie statystyk protokołów, IP, portów, MAC adresów itp.
    for packet in data:
        # Wielkość pakietu
        stats['packet_sizes'].append(packet['length'])
        
        # Zbieranie statystyk adresów MAC
        if 'ethernet' in packet:
            src_mac = packet['ethernet']['src']
            dst_mac = packet['ethernet']['dst']
            src_vendor = packet['ethernet']['src_vendor']
            dst_vendor = packet['ethernet']['dst_vendor']
            
            # Zbieranie statystyk MAC
            stats['top_mac_addresses'][src_mac] = stats['top_mac_addresses'].get(src_mac, 0) + 1
            stats['top_mac_addresses'][dst_mac] = stats['top_mac_addresses'].get(dst_mac, 0) + 1
            
            # Zbieranie statystyk producentów
            stats['top_mac_vendors'][src_vendor] = stats['top_mac_vendors'].get(src_vendor, 0) + 1
            stats['top_mac_vendors'][dst_vendor] = stats['top_mac_vendors'].get(dst_vendor, 0) + 1
            
            # Dodawanie komunikacji MAC do grafu
            if src_mac not in [n.get('id') for n in mac_graph['nodes']]:
                mac_graph['nodes'].append({
                    'id': src_mac,
                    'label': src_mac,
                    'title': src_vendor,
                    'value': stats['top_mac_addresses'][src_mac]
                })
            
            if dst_mac not in [n.get('id') for n in mac_graph['nodes']]:
                mac_graph['nodes'].append({
                    'id': dst_mac,
                    'label': dst_mac,
                    'title': dst_vendor,
                    'value': stats['top_mac_addresses'][dst_mac]
                })
            
            # Dodanie krawędzi z wartością
            edge_id = f"{src_mac}-{dst_mac}"
            existing_edge = next((e for e in mac_graph['edges'] if e.get('id') == edge_id), None)
            
            if existing_edge:
                existing_edge['value'] += 1
                existing_edge['title'] = f"Pakiety: {existing_edge['value']}"
            else:
                mac_graph['edges'].append({
                    'id': edge_id,
                    'from': src_mac,
                    'to': dst_mac,
                    'value': 1,
                    'title': 'Pakiety: 1'
                })
        
        if 'ip' in packet:
            # Protokoły
            if 'tcp' in packet:
                stats['protocols']['TCP'] = stats['protocols'].get('TCP', 0) + 1
            elif 'udp' in packet:
                stats['protocols']['UDP'] = stats['protocols'].get('UDP', 0) + 1
            else:
                proto_num = packet['ip']['proto']
                proto_name = f"Protokół {proto_num}"
                stats['protocols'][proto_name] = stats['protocols'].get(proto_name, 0) + 1
            
            # Adresy IP
            src_ip = packet['ip']['src']
            dst_ip = packet['ip']['dst']
            stats['top_ips'][src_ip] = stats['top_ips'].get(src_ip, 0) + 1
            stats['top_ips'][dst_ip] = stats['top_ips'].get(dst_ip, 0) + 1
            
            # Network graph (dodawanie węzłów i krawędzi)
            if src_ip not in [n.get('id') for n in network_graph['nodes']]:
                network_graph['nodes'].append({
                    'id': src_ip,
                    'label': src_ip,
                    'value': stats['top_ips'][src_ip]
                })
            
            if dst_ip not in [n.get('id') for n in network_graph['nodes']]:
                network_graph['nodes'].append({
                    'id': dst_ip,
                    'label': dst_ip,
                    'value': stats['top_ips'][dst_ip]
                })
            
            # Dodanie krawędzi z wartością
            edge_id = f"{src_ip}-{dst_ip}"
            existing_edge = next((e for e in network_graph['edges'] if e.get('id') == edge_id), None)
            
            if existing_edge:
                existing_edge['value'] += 1
                existing_edge['title'] = f"Pakiety: {existing_edge['value']}"
            else:
                network_graph['edges'].append({
                    'id': edge_id,
                    'from': src_ip,
                    'to': dst_ip,
                    'value': 1,
                    'title': 'Pakiety: 1'
                })
            
            # Porty
            if 'tcp' in packet:
                sport = packet['tcp']['sport']
                dport = packet['tcp']['dport']
                stats['top_ports'][sport] = stats['top_ports'].get(sport, 0) + 1
                stats['top_ports'][dport] = stats['top_ports'].get(dport, 0) + 1
            elif 'udp' in packet:
                sport = packet['udp']['sport']
                dport = packet['udp']['dport']
                stats['top_ports'][sport] = stats['top_ports'].get(sport, 0) + 1
                stats['top_ports'][dport] = stats['top_ports'].get(dport, 0) + 1
    
    # Sortowanie czasowych bucketów
    sorted_time_buckets = dict(sorted(time_buckets.items()))
    stats['time_distribution'] = {
        'labels': list(sorted_time_buckets.keys()),
        'values': list(sorted_time_buckets.values())
    }
    
    # Histogram wielkości pakietów
    if stats['packet_sizes']:
        # Tworzenie przedziałów dla wielkości pakietów
        bins = [0, 64, 128, 256, 512, 1024, 1500, max(stats['packet_sizes']) + 1]
        labels = ['0-64', '65-128', '129-256', '257-512', '513-1024', '1025-1500', '1500+']
        
        # Liczenie histogramu
        hist, _ = np.histogram(stats['packet_sizes'], bins=bins)
        
        stats['packet_size_distribution'] = {
            'labels': labels,
            'values': hist.tolist()
        }
    else:
        stats['packet_size_distribution'] = {
            'labels': [],
            'values': []
        }
    
    # Sortowanie statystyk
    stats['top_ips'] = dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
    stats['top_ports'] = dict(sorted(stats['top_ports'].items(), key=lambda x: x[1], reverse=True)[:10])
    stats['top_mac_addresses'] = dict(sorted(stats['top_mac_addresses'].items(), key=lambda x: x[1], reverse=True)[:10])
    stats['top_mac_vendors'] = dict(sorted(stats['top_mac_vendors'].items(), key=lambda x: x[1], reverse=True)[:10])
    
    # Konwersja top_ports do formatu dla wykresu
    top_ports_data = [{'port': port, 'count': count} for port, count in list(stats['top_ports'].items())[:5]]
    stats['top_ports_data'] = top_ports_data
    
    # Konwersja top_mac_addresses do formatu dla wykresu
    top_mac_data = [{'mac': mac, 'count': count} for mac, count in list(stats['top_mac_addresses'].items())[:5]]
    stats['top_mac_data'] = top_mac_data
    
    # Dodanie danych do network graph
    stats['network_graph'] = network_graph
    
    # Dodanie danych do mac graph
    stats['mac_graph'] = mac_graph
    
    # Dodanie danych geolokalizacyjnych (puste, do rozszerzenia)
    stats['geo_data'] = geo_data
    
    return stats

# Funkcja generująca obrazy dla raportu PDF z poprawioną jakością
def generate_chart_image(chart_type, data, title, width=800, height=400):
    import numpy as np
    # Zwiększyłem DPI dla lepszej jakości wydruku
    plt.figure(figsize=(width/100, height/100), dpi=300)
    
    if chart_type == 'pie':
        # Wykres kołowy (np. dla protokołów)
        labels = list(data.keys())
        values = list(data.values())
        plt.pie(values, labels=labels, autopct='%1.1f%%', shadow=True, startangle=140)
        plt.axis('equal')
    
    elif chart_type == 'bar':
        # Wykres słupkowy (np. dla portów)
        if isinstance(data, dict):
            labels = list(data.keys())
            values = list(data.values())
        else:  # Lista słowników
            labels = [str(item.get('port', item.get('mac', ''))) for item in data]
            values = [item['count'] for item in data]
        
        plt.bar(labels, values)
        plt.xticks(rotation=45)
        plt.ylabel('Number of Packets')
        # Dostosowanie wielkości etykiet
        plt.tick_params(axis='both', which='major', labelsize=10)
    
    elif chart_type == 'line':
        # Wykres liniowy (np. dla rozkładu czasowego)
        plt.plot(data['labels'], data['values'], linewidth=2)
        plt.xticks(rotation=45)
        plt.ylabel('Number of Packets')
        plt.tick_params(axis='both', which='major', labelsize=10)
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
    
    elif chart_type == 'histogram':
        # Histogram (np. dla wielkości pakietów)
        plt.bar(data['labels'], data['values'])
        plt.xticks(rotation=45)
        plt.ylabel('Number of Packets')
        plt.xlabel('Packet Size (bytes)')
        plt.tick_params(axis='both', which='major', labelsize=10)
        plt.grid(True, linestyle='--', alpha=0.7)
    
    elif chart_type == 'network':
        # Graf sieci (dla komunikacji między hostami)
        G = nx.DiGraph()
        
        # Dodawanie węzłów
        for node in data['nodes']:
            G.add_node(node['id'], weight=node.get('value', 1))
        
        # Dodawanie krawędzi
        for edge in data['edges']:
            G.add_edge(edge['from'], edge['to'], weight=edge.get('value', 1))
        
        # Layout
        pos = nx.spring_layout(G, seed=42)  # Stały seed dla powtarzalności
        
        # Rysowanie węzłów
        node_weights = [G.nodes[node].get('weight', 1) * 100 for node in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_size=node_weights, alpha=0.7, 
                               node_color='skyblue', edgecolors='black')
        
        # Rysowanie krawędzi z dostosowaną grubością
        edge_weights = [max(1, G.edges[edge].get('weight', 1)) for edge in G.edges()]
        nx.draw_networkx_edges(G, pos, width=edge_weights, alpha=0.6, arrows=True, 
                              arrowstyle='->', arrowsize=15)
        
        # Etykiety z lepszą czytelnością
        nx.draw_networkx_labels(G, pos, font_size=9, font_weight='bold',
                              bbox=dict(facecolor='white', alpha=0.7, edgecolor='none', pad=1))
    
    elif chart_type == 'mac_network':
        # Graf komunikacji między adresami MAC
        G = nx.DiGraph()
        
        # Dodawanie węzłów
        for node in data['nodes']:
            G.add_node(node['id'], weight=node.get('value', 1), title=node.get('title', ''))
        
        # Dodawanie krawędzi
        for edge in data['edges']:
            G.add_edge(edge['from'], edge['to'], weight=edge.get('value', 1))
        
        # Layout
        pos = nx.spring_layout(G, seed=42)  # Stały seed dla powtarzalności
        
        # Rysowanie węzłów z kolorami opartymi na producentach
        node_weights = [G.nodes[node].get('weight', 1) * 80 for node in G.nodes()]
        
        # Określenie kolorów węzłów na podstawie producentów
        node_colors = []
        unique_vendors = set()
        for node in G.nodes:
            vendor = G.nodes[node].get('title', 'Unknown')
            unique_vendors.add(vendor)
        
        vendor_color_map = {}
        colors = plt.cm.tab20(np.linspace(0, 1, len(unique_vendors)))
        for i, vendor in enumerate(unique_vendors):
            vendor_color_map[vendor] = colors[i]
        
        for node in G.nodes:
            vendor = G.nodes[node].get('title', 'Unknown')
            node_colors.append(vendor_color_map.get(vendor, 'gray'))
        
        nx.draw_networkx_nodes(G, pos, node_size=node_weights, alpha=0.7, 
                               node_color=node_colors, edgecolors='black')
        
        # Rysowanie krawędzi z dostosowaną grubością
        edge_weights = [max(1, G.edges[edge].get('weight', 1)) for edge in G.edges()]
        nx.draw_networkx_edges(G, pos, width=edge_weights, alpha=0.6, arrows=True, 
                              arrowstyle='->', arrowsize=15)
        
        # Etykiety z lepszą czytelnością - skrócone adresy MAC dla lepszej czytelności
        short_labels = {node: node[-8:] for node in G.nodes}
        nx.draw_networkx_labels(G, pos, labels=short_labels, font_size=8, font_weight='bold',
                              bbox=dict(facecolor='white', alpha=0.7, edgecolor='none', pad=1))
        
        # Legenda producentów
        legend_elements = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=vendor_color_map[vendor], 
                                     markersize=10, label=vendor) for vendor in vendor_color_map]
        
        # Dodaj legendę tylko jeśli nie jest za duża
        if len(legend_elements) <= 10:
            plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1))
    
    plt.title(title, fontsize=14, fontweight='bold')
    
    # Zwiększenie marginesów dla lepszego wyglądu
    plt.tight_layout(pad=2.0)
    
    # Zapisz wykres w wysokiej jakości
    img_data = BytesIO()
    plt.savefig(img_data, format='png', bbox_inches='tight', dpi=300)
    img_data.seek(0)
    plt.close()
    
    return img_data

# Funkcja do generowania raportu PDF (bez interaktywnych linków)
def generate_pdf_report(filename, data, stats, options):
    # Utworzenie dokumentu PDF
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # Wyciągnij podstawową nazwę pliku bez rozszerzenia
    base_filename = os.path.splitext(os.path.basename(filename))[0]
    # Utwórz nazwę raportu zgodnie z formatem: "raport_pcap_<data>_<godzina>.pdf"
    report_filename = f"report_{base_filename}_{timestamp}.pdf"
    report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)
    
    # Tworzenie dokumentu
    doc = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=72, leftMargin=72,
        topMargin=72, bottomMargin=72
    )
    
    # Style
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Lista elementów do dodania do dokumentu
    elements = []
    
    # Tytuł
    elements.append(Paragraph(f"Network Traffic Analysis Report", title_style))
    elements.append(Paragraph(f"File: {filename}", subtitle_style))
    elements.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 0.5*inch))
    
    # Spis treści
    elements.append(Paragraph("Table of Contents", subtitle_style))
    
    # Tworzenie pozycji spisu treści
    toc_items = []
    if 'summary' in options:
        toc_items.append("Summary")
    if 'protocols' in options and stats['protocols']:
        toc_items.append("Protocol Distribution")
    if 'ports' in options and stats['top_ports']:
        toc_items.append("Most Used Ports")
    if 'mac_addresses' in options and stats['top_mac_addresses']:
        toc_items.append("Most Used MAC Addresses")
    if 'mac_vendors' in options and stats['top_mac_vendors']:
        toc_items.append("MAC Vendors Distribution")
    if 'time' in options and 'time_distribution' in stats:
        toc_items.append("Time Distribution")
    if 'packet_size' in options and 'packet_size_distribution' in stats:
        toc_items.append("Packet Size Distribution")
    if 'network' in options and 'network_graph' in stats:
        toc_items.append("IP Network Communication Graph")
    if 'mac_network' in options and 'mac_graph' in stats:
        toc_items.append("MAC Address Communication Graph")
    if 'top_ips' in options and stats['top_ips']:
        toc_items.append("Most Common IP Addresses")
    
    # Dodanie spisu treści jako zwykłego tekstu
    for title in toc_items:
        elements.append(Paragraph(f"• {title}", normal_style))
    elements.append(Spacer(1, 0.5*inch))
    
    # Podsumowanie (jeśli wybrane)
    if 'summary' in options:
        elements.append(Paragraph("Summary", subtitle_style))
        
        summary_data = [
            ["Total number of packets", str(stats['total_packets'])],
        ]
        
        # Tworzenie tabeli podsumowania
        summary_table = Table(summary_data, colWidths=[200, 200])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.2*inch))
    
    if 'protocols' in options and stats['protocols']:
        elements.append(Paragraph("Protocol Distribution", subtitle_style))
        
        # Generowanie wykresu protokołów z lepszą jakością
        chart_img = generate_chart_image('pie', stats['protocols'], 'Protocol Distribution', width=600, height=450)
        img = Image(chart_img, width=400, height=300)
        img.hAlign = 'CENTER'  # Wyśrodkowanie obrazu
        elements.append(img)
        elements.append(Spacer(1, 0.3*inch))

    # Dla wykresów portów:
    if 'ports' in options and stats['top_ports']:
        elements.append(Paragraph("Most Used Ports", subtitle_style))
        
        # Generowanie wykresu portów z lepszą jakością
        chart_img = generate_chart_image('bar', stats['top_ports_data'], 'Most Used Ports', width=600, height=450)
        img = Image(chart_img, width=450, height=300)
        img.hAlign = 'CENTER'  # Wyśrodkowanie obrazu
        elements.append(img)
        elements.append(Spacer(1, 0.3*inch))
    
    # Dla wykresów adresów MAC:
    if 'mac_addresses' in options and stats['top_mac_addresses']:
        elements.append(Paragraph("Most Used MAC Addresses", subtitle_style))
        
        # Generowanie wykresu adresów MAC z lepszą jakością
        chart_img = generate_chart_image('bar', stats['top_mac_data'], 'Most Used MAC Addresses', width=600, height=450)
        img = Image(chart_img, width=450, height=300)
        img.hAlign = 'CENTER'  # Wyśrodkowanie obrazu
        elements.append(img)
        elements.append(Spacer(1, 0.3*inch))
    
    # Dla wykresów producentów MAC:
    if 'mac_vendors' in options and stats['top_mac_vendors']:
        elements.append(Paragraph("MAC Vendors Distribution", subtitle_style))
        
        # Generowanie wykresu producentów MAC z lepszą jakością
        chart_img = generate_chart_image('pie', stats['top_mac_vendors'], 'MAC Vendors Distribution', width=600, height=450)
        img = Image(chart_img, width=450, height=300)
        img.hAlign = 'CENTER'  # Wyśrodkowanie obrazu
        elements.append(img)
        elements.append(Spacer(1, 0.3*inch))

    # Dla rozkładu czasowego:
    if 'time' in options and 'time_distribution' in stats:
        elements.append(Paragraph("Time Distribution", subtitle_style))
        
        # Generowanie wykresu czasowego z lepszą jakością
        chart_img = generate_chart_image('line', stats['time_distribution'], 'Time Distribution', width=700, height=450)
        img = Image(chart_img, width=500, height=300)
        img.hAlign = 'CENTER'  # Wyśrodkowanie obrazu
        elements.append(img)
        elements.append(Spacer(1, 0.3*inch))

    # Dla rozkładu wielkości pakietów:
    if 'packet_size' in options and 'packet_size_distribution' in stats:
        elements.append(Paragraph("Packet Size Distribution", subtitle_style))
        
        # Generowanie histogramu wielkości pakietów z lepszą jakością
        chart_img = generate_chart_image('histogram', stats['packet_size_distribution'], 'Packet Size Distribution', width=600, height=450)
        img = Image(chart_img, width=450, height=300)
        img.hAlign = 'CENTER'  # Wyśrodkowanie obrazu
        elements.append(img)
        elements.append(Spacer(1, 0.3*inch))

    # Dla grafu komunikacji IP:
    if 'network' in options and 'network_graph' in stats:
        elements.append(Paragraph("IP Network Communication Graph", subtitle_style))
        
        # Generowanie grafu sieci z lepszą jakością
        chart_img = generate_chart_image('network', stats['network_graph'], 'IP Communication Graph', width=800, height=600)
        img = Image(chart_img, width=550, height=450)
        img.hAlign = 'CENTER'  # Wyśrodkowanie obrazu
        elements.append(img)
        elements.append(Spacer(1, 0.3*inch))
    
    # Dla grafu komunikacji MAC:
    if 'mac_network' in options and 'mac_graph' in stats:
        elements.append(Paragraph("MAC Address Communication Graph", subtitle_style))
        
        # Generowanie grafu sieci MAC z lepszą jakością
        chart_img = generate_chart_image('mac_network', stats['mac_graph'], 'MAC Communication Graph', width=800, height=600)
        img = Image(chart_img, width=550, height=450)
        img.hAlign = 'CENTER'  # Wyśrodkowanie obrazu
        elements.append(img)
        elements.append(Spacer(1, 0.3*inch))
    
    # Najczęściej występujące adresy IP (jeśli wybrane)
    if 'top_ips' in options and stats['top_ips']:
        elements.append(Paragraph("Most Common IP Addresses", subtitle_style))
        
        # Tworzenie tabeli z adresami IP
        ip_data = [["IP Address", "Number of Packets"]]
        for ip, count in stats['top_ips'].items():
            ip_data.append([ip, str(count)])
        
        ip_table = Table(ip_data, colWidths=[200, 200])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(ip_table)
        elements.append(Spacer(1, 0.2*inch))
    
    # Najczęściej występujące adresy MAC (jeśli wybrane)
    if 'mac_addresses' in options and stats['top_mac_addresses']:
        elements.append(Paragraph("Most Common MAC Addresses", subtitle_style))
        
        # Tworzenie tabeli z adresami MAC
        mac_data = [["MAC Address", "Vendor", "Number of Packets"]]
        for mac, count in stats['top_mac_addresses'].items():
            vendor = get_mac_vendor(mac)
            mac_data.append([mac, vendor, str(count)])
        
        mac_table = Table(mac_data, colWidths=[200, 150, 100])
        mac_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(mac_table)
        elements.append(Spacer(1, 0.2*inch))
    
    # Dodaj prostą stopkę z numerem strony
    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 10)
        canvas.drawCentredString(
            doc.pagesize[0] / 2, 
            20, 
            f"Page {canvas.getPageNumber()}"
        )
        canvas.restoreState()
    
    # Zbudowanie dokumentu ze stopką
    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    
    return report_filename

def generate_filtered_packets_report(filename, packets, filter_params):
    """
    Generuje raport PDF zawierający tylko pakiety przefiltrowane według ustawionych parametrów
    
    Args:
        filename (str): Nazwa pliku wejściowego do umieszczenia w raporcie
        packets (list): Lista przefiltrowanych pakietów do umieszczenia w raporcie
        filter_params (dict): Słownik z parametrami filtrowania do umieszczenia w raporcie
    
    Returns:
        str: Nazwa wygenerowanego pliku raportu
    """
    # Utworzenie dokumentu PDF
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = os.path.splitext(os.path.basename(filename))[0]
    report_filename = f"filtered_packets_{base_filename}_{timestamp}.pdf"
    report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)
    
    # Tworzenie dokumentu
    doc = SimpleDocTemplate(
        report_path,
        pagesize=landscape(A4),
        rightMargin=36, leftMargin=36,
        topMargin=36, bottomMargin=36
    )
    
    # Style
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Lista elementów do dodania do dokumentu
    elements = []
    
    # Tytuł
    elements.append(Paragraph(f"Filtered Packets Report", title_style))
    elements.append(Paragraph(f"File: {filename}", subtitle_style))
    elements.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 0.5*inch))
    
    # Zastosowane filtry
    elements.append(Paragraph("Applied Filters", subtitle_style))
    
    # Tworzenie tabeli filtrów
    filter_data = []
    for param, value in filter_params.items():
        if value:  # Dodawaj tylko niepuste filtry
            filter_data.append([param, value])
    
    if filter_data:
        filter_table = Table(filter_data, colWidths=[150, 300])
        filter_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(filter_table)
    else:
        elements.append(Paragraph("No filters applied", normal_style))
    
    elements.append(Spacer(1, 0.5*inch))
    
    # Podsumowanie
    elements.append(Paragraph("Summary", subtitle_style))
    elements.append(Paragraph(f"Total packets matching filters: {len(packets)}", normal_style))
    elements.append(Spacer(1, 0.5*inch))
    
    # Tabela pakietów
    elements.append(Paragraph("Packets Table", subtitle_style))
    
    # Nagłówki kolumn
    headers = ["#", "Time", "Source MAC", "Destination MAC", "MAC Vendor", "Source IP", "Destination IP", "Protocol", "Ports", "Length"]
    packet_data = [headers]
    
    # Wypełnianie danymi pakietów
    for packet in packets:
        row = [
            str(packet.get('packet_number', '')),
            packet.get('time', ''),
            packet.get('ethernet', {}).get('src', ''),
            packet.get('ethernet', {}).get('dst', ''),
            packet.get('ethernet', {}).get('src_vendor', ''),
            packet.get('ip', {}).get('src', ''),
            packet.get('ip', {}).get('dst', ''),
            get_protocol_name(packet),
            get_ports_str(packet),
            str(packet.get('length', ''))
        ]
        packet_data.append(row)
    
    # Tworzenie tabeli pakietów
    col_widths = [25, 110, 100, 100, 80, 80, 80, 50, 70, 40]
    packets_table = Table(packet_data, colWidths=col_widths, repeatRows=1)
    packets_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # Numer pakietu wyśrodkowany
        ('ALIGN', (9, 1), (9, -1), 'RIGHT'),   # Długość wyrównana do prawej
    ]))
    
    elements.append(packets_table)
    
    # Dodaj prostą stopkę z numerem strony
    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 10)
        canvas.drawCentredString(
            doc.pagesize[0] / 2, 
            20, 
            f"Page {canvas.getPageNumber()}"
        )
        canvas.restoreState()
    
    # Zbudowanie dokumentu ze stopką
    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    
    return report_filename

    # Funkcje pomocnicze do formatowania danych pakietów
def get_protocol_name(packet):
    """Zwraca nazwę protokołu pakietu"""
    if 'tcp' in packet:
        return "TCP"
    elif 'udp' in packet:
        return "UDP"
    elif 'ip' in packet:
        return f"IP({packet['ip']['proto']})"
    else:
        return "Other"

def get_ports_str(packet):
    """Zwraca sformatowany ciąg portów (źródłowy -> docelowy)"""
    if 'tcp' in packet:
        return f"{packet['tcp']['sport']} → {packet['tcp']['dport']}"
    elif 'udp' in packet:
        return f"{packet['udp']['sport']} → {packet['udp']['dport']}"
    else:
        return "-"
    
# Strona główna
@app.route('/')
def index():
    # Pobierz listę przetworzonych plików JSON
    json_files = os.listdir(app.config['JSON_FOLDER'])
    json_files = [f for f in json_files if f.endswith('.json')]
    json_files.sort(reverse=True)  # Sortowanie od najnowszych
    
    return render_template('index.html', json_files=json_files)

# Formularz przesyłania pliku
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files and 'file_path' not in request.form:
        flash('Nie wybrano pliku ani nie podano ścieżki')
        return redirect(request.url)
    
    # Obsługa przesłanego pliku
    if 'file' in request.files and request.files['file'].filename:
        file = request.files['file']
        
        if not allowed_file(file.filename):
            flash('Nieprawidłowy format pliku. Dozwolone formaty: .pcap, .pcapng, .cap')
            return redirect(url_for('index'))
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
    
    # Obsługa ścieżki do pliku
    elif 'file_path' in request.form and request.form['file_path'].strip():
        file_path = request.form['file_path'].strip()
        
        if not os.path.exists(file_path):
            flash(f'Plik nie istnieje: {file_path}')
            return redirect(url_for('index'))
        
        if not allowed_file(file_path):
            flash('Nieprawidłowy format pliku. Dozwolone formaty: .pcap, .pcapng, .cap')
            return redirect(url_for('index'))
    
    else:
        flash('Nie wybrano pliku ani nie podano ścieżki')
        return redirect(url_for('index'))
    
    # Przetwarzanie pliku PCAP
    try:
        packets_data = pcap_to_json(file_path)
        
        # Generowanie nazwy pliku JSON na podstawie daty i godziny
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = f"pcap_analysis_{timestamp}.json"
        json_path = os.path.join(app.config['JSON_FOLDER'], json_filename)
        
        # Zapisanie danych do pliku JSON
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(packets_data, f, indent=2, default=json_serial)
        
        flash(f'Pomyślnie przetworzono plik. Zapisano jako {json_filename}')
        return redirect(url_for('view_json', filename=json_filename))
        
    except Exception as e:
        flash(f'Błąd podczas przetwarzania pliku: {str(e)}')
        return redirect(url_for('index'))

# Wyświetlanie przetworzonego pliku JSON
@app.route('/view/<filename>')
def view_json(filename):
    try:
        file_path = os.path.join(app.config['JSON_FOLDER'], filename)
        
        if not os.path.exists(file_path):
            flash('Plik nie istnieje')
            return redirect(url_for('index'))
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Generowanie rozszerzonych statystyk
        stats = generate_extended_stats(data)
        
        return render_template('view.html', filename=filename, data=data, stats=stats)
        
    except Exception as e:
        flash(f'Błąd podczas odczytu pliku: {str(e)}')
        return redirect(url_for('index'))

    # Pobieranie pliku JSON
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['JSON_FOLDER'], filename, as_attachment=True)

# API do pobierania danych JSON
@app.route('/api/json/<filename>')
def get_json_data(filename):
    try:
        file_path = os.path.join(app.config['JSON_FOLDER'], filename)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return jsonify(data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Endpoint do generowania raportów z filtrowanych pakietów
@app.route('/generate_filtered_report/<filename>', methods=['POST'])
def generate_filtered_report(filename):
    try:
        file_path = os.path.join(app.config['JSON_FOLDER'], filename)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Pobierz dane JSON
        with open(file_path, 'r', encoding='utf-8') as f:
            all_packets = json.load(f)
        
        # Pobierz parametry filtrowania z zapytania POST
        filter_params = {
            'Source IP': request.json.get('srcIp', ''),
            'Destination IP': request.json.get('dstIp', ''),
            'Source MAC': request.json.get('srcMac', ''),
            'Destination MAC': request.json.get('dstMac', ''),
            'Protocol': request.json.get('protocol', ''),
            'Port': request.json.get('port', ''),
            'Min Length': request.json.get('lengthMin', ''),
            'Max Length': request.json.get('lengthMax', ''),
            'Start Time': request.json.get('timeStart', ''),
            'End Time': request.json.get('timeEnd', '')
        }
        
        # Filtrowanie pakietów według parametrów
        filtered_packets = filter_packets(all_packets, filter_params)
        
        # Generowanie raportu
        report_filename = generate_filtered_packets_report(filename, filtered_packets, filter_params)
        
        # Zwracanie ścieżki do wygenerowanego raportu
        return jsonify({
            'success': True,
            'message': 'Report generated successfully',
            'report_url': url_for('download_report', filename=report_filename)
        })
        
    except Exception as e:
        app.logger.error(f"Error generating filtered report: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Funkcja do filtrowania pakietów
def filter_packets(packets, filter_params):
    """
    Filtruje pakiety według określonych parametrów
    
    Args:
        packets (list): Lista wszystkich pakietów do filtrowania
        filter_params (dict): Parametry filtrowania
    
    Returns:
        list: Przefiltrowana lista pakietów
    """
    filtered = []
    
    srcIp = filter_params.get('Source IP', '')
    dstIp = filter_params.get('Destination IP', '')
    srcMac = filter_params.get('Source MAC', '')
    dstMac = filter_params.get('Destination MAC', '')
    protocol = filter_params.get('Protocol', '')
    port = filter_params.get('Port', '')
    lengthMin = filter_params.get('Min Length', '')
    lengthMax = filter_params.get('Max Length', '')
    timeStart = filter_params.get('Start Time', '')
    timeEnd = filter_params.get('End Time', '')
    
    for packet in packets:
        # Inicjalizacja wartości ważne dla filtrów
        valid = True
        
        # MAC Źródłowe
        if srcMac and 'ethernet' in packet and packet['ethernet']['src'] != srcMac:
            if not srcMac.lower() in packet['ethernet']['src'].lower():  # Częściowe dopasowanie
                valid = False
        
        # MAC Docelowe
        if dstMac and 'ethernet' in packet and packet['ethernet']['dst'] != dstMac:
            if not dstMac.lower() in packet['ethernet']['dst'].lower():  # Częściowe dopasowanie
                valid = False
        
        # IP Źródłowe
        if srcIp and 'ip' in packet and packet['ip']['src'] != srcIp:
            if not srcIp in packet['ip']['src']:  # Częściowe dopasowanie
                valid = False
        
        # IP Docelowe
        if dstIp and 'ip' in packet and packet['ip']['dst'] != dstIp:
            if not dstIp in packet['ip']['dst']:  # Częściowe dopasowanie
                valid = False
        
        # Protokół
        if protocol:
            packet_protocol = ""
            if 'tcp' in packet:
                packet_protocol = "TCP"
            elif 'udp' in packet:
                packet_protocol = "UDP"
            elif 'ip' in packet:
                packet_protocol = f"IP({packet['ip']['proto']})"
            
            if protocol != packet_protocol:
                valid = False
        
        # Port (źródłowy lub docelowy)
        if port:
            port_num = int(port)
            port_found = False
            
            if 'tcp' in packet:
                if packet['tcp']['sport'] == port_num or packet['tcp']['dport'] == port_num:
                    port_found = True
            elif 'udp' in packet:
                if packet['udp']['sport'] == port_num or packet['udp']['dport'] == port_num:
                    port_found = True
            
            if not port_found:
                valid = False
        
        # Długość pakietu
        if lengthMin and int(packet['length']) < int(lengthMin):
            valid = False
        
        if lengthMax and int(packet['length']) > int(lengthMax):
            valid = False
        
        # Zakres czasowy
        if timeStart or timeEnd:
            packet_time = datetime.datetime.fromisoformat(packet['time'])
            
            if timeStart:
                start_time = datetime.datetime.fromisoformat(timeStart)
                if packet_time < start_time:
                    valid = False
            
            if timeEnd:
                end_time = datetime.datetime.fromisoformat(timeEnd)
                if packet_time > end_time:
                    valid = False
        
        # Jeśli pakiet przeszedł wszystkie filtry, dodaj go do listy
        if valid:
            filtered.append(packet)
    
    return filtered

# Generowanie raportu PDF
@app.route('/generate_report/<filename>')
def generate_report(filename):
   try:
       file_path = os.path.join(app.config['JSON_FOLDER'], filename)
       
       if not os.path.exists(file_path):
           flash('Plik nie istnieje')
           return redirect(url_for('index'))
       
       # Pobierz opcje raportu z parametrów URL
       options = request.args.getlist('options[]')
       
       if not options:
           options = ['summary', 'protocols', 'ports', 'mac_addresses', 'mac_vendors', 'time', 'packet_size', 'network', 'mac_network', 'top_ips']
       
       # Wczytaj dane
       with open(file_path, 'r', encoding='utf-8') as f:
           data = json.load(f)
       
       # Generowanie rozszerzonych statystyk
       stats = generate_extended_stats(data)
       
       # Generowanie raportu PDF
       report_filename = generate_pdf_report(filename, data, stats, options)
       
       # Przekierowanie do pobrania wygenerowanego pliku PDF
       return redirect(url_for('download_report', filename=report_filename))
   
   except Exception as e:
       flash(f'Błąd podczas generowania raportu: {str(e)}')
       return redirect(url_for('view_json', filename=filename))

# Pobieranie wygenerowanego raportu PDF
@app.route('/download_report/<filename>')
def download_report(filename):
   # Ustawienie nagłówka Content-Disposition, aby przeglądarka zapisała plik
   response = make_response(send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True))
   response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
   return response

# Ścieżka do plików statycznych JavaScript i CSS
@app.route('/static/<path:path>')
def send_static(path):
   return send_from_directory('static', path)

# Obsługa błędów
@app.errorhandler(404)
def page_not_found(e):
   return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
   return render_template('500.html'), 500

if __name__ == '__main__':
   app.run(debug=True)