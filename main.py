from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, make_response
from werkzeug.utils import secure_filename
from scapy.all import rdpcap, IP, TCP, UDP
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
        'packet_sizes': [],
        'time_distribution': {}
    }
    
    # Dane do network graph
    network_graph = {
        'nodes': [],
        'edges': []
    }
    
    # Obsługa geolokalizacji (bardzo podstawowa - można rozszerzyć)
    geo_data = []
    
    # Wykres czasu (przetwarzanie czasu do bucketów)
    time_buckets = {}
    
    # Zbieranie statystyk
    for packet in data:
        # Wielkość pakietu
        stats['packet_sizes'].append(packet['length'])
        
        # Czas (bucketing)
        try:
            packet_time = datetime.datetime.fromisoformat(packet['time'])
            time_bucket = packet_time.strftime('%Y-%m-%d %H:%M')
            time_buckets[time_bucket] = time_buckets.get(time_bucket, 0) + 1
        except:
            pass
        
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
    
    # Konwersja top_ports do formatu dla wykresu
    top_ports_data = [{'port': port, 'count': count} for port, count in list(stats['top_ports'].items())[:5]]
    stats['top_ports_data'] = top_ports_data
    
    # Dodanie danych do network graph
    stats['network_graph'] = network_graph
    
    # Dodanie danych geolokalizacyjnych (puste, do rozszerzenia)
    stats['geo_data'] = geo_data
    
    return stats

# Funkcja generująca obrazy dla raportu PDF
def generate_chart_image(chart_type, data, title, width=800, height=400):
    import numpy as np
    plt.figure(figsize=(width/100, height/100), dpi=100)
    
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
            labels = [str(item['port']) for item in data]
            values = [item['count'] for item in data]
        
        plt.bar(labels, values)
        plt.xticks(rotation=45)
        plt.ylabel('Number of Packets')
    
    elif chart_type == 'line':
        # Wykres liniowy (np. dla rozkładu czasowego)
        plt.plot(data['labels'], data['values'])
        plt.xticks(rotation=45)
        plt.ylabel('Number of Packets')
        plt.tight_layout()
    
    elif chart_type == 'histogram':
        # Histogram (np. dla wielkości pakietów)
        plt.bar(data['labels'], data['values'])
        plt.xticks(rotation=45)
        plt.ylabel('Number of Packets')
        plt.xlabel('Packet Size (bytes)')
    
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
        pos = nx.spring_layout(G)
        
        # Rysowanie węzłów
        node_weights = [G.nodes[node].get('weight', 1) * 100 for node in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_size=node_weights, alpha=0.7)
        
        # Rysowanie krawędzi
        edge_weights = [G.edges[edge].get('weight', 1) for edge in G.edges()]
        nx.draw_networkx_edges(G, pos, width=edge_weights, alpha=0.5, arrows=True)
        
        # Etykiety
        nx.draw_networkx_labels(G, pos, font_size=8)
    
    plt.title(title)
    
    # Zapisz wykres do obiektu BytesIO
    img_data = BytesIO()
    plt.savefig(img_data, format='png', bbox_inches='tight')
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
    if 'time' in options and 'time_distribution' in stats:
        toc_items.append("Time Distribution")
    if 'packet_size' in options and 'packet_size_distribution' in stats:
        toc_items.append("Packet Size Distribution")
    if 'network' in options and 'network_graph' in stats:
        toc_items.append("Network Communication Graph")
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
    
    # Protokoły (jeśli wybrane)
    if 'protocols' in options and stats['protocols']:
        elements.append(Paragraph("Protocol Distribution", subtitle_style))
        
        # Generowanie wykresu protokołów
        chart_img = generate_chart_image('pie', stats['protocols'], 'Protocol Distribution')
        img = Image(chart_img, width=400, height=300)
        elements.append(img)
        elements.append(Spacer(1, 0.2*inch))
    
    # Porty (jeśli wybrane)
    if 'ports' in options and stats['top_ports']:
        elements.append(Paragraph("Most Used Ports", subtitle_style))
        
        # Generowanie wykresu portów
        chart_img = generate_chart_image('bar', stats['top_ports_data'], 'Most Used Ports')
        img = Image(chart_img, width=400, height=300)
        elements.append(img)
        elements.append(Spacer(1, 0.2*inch))
    
    # Rozkład czasowy (jeśli wybrane)
    if 'time' in options and 'time_distribution' in stats:
        elements.append(Paragraph("Time Distribution", subtitle_style))
        
        # Generowanie wykresu czasowego
        chart_img = generate_chart_image('line', stats['time_distribution'], 'Time Distribution')
        img = Image(chart_img, width=500, height=300)
        elements.append(img)
        elements.append(Spacer(1, 0.2*inch))
    
    # Rozkład wielkości pakietów (jeśli wybrane)
    if 'packet_size' in options and 'packet_size_distribution' in stats:
        elements.append(Paragraph("Packet Size Distribution", subtitle_style))
        
        # Generowanie histogramu wielkości pakietów
        chart_img = generate_chart_image('histogram', stats['packet_size_distribution'], 'Packet Size Distribution')
        img = Image(chart_img, width=400, height=300)
        elements.append(img)
        elements.append(Spacer(1, 0.2*inch))
    
    # Graf komunikacji (jeśli wybrane)
    if 'network' in options and 'network_graph' in stats:
        elements.append(Paragraph("Network Communication Graph", subtitle_style))
        
        # Generowanie grafu sieci
        chart_img = generate_chart_image('network', stats['network_graph'], 'Communication Graph')
        img = Image(chart_img, width=500, height=400)
        elements.append(img)
        elements.append(Spacer(1, 0.2*inch))
    
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
            options = ['summary', 'protocols', 'ports', 'time', 'packet_size', 'network', 'top_ips']
        
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