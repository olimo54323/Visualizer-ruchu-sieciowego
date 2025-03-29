from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from scapy.all import rdpcap, IP, TCP, UDP
import os
import json
import datetime
import ipaddress

# Konfiguracja aplikacji
app = Flask(__name__)
app.config['SECRET_KEY'] = 'klucz_tajny_aplikacji'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['JSON_FOLDER'] = 'json_files'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Limit 100MB

# Tworzenie katalogów, jeśli nie istnieją
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['JSON_FOLDER'], exist_ok=True)

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
        
        # Podstawowe statystyki
        stats = {
            'total_packets': len(data),
            'protocols': {},
            'top_ips': {},
            'top_ports': {}
        }
        
        # Zbieranie statystyk
        for packet in data:
            if 'ip' in packet:
                # Protokoły
                if 'tcp' in packet:
                    stats['protocols']['TCP'] = stats['protocols'].get('TCP', 0) + 1
                elif 'udp' in packet:
                    stats['protocols']['UDP'] = stats['protocols'].get('UDP', 0) + 1
                else:
                    stats['protocols']['Other'] = stats['protocols'].get('Other', 0) + 1
                
                # Adresy IP
                src_ip = packet['ip']['src']
                dst_ip = packet['ip']['dst']
                stats['top_ips'][src_ip] = stats['top_ips'].get(src_ip, 0) + 1
                stats['top_ips'][dst_ip] = stats['top_ips'].get(dst_ip, 0) + 1
                
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
        
        # Sortowanie statystyk
        stats['top_ips'] = dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_ports'] = dict(sorted(stats['top_ports'].items(), key=lambda x: x[1], reverse=True)[:10])
        
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

if __name__ == '__main__':
    app.run(debug=True)