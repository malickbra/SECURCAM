# app.py - Version corrigée pour les rapports
from flask import Flask, render_template, request, jsonify, send_file
from modules.scanner import IoTScanner
from modules.reporter import PDFReporter
from database.models import DatabaseManager
import json
import time
import threading
import os

app = Flask(__name__)
scanner = IoTScanner()
db_manager = DatabaseManager()

# Variables globales pour suivre l'état du scan
scan_in_progress = False
scan_results = []
current_network_range = ""

@app.route('/')
def index():
    """Page d'accueil"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_network():
    """Endpoint pour lancer un scan"""
    global scan_in_progress, scan_results, current_network_range
    
    if scan_in_progress:
        return jsonify({'error': 'Scan déjà en cours'}), 409
    
    network_range = request.form.get('network_range', '192.168.1.0/24')
    current_network_range = network_range
    
    # Validation de la plage IP
    if not validate_network_range(network_range):
        return jsonify({'error': 'Plage réseau invalide. Format attendu: XXX.XXX.XXX.XXX/XX (ex: 192.168.1.0/24)'}), 400
    
    # Réinitialiser les résultats précédents
    scan_results = []
    
    # Lancement du scan dans un thread séparé
    scan_in_progress = True
    scan_thread = threading.Thread(
        target=run_comprehensive_scan, 
        args=(network_range,),
        daemon=True
    )
    scan_thread.start()
    
    return jsonify({
        'message': 'Scan démarré avec succès', 
        'network_range': network_range,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    })

def run_comprehensive_scan(network_range):
    """Exécution du scan complet"""
    global scan_in_progress, scan_results
    
    try:
        print(f"🔍 Démarrage du scan sur: {network_range}")
        start_time = time.time()
        
        # Scan complet
        devices = scanner.comprehensive_scan(network_range)
        scan_duration = time.time() - start_time
        
        # Sauvegarde en base
        db_manager.save_scan_results(devices, network_range, scan_duration)
        
        scan_results = devices
        scan_in_progress = False
        
        print(f"✅ Scan terminé en {scan_duration:.2f}s - {len(devices)} appareils trouvés")
        
    except Exception as e:
        print(f"❌ Erreur pendant le scan: {e}")
        scan_in_progress = False
        scan_results = [{'error': str(e)}]

@app.route('/scan/status')
def scan_status():
    """Statut du scan en cours"""
    global scan_in_progress, scan_results
    
    has_error = False
    error_message = ""
    
    if scan_results and isinstance(scan_results, list) and len(scan_results) > 0:
        if isinstance(scan_results[0], dict) and 'error' in scan_results[0]:
            has_error = True
            error_message = scan_results[0]['error']
    
    return jsonify({
        'in_progress': scan_in_progress,
        'results_ready': len(scan_results) > 0 and not has_error,
        'device_count': len(scan_results) if not has_error else 0,
        'has_error': has_error,
        'error_message': error_message
    })

@app.route('/results')
def get_results():
    """Récupération des résultats"""
    global scan_results, current_network_range
    
    if not scan_results:
        return jsonify({'devices': [], 'summary': {}})
    
    # Vérifier si il y a une erreur
    if isinstance(scan_results, list) and len(scan_results) > 0 and 'error' in scan_results[0]:
        return jsonify({
            'error': scan_results[0]['error'],
            'devices': [],
            'summary': {}
        })
    
    # Calcul des statistiques
    vulnerable_count = sum(1 for device in scan_results if device.get('vulnerable', False))
    secure_count = len(scan_results) - vulnerable_count
    open_ports_count = sum(len(device.get('open_ports', [])) for device in scan_results)
    
    # Structure les résultats pour le frontend
    formatted_results = {
        'devices': scan_results,
        'summary': {
            'total_devices': len(scan_results),
            'vulnerable_devices': vulnerable_count,
            'secure_devices': secure_count,
            'open_ports': open_ports_count,
            'network_range': current_network_range,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    }
    
    return jsonify(formatted_results)

@app.route('/generate-report', methods=['POST'])
def generate_report():
    """Génération du rapport PDF"""
    global scan_results, current_network_range
    
    try:
        if not scan_results or (isinstance(scan_results, list) and len(scan_results) > 0 and 'error' in scan_results[0]):
            return jsonify({'error': 'Aucun résultat de scan disponible pour générer le rapport'}), 400
        
        # Récupérer les options du rapport
        report_options = request.get_json() or {}
        include_vulnerabilities = report_options.get('include_vulnerabilities', True)
        include_open_ports = report_options.get('include_open_ports', True)
        include_recommendations = report_options.get('include_recommendations', True)
        report_title = report_options.get('title', 'Rapport de Sécurité IoT')
        
        print(f"📊 Génération du rapport avec {len(scan_results)} appareils...")
        
        reporter = PDFReporter()
        filename = reporter.generate_report(
            scan_results,
            network_range=current_network_range,
            include_vulnerabilities=include_vulnerabilities,
            include_open_ports=include_open_ports,
            include_recommendations=include_recommendations,
            title=report_title
        )
        
        if not filename or not os.path.exists(filename):
            print(f"❌ Fichier non généré: {filename}")
            return jsonify({'error': 'Erreur lors de la génération du rapport PDF'}), 500
        
        print(f"✅ Rapport généré: {filename}")
        
        return send_file(
            filename,
            as_attachment=True,
            download_name=f"rapport_iot_securite_{time.strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        print(f"❌ Erreur génération rapport: {e}")
        return jsonify({'error': f'Erreur lors de la génération du rapport: {str(e)}'}), 500

@app.route('/generate-csv', methods=['GET', 'POST'])
def generate_csv():
    """Génération du rapport CSV"""
    global scan_results, current_network_range
    
    try:
        if not scan_results or (isinstance(scan_results, list) and len(scan_results) > 0 and 'error' in scan_results[0]):
            return jsonify({'error': 'Aucun résultat de scan disponible pour générer le CSV'}), 400
        
        print(f"📊 Génération du CSV avec {len(scan_results)} appareils...")
        
        # Créer le CSV directement
        csv_filename = create_basic_csv(scan_results, current_network_range)
        
        if not os.path.exists(csv_filename):
            return jsonify({'error': 'Erreur lors de la génération du fichier CSV'}), 500
        
        print(f"✅ CSV généré: {csv_filename}")
        
        return send_file(
            csv_filename,
            as_attachment=True,
            download_name=f"rapport_iot_securite_{time.strftime('%Y%m%d_%H%M%S')}.csv",
            mimetype='text/csv'
        )
    except Exception as e:
        print(f"❌ Erreur génération CSV: {e}")
        return jsonify({'error': f'Erreur lors de la génération du CSV: {str(e)}'}), 500

def create_basic_csv(devices, network_range):
    """Créer un CSV basique"""
    import csv
    
    filename = f"temp_rapport_iot_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['ip', 'mac', 'hostname', 'vendor', 'vulnerable', 'open_ports', 'services', 'recommendations']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for device in devices:
            # Préparer les données
            ports_ouverts = ','.join(map(str, device.get('open_ports', [])))
            services = ','.join(device.get('services', []))
            recommendations = '|'.join(device.get('recommendations', []))
            
            writer.writerow({
                'ip': device.get('ip', 'N/A'),
                'mac': device.get('mac', 'N/A'),
                'hostname': device.get('hostname', 'N/A'),
                'vendor': device.get('vendor', 'N/A'),
                'vulnerable': 'OUI' if device.get('vulnerable', False) else 'NON',
                'open_ports': ports_ouverts,
                'services': services,
                'recommendations': recommendations
            })
    
    return filename

@app.route('/history')
def scan_history():
    """Historique des scans"""
    try:
        history = db_manager.get_scan_history()
        return jsonify({
            'history': history,
            'count': len(history)
        })
    except Exception as e:
        return jsonify({'error': f'Erreur lors de la récupération de l\'historique: {str(e)}'}), 500

@app.route('/clear-results', methods=['POST'])
def clear_results():
    """Effacer les résultats actuels"""
    global scan_results, current_network_range
    scan_results = []
    current_network_range = ""
    return jsonify({'message': 'Résultats effacés avec succès'})

def validate_network_range(network_range):
    """Validation de la plage réseau"""
    try:
        # Validation basique format CIDR
        parts = network_range.split('/')
        if len(parts) != 2:
            return False
        
        ip_parts = parts[0].split('.')
        if len(ip_parts) != 4:
            return False
        
        # Validation des octets IP
        for octet in ip_parts:
            octet_num = int(octet)
            if octet_num < 0 or octet_num > 255:
                return False
        
        # Validation du masque
        mask = int(parts[1])
        if mask < 0 or mask > 32:
            return False
            
        return True
    except Exception:
        return False

if __name__ == '__main__':
    print("🚀 Démarrage de l'application RAPPIOT...")
    print("📊 Interface disponible sur: http://0.0.0.0:5000")
    print("🔍 Scanner de sécurité IoT prêt")
    app.run(debug=True, host='0.0.0.0', port=5000)
                                                        