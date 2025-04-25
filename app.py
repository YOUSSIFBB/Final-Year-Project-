
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from models import initialize_user_db, register_user, authenticate_user
import os
import sqlite3
import nmap  # Import the nmap library
import requests
import time
import hashlib
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = 'My_secret_key'
CORS(app)  # Allow cross-origin requests

# Initialize database for storage of scan results
initialize_user_db()
DATABASE_PATH = os.path.join("databaseF", "scan_results.db")
if not os.path.exists(DATABASE_PATH):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE results (id INTEGER PRIMARY KEY, target TEXT, scan_output TEXT)''')
    conn.commit()
    conn.close()

# Configuration for file scanning
VT_API_KEY = '56c33f60080c531466befc122e765ca92677231af7aae620af3e2642b4a3f936'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25MB limit

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def get_file_hashes(filepath):
    hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}

@app.route('/')
def home():
    if 'user' in session:
        return render_template('index.html', user=session['user'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate_user(username, password)
        if user:
            session['user'] = username
            flash('Welcome back!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if register_user(username, password):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists!', 'error')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/scan')
def scan_page():
    if 'user' not in session:
        flash('Please log in to access this feature.', 'error')
        return redirect(url_for('login'))
    return render_template('scan.html')

@app.route('/trafficMonitor')
def vscan_page():
    return render_template('trafficMonitor.html')

@app.route('/nmap-scan', methods=['POST'])
def nmap_scan():
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized. Please log in.'}), 401

    target = request.json.get('target', '127.0.0.1')
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-sV')
        scan_results = []

        for host in nm.all_hosts():
            host_info = {
                'host': host,
                'status': nm[host].state(),
                'protocols': []
            }
            for protocol in nm[host].all_protocols():
                ports = []
                for port in nm[host][protocol].keys():
                    ports.append({
                        'port': port,
                        'state': nm[host][protocol][port]['state'],
                        'service': nm[host][protocol][port]['name']
                    })
                host_info['protocols'].append({
                    'protocol': protocol,
                    'ports': ports
                })
            scan_results.append(host_info)

        return jsonify({'success': True, 'results': scan_results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/capturePackets', methods=['GET'])
def capture_packets():
    from scapy.all import sniff

    def packet_to_dict(pkt):
        return {
            "protocol": pkt.summary().split(" ")[0],
            "source": pkt.src if hasattr(pkt, "src") else "Unknown",
            "destination": pkt.dst if hasattr(pkt, "dst") else "Unknown",
            "details": pkt.summary()
        }

    packets = sniff(count=100, timeout=10)
    packet_data = [packet_to_dict(pkt) for pkt in packets]
    return jsonify(packet_data)

@app.route('/file-scan', methods=['GET', 'POST'])
def file_scan():
    if 'user' not in session:
        flash('Please log in to access this feature.', 'error')
        return redirect(url_for('login'))

    result = None
    filename = None

    if request.method == 'POST':
        uploaded_file = request.files.get('file')

        if not uploaded_file:
            flash('No file uploaded!', 'error')
            return redirect(request.url)

        filename = uploaded_file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Try to save the file to disk
        try:
            uploaded_file.save(file_path)
        except OSError as e:
            if "Invalid argument" in str(e) or "cannot find the file" in str(e).lower():
                result = {
                    'harmless': 0,
                    'malicious': 1,
                    'suspicious': 0,
                    'undetected': 0,
                    'timeout': 0,
                    'total': 1,
                    'scan_time': 0,
                    'threat_percentage': 100,
                    'verdict': "🔥 Dangerous (blocked by antivirus)",
                    'size': 0,
                    'type': 'unknown',
                    'hashes': {
                        'md5': 'N/A',
                        'sha1': 'N/A',
                        'sha256': 'N/A'
                    },
                    'names': [filename],
                    'type_description': 'Unavailable',
                    'type_tag': 'blocked',
                    'creation_date': 'Unknown',
                    'last_submission_date': 'Unknown',
                    'publisher': 'N/A',
                    'signature_status': 'Unsigned',
                    'tags': ['blocked', 'quarantined', 'simulated']
                }
                flash('⚠️ The file was blocked by antivirus and could not be scanned. This is a simulated result.', 'error')
                return render_template('fileScan.html', result=result, filename=filename)
            else:
                flash(f"File access error: {str(e)}", "error")
                return redirect(request.url)

        start_time = time.time()

        # Try to upload the file to VirusTotal
        try:
            with open(file_path, 'rb') as f:
                upload_response = requests.post(
                    'https://www.virustotal.com/api/v3/files',
                    headers={'x-apikey': VT_API_KEY},
                    files={'file': f}
                )
        except (OSError, IOError) as e:
            if "Invalid argument" in str(e) or "cannot find the file" in str(e).lower():
                result = {
                    'harmless': 0,
                    'malicious': 1,
                    'suspicious': 0,
                    'undetected': 0,
                    'timeout': 0,
                    'total': 1,
                    'scan_time': 0,
                    'threat_percentage': 100,
                    'verdict': "🔥 Dangerous (blocked by antivirus)",
                    'size': 0,
                    'type': 'unknown',
                    'hashes': {
                        'md5': 'N/A',
                        'sha1': 'N/A',
                        'sha256': 'N/A'
                    },
                    'names': [filename],
                    'type_description': 'Unavailable',
                    'type_tag': 'blocked',
                    'creation_date': 'Unknown',
                    'last_submission_date': 'Unknown',
                    'publisher': 'N/A',
                    'signature_status': 'Unsigned',
                    'tags': ['blocked', 'quarantined', 'simulated']
                }
                flash('⚠️ The file was blocked by antivirus and could not be uploaded. This is a simulated result.', 'error')
                return render_template('fileScan.html', result=result, filename=filename)
            else:
                flash(f"Error sending file to VirusTotal: {str(e)}", "error")
                return redirect(request.url)

        if upload_response.status_code != 200:
            flash('Error uploading file to VirusTotal.', 'error')
            return redirect(request.url)

        file_id = upload_response.json()['data']['id']

        report_response = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{file_id}',
            headers={'x-apikey': VT_API_KEY}
        )

        if report_response.status_code != 200:
            flash('Error retrieving scan report.', 'error')
            return redirect(request.url)

        scan_time = round(time.time() - start_time, 2)
        file_info = report_response.json()['data']['attributes']
        stats = file_info['stats']
        total = stats['harmless'] + stats['malicious'] + stats['suspicious'] + stats['undetected'] + stats['timeout']
        threats = stats['malicious'] + stats['suspicious']
        threat_percentage = round((threats / total) * 100, 1) if total > 0 else 0

        if threat_percentage <= 10:
            verdict = "✅ Safe"
        elif threat_percentage <= 40:
            verdict = "⚠️ Caution"
        else:
            verdict = "🔥 Dangerous"

        result = {
            'harmless': stats['harmless'],
            'malicious': stats['malicious'],
            'suspicious': stats['suspicious'],
            'undetected': stats['undetected'],
            'timeout': stats['timeout'],
            'total': total,
            'scan_time': scan_time,
            'threat_percentage': threat_percentage,
            'verdict': verdict,
            'size': os.path.getsize(file_path),
            'type': uploaded_file.content_type,
            'hashes': get_file_hashes(file_path),
            'names': file_info.get('names', []),
            'type_description': file_info.get('type_description', 'Unknown'),
            'type_tag': file_info.get('type_tag', 'Unknown'),
            'creation_date': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(file_info.get('creation_date', 0))),
            'last_submission_date': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(file_info.get('last_submission_date', 0))),
            'publisher': file_info.get('signature_info', {}).get('publisher', 'N/A'),
            'signature_status': file_info.get('signature_info', {}).get('signer', 'Unsigned'),
            'tags': file_info.get('tags', [])
        }

    return render_template('fileScan.html', result=result, filename=filename)



if __name__ == '__main__':
    app.run(debug=True)
