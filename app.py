from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from models import initialize_user_db, register_user, authenticate_user
import os
import sqlite3
import nmap  # Import the nmap library
import requests
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

# Routes
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

    print(f"Received POST request: {request.json}")
    target = request.json.get('target', '127.0.0.1')
    nm = nmap.PortScanner()
    try:
        print(f"Starting Nmap scan on target: {target}")
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

        print(f"Scan Results: {scan_results}")
        return jsonify({'success': True, 'results': scan_results})
    except Exception as e:
        print(f"Error during scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/capturePackets', methods=['GET'])
def capture_packets():
    import time
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
        uploaded_file.save(file_path)

        with open(file_path, 'rb') as f:
            upload_response = requests.post(
                'https://www.virustotal.com/api/v3/files',
                headers={'x-apikey': VT_API_KEY},
                files={'file': f}
            )

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

        result = report_response.json()['data']['attributes']['stats']

    return render_template('fileScan.html', result=result, filename=filename)

if __name__ == '__main__':
    app.run(debug=True)
