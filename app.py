from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from models import initialize_user_db, register_user, authenticate_user
import os
import sqlite3
import nmap  # Import the nmap library
from flask_cors import CORS



app = Flask(__name__)
app.secret_key = 'My_secret_key'



CORS(app)  # Allow cross-origin requests


#Initialise database for storage of scan resutls (not used, fucntionality deleted)
initialize_user_db()
DATABASE_PATH = os.path.join("databaseF", "scan_results.db")
if not os.path.exists(DATABASE_PATH):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE results (id INTEGER PRIMARY KEY, target TEXT, scan_output TEXT)''')
    conn.commit()
    conn.close()
    
#render main page
@app.route('/')
def home():
    if 'user' in session:
        return render_template('index.html', user=session['user'])
    return redirect(url_for('login'))

#render login page 
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

#render regestration page
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

#render logout page
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

#render Scan page 
@app.route('/scan')
def scan_page():
    if 'user' not in session:
        flash('Please log in to access this feature.', 'error')
        return redirect(url_for('login'))
    return render_template('scan.html')

#render montior page for packet sniffing 
@app.route('/trafficMonitor')
def vscan_page():
    return render_template('trafficMonitor.html')


#post request for vulranability port scanning 
@app.route('/nmap-scan', methods=['POST'])
def nmap_scan():
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized. Please log in.'}), 401

    print(f"Received POST request: {request.json}")  # debugging request log in cmd
    target = request.json.get('target', '127.0.0.1')  # handel jason input and set target to my local hsotg machine  127.0.0.1
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


#temporaryr live packet sniffing solution 
@app.route('/capturePackets', methods=['GET'])
def capture_packets():
    import time
    from scapy.all import sniff

    # Extend capture duration or limit to capture more packets
    def packet_to_dict(pkt):
        return {
            "protocol": pkt.summary().split(" ")[0],
            "source": pkt.src if hasattr(pkt, "src") else "Unknown",
            "destination": pkt.dst if hasattr(pkt, "dst") else "Unknown",
            "details": pkt.summary()
        }

    packets = sniff(count=100, timeout=10)  #capute packets for a number of seconds
    packet_data = [packet_to_dict(pkt) for pkt in packets]
    return jsonify(packet_data)



if __name__ == '__main__':
    app.run(debug=True)
