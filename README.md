ThreatGuard - Comprehensive Cybersecurity Toolkit

Project Overview:

**ThreatGuard** is a versatile cybersecurity toolkit designed to provide users with multiple layers of digital protection. It is a complete suite of security tools, including file scanning, URL threat detection, phishing detection, real-time traffic monitoring, and more.

📌 Key Features:
* User Authentication System:**
* Secure login and registration system with hashed passwords (SQLite).
* Robust password strength validation.

File Scanner
  * Scans uploaded files for malware using VirusTotal.
  * Supports multiple file types and provides detailed scan results.
  * Clean, Suspicious, and Malicious verdicts.

URL Scanner:
  * Analyzes URLs for potential threats.
  * Categorizes URLs as Safe, Low Risk, or High Risk.
  * Supports live URL screenshots using ScrapFly.
    
Phishing Detection:
  * Detects phishing content in email images (PNG, JPEG, PDF).
  * Uses OCR (Optical Character Recognition) for text extraction.
  * Highlights suspicious phrases and links.

Traffic Monitor (Real-Time Network Analysis):
  * Captures and analyzes network packets (TCP, UDP, ICMP).
  * Provides live traffic analysis.
  * Allows saving captured packets to PCAP files.

  Interactive User Dashboard:
  * Displays scan history and statistics.
  * Provides real-time visualization of security data.







## 🌐 Installation Instructions

### Prerequisites:

* Python 3.8+
* Virtual environment (recommended)
* Required Python libraries (listed in `requirements.txt`)

### Setup:

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/ThreatGuard.git
   cd ThreatGuard
   ```

2. **Create a Virtual Environment for testing: 

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt (Incluide in insillation folder)
   ```

4. **Set Up the Database:**

   ```bash
   python -m ThreatGuard.models  # This will initialise the user database
   ```

---

## Usage Guide📖

### Running the Application:

```bash
python -m ThreatGuard.main
```

### Logging In:

* Use the Register button to create an account.
* Login using your credentials.

### Scanning Files:

* Navigate to the "File Scanner" section.
* Upload a file to scan for malware.

### Scanning URLs:

* Navigate to the "URL Scanner" section.
* Enter the URL you want to scan.

### Monitoring Network Traffic:

* Navigate to the "Traffic Monitor" section.
* Start the capture to analyze real-time traffic.

### Phishing Detection: 
*Go to the "Phishing Scanner" section.
*Upload an email screenshot or PDF.
*Detects phishing content using OCR (Optical Character Recognition).
*Highlights suspicious phrases and links.

### Real-Time Traffic Monitoring:

*Go to the "Traffic Monitor" section.
*Start the capture to monitor network traffic (TCP, UDP, ICMP).
*View packet details in real-time.
*Save captured packets as a PCAP file.

