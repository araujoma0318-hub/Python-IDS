
# Python Intrusion Detection System (IDS)

## Project Overview
A Python-based network intrusion detection system that
monitors network traffic and identifies suspicious activity.

The project combines rule-based detection, statistical
traffic analysis, and machine learning.

## Features
- Live packet capture using Scapy AsyncSniffer
- SYN flood detection
- Port-scan detection
- Packet-rate monitoring
- Average packet-size tracking
- Statistical anomaly detection
- Machine-learning anomaly detection using Isolation Forest
- Security alert logging
- Thread-safe traffic monitoring

## Technologies Used
- Python
- Scapy
- Pandas
- Scikit-learn
- Joblib
- Npcap (Windows)

## How It Works
The IDS captures network packets and monitors traffic
statistics approximately every second.

Rule-based detection examines TCP SYN activity for
possible SYN floods and port scans.

An Isolation Forest model evaluates packet rates and
average packet sizes to identify unusual traffic patterns.

Detected anomalies are reported in the terminal and
recorded in alerts.log.

## Limitations
- Machine-learning anomalies are not confirmed attacks.
- Detection thresholds may require tuning.
- This project is intended for educational use and
  monitoring networks where permission has been granted.

## Installation

### 1. Requirements
- Python 3.13
- Npcap (Windows)
- Administrator privileges may be required for packet capture.

### 2. Clone the Repository
```bash
git clone https://github.com/YOUR-USERNAME/Python-IDS.git
cd Python-IDS
```

### 3. Create a Virtual Environment
```powershell
python -m venv .venv
```

### 4. Activate the Virtual Environment

On Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```

### 5. Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 6. Run the IDS
```powershell
python ids.py
```
Press Ctrl+C to stop monitoring.
Only capture traffic on networks you own or have permission to monitor.


## Machine-Learning Model

The IDS uses an Isolation Forest model from Scikit-learn
to identify unusual network traffic patterns.

The model was trained using traffic statistics collected
from network monitoring.

### Features Used
- Packet rate (packets per second)
- Average packet size (bytes)

### Training
The training script is `train_real_data.py`.

To retrain the model using your own collected traffic data:

1. Run the IDS to collect traffic measurements.
2. Stop the IDS using Ctrl+C.
3. Run the following command:

    python train_real_data.py

The script saves the trained model as `ids_model.pkl`.

### Important Notes
- The model uses unsupervised learning.
- Anomaly predictions do not necessarily indicate attacks.
- Only load `.pkl` model files from trusted sources.
- The model may require retraining for different networks.
