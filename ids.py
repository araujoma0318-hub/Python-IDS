

from scapy.all import sniff, AsyncSniffer, IP, TCP
from collections import defaultdict
import time
import threading
import csv
import joblib
import pandas as pd

# Track SYN packets by source IP address
syn_tracker = defaultdict(list)


# Track destination ports contacted by each source
port_tracker = defaultdict(list)

# Remember when each source last triggered a port-scan alert
last_port_alert = {}


# Track the last SYN flood alert for each source
last_syn_alert = {}


# Wait 30 seconds before repeating an alert
ALERT_COOLDOWN = 30

# Remember when the last ML alert occurred
last_ml_alert = 0

# Load the trained machine-learning model
ml_model = joblib.load("ids_model.pkl")

print("Machine-learning IDS model loaded!")

#packet rate tracking
packet_count = 0
packet_lock = threading.Lock()

interval_start = time.monotonic()
packet_sizes = []

PACKET_RATE_THRESHOLD = 50 # packets per second

# Store previous packet-rate measurements
packet_rate_history = []

# Number of measurements to keep
BASELINE_WINDOW = 10

# How much higher than normal triggers an alert
ANOMALY_MULTIPLIER = 3

from datetime import datetime

def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = f"[{timestamp}] [ALERT] {message}"

    print(alert)

    with open("alerts.log", "a", encoding="utf-8") as file:
        file.write(alert + "\n")

def check_traffic_interval():
    global packet_count, interval_start, last_ml_alert

    with packet_lock:
        interval_end = time.monotonic()
        elapsed_time = interval_end - interval_start
        count = packet_count
        packet_rate = count / elapsed_time if elapsed_time > 0 else 0
        if packet_sizes:
            average_packet_size = sum(packet_sizes) / len(packet_sizes)
        else:
            average_packet_size = 0

        packet_count = 0
        packet_sizes.clear()
        interval_start = interval_end
    print(f"Packets counted: {count}")
    print(f"Elapsed time: {elapsed_time:.4f} seconds")
    print(f"Packet rate: {packet_rate:.2f} packets/sec")
    print(f"Average packet size: {average_packet_size:.2f} bytes")

    traffic_feature = [packet_rate, average_packet_size]
    ml_data = pd.DataFrame(
        [traffic_feature],
        columns=["packet_rate", "average_packet_size"]
    )

    ml_prediction = ml_model.predict(ml_data)[0]
    ml_alert_logged = False
    if ml_prediction == -1:
        print("[ML] Unusual traffic detected!")

        ml_current_time = time.monotonic()

        if ml_current_time - last_ml_alert > ALERT_COOLDOWN:
            log_alert(
                f"ML anomaly: {packet_rate:.2f} packets/sec, "
                f"average packet size: {average_packet_size:.2f} bytes"
            )
            last_ml_alert = ml_current_time
            ml_alert_logged = True
    else:
        print("[ML] Traffic is normal.")

        is_anomaly = False
        if len(packet_rate_history) < 5:
            if packet_rate > PACKET_RATE_THRESHOLD:
                is_anomaly = True
                if not ml_alert_logged:
                    log_alert(
                        f"High traffic during basline collection: "
                        f"{packet_rate:.2f} packets/sec"
                    )
        else:
            baseline = sum(packet_rate_history) / len(packet_rate_history)
            print(f"Baseline: {baseline:.2f} packets/sec")

            if packet_rate > baseline * ANOMALY_MULTIPLIER:
                is_anomaly = True

                if not ml_alert_logged:
                    log_alert(
                        f"Traffic anomaly detected! "
                        f"Current: {packet_rate:.2f} packets/sec, "
                        f"Baseline: {baseline:.2f} packets/sec"
                    )
        if not is_anomaly and count > 0:
            packet_rate_history.append(packet_rate)

        if len(packet_rate_history) > BASELINE_WINDOW:
            packet_rate_history.pop(0)

        with open("traffic_data.csv","a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(traffic_feature)

def analyze_packet(packet):
    global packet_count

    with packet_lock:
        packet_count += 1
        packet_sizes.append(len(packet))

    current_time = time.monotonic()

    if IP in packet and TCP in packet:
        source_ip = packet[IP].src
        tcp_flags = packet[TCP].flags
        destination_ip = packet[IP].dst

        connection = (source_ip, destination_ip)

        destination_port = packet[TCP].dport
        current_time = time.time()

        port_tracker[connection] = [
            (timestamp, port)
            for timestamp, port in port_tracker[connection]
            if current_time - timestamp < 10
        ]
        if tcp_flags == 0x02:
            port_tracker[connection].append((current_time, destination_port))

        unique_ports = {port for timestamp, port in port_tracker[connection]}


        if len(unique_ports) > 10:
            last_alert = last_port_alert.get(connection, 0)

            if current_time - last_alert >= ALERT_COOLDOWN:
                log_alert(f"Possible port scan from {source_ip} targeting {destination_ip}")
                last_port_alert[connection] = current_time

            port_tracker[connection].clear()




        # Check for a SYN packet without ACK
        if tcp_flags == 0x02:
            current_time = time.time()

            # Keep SYN timestamps from the last 10 seconds
            syn_tracker[source_ip] = [
                t for t in syn_tracker[source_ip]
                if current_time - t < 10
            ]

            syn_tracker[source_ip].append(current_time)

            # Alert if more than 20 SYN packets

            if len(syn_tracker[source_ip]) > 20:
                last_alert = last_syn_alert.get(source_ip, 0)

                if current_time - last_alert >= ALERT_COOLDOWN:
                    log_alert(f"Possible SYN flood from {source_ip}")
                    last_syn_alert[source_ip] = current_time

def monitor_traffic():
    while True:
        time.sleep(1)
        check_traffic_interval()

if __name__ == "__main__":
    print("IDS is monitoring network traffic...")
    sniff = AsyncSniffer(prn=analyze_packet, store=False)
    sniff.start()
    try:
        monitor_traffic()
    except KeyboardInterrupt:
        print("Stopping IDS...")
    finally:
        if sniff.running:
            sniff.stop()
        print("IDS stopped.")