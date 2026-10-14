

from scapy.all import IP, TCP
from ids import analyze_packet

source_ip = "192.0.2.10"
destination_ip = "192.0.2.20"

print("Testing actual IDS port-scan detection...")

for port in range(20, 35):
    packet = IP(
        src=source_ip,
        dst=destination_ip
    ) / TCP(
        dport=port,
        flags="S"
    )

    analyze_packet(packet)

print("Test completed.")
