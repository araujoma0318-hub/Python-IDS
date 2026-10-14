
from scapy.all import IP, TCP
from ids import analyze_packet

# Simulated source and destination
source_ip = "192.0.2.10"
destination_ip = "192.0.2.20"

print("Testing actual IDS SYN flood detection...")

# Simulate 25 SYN packets to one destination port
for i in range(25):
    packet = IP(
        src=source_ip,
        dst=destination_ip
    ) / TCP(
        sport=40000 + i,
        dport=80,
        flags="S"
    )

    analyze_packet(packet)

print("Test completed.")
