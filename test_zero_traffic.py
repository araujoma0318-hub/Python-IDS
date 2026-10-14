
import time
import ids

print("Testing an interval with zero packets...")

with ids.packet_lock:
    ids.packet_count = 0
    ids.packet_sizes.clear()
    ids.interval_start = time.monotonic() - 1

ids.check_traffic_interval()

print("Zero-traffic test completed.")
print("Baseline history:", ids.packet_rate_history)