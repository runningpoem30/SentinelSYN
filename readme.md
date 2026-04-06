SentinelSYN: Real-Time TCP SYN Flood Detection System
SentinelSYN is a high-performance Network Intrusion Detection System (NIDS) built in C++ using the libpcap library. It is designed to monitor live network traffic, analyze TCP handshake patterns, and identify SYN Flood Denial-of-Service (DoS) attacks in real-time.

🚀 Project Overview
In a standard TCP three-way handshake, a client sends a SYN packet, the server responds with SYN-ACK, and the client completes the connection with an ACK.

A SYN Flood attack exploits this by sending thousands of SYN packets but never sending the final ACK. This leaves the server with thousands of "half-open" connections, consuming all available memory and crashing the service. SentinelSYN acts as a shield by monitoring these incoming requests and flagging IPs that exceed a safe threshold.

🛠️ Tech Stack
Language: C++ (Core Logic & Packet Processing)

Library: libpcap (Low-level packet capturing)

Testing: Python 3 + Scapy (Traffic Generation)

Environment: macOS / Linux (Systems Programming)

🏗️ System Architecture
The project is divided into two main components:

The Detector (C++): * Opens a live stream on the network interface (e.g., en0).

Filters for IPv4 and TCP protocols.

Extracts the Source IP and checks the TCP Control Flags.

Maintains a frequency map to track the "SYN-rate" per IP.

The Attacker (Python): * A custom script that bypasses the standard OS network stack to forge raw TCP packets.

Simulates a high-intensity flood to validate the detector's logic.

📋 Features
Real-Time Packet Sniffing: Zero-latency monitoring of network interfaces.

Threshold-Based Detection: Automatically flags an IP after N suspicious packets (Default: 20).

Live Console Dashboard: Color-coded terminal logs for instant visual feedback.

Network Header Parsing: Manual decoding of Ethernet, IP, and TCP headers.


Prerequisites : 
# Install pcap headers
brew install libpcap

# Setup Python Virtual Environment for Scapy
python3 -m venv venv
source venv/bin/activate
pip install scapy


Compilation
make


Execution
sudo ./sentinel en0

📊 Result Analysis (For Report)
The system successfully differentiates between normal traffic and an attack state.

Normal State: The monitor logs incoming SYN packets with an incremental count.

Attack State: Once the frequency exceeds the defined threshold, the system triggers a CRITICAL ALERT.

Impact: By identifying the attacker's IP instantly, this system provides the necessary data for a firewall (like iptables) to drop the malicious traffic.

📈 Future Scope
Automated Mitigation: Integrate with pf (macOS) or iptables (Linux) to automatically block the flagged IP.

Packet Logging: Export attack logs to a .pcap file for forensic analysis.

Web Dashboard: Create a GUI to visualize traffic spikes using WebSockets.


Developed by : 
Bhunesh Pratap Singh 
Archie Tansaria 
Arya Anand Pathak 