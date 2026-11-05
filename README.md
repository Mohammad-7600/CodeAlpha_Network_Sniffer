# CodeAlpha_Network_Sniffer
Basic Network Sniffer using Scapy - CodeAlpha Task 1

#Author
#Mohammad Balva
#CodeAlpha Cyber Security Intern (November 2026)

# CodeAlpha Cyber Security Internship
## Task 1: Basic Network Sniffer

### Project Description
A Python-based network packet sniffer built using the Scapy library. It captures live network traffic and displays useful information such as source/destination IP addresses, protocols, ports, TCP flags, and payload preview.

### Features
- Live packet capture on any network interface
- Displays Source IP, Destination IP, Protocol, and Ports
- TCP Flags and ICMP Type/Code support
- Payload preview (ASCII / Hex)
- BPF filter support
- Summary statistics (protocol counts + Top Source/Destination IPs)
- Colored terminal output

### Requirements
- Python 3.7+
- Scapy library
- Root / Administrator privileges

### Installation
```bash
pip install scapy
sudo python3 network_sniffer.py
sudo python3 network_sniffer.py -i eth0 -c 50
sudo python3 network_sniffer.py --filter "tcp port 80"
