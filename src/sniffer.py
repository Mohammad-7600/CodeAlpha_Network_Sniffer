
"""
CodeAlpha Cyber Security Internship
Project 1: Basic Network Sniffer

Python + Scapy
"""

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS
from datetime import datetime

PACKET_COUNT = 50


def identify_protocol(packet):
    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        if packet.haslayer(DNS):
            return "DNS/UDP"
        return "UDP"

    return "OTHER"


def analyze_packet(packet):

    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst

    elif packet.haslayer(IPv6):
        source = packet[IPv6].src
        destination = packet[IPv6].dst

    else:
        return

    print("\n" + "=" * 55)
    print("NETWORK PACKET DETECTED")
    print("=" * 55)

    print("Time:", datetime.now().strftime("%H:%M:%S"))
    print("Source IP:", source)
    print("Destination IP:", destination)
    print("Protocol:", identify_protocol(packet))
    print("Packet Size:", len(packet), "bytes")

    if packet.haslayer(TCP):
        print("Source Port:", packet[TCP].sport)
        print("Destination Port:", packet[TCP].dport)

    elif packet.haslayer(UDP):
        print("Source Port:", packet[UDP].sport)
        print("Destination Port:", packet[UDP].dport)

    print("=" * 55)


def start_sniffer():

    print("\nCODEALPHA BASIC NETWORK SNIFFER")
    print("Starting packet capture...")
    print("Maximum packets:", PACKET_COUNT)
    print("Press Ctrl+C to stop.")

    try:
        sniff(
            prn=analyze_packet,
            count=PACKET_COUNT,
            store=False
        )

        print("Capture completed.")

    except KeyboardInterrupt:
        print("Capture stopped by user.")

    except Exception as error:
        print("Capture error:", error)


if __name__ == "__main__":
    start_sniffer()
