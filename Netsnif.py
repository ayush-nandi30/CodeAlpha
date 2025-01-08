from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, ICMP
from prettytable import PrettyTable
from datetime import datetime

# Table to display packets
packet_table = PrettyTable()
packet_table.field_names = ["Time", "Src IP", "Dst IP", "Protocol", "Src Port", "Dst Port", "Info"]

def parse_packet(packet):
    """
    Parse captured packet and extract simplified information.
    """
    time = datetime.now().strftime("%H:%M:%S")  # Capture time
    src_ip, dst_ip, protocol, src_port, dst_port, info = "-", "-", "-", "-", "-", "Other"

    # Ethernet layer (for additional context, optional)
    if Ether in packet:
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst
        # Ethernet details can be added here if needed

    # IP Layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(packet[IP].proto, "Other")

        # TCP Layer
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            info = f"TCP connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}"

        # UDP Layer
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            info = f"UDP datagram from {src_ip}:{src_port} to {dst_ip}:{dst_port}"

        # ICMP Layer
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            if icmp_type == 8:
                info = f"ICMP Echo Request from {src_ip} to {dst_ip}"
            elif icmp_type == 0:
                info = f"ICMP Echo Reply from {src_ip} to {dst_ip}"
            else:
                info = f"ICMP Type {icmp_type} from {src_ip} to {dst_ip}"

    # ARP Layer
    elif ARP in packet:
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        protocol = "ARP"
        info = f"ARP request: {src_ip} is asking for {dst_ip}" if packet[ARP].op == 1 else f"ARP reply: {src_ip} has {dst_ip}"

    # Add packet details to the table
    packet_table.add_row([time, src_ip, dst_ip, protocol, src_port, dst_port, info])
    print(packet_table)

def main():
    """
    Start packet sniffing with simplified information output.
    """
    print("Starting simplified network sniffer...")
    print("Press Ctrl+C to stop.")
    try:
        # Sniff packets and call the parse_packet function for each
        sniff(filter="ip or arp", prn=parse_packet, store=0)
    except KeyboardInterrupt:
        print("\nStopping network sniffer...")
        print(packet_table)
        sys.exit()

if __name__ == "__main__":
    main()
