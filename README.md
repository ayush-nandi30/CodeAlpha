
# CodeAlpha INTERNSHIP

#TASK 1
Basic Network Sniffer:-
Build a network sniffer in Python that captures and analyzes network traffic. This project will help you understand how data flows on a network and how network packets are structured.

Solutions

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


![image](https://github.com/user-attachments/assets/5e4f714e-f438-4293-a831-1de79f194bb5)

#TASK2




#TASK3 {The task has been submit in the form of Task_Report in pdf.}

Secure Coding Review:-
Choose a programming language and application. Review the code for security vulnerabilities andprovide recommendations for secure coding practices. Use tools like static code analyzers or manual code review.

I have take a random application code for the anaylsis from the open source 

CODE:-
from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secure connection to the database
def get_db_connection():
    conn = sqlite3.connect('example.db')
    conn.row_factory = sqlite3.Row
    return conn

# Secure user data retrieval
@app.route('/user/<username>', methods=['GET'])
def get_user(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if user is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"username": user["username"]})  # Expose only necessary fields

# Secure user addition
@app.route('/user', methods=['POST'])
def add_user():
    data = request.json
    username = data['username']
    password = data['password']
    hashed_password = generate_password_hash(password)  # Hash the password
    conn = get_db_connection()
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()
    return jsonify({"message": "User added"}), 201

if __name__ == "__main__":
    app.run()  # Remove debug=True for production


After this I use the Bandit tool (Static Analysis Tool) for Code Review 

OUTPUT:-
![image](https://github.com/user-attachments/assets/f933129e-3c2a-4d51-a35c-550884d38fe0)

![image](https://github.com/user-attachments/assets/1a20888b-7975-4cd5-bc67-0411ed2e2888)

![image](https://github.com/user-attachments/assets/bc698a88-a174-413f-8a00-68dcedfd713e)


