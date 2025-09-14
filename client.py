from scapy.all import rdpcap, UDP, DNS
from datetime import datetime
import socket
import pandas as pd

pcap_file = "/Users/sohamshrivastava/Library/CloudStorage/OneDrive-iitgn.ac.in/Semester 5/CN/0.pcap"
server_ip = "127.0.0.1"
server_port = 12345

def send_to_server(payload):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((server_ip, server_port))
            s.sendall(payload)
            data = s.recv(1024)
            return data.decode('utf-8', errors='ignore')
        except ConnectionRefusedError:
            print("connection to server failed.")
            return None

def main():
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"pcap file '{pcap_file}' not found.")
        return

    dns_query_id = 0
    results_data = []

    print("Starting to process packets: \n")
    print()

    for packet in packets:
        if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(UDP) and packet[UDP].dport == 53:
            now = datetime.now()
            hh = now.strftime("%H")
            mm = now.strftime("%M")
            ss = now.strftime("%S")

            id_str = f"{dns_query_id:02d}"
            custom_header = f"{hh}{mm}{ss}{id_str}"

            header_bytes = custom_header.encode('utf-8')
            orgnl_dns_bytes = bytes(packet[DNS])
            payload = header_bytes + orgnl_dns_bytes

            resolved_ip = send_to_server(payload)
            if resolved_ip:
                domain_name = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                print(f"Query ID: {dns_query_id}, Domain: {domain_name}, Resolved IP: {resolved_ip}")
                results_data.append({"Custom Header value (HHMMSSID)": custom_header,"Domain name": domain_name,"Resolved IP address": resolved_ip})
            
            dns_query_id += 1
    report_df = pd.DataFrame(results_data)
    print("summary of queries:\n")
    print(report_df.to_string())

    report_df.to_csv("dns_report.csv", index=False)
    print("report saved as 'dns_report.csv' \n")

if __name__ == "__main__":
    main()