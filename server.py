import socket
import json
from scapy.all import DNS


host = '127.0.0.1'
port = 12345


#15 IPs for maintaing load balancing
ip_pool = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

# header format: HHMMSSID
def get_resolved_ip(header):
    try:
        hour = int(header[0:2])
        query_id = int(header[6:8])

    except(ValueError, IndexError):
        print("Invalid Header")

    #determining ip pool through hour
    ip_pool_start = 0
    if hour >= 4 and hour <= 11:
        ip_pool_start = 0
    elif hour >= 12 and hour <= 19:
        ip_pool_start = 5
    else:
        ip_pool_start = 10

    #select ip from pool
    offset = query_id % 5
    final_idx = ip_pool_start + offset


    #boundary check for index
    if final_idx >= 0 and final_idx < len(ip_pool):
        return ip_pool[final_idx]
    else:
        print("Index out of range") 
        return None   

def server():
    # create a tcp/ip socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"server listening on {host}:{port}")

        while True: #wait for connection
            conn, addr = s.accept()
            with conn:
                print(f"connected by {addr}")
                data = conn.recv(2048) # receive data from client 
                if not data:
                    break
                
                header_bytes = data[:8] #first 8 bytes of header
                dns_packet_bytes = data[8:] #rest is dns query

                custom_header = header_bytes.decode('utf-8', errors='ignore')

                #parsing dns query 
                dns_query = DNS(dns_packet_bytes)
                domain_name = dns_query.qd.qname.decode('utf-8', errors='ignore')
                resolved_ip = get_resolved_ip(custom_header) #getting resolved ip

                print(f"received query for: {domain_name}, with header: {custom_header}")
                print(f"resolved ip: {resolved_ip}")
                if resolved_ip:    
                    conn.sendall(resolved_ip.encode('utf-8')) #send resolved IP back to client
                    print("response sent back to client\n")
                else:
                    print("Failed to resolve IP\n")    

if __name__ == "__main__":
    server()