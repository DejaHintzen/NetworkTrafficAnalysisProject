from scapy.all import rdpcap, TCP, IP, DNS, UDP, Raw

def detect_anomalous_packets(pcap_file):
    print(f"Analyzing {pcap_file} for anomalous packets.")
    packets = rdpcap(pcap_file)
    for packet in packets:
        #TCP packets with unusual flags or non-standard sizes.
        if TCP in packet:
            tcp = packet[TCP]
            if tcp.flags not in ['S', 'A', 'PA', 'RA'] or len(packet) > 1500:
                print(f"Anomalous TCP packet detected: {packet.summary()}")

def detect_dns_anomalies(pcap_file):
    print(f"Analyzing {pcap_file} for DNS anomalies.")
    packets = rdpcap(pcap_file)
    for packet in packets:
        if DNS in packet and packet[DNS].qr == 0:  # DNS query
            dns = packet[DNS]
            #Query types other than A (IPv4 address) records
            if dns.qd.qtype != 1:  #Type A is 1
                print(f"DNS anomaly detected (uncommon query type): {packet.summary()}")
            #Look for unusual domain names

def detect_protocol_abnormalities_from_pcap(pcap_file):
    print(f"Analyzing {pcap_file} for protocol abnormalities.")
    packets = rdpcap(pcap_file)
    for packet in packets:
        #Checks for protocol abnormalities (not on standard HTTP/HTTPS ports)
        if TCP in packet:
            if packet[TCP].dport not in [80, 443] and packet[TCP].sport not in [80, 443]:
                print(f"Protocol abnormality detected: {packet.summary()}")


def detect_malware_infections(pcap_file):
    print(f"Analyzing {pcap_file} for malware infections.")
    packets = rdpcap(pcap_file)
    for packet in packets:
        #Detect traffic to known malicious domains or IP addresses
        if IP in packet:
            if packet[IP].dst in ["malicious_domain1.com", "malicious_domain2.com"]:
                print(f"Malware infection detected: {packet.summary()}")

def detect_dos_attacks(pcap_file):
    print(f"Analyzing {pcap_file} for Denial-of-Service (DoS) attacks.")
    packets = rdpcap(pcap_file)
    for packet in packets:
        #Detect SYN flood attacks (large number of SYN packets)
        if TCP in packet:
            if packet[TCP].flags & 2:  #if SYN flag is set
                print(f"Potential DoS attack detected: {packet.summary()}")

def detect_intrusion_attempts(pcap_file):
    print(f"Analyzing {pcap_file} for intrusion attempts.")
    packets = rdpcap(pcap_file)
    for packet in packets:
        #Detect port scans or brute force attempts
        if TCP in packet:
            if packet[TCP].flags & 2:  #if SYN flag is set
                print(f"Intrusion attempt detected: {packet.summary()}")





def detect_data_exfiltration(p):
      if IP in p:
        src_ip = p[IP].src
        dst_ip = p[IP].dst
        if Raw in p:
            data = p[Raw].load

            if 'base64' in data or 'AES' in data or 'RSA' in data:
                print(f"Data exfiltration detected from {src_ip} to {dst_ip}")
                print(f"Exfiltrated data: {data}")
            else:
                print(f"Data transfer found but not likely data exfiltration from {src_ip} to {dst_ip}")
                print(f"Transferred data: {data}")


def detect_cryptojacking(p):
   if IP in p:
        src_ip = p[IP].src
        dst_ip = p[IP].dst
        if TCP in p:
            dst_port = p[TCP].dport
            if dst_port == 3333:  #Example port for cryptojacking
                print(f"Cryptojacking activity detected from {src_ip} to {dst_ip} on port {dst_port}")
            else:
                if UDP in p:
                    dst_port_udp = p[UDP].dport
                    #Check for any UDP ports associated with cryptojacking
                    if dst_port_udp == 4444:
                        print(f"Cryptojacking activity detected from {src_ip} to {dst_ip} on UDP port {dst_port_udp}")

if __name__ == "__main__":
    pcap_file = ""   #Enter the path to your pcap file
    detect_anomalous_packets(pcap_file)
    detect_dns_anomalies(pcap_file)
    detect_protocol_abnormalities_from_pcap(pcap_file)
    detect_malware_infections(pcap_file)
    detect_dos_attacks(pcap_file)
    detect_intrusion_attempts(pcap_file)
    detect_data_exfiltration(pcap_file)
    detect_cryptojacking(pcap_file)
