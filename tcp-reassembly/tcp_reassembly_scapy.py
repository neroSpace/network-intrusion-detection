from scapy.all import *
from scapy.layers.inet import TCP, IP

def tcp_reassembly(pcap_file):
    print("reading packets from pcap file........")
    packets = rdpcap(pcap_file)
    filename = os.path.basename(pcap_file) 
    
    sessions = {}
    for packet in packets:
        if TCP in packet:
            session = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
            if session in sessions:
                reversed_session = (session[2], session[3], session[0], session[1])
                if reversed_session in sessions:
                    sessions[reversed_session].append(packet)
            else:
                sessions[session] = []
                sessions[session].append(packet)
    print("done iterating over each packet in the pcap file........")

    new_pcap = PcapWriter(os.path.join("C:\\Users\\asus\\Documents\\nids-pcap-dataset\\trial_unsw_nb_reassembled\\result",("reassembled_http_only_"+filename)))

    # Iterate over each TCP session in the dictionary
    print("iterating over each TCP session in the dictionary........")
    for session in sessions.values():
        session.sort(key=lambda p: p[TCP].seq)
        payload = b"".join(bytes(packet[TCP].payload) for packet in session)
        # Check if the reassembled payload contains HTTP data
        if b"HTTP" in payload:
            for packet in session:
                new_pcap.write(packet)
    print("done iterating over each TCP session in the dictionary........")
    new_pcap.close()
    print("done writing to new pcap file........")

if __name__ == "__main__":
    # Define the path to the pcap file
    # pcap_file = "C:\\Users\\asus\\Documents\\tugas-akhir\\resources\\nids-pcap-dataset\\unsw_nb_full_pcap\\17022015UNSW-NB15_1.pcap"
    dir = "C:\\Users\\asus\\Documents\\nids-pcap-dataset\\reassembled_pcap\\"
    for file in os.listdir(dir):
        if file.endswith(".pcap"):
            pcap_file = dir + file
            print("Processing file: " + file)
            # Reassemble TCP sessions
            tcp_reassembly(pcap_file)
            # sniff(offline=pcap_file, prn=tcp_reassembly, store=0)


    # Reassemble TCP sessions
    # tcp_reassembly(pcap_file)