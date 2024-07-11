import platform
from scapy.all import sniff, wrpcap, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to handle captured packets
def packet_handler(packet):
    print(packet.summary())
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"Source Port: {udp_layer.sport}")
        print(f"Destination Port: {udp_layer.dport}")
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        print(f"ICMP Type: {icmp_layer.type}")
        print(f"ICMP Code: {icmp_layer.code}")

# Function to start packet capture
def start_sniffing(interface, count, duration, protocol, output_file):
    protocols = {
        'tcp': 'tcp',
        'udp': 'udp',
        'icmp': 'icmp'
    }
    filter_str = protocols.get(protocol.lower(), None)
    
    packets = sniff(iface=interface, count=count, timeout=duration, filter=filter_str, prn=packet_handler)
    
    if output_file:
        wrpcap(output_file, packets)
        print(f"Captured packets saved to {output_file}")

# Main function to gather user inputs and start the sniffer
def main():
    os_name = platform.system()
    
    print("Available network interfaces:")
    if os_name == "Windows":
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        for i, iface in enumerate(interfaces):
            print(f"{i}: {iface['name']} - {iface['description']}")
        
        iface_index = input("Select the network interface by index: ")
        iface_index = int(iface_index) if iface_index.isdigit() and int(iface_index) in range(len(interfaces)) else None
        if iface_index is None:
            print("Invalid interface index. Please select a valid index from the list above.")
            return
        
        interface = interfaces[iface_index]['name']
    
    else:
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            print(f"{i}: {iface}")
        
        iface_index = input("Select the network interface by index: ")
        iface_index = int(iface_index) if iface_index.isdigit() and int(iface_index) in range(len(interfaces)) else None
        if iface_index is None:
            print("Invalid interface index. Please select a valid index from the list above.")
            return
        
        interface = interfaces[iface_index]
    
    count = input("Enter the number of packets to capture (0 for infinite): ")
    count = int(count) if count.isdigit() else 0
    duration = input("Enter the duration to capture packets in seconds (0 for infinite): ")
    duration = int(duration) if duration.isdigit() else 0
    protocol = input("Enter the protocol to filter by (tcp, udp, icmp) or leave blank for all: ").lower()
    output_file = input("Enter the output file to save captured packets or leave blank to skip saving: ")
    
    print(f"Starting packet capture on interface {interface}...")
    start_sniffing(interface, count, duration, protocol, output_file)

if __name__ == "__main__":
    main()
