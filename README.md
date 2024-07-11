```markdown
# Network Sniffer 🕵️‍♂️

This project is a simple network sniffer written in Python using the Scapy library. It captures and analyzes network traffic, displaying packet details and optionally saving the captured packets to a file. The script is compatible with both Windows and Linux operating systems.

## Features ✨

- Capture packets on a specified network interface
- Filter packets by protocol (TCP, UDP, ICMP)
- Display summary information for each captured packet
- Save captured packets to a file (optional)
- Cross-platform compatibility (Windows and Linux)

## Requirements 📋

- Python 3.x
- Scapy library

## Installation 🛠️

1. **Install Python 3**: Ensure you have Python 3 installed on your system. You can download it from [python.org](https://www.python.org/).

2. **Install Scapy**: Install the Scapy library using pip:
    ```bash
    pip install scapy
    ```

## Usage 🚀

Run the script with the necessary privileges:

- **On Windows**: Right-click the script and select "Run as administrator" or run it from an elevated Command Prompt.
- **On Linux**: Run the script with sudo:
    ```bash
    sudo python3 Network_Sniffer.py
    ```

Follow the prompts:

1. The script will list all available network interfaces. Select the interface by entering the corresponding index.
2. Enter the number of packets to capture (0 for infinite).
3. Enter the duration to capture packets in seconds (0 for infinite).
4. Enter the protocol to filter by (tcp, udp, icmp) or leave blank for all protocols.
5. Enter the output file to save captured packets or leave blank to skip saving.

### Example:

```plaintext
Available network interfaces:
0: Ethernet - Realtek PCIe GBE Family Controller
1: Wi-Fi - Intel(R) Wireless-AC 9560
2: Loopback Pseudo-Interface 1
Select the network interface by index: 1
Enter the number of packets to capture (0 for infinite): 10
Enter the duration to capture packets in seconds (0 for infinite): 10
Enter the protocol to filter by (tcp, udp, icmp) or leave blank for all: tcp
Enter the output file to save captured packets or leave blank to skip saving:
Starting packet capture on interface Wi-Fi...
```

## Script Details 🔍

```python
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
```

## Contributing 🤝

Contributions are welcome! Please fork this repository and submit pull requests with your changes.

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments 🙏

- [Scapy](https://scapy.net/) - The Python library used for packet capturing and analysis.
- [Wireshark](https://www.wireshark.org/) - For network protocol analysis inspiration.
```