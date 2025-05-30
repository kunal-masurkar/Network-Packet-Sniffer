# 🛰️ Network Packet Sniffer

A powerful network packet sniffer built with Python and Scapy that allows you to capture, analyze, and save network packets in real-time.

## ✨ Features

- 🔍 Real-time packet capture and analysis
- 🌐 Support for multiple protocols (TCP, UDP, ICMP, ARP)
- 🎨 Beautiful console output with packet details
- 🔧 BPF filter support
- 💾 Packet saving capability (.pcap format)
- 💻 Cross-platform compatibility

## 📋 Prerequisites

- 🐍 Python 3.7 or higher
- 🔑 Administrator/root privileges (required for packet capture)
- 🪟 Windows: Npcap or WinPcap installed
- 🐧 Linux: No additional requirements
- 🍎 macOS: No additional requirements

## 🚀 Installation

1. Clone this repository:
```bash
git clone https://github.com/kunal-masurkar/Network-Packet-Sniffer
cd network-packet-sniffer
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## 💡 Usage

Run the packet sniffer with basic options:
```bash
python packet_sniffer.py
```

Run the GUI version:
```bash
python packet_sniffer_gui.py
```

### 🔧 Command Line Arguments

- `-i, --interface`: Specify the network interface to capture packets from
- `-f, --filter`: Apply a BPF filter (e.g., 'tcp port 80')
- `-c, --count`: Number of packets to capture (0 for unlimited)
- `-o, --output`: Save captured packets to a .pcap file

### 📝 Examples

1. Capture all packets on the default interface:
```bash
python packet_sniffer.py
```

2. Capture only HTTP traffic (port 80):
```bash
python packet_sniffer.py -f "tcp port 80"
```

3. Capture packets from a specific interface:
```bash
python packet_sniffer.py -i eth0
```

4. Capture 100 packets and save them:
```bash
python packet_sniffer.py -c 100 -o capture.pcap
```

5. Capture DNS traffic:
```bash
python packet_sniffer.py -f "udp port 53"
```

## 📊 Output Format

The sniffer displays packet information in a table format, including:
- ⏰ Timestamp
- 📡 Source and destination IP addresses
- 🔌 Protocol information
- 🔢 Port numbers (for TCP/UDP)
- 📏 Packet length
- ℹ️ Additional protocol-specific details

## ⚠️ Security Notice

⚠️ **Important**: This tool should only be used on networks you own or have permission to monitor. Unauthorized packet capture may be illegal in some jurisdictions.

## 🔧 Troubleshooting

1. **Permission Denied Error**
   - 🪟 Windows: Run as Administrator
   - 🐧 Linux/macOS: Use sudo or run as root

2. **No Packets Captured**
   - ✅ Verify you have the correct interface selected
   - 🛡️ Check if your firewall is blocking packet capture
   - 🔑 Ensure you have the necessary permissions

3. **Interface Not Found**
   - 📡 List available interfaces using `ifconfig` (Linux/macOS) or `ipconfig` (Windows)
   - 🔧 Use the correct interface name with the `-i` option

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🏆 Author

🌐 [GitHub](https://github.com/kunal-masurkar) <br> 👉 [LinkedIn](https://linkedin.com/in/kunal-masurkar-8494a123a)

## 📄 License

This project is **Apache2.0 Licence**. 
