#!/usr/bin/env python3

import argparse
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap
from rich.console import Console
from rich.table import Table
from rich import print as rprint
import colorama
from colorama import Fore, Style

# Initialize colorama for Windows compatibility
colorama.init()

# Initialize Rich console
console = Console()

class PacketSniffer:
    def __init__(self, interface=None, filter=None, output_file=None):
        self.interface = interface
        self.filter = filter
        self.output_file = output_file
        self.packets = []
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            # Store packet for potential saving
            self.packets.append(packet)
            
            # Create a table for packet details
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            
            # Get timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            table.add_row("Timestamp", timestamp)
            
            # Layer 2 (Ethernet) information
            if packet.haslayer(IP):
                table.add_row("Source IP", packet[IP].src)
                table.add_row("Destination IP", packet[IP].dst)
                table.add_row("Protocol", packet[IP].proto)
                
            # Layer 3 (Transport) information
            if packet.haslayer(TCP):
                table.add_row("Source Port", str(packet[TCP].sport))
                table.add_row("Destination Port", str(packet[TCP].dport))
                table.add_row("TCP Flags", str(packet[TCP].flags))
            elif packet.haslayer(UDP):
                table.add_row("Source Port", str(packet[UDP].sport))
                table.add_row("Destination Port", str(packet[UDP].dport))
            elif packet.haslayer(ICMP):
                table.add_row("ICMP Type", str(packet[ICMP].type))
                table.add_row("ICMP Code", str(packet[ICMP].code))
            elif packet.haslayer(ARP):
                table.add_row("ARP Operation", str(packet[ARP].op))
                table.add_row("ARP Source MAC", packet[ARP].hwsrc)
                table.add_row("ARP Target MAC", packet[ARP].hwdst)
            
            # Packet length
            table.add_row("Length", str(len(packet)))
            
            # Print the table
            console.print(table)
            console.print("-" * 80)
            
        except Exception as e:
            rprint(f"[red]Error processing packet: {str(e)}[/red]")
    
    def start_sniffing(self, count=0):
        """Start the packet capture"""
        try:
            rprint(f"[yellow]Starting packet capture on interface: {self.interface or 'default'}[/yellow]")
            if self.filter:
                rprint(f"[yellow]Using filter: {self.filter}[/yellow]")
            
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter=self.filter,
                count=count,
                store=0
            )
            
        except KeyboardInterrupt:
            rprint("\n[yellow]Stopping packet capture...[/yellow]")
            if self.output_file and self.packets:
                self.save_packets()
            sys.exit(0)
        except Exception as e:
            rprint(f"[red]Error during packet capture: {str(e)}[/red]")
            sys.exit(1)
    
    def save_packets(self):
        """Save captured packets to a file"""
        try:
            wrpcap(self.output_file, self.packets)
            rprint(f"[green]Saved {len(self.packets)} packets to {self.output_file}[/green]")
        except Exception as e:
            rprint(f"[red]Error saving packets: {str(e)}[/red]")

def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to capture packets from")
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("-o", "--output", help="Output file to save captured packets (.pcap format)")
    
    args = parser.parse_args()
    
    # Create and start the packet sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        filter=args.filter,
        output_file=args.output
    )
    
    sniffer.start_sniffing(count=args.count)

if __name__ == "__main__":
    main() 