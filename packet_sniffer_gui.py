#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap, get_if_list, conf
import colorama
from colorama import Fore, Style
from rich.console import Console
from rich.table import Table

# Initialize colorama for Windows compatibility
colorama.init()

# Initialize Rich console for better error handling
console = Console()

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("1200x800")
        
        # Set theme
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Use a modern theme
        
        # Initialize variables
        self.is_sniffing = False
        self.packet_queue = queue.Queue()
        self.packets = []
        self.packet_count = 0
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(3, weight=1)
        
        # Create widgets
        self.create_control_panel()
        self.create_packet_display()
        self.create_status_bar()
        
        # Start packet processing
        self.process_packets()
        
        # Configure window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_control_panel(self):
        # Control Panel Frame
        control_frame = ttk.LabelFrame(self.main_frame, text="Control Panel", padding="5")
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Interface Selection
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var)
        self.interface_combo['values'] = get_if_list()
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5)
        if self.interface_combo['values']:
            self.interface_combo.current(0)
        
        # Filter Entry
        ttk.Label(control_frame, text="Filter:").grid(row=0, column=2, padx=5, pady=5)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=30)
        self.filter_entry.grid(row=0, column=3, padx=5, pady=5)
        
        # Packet Count
        ttk.Label(control_frame, text="Packet Count:").grid(row=0, column=4, padx=5, pady=5)
        self.count_var = tk.StringVar(value="0")
        self.count_entry = ttk.Entry(control_frame, textvariable=self.count_var, width=10)
        self.count_entry.grid(row=0, column=5, padx=5, pady=5)
        
        # Buttons
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=6, padx=5, pady=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=7, padx=5, pady=5)
        
        self.save_button = ttk.Button(control_frame, text="Save Packets", command=self.save_packets)
        self.save_button.grid(row=0, column=8, padx=5, pady=5)
        
        self.clear_button = ttk.Button(control_frame, text="Clear Display", command=self.clear_display)
        self.clear_button.grid(row=0, column=9, padx=5, pady=5)
        
        # Add refresh interfaces button
        self.refresh_button = ttk.Button(control_frame, text="Refresh Interfaces", command=self.refresh_interfaces)
        self.refresh_button.grid(row=0, column=10, padx=5, pady=5)
        
    def create_packet_display(self):
        # Packet Display Frame
        display_frame = ttk.LabelFrame(self.main_frame, text="Packet Display", padding="5")
        display_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Create Treeview
        self.tree = ttk.Treeview(display_frame, columns=("Time", "Source", "Destination", "Protocol", "Length", "Info"),
                                show="headings")
        
        # Configure columns
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.heading("Info", text="Info")
        
        self.tree.column("Time", width=150)
        self.tree.column("Source", width=150)
        self.tree.column("Destination", width=150)
        self.tree.column("Protocol", width=100)
        self.tree.column("Length", width=100)
        self.tree.column("Info", width=500)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(display_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights
        display_frame.columnconfigure(0, weight=1)
        display_frame.rowconfigure(0, weight=1)
        
        # Add right-click menu
        self.create_context_menu()
        
    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.copy_selected)
        self.context_menu.add_command(label="Clear Selected", command=self.clear_selected)
        self.tree.bind("<Button-3>", self.show_context_menu)
        
    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
            
    def copy_selected(self):
        selected_items = self.tree.selection()
        if selected_items:
            text = ""
            for item in selected_items:
                values = self.tree.item(item)['values']
                text += "\t".join(str(v) for v in values) + "\n"
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            
    def clear_selected(self):
        selected_items = self.tree.selection()
        for item in selected_items:
            self.tree.delete(item)
        
    def create_status_bar(self):
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
    def refresh_interfaces(self):
        """Refresh the list of available network interfaces"""
        try:
            interfaces = get_if_list()
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_combo.current(0)
            self.status_var.set("Interfaces refreshed")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh interfaces: {str(e)}")
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            # Store packet for potential saving
            self.packets.append(packet)
            self.packet_count += 1
            
            # Extract packet information
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            source = ""
            destination = ""
            protocol = ""
            length = str(len(packet))
            info = ""
            
            if packet.haslayer(IP):
                source = packet[IP].src
                destination = packet[IP].dst
                protocol = "IP"
                
            if packet.haslayer(TCP):
                protocol = "TCP"
                info = f"TCP {packet[TCP].sport} → {packet[TCP].dport}"
                if packet.haslayer(Raw):
                    info += f" [Raw Data: {len(packet[Raw].load)} bytes]"
            elif packet.haslayer(UDP):
                protocol = "UDP"
                info = f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
            elif packet.haslayer(ARP):
                protocol = "ARP"
                info = f"Operation: {packet[ARP].op}"
            
            # Add packet to queue
            self.packet_queue.put((timestamp, source, destination, protocol, length, info))
            
            # Update status
            self.status_var.set(f"Captured {self.packet_count} packets")
            
        except Exception as e:
            self.packet_queue.put(("ERROR", str(e), "", "", "", ""))
    
    def process_packets(self):
        """Process packets from the queue"""
        try:
            while True:
                packet_info = self.packet_queue.get_nowait()
                if packet_info[0] == "ERROR":
                    messagebox.showerror("Error", packet_info[1])
                else:
                    self.tree.insert("", 0, values=packet_info)
                self.packet_queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_packets)
    
    def start_capture(self):
        """Start packet capture"""
        if not self.is_sniffing:
            try:
                count = int(self.count_var.get())
                if count < 0:
                    raise ValueError("Packet count must be non-negative")
                
                self.is_sniffing = True
                self.start_button.configure(state=tk.DISABLED)
                self.stop_button.configure(state=tk.NORMAL)
                self.status_var.set("Capturing packets...")
                
                # Start capture in a separate thread
                self.capture_thread = threading.Thread(
                    target=self.capture_packets,
                    args=(self.interface_var.get(), self.filter_var.get(), count)
                )
                self.capture_thread.daemon = True
                self.capture_thread.start()
                
            except ValueError as e:
                messagebox.showerror("Error", str(e))
                self.is_sniffing = False
                self.start_button.configure(state=tk.NORMAL)
                self.stop_button.configure(state=tk.DISABLED)
    
    def capture_packets(self, interface, filter_str, count):
        """Capture packets in a separate thread"""
        try:
            sniff(
                iface=interface,
                prn=self.packet_callback,
                filter=filter_str,
                count=count,
                store=0
            )
        except Exception as e:
            self.packet_queue.put(("ERROR", str(e), "", "", "", ""))
        finally:
            self.root.after(0, self.stop_capture)
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_sniffing = False
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self.status_var.set(f"Capture stopped. Total packets: {self.packet_count}")
    
    def save_packets(self):
        """Save captured packets to a file"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to save")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                wrpcap(file_path, self.packets)
                messagebox.showinfo("Success", f"Saved {len(self.packets)} packets to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save packets: {str(e)}")
    
    def clear_display(self):
        """Clear the packet display"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packets = []
        self.packet_count = 0
        self.status_var.set("Display cleared")
        
    def on_closing(self):
        """Handle window closing"""
        if self.is_sniffing:
            if messagebox.askokcancel("Quit", "Capture is still running. Do you want to stop and quit?"):
                self.stop_capture()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 