
# sudo chmod +s /usr/bin/python3 
# sudo python3 /home/siva/Desktop/dsa_project/network_packet_sniffer.py


import tkinter as tk
from tkinter import scrolledtext
import threading
import scapy.all as scapy
from collections import defaultdict
from datetime import datetime

# Global variables
capturing_active = False
packet_count_by_ip = defaultdict(int)
total_packet_count = 0
total_packet_length = 0

# Function to start capturing in a separate thread
def start_capturing():
    global capturing_active
    global total_packet_count
    global total_packet_length
    global packet_count_by_ip

    capturing_active = True
    total_packet_count = 0
    total_packet_length = 0
    packet_count_by_ip = defaultdict(int)

    capture_thread = threading.Thread(target=packet_capture_thread)
    capture_thread.start()

# Function to stop capturing
def stop_capturing():
    global capturing_active
    capturing_active = False

    message = "Capturing stopped".center(layout_width)

    text_widget.insert(tk.END, f"\n\n\n\n\n{message}\n\n\n\n\n")
    text_widget.yview(tk.END)

# Function to capture packets in a separate thread
def packet_capture_thread():
    # Set the network interface to capture packets
    interface = "eth0"

    try:
        # Start capturing packets
        scapy.sniff(iface=interface, store=False, prn=packet_callback)

    except KeyboardInterrupt:
        print("Packet capture stopped by user.")

# Function to handle packet callback
def packet_callback(packet):
    global total_packet_count
    global total_packet_length
    global packet_count_by_ip

    if capturing_active and packet.haslayer(scapy.IP):
        # Extract and display packet information in the text_widget
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        packet_capture_time = datetime.fromtimestamp(packet.time)

        # Initialize ports to None
        src_port = None
        dst_port = None

        # Extract more information based on the protocol (TCP, UDP, etc.)
        # TCP
        if protocol == 6 and scapy.TCP in packet:  
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport

        #UDP
        elif protocol == 17 and scapy.UDP in packet:
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            #aa = packet[sca]
            

        # Extract payload data if applicable
        payload_length = len(packet[scapy.Raw].load) if packet.haslayer(scapy.Raw) else 0

        # Update total packet count and length
        total_packet_count += 1
        total_packet_length += len(packet)

        # Update packet count by IP
        packet_count_by_ip[src_ip] += 1

        # Calculate and display average packet length
        average_length = total_packet_length / total_packet_count if total_packet_count > 0 else 0
        display_text_analysis = f"Average Packet Length: {average_length:.2f} bytes\nTotal Length received: {total_packet_length/1000:.2f} KB\nTotal number of packets received : {total_packet_count}\n"

        # Display packet count by IP in the text_widget_analysis
        display_text_analysis += "Packet Count by IP:\n"
        for ip, count in packet_count_by_ip.items():
            display_text_analysis += f"{ip}: {count} packets\n"

        # Display packet information in the text_widget
        text_widget_analysis.config(state=tk.NORMAL)  # Enable text widget for editing
        text_widget_analysis.delete(1.0, tk.END)  # Clear existing content
        text_widget_analysis.insert(tk.END, display_text_analysis)
        text_widget_analysis.config(state=tk.DISABLED)  # Disable text widget to prevent editing

        # Display packet information in the text_widget
        display_text = f"Source IP: {src_ip}, Source Port: {src_port} -> " \
                       f"Destination IP: {dst_ip}, Destination Port: {dst_port}, Protocol: {protocol}" \
                       f" Payload Length: {payload_length} bytes Time : {packet_capture_time}\n"
        text_widget.insert(tk.END, display_text)
        text_widget.yview(tk.END)  # Auto-scroll to the bottom

# GUI setup
root = tk.Tk()
root.title("Packet Sniffer")

layout_width = 180
# Create and configure the text widget
text_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=layout_width, height=27)
text_widget.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

text_widget_analysis = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=13)
text_widget_analysis.grid(row=1, column=0, columnspan=2, padx=10, pady=10)
text_widget_analysis.insert(tk.END, "Average Packet Length: 0.00 bytes\nTotal Length received: 0 bytes\nTotal number of packets received : 0\n")
text_widget_analysis.config(state=tk.DISABLED)  # Disable text widget to prevent editing

# Create "Start Capturing" button
start_button = tk.Button(root, text="Start Capturing", command=start_capturing)
start_button.grid(row=2, column=0, padx=10, pady=10)

# Create "Stop Capturing" button
stop_button = tk.Button(root, text="Stop Capturing", command=stop_capturing)
stop_button.grid(row=2, column=1, padx=10, pady=10)

# Run the Tkinter main loop
root.mainloop()
