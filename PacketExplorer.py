import re
import argparse
from scapy.all import IP, TCP, Raw, rdpcap
from colorama import Fore, init
from datetime import datetime

"""
Author: Osman Tunahan ARIKAN
GitHub: https://github.com/OsmanTunahan
Version: 1.0
"""

class ProtocolAnalyzer:
    def __init__(self):
        self.protocol_states = {}
        init(autoreset=True)

    def add_protocol(self, protocol_name, start_patterns, end_patterns):
        self.protocol_states[protocol_name] = {
            'start_patterns': [re.compile(pattern) for pattern in start_patterns],
            'end_patterns': [re.compile(pattern) for pattern in end_patterns],
            'current_state': None,
            'data': []
        }

    def process_packet(self, packet):
        if IP in packet and TCP in packet and Raw in packet:
            raw_data = bytes(packet[Raw].load).decode('utf-8', 'ignore')
            for protocol_name, protocol_info in self.protocol_states.items():
                for pattern in protocol_info['start_patterns']:
                    if pattern.search(raw_data):
                        protocol_info['current_state'] = protocol_name
                        protocol_info['data'].append(
                            (packet.time, raw_data, packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport))
                        return
                for pattern in protocol_info['end_patterns']:
                    if pattern.search(raw_data) and protocol_info['current_state'] == protocol_name:
                        protocol_info['current_state'] = None
                        return
                if protocol_info['current_state'] == protocol_name:
                    protocol_info['data'].append(
                        (packet.time, raw_data, packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport))

    def display_data(self):
        for protocol_name, protocol_info in self.protocol_states.items():
            sorted_data = sorted(protocol_info['data'], key=lambda x: x[0])
            print(f"{Fore.LIGHTCYAN_EX}Protocol: {Fore.RED}{protocol_name}")
            old_ip = ''
            for timestamp, data, src_ip, dst_ip, sport, dport in sorted_data:
                if old_ip != '' and old_ip == dst_ip and 'GET' in data:
                    print(f'{Fore.LIGHTYELLOW_EX}--- WEBSHELL FOUND!! ---')
                    break
                timestamp = datetime.utcfromtimestamp(int(timestamp))
                print(f"{Fore.LIGHTGREEN_EX}-> Date: {timestamp}, Source IP: {src_ip}, Dest IP: {dst_ip}, Sport: {sport}, Dport: {dport}")
                print(f"Data: {data}")
                old_ip = src_ip
            print("-" * 50)

    def run(self, pcap_file):
        packets = rdpcap(pcap_file)
        for packet in packets:
            self.process_packet(packet)

        self.display_data()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This program analyzes TCP Packets and provides readable data.')
    parser.add_argument('file', help='Path to the pcap file')
    parser.add_argument('-s', '--services', nargs='+', help='Enter the services to be filtered (Example: ftp ssh telnet)')
    args = parser.parse_args()

    analyzer = ProtocolAnalyzer()
    analyzer.add_protocol('FTP', ['220', '331', '230', '215', '257', '150', '226', '200', '221'], ['QUIT'])
    analyzer.add_protocol('SSH', ['SSH-2.0'], ['Bye'])
    analyzer.add_protocol('Telnet', ['Telnet'], ['Connection closed'])
    analyzer.add_protocol('HTTP', ['GET', 'POST', 'HTTP'], ['HTTP/1.1'])

    analyzer.run(args.file)
