# TCP Packet Explorer

TCP Packet Analyzer is a Python tool for analyzing TCP packets in pcap files and providing readable data based on defined protocols. It uses Scapy for packet manipulation and Colorama for colored console output.

## Features
- Analyzes FTP, SSH, Telnet, and HTTP protocols in TCP packets.
- Detects potential web shells based on HTTP traffic.
- Provides detailed information about packet data, including timestamps, source/destination IPs, and ports.

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/OsmanTunahan/PacketExplorer.git
   cd PacketExplorer
   ```

2. Run the tool:
   ```bash
   python PacketExplorer.py <pcap_file_path>
   ```

   Optional: Use the `-s` or `--services` flag to filter specific services (e.g., `ftp ssh telnet`).

## Example
```bash
python PacketExplorer.py sample.pcap -s ftp ssh telnet
```

<img src="https://i.hizliresim.com/5sbudxd.png" width="auto">
<img src="https://i.hizliresim.com/6a2mkai.png" width="auto">
<img src="https://i.hizliresim.com/syw50wk.png" width="auto">

## Contributing
Contributions are welcome! Feel free to open issues or submit pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
