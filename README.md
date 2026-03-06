# Packet Sniffer in C

A network packet sniffer that captures and analyzes network traffic using raw sockets in C.

## Features

- Captures all network packets on the interface
- Parses and displays Ethernet headers
- Parses and displays IP headers
- Supports TCP, UDP, and ICMP protocols
- Shows detailed packet information including:
  - Source and destination MAC addresses
  - Source and destination IP addresses
  - Port numbers (for TCP/UDP)
  - Protocol-specific flags and fields

## Requirements

- Linux operating system
- GCC compiler
- Root/sudo privileges (required for raw socket access)

## Compilation

Compile the packet sniffer using make:

```bash
make
```

Or compile manually:

```bash
gcc -Wall -Wextra -o packet_sniffer packet_sniffer.c
```

## Usage

Run the packet sniffer with root privileges:

```bash
sudo ./packet_sniffer
```

Press `Ctrl+C` to stop capturing packets.

## How It Works

1. Creates a raw socket using `AF_PACKET` and `SOCK_RAW`
2. Captures all Ethernet frames on the network interface
3. Parses the packet headers (Ethernet, IP, TCP/UDP/ICMP)
4. Displays formatted packet information to the console

## Security Note

This tool is designed for educational purposes and authorized security testing only. Always ensure you have proper authorization before capturing network traffic. Unauthorized packet sniffing may be illegal in your jurisdiction.

## Clean Up

Remove the compiled binary:

```bash
make clean
```
