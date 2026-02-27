
# WireZack
is a simple C-based network tool that allows you to scan available network interfaces and sniff live network packets using libpcap. Ideal for learning network analysis, monitoring traffic, and exploring TCP/IP protocols in real-time.

### Features
  - Lists all available network interfaces on your machine.
  - Select a network interface for live monitoring.
  - Capture and display network packets in real-time.
  - Shows packet details including:
    - Timestamp
    - Source IP
    - Destination IP
    - Protocol (TCP, UDP, ICMP, IGMP, IPv6, GRE, ESP, AH)
    - Packet length
  - Interactive menu with ASCII art introduction.

### Dependencies
  - libpcap (packet capture library)
  - GCC compiler (gcc)
  - Linux-based system (tested on Ubuntu/Debian)


### Usage
  1. Launch the program.
  2. Select Scan Network Interfaces to view all available interfaces.
  3. Choose an interface for live packet capture.
  4. Select Sniff Network Packets to start monitoring traffic.
  5. Press 0 + Enter to stop sniffing.

E.x. Output

```
Time                      | Source          | Destination     | Protocol | Length
-------------------------------------------------------------------------------
2026-02-26 18:00:01       | 192.168.1.5    | 192.168.1.1    | TCP      | 60
2026-02-26 18:00:02       | 10.0.0.2       | 10.0.0.1       | UDP      | 128
```
