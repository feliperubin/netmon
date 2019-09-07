https://docs.python.org/3/library/socket.html

import socket, sys
import struct

ETH_P_ALL = 0x0003

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
except OSError as msg:
    print('Error'+str(msg))
    sys.exit(1)

print('Socket created!')

s.bind(('enp4s0',0))

(packet,addr) = s.recvfrom(65536)

eth_length = 14
eth_header = packet[:14]

eth = struct.unpack("!6s6sH",eth_header)

print("MAC Dst: "+bytes_to_mac(eth[0]))
print("MAC Src: "+bytes_to_mac(eth[1]))
print("Type: "+hex(eth[2]))

if eth[2] == 0x0800 :
    print("IP Packet")

    ip_header = packet[eth_length:20+eth_length]

    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl*4

    ttl = iph[5]

    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    print("IP Src: "+s_addr)
    print("IP Dst: "+d_addr)

---

import socket, sys
import struct

ETH_P_ALL = 0x0003

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
except OSError as msg:
    print('Error'+str(msg))
    sys.exit(1)

print('Socket created!')

s.bind(('enp4s0',0))

# Header Ethernet
# MAC Destino - 6 bytes
dest_mac = b"\xff\xff\xff\xff\xff\xff"
# MAC Origem - 6 bytes
source_mac = b"\xa4\x1f\x72\xf5\x90\x41"
protocol = 0x0806

eth_hdr = struct.pack("!6s6sH", dest_mac, source_mac, protocol)

# Header ARP
htype = 1
ptype = 0x0800
hlen = 6
plen = 4
op = 1 # request
src_ip = socket.inet_aton("10.32.143.98")
target_mac = b"\x00\x00\x00\x00\x00\x00"
target_ip = socket.inet_aton("10.32.143.140")

arp_hdr = struct.pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen, op, source_mac, src_ip, target_mac, target_ip)

packet = eth_hdr+arp_hdr

s.send(packet)



import socket, sys
import struct

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        a = msg[i]
        b = msg[i+1]
        s = s + (a+(b << 8))
    s = s + (s >> 16)
    s = ~s + 0xffff
    return socket.ntohs(s)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
except OSError as msg:
    print('Error'+str(msg))
    sys.exit(1)

print('Socket created!')

# s.bind(('enp4s0',0))

# ICMP Echo Request Header
type = 8
code = 0
mychecksum = 0xc233
identifier = 12345
seqnumber = 0
payload = b"istoehumteste"

icmp_packet = struct.pack("!BBHHH13s", type, code, mychecksum, identifier, seqnumber, payload)

# mychecksum = checksum(icmp_packet)

# print("Checksum: {.02x}".format(mychecksum))

# icmp_packet = struct.pack("!BBHHH14s", type, code, mychecksum, identifier, seqnumber, payload)

dest_ip = "10.32.143.102"
dest_addr = socket.gethostbyname(dest_ip)

s.sendto(icmp_packet, (dest_addr,0))



---


import socket, sys
import struct

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        a = msg[i]
        b = msg[i+1]
        s = s + (a+(b << 8))
    s = s + (s >> 16)
    s = ~s + 0xffff
    return socket.ntohs(s)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
except OSError as msg:
    print('Error'+str(msg))
    sys.exit(1)

print('Socket created!')

# Include IP header
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Header IP
ip_ver = 4
ip_ihl = 5
ip_tos = 0
ip_tot_len = 0
ip_id = 54321
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_ICMP
ip_check = 0
ip_saddr = socket.inet_aton("10.32.143.102")
ip_daddr = socket.inet_aton("10.32.143.194")

ip_ihl_ver = (ip_ver << 4) + ip_ihl

ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
    ip_proto, ip_check, ip_saddr, ip_daddr)

# ICMP Echo Request Header
type = 8
code = 0
mychecksum = 0xc233
identifier = 12345
seqnumber = 0
payload = b"istoehumteste"

icmp_packet = struct.pack("!BBHHH13s", type, code, mychecksum, identifier, seqnumber, payload)

# mychecksum = checksum(icmp_packet)

# print("Checksum: {.02x}".format(mychecksum))

# icmp_packet = struct.pack("!BBHHH14s", type, code, mychecksum, identifier, seqnumber, payload)

dest_ip = "10.32.143.194"
dest_addr = socket.gethostbyname(dest_ip)

s.sendto(ip_header+icmp_packet, (dest_addr,0))
