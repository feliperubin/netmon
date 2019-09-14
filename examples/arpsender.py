
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