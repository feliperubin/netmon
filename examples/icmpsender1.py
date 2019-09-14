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