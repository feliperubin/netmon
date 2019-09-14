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