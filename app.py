import socket,sys
import struct
import os
import time

# - Ethernet: endereços MAC origem e destino, tipo do pacote
# - ARP: ARP request/reply, endereços MAC origem e destino, endereços IP origem e destino
# - IP: endereços IP origem e destino, protocolo encapsulado, TTL
# - TCP: portas origem e destino
# - UDP: portas origem e destino

# Além disso, a ferramenta deve gerar as seguintes estatísticas no término da monitoração (quando for solicitado o término da ferramenta através de Control+C):

# - quantidade de pacotes monitorados
# - porcentagem de pacotes por protocolo
# - tamanhos mínimo e máximo dos pacotes
# - 5 IPs que mais enviaram pacotes
# - 5 IPS que mais receberam pacotes
# - incluir mais 2 estatísticas que acharem interessante

# From /usr/include/linux/if_ether.h
ETH_P_ALL = 0x0003 # Every Packet
ETH_P_IP=0x0800 # IP
ETH_P_ARP=0x0806 # ARP

# https://docs.python.org/3/library/struct.html

# class BinaryTools():
	# def self():

bytes2mac = lambda x: ":".join(["{:02x}".format(xi) for xi in x])

# hex_packet_t = lambda x: '{:04x}'.format(x)
# def packet_type():


# def bytes_to_mac(bytesmac):
#     return ":".join("{:02x}".format(x) for x in bytesmac)

#ascii representation of an hex chart (ex: 707 -> 'p')
# hex2ascii = lambda x: chr(int(x[:-1], 16))


# ! network=big-endian
#
# Creates a Socket RAW
def init_socket_raw(iface="eth0"):
	try:
	    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))

	except OSError as msg:
	    print('Error'+str(msg))
	    sys.exit(1)
	s.bind((iface,0))
	print('Socket created on interface',iface)
	return s

def nextp(s): # Reads next packet
	while True:
		yield s.recvfrom(65536)




# RFC 793 - TCP
# [:y)
# (x:]
# !6s6sH = 6bytes + 6bytes  + 1 unsigned short
# s: byte, 6s = 6 bytes


def read_tcp(p):

	# version = p[:4]
	# hlen = p[4:8]
	
	headp = p[:16]
	nhead = struct.unpack("!4s4sH",headp)

	# print('v: ',nhead[0], " hlen: ",nhead[1])
	print('V: ',nhead[0]," hlen: ",nhead[1], " tos:",nhead[2])

	# src_port = packet[:14]
	# dst_port = packet[14:28]

s = init_socket_raw("eth2")
sread = nextp(s)
while True:
	packet,address = next(sread)
	eth_h = packet[:14]
	dst_addr,src_addr,eth_t = struct.unpack("!6s6sH",eth_h)
	print("src:%s,dst:%s,type:%s" % (bytes2mac(dst_addr),bytes2mac(src_addr),hex(eth_t)))
	# TCP Packet 
	if eth_t == ETH_P_IP:
		print(" Packet Type: IP")
	elif eth_t == ETH_P_ARP:
		print(" Packet Type: ARP")
	else:
		print(" Packet Type: Unknown")
	

	time.sleep(1)



# def __main__():
# 	return 0

# packet = s.recvfrom(65536) # Max Packet Size


































