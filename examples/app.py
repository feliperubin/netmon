import socket,sys
import struct
import os
import time

# - Ethernet: endereços MAC origem e destino, tipo do pacote
# - ARP: ARP request/reply, endereços MAC origem e destino, endereços IP origem e destino
# - IP: endereços IP origem e destino, protocolo encapsulado, TTL
#- ICMP: tipo de pacote (Echo Reply, Destination Unreachable, etc) - https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
 #  - se for Echo Request ou Echo Reply, incluir também: identificador, número de sequência e payload (em ASCII)
# - TCP: portas origem e destino
# - UDP: portas origem e destino

# Além disso, a ferramenta deve gerar as seguintes estatísticas no término da monitoração (quando for solicitado o término da ferramenta através de Control+C):

# - quantidade de pacotes monitorados
# - porcentagem de pacotes por protocolo
# - tamanhos mínimo e máximo dos pacotes
# - 5 IPs que mais enviaram pacotes
# - 5 IPS que mais receberam pacotes
# - incluir mais 2 estatísticas que acharem interessante


# intervalo de portas nos decidimos o formato quevai ser passado

# Mostrar maior e menor tamanhos (ao todo)
# Termos:
# TCP segments
# UDP datagrams
# IP packets
# Ethernet frames

# Conn UDP
# 
# <- ICMP Destination Unreachable (Port Unreachable)

# Conn TCP
# Syn -> 
# <- Syn, Ack
# Ack ->
# Só precisamos fazer

# From /usr/include/linux/if_ether.h
ETH_P_ALL = 0x0003 # Every Packet
ETH_P_IP=0x0800 # IP
ETH_P_ARP=0x0806 # ARP

ARP_OP_EQ=0x1 # ARP REQUEST
ARP_OP_RE=0x2 # ARP REPLY
# Note: Target HW Address is not filled in a request

IP_H_LEN=20
ETH_H_LEN=14
ARP_H_LEN=28

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



# class ARP_P(Packet):
# 	def __init__():
# 		self

# class Packet():
# 	def __init__(header):
# 		self.header = header

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
	print("Source: %s Target: %s Type: %s" % (bytes2mac(dst_addr),bytes2mac(src_addr),hex(eth_t)))
	# TCP Packet 
	if eth_t == ETH_P_IP:
		print(" Packet Type: IP")
		ip_h = struct.unpack("!BBHHHBBH4s4s",packet[14:34])
		print("  Version: ",(ip_h[0] & 0xf0) >> 4)
		print("  TOS: ",hex(ip_h[1]))
		print("  Length: ",int(hex(ip_h[2]),16))

	elif eth_t == ETH_P_ARP:
		print(" Packet Type: ARP")

		# arp_p = struct.unpack("!HHccH4sHHHH4s4s",packet[14:42])
		arp_p = struct.unpack("!HHBBH6s4s6s4s",packet[14:42])
		print("  Hardware Type: ",hex(arp_p[0]))
		print("  Protocol Type: ",hex(arp_p[1]))
		print("  Hardware Size: ",hex(arp_p[2]))
		print("  Protocol Size: ",hex(arp_p[3]))
		print("  OPcode: ",hex(arp_p[4])," ("+ ("REQUEST" if arp_p[4] == 0x1 else "REPLY") +")")
		print("  Sender MAC Address: ",bytes2mac(arp_p[5]))
		print("  Sender Protocol Address: ",socket.inet_ntoa(arp_p[6]))
		print("  Target MAC Address: ",bytes2mac(arp_p[7]))
		print("  Target Protocol Address: ",socket.inet_ntoa(arp_p[8]))

	else:
		# print(" Packet Type: Unknown")
		pass


	# time.sleep(1)



# def __main__():
# 	return 0

# packet = s.recvfrom(65536) # Max Packet Size


































