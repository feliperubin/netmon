#
#
# Responsible for parsing the packet
#
#
#
import struct
import socket
# Information From
# /usr/include/linux/if_ether.h


# Ethernet Frame Type
ETH_P_IP=0x0800 # IP
ETH_P_ARP=0x0806 # ARP

# ARP Operation Type
ARP_OP_RQ=0x1 # ARP REQUEST
ARP_OP_RE=0x2 # ARP REPLY

# Note: Target HW Address is not filled in a request

# Minimum Length of each packet
IP_H_LEN=20
ETH_H_LEN=14
ARP_H_LEN=28


ETH_H_FORMAT = "!6s6sH" # [MAC DST(8B)|MAC SRC(8B)|ETH TYPE/LENGTH(2B)]
# TCP_H_FORMAT = "!4s4sH" # 
ARP_H_FORMAT = "!HHBBH6s4s6s4s"

class PacketInspector():
	# def __init__(self):

	# Convert Mac Address format from Bytes to Hex
	def bytes2mac(self,bytesmac):
		return ":".join("{:02x}".format(x) for x in bytesmac)

	# Process UDP Datagram
	def udp_processing(self,rawp):
		return 0
	# Process TCP Segment
	def tcp_processing(self,rawp):
		return 0
	# Process IP Packet
	def ip_processing(self,rawp):
		return 0

	# Process ARP Packet
	def arp_processing(self,rawp):
		arp_p = rawp[ETH_H_LEN:ARP_H_LEN+ETH_H_LEN]
		hwtype,addrtype,hwlen,protolen,\
		op,srcmac,srcip,tgtmac,tgtip = struct.unpack(ARP_H_FORMAT,arp_p)
		return {'op':op,\
		'src':{'mac':self.bytes2mac(srcmac),'ip':socket.inet_ntoa(srcip)},\
		'tgt':{'mac':self.bytes2mac(tgtmac),'ip':socket.inet_ntoa(tgtip)}}
	# Process Ethernet Frame
	def eth_processing(self,rawp):
		eth_h = rawp[:ETH_H_LEN]
		dst,src,eth_t = struct.unpack(ETH_H_FORMAT,eth_h)
		return {'dst':self.bytes2mac(dst),'src':self.bytes2mac(src),'type':eth_t}

	# Processes a packet, returns None if unecessary
	# rawp: Raw packet
	def process(self,rawp):
		# Parse Ethernet Header
		packet = {'eth':self.eth_processing(rawp)}
		if packet['eth']['type'] == ETH_P_ARP:
			packet['arp'] = self.arp_processing(rawp)
			return packet
		if packet['eth']['type'] == ETH_P_IP:
			# return packet
			return packet

		# else : 
		# 	print("Packet Type Unknown",packet['eth']['type'])
		return None

























