
import struct
import socket


class PacketCreator():
	def arp_request(self,ip_src,mac_src,ip_dst):
		# Protocol
		protocol = 0x0806
		# Header Ethernet
		mac_dst = b"\xff\xff\xff\xff\xff\xff" # MAC Destino - 6 bytes
		eth_hdr = struct.pack("!6s6sH", mac_dst, mac_src, protocol)
		# Header ARP
		htype = 0x1
		ptype = 0x0800
		hlen = 0x6
		plen = 0x4
		op = 0x1 # ARP Request
		mac_dst = b"\x00\x00\x00\x00\x00\x00"
		arp_hdr = struct.pack("!HHBBH6s4s6s4s", htype, ptype,\
		 hlen, plen, op, mac_src, ip_src, mac_dst,socket.inet_aton(ip_dst))

		return eth_hdr+arp_hdr
	# def create(proto,ip_src=None,mac_src=None,ip_dst=None,mac_dst=None,):
	# 	if proto == "arp":





