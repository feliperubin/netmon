
import struct
import socket
import utils

class PacketCreator():
	def arp_request(self,ip_src,mac_src,ip_dst):
		# Protocol
		protocol = 0x0806
		# Header Ethernet
		mac_dst = b"\xff\xff\xff\xff\xff\xff" # MAC Destino - 6 bytes
		eth_hdr = struct.pack("!6s6sH", mac_dst, mac_src, protocol)

		# ARP Header 
		htype = 0x1
		ptype = 0x0800
		hlen = 0x6
		plen = 0x4
		op = 0x1 # ARP Request
		mac_dst = b"\x00\x00\x00\x00\x00\x00"
		arp_hdr = struct.pack("!HHBBH6s4s6s4s", htype, ptype,\
		 hlen, plen, op, mac_src, ip_src, mac_dst,socket.inet_aton(ip_dst))
		return eth_hdr+arp_hdr

	# def icmp_echo_request(self,ip_src,mac_src,ip_dst,mac_dst):
	def icmp_echo_request(self,ip_src,ip_dst):
		# Protocol
		# protocol = 0x0800
		# Ethernet Header 
		# eth_hdr = struct.pack("!6s6sH", mac_dst, mac_src, protocol)

		# IP Header 20 bytes
		ip_ver = 4
		ip_ihl = 5
		ip_tos = 0
		ip_id = 5432
		ip_frag_off = 0
		ip_ttl = 255
		ip_proto = 0x1
		ip_total_len = 20 + 21
		# ip_check = 0xc6a0
		ip_check = 0
		ip_saddr = ip_src
		ip_daddr = ip_dst
		# ip_saddr = socket.inet_aton(ip_src)
		# ip_daddr = socket.inet_aton(ip_dst)
		ip_ihl_ver = (ip_ver << 4) + ip_ihl
		# First time to calculate the checksum
		ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, \
			ip_total_len, ip_id, ip_frag_off, ip_ttl,\
			ip_proto, ip_check, ip_saddr, ip_daddr)
		
		# Second time with the correct checksum
		# print("ip header:",ip_header)
		ip_check = utils.checksum(ip_header)

		ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, \
			ip_total_len, ip_id, ip_frag_off, ip_ttl,\
			ip_proto, ip_check, ip_saddr, ip_daddr)		


		# ICMP Echo Request Header
		icmp_type = 8
		code = 0
		mychecksum = 0
		identifier = 12345
		seqnumber = 0
		payload = b"istoehumteste"

		icmp_packet = struct.pack("!BBHHH13s", icmp_type, code,\
			mychecksum, identifier, seqnumber, payload)

		mychecksum = utils.checksum(icmp_packet)
		icmp_packet = struct.pack("!BBHHH13s", icmp_type, code,\
			mychecksum, identifier, seqnumber, payload)



		# dest_addr = socket.gethostbyname(ip_dst)
		# return eth_hdr+ip_header+icmp_packet
		return ip_header+icmp_packet

	# cat /usr/include/linux/tcp.h
	def tcp_syn(self,ip_src,srcp,ip_dst,dstp):
		# Protocol
		# protocol = 0x0800
		# Ethernet Header 
		# eth_hdr = struct.pack("!6s6sH", mac_dst, mac_src, protocol)

		# IP Header 20 bytes
		ip_ver = 4
		ip_ihl = 5
		ip_tos = 0
		ip_id = 5432
		ip_frag_off = 0
		ip_ttl = 255
		ip_proto = 0x6
		ip_total_len = 20 + 20
		# ip_check = 0xc6a0
		ip_check = 0
		ip_saddr = ip_src
		ip_daddr = ip_dst
		# ip_saddr = socket.inet_aton(ip_src)
		# ip_daddr = socket.inet_aton(ip_dst)
		ip_ihl_ver = (ip_ver << 4) + ip_ihl
		# First time to calculate the checksum
		ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, \
			ip_total_len, ip_id, ip_frag_off, ip_ttl,\
			ip_proto, ip_check, ip_saddr, ip_daddr)
		
		# Second time with the correct checksum
		# print("ip header:",ip_header)
		ip_check = utils.checksum(ip_header)

		ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, \
			ip_total_len, ip_id, ip_frag_off, ip_ttl,\
			ip_proto, ip_check, ip_saddr, ip_daddr)		

		
		#srcp,dstp args
		# tcp_srcp = srcp
		# tcp_dstp = dstp
		tcp_seq = 0
		tcp_ack = 0
		tcp_hl = 5
		tcp_r = 0
		tcp_offset = (tcp_hl << 4) + 0
		#
		#
		tcp_flags = 2 # Syn
		tcp_wsize = socket.htons(5840)
		# tcp_wsize=  5840
		tcp_check = 0
		tcp_urgptr = 0
		# tcp_payload = 1
		# payload = ("[("*30)+"Hello"+("]"*30)

		tcp_header = struct.pack("!HHLLBBHHH",\
			srcp,dstp,tcp_seq,tcp_ack,tcp_offset,tcp_flags,tcp_wsize,tcp_check,tcp_urgptr)

		tcp_pseudo_header = struct.pack("!4s4sBBH",\
		 ip_src , ip_dst , 0 , socket.IPPROTO_TCP, len(tcp_header));

		tcp_check = utils.checksum(tcp_pseudo_header+tcp_header)

		

		tcp_header = struct.pack("!HHLLBBHHH",\
			srcp,dstp,tcp_seq,tcp_ack,tcp_offset,tcp_flags,tcp_wsize,tcp_check,tcp_urgptr)

		# return ip_header+tcp_header
		return ip_header+tcp_header



	def udp_packet(self,ip_src,srcp,ip_dst,dstp):
		
		ip_ver = 4
		ip_ihl = 5
		ip_tos = 0
		ip_id = 5432
		ip_frag_off = 0
		ip_ttl = 255
		ip_proto = 17
		ip_total_len = 20 + 8 # UDP
		# ip_check = 0xc6a0
		ip_check = 0
		ip_saddr = ip_src
		ip_daddr = ip_dst
		# ip_saddr = socket.inet_aton(ip_src)
		# ip_daddr = socket.inet_aton(ip_dst)
		ip_ihl_ver = (ip_ver << 4) + ip_ihl
		# First time to calculate the checksum
		ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, \
			ip_total_len, ip_id, ip_frag_off, ip_ttl,\
			ip_proto, ip_check, ip_saddr, ip_daddr)
		
		# Second time with the correct checksum
		# print("ip header:",ip_header)
		ip_check = utils.checksum(ip_header)

		ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, \
			ip_total_len, ip_id, ip_frag_off, ip_ttl,\
			ip_proto, ip_check, ip_saddr, ip_daddr)		




		udp_len = 8 # It's actually 8 + len(data) , but we do not pass any
		protocol = socket.IPPROTO_UDP #
		udp_check = 0

		udp_pseudo_header = ip_src + ip_dst + struct.pack('!BBH', 0, protocol, udp_len)
		udp_header = struct.pack('!4H', srcp, dstp, udp_len, udp_check)

		udp_check = utils.checksum(udp_pseudo_header + udp_header) # + data , we don't pass any
		udp_header = struct.pack('!4H', srcp, dstp, udp_len, udp_check)

		return ip_header + udp_header


		







