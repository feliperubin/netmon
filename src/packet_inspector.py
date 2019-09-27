#
#
# Responsible for parsing the packet
#
#
#
import struct
import socket
import utils
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
UDP_H_LEN=8
ICMP_H_LEN=8
TCP_H_LEN=20
# [MAC DST(8B)|MAC SRC(8B)|ETH TYPE/LENGTH(2B)]
ETH_H_FORMAT = "!6s6sH"
ARP_H_FORMAT = "!HHBBH6s4s6s4s"
IP_H_FORMAT = "!BBHHHBBH4s4s"
# [SRC PORT(2B)|DST PORT(2B)|LENGTH(2B)|CHECKSUM(2B)]
UDP_H_FORMAT = "!HHHH"

# TCP_H_FORMAT = "!HH4s4sBBHHH"
TCP_H_FORMAT = "!HHLLBBHHH"

# Only Echo Request/Reply
ICMP_H_FORMAT="!BBHHH"
# ICMP Generic Format
# ICMP_H_FORMAT="!BBH4B"

# Notes: 
# Ethernet Packets: if not ARP or IP will return as None
#

###########  ICMP Spec #############
#
# For More Information,
# See: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
# Also, For Deprecated Information
# See: https://tools.ietf.org/html/rfc6918
icmp_iana_t = {'0':{"str": "Echo Reply","rfc":"RFC792"},
'3':{"str": "Destination Unreachable","rfc":"RFC792"},
'5':{"str": "Redirect","rfc":"RFC792"},
'8':{"str": "Echo Request","rfc":"RFC792"},
'9':{"str": "Router Advertisement","rfc":"RFC1256"},
'10':{"str": "Router Solicitation","rfc":"RFC1256"},
'11':{"str": "Time Exceeded","rfc":"RFC792"},
'12':{"str": "Parameter Problem","rfc":"RFC792"},
'13':{"str": "Timestamp","rfc":"RFC792"},
'14':{"str": "Timestamp Reply","rfc":"RFC792"},
'40':{"str": "Photuris","rfc":"RFC2521"},
'41':{"str": "ICMP messages utilized by experimental mobility\
 protocols such as Seamoby","rfc":"RFC4065"},
'42':{"str": "Extended Echo Request","rfc":"RFC8335"},
'43':{"str": "Extended Echo Reply","rfc":"RFC8335"},
'253':{"str": "RFC3692-style Experiment 1","rfc":"RFC4727"},
'254':{"str": "RFC3692-style Experiment 2","rfc":"RFC4727"}}

# TO DO: SEE IF I'M CORRECTLY CONVERTING THE VALUES TO INTEGER
#  WHEN THEY HAVE MORE THAN 1 BYTE
# NOTE: I NEED TO VERIFY THE CHECKSUM OF ARRIVING PACKETS, IF THEY
# ARE NOT CORRET, THEY SHOULD BE DISCARDED.
class PacketInspector():

	# Receiving a timestamp on the IP payload is totally
	# optional. Thus, even if it is there, the timestamp will
	# also be considered part of the ASCII.
	# Total Length - IP Header(20) - ICMP Header(8)
	# Process ICMP Packet
	def icmp_processing(self,rawp,no_offset=False):
		if no_offset:
			icmp_h = rawp
		else:
			icmp_h = rawp[ETH_H_LEN+IP_H_LEN:ETH_H_LEN+IP_H_LEN+ICMP_H_LEN]
		# Note: This only works for ECHO Request/Reply
		# Otherwise we should read the first 4,
		# then the others accordingly

		# Do consider that with the current information,
		# only icmp_t(1B),code(1B) and checksum(2B) have the correct format
		# the remainding 4 Bytes depend on the type/code.
		icmp_t,code,checksum,\
		icmp_id,icmp_seq = struct.unpack(ICMP_H_FORMAT,icmp_h)
		
		total_len = struct.unpack("!H",rawp[ETH_H_LEN+2:ETH_H_LEN+4])[0]
		payload_len = total_len - IP_H_LEN - ICMP_H_LEN
		

		# IF it is ICMP ECHO Request or ICMP Echo Reply
		if icmp_t == 0x0 or icmp_t == 0x8:
			# Read the payload length according to total_len
			payload_raw = rawp[ETH_H_LEN+IP_H_LEN+ICMP_H_LEN:\
			ETH_H_LEN+IP_H_LEN+ICMP_H_LEN+payload_len]
			
			# The format of a char[]
			payload_format = "!"+str(payload_len)+"s"
			payload = struct.unpack(payload_format,payload_raw)[0]
			# Decode as ascii
			payload = payload.decode("ascii","backslashreplace")
			return {
			'type':icmp_iana_t[str(icmp_t)]["str"],
			'id':int(hex(icmp_id),16),
			'sequence':int(hex(icmp_seq),16),
			'payload':payload}

		if str(icmp_t) in icmp_iana_t:
			return {'type':icmp_iana_t[str(icmp_t)]["str"]}
		else:
			return None # Unknown iana message
		# return {'type':icmp_iana_t[str(icmp_t)]["str"]}
	# Process UDP Datagram
	def udp_processing(self,rawp):
		udp_h = rawp[ETH_H_LEN+IP_H_LEN:ETH_H_LEN+IP_H_LEN+UDP_H_LEN]
		src,dst,length,checksum = struct.unpack(UDP_H_FORMAT,udp_h)
		return {'src':src,'dst':dst}
	# Process TCP Segment
	def tcp_processing(self,rawp):
		tcp_h = rawp[ETH_H_LEN+IP_H_LEN:ETH_H_LEN+IP_H_LEN+TCP_H_LEN]
		src,dst,seq,ack,\
		hl_r,flags,window,\
		checksum,urgent = struct.unpack(TCP_H_FORMAT,tcp_h)
		# return {'src':src,'dst':dst}
		return {'src':src,'dst':dst,'flag':flags}
	# Process IP Packet
	def ip_processing(self,rawp):
		ip_h = rawp[ETH_H_LEN:IP_H_LEN+ETH_H_LEN]
		ver_ihl,tos,total_length,\
		ip_ident,flag_offset,\
		ttl,proto,checksum,\
		src,dst = struct.unpack(IP_H_FORMAT,ip_h)
		# Check if version 4
		if ver_ihl >> 4 == 0x4:
			proto_str = None
			if proto == 0x1: # 1
				proto_str = "icmp"
			elif proto == 0x6: # 6
				proto_str = "tcp"
			elif proto == 0x11: # 17
				proto_str = "udp"
			else: # Unknown
				pritn("Proto was",proto)
				proto_str = None

			return {'protocol':proto_str,\
			'ttl':ttl,\
			'src':socket.inet_ntoa(src),\
			'dst':socket.inet_ntoa(dst)}
		return None

	# Process ARP Packet
	def arp_processing(self,rawp):
		arp_p = rawp[ETH_H_LEN:ARP_H_LEN+ETH_H_LEN]
		hwtype,addrtype,hwlen,protolen,\
		op,srcmac,srcip,tgtmac,tgtip = struct.unpack(ARP_H_FORMAT,arp_p)
		return {'op':op,\
		'src':{'mac':utils.bytes2mac(srcmac),'ip':socket.inet_ntoa(srcip)},\
		'dst':{'mac':utils.bytes2mac(tgtmac),'ip':socket.inet_ntoa(tgtip)}}
	# Process Ethernet Frame
	def eth_processing(self,rawp):
		eth_h = rawp[:ETH_H_LEN]
		dst,src,eth_t = struct.unpack(ETH_H_FORMAT,eth_h)
		eth_t_str = None
		if eth_t == ETH_P_ARP:
			eth_t_str = "arp"
		elif eth_t == ETH_P_IP:
			eth_t_str = "ip"
		return {'dst':utils.bytes2mac(dst),'src':utils.bytes2mac(src),'type':eth_t_str}

	# Processes a packet, returns None if unecessary
	# rawp: Raw packet
	def process(self,rawp):
		# Parse Ethernet Header
		# TO DO: offset calculation here! no need to pass all packet
		try:
			packet = {'eth':self.eth_processing(rawp)}
			if packet['eth']['type'] == "arp":
				packet['arp'] = self.arp_processing(rawp)
			elif packet['eth']['type'] == "ip":
				packet['ip'] = self.ip_processing(rawp)
				if packet['ip']['protocol'] == "icmp":
					packet['icmp'] = self.icmp_processing(rawp)
				elif packet['ip']['protocol'] == "tcp":
					packet['tcp'] = self.tcp_processing(rawp)
				elif packet['ip']['protocol'] == "udp":
					packet['udp'] = self.udp_processing(rawp)
				else:
					return None
			else:
				return None
			# else : 
			# 	print("Packet Type Unknown",packet['eth']['type'])
			return packet
		except:
			# print("Error on Packet Inspector")
			return None


