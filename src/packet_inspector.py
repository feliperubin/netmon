#
#
# Responsible for parsing the packet
#
#
#

ETH_P_IP=0x0800 # IP
ETH_P_ARP=0x0806 # ARP

ARP_OP_EQ=0x1 # ARP REQUEST
ARP_OP_RE=0x2 # ARP REPLY
# Note: Target HW Address is not filled in a request

IP_H_LEN=20
ETH_H_LEN=14
ARP_H_LEN=28

PARSE_TCP_HEADER = "!4s4sH"


class PacketInspector():
	def __init__(self):
		return 0

	# Processes a packet, returns None if unecessary
	def process(self):
		return 0


