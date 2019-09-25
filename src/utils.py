#
# Utility Functions
#
#
#
import socket
# Convert Mac Address format from Bytes to Hex
def bytes2mac(bytesmac):
	return ":".join("{:02x}".format(x) for x in bytesmac)

def checksum(msg):
	s = 0
	for i in range(0, len(msg), 2):
		b = msg[i+1]
		s = s + (a+(b << 8))
	s = s + (s >> 16)
	s = ~s + 0xffff
	return socket.ntohs(s)

# Convert CIDR notation to network mask
# cidr: int [0;32]
# return: array with 4 octets [255,255,255,255]
def cidr2mask(cidr):
	bits = (cidr*'1')+('0'*(32 - cidr))

	return [
		int(bits[0:8],2),
		int(bits[8:16],2),
		int(bits[16:24],2),
		int(bits[24:32],2),
	]
	# return [
	# 	255 >> (8-cidr)*(cidr<8),
	# 	255 >> (16-cidr)*(cidr<16),
	# 	255 >> (24-cidr)*(cidr<24),
	# 	255 >> (32-cidr)*(cidr<32)
	# ]



