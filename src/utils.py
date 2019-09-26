#
# Utility Functions
#
#
#
import socket
import struct
# Convert Mac Address format from Bytes to Hex
def bytes2mac(bytesmac):
	return ":".join("{:02x}".format(x) for x in bytesmac)

def mac2bytes(mac):
	return struct.pack("!6B",*[int(x,16) for x in mac.split(":")])

def checksum(msg):
	s = 0
	for i in range(0, len(msg), 2):
		a = msg[i]
		b = msg[i+1]
		s = s + (a+(b << 8))
	s = s + (s >> 16)
	s0 = s
	s = int(bin(~s)[1:],2) + 0xffff
	print('~',s0,' + 0xffff =',s)
	return socket.ntohs(s)



# Replace all code which uses socket directly with the following
def bytes2dotted(bytesip):
	return socket.inet_ntoa(bytesip)
def dotted2bytes(dottedip):
	return socket.inet_aton(dottedip)


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



