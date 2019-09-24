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
		a = msg[i]
		b = msg[i+1]
		s = s + (a+(b << 8))
	s = s + (s >> 16)
	s = ~s + 0xffff
	return socket.ntohs(s)





