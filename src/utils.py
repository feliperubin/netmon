#
# Utility Functions
#
#
#

# Convert Mac Address format from Bytes to Hex
def bytes2mac(bytesmac):
	return ":".join("{:02x}".format(x) for x in bytesmac)








