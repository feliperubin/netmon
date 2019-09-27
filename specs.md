

**Ethernet Header**

```
<DST MAC: 6B> <SRC MAC: 6B> <ETH Type / LENGTH: 2B>
```

**ARP**


**IP Header**

- Ver: 4bits, IHL: 4bits
- Type of Service (TOS): 2B
- Total Length: 2B
- Identification: 2B
- Flags: 3bits , Fragment Offset: 13bits
- TTL: 1B
- Protocol: 1B
- Checksum: 2B
- Source Addr: 4B
- Dest Addr: 4B
- Data: 4B
- Options (Remaining Data): ?

```c
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver= 4 |IHL= 5 |Type of Service|       Total Length = 276      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Identification = 111      |Flg=1|     Fragment Offset = 0 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Time = 119  | Protocol = 6  |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         source address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      destination address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
\                                                               \
\                                                               \
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**ICMP**

```python
Character	Byte order	Size and alignment
@	native	native
=	native	standard
<	little-endian	standard
>	big-endian	standard
!	network (= big-endian)	standard
```



```python
Format	C Type	Python	Notes
x	pad byte	no value	 
c	char	bytes of length 1	 
b	signed char	integer	(1)
B	unsigned char	integer	 
?	_Bool	bool	(2)
h	short	integer	 
H	unsigned short	integer	 
i	int	integer	 
I	unsigned int	integer	 
l	long	integer	 
L	unsigned long	integer	 
q	long long	integer	(3)
Q	unsigned long long	integer	(3)
f	float	float	 
d	double	float	 
s	char[]	bytes	(1)
p	char[]	bytes	(1)
P	void *	integer	 
```
















SIGINT(2)
SIGKILL(9)


Test TCP Connection with curl
```bash
# Local Host
curl -vvv 192.168.15.35:3000
# Remote Host
curl -vvv https://cloud.fpbin.com
```

Ethernet
	|- ARP
	|- IP
		|-ICMP
		|-TCP
		|-UDP

Ethernet


**Python Stuff**
**Format**

IEEE 754 
'f', 'd' and 'e'  binary32, binary64 or binary16 regardless of the floating-point format used by the platform.


```bash
str[x:y]
(x:] , [y:) and (x:y)

[1,2,3,4,5,6,7,8][1:] = [2,3,4,5,6,7,8]  #here is a slice from index 1 until end
[1,2,3,4,5,6,7,8][2:4] = [3,4]    # [x,y] -> [ x; y-1] , same as for
[1,2,3,4,5,6,7,8][:2] = [1,2]    # here is from the start until before index(2)

```

```bash
socket.socket(socket.AF_PACKET, )
```
### Network Debugger

ETH_P_ALL = 0x0003


/usr/include/linux/


- Execute as root









