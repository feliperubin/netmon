

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
























