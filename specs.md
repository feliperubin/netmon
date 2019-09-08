

**Ethernet Header**

```
<DST ADDR: 6B> <SRC ADDR: 6B> <LENGTH: 2B>
```



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
























