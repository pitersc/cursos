#Curso IPv6
##Notas importantes

###Referencias:
https://docs.oracle.com/cd/E19957-01/820-2981/6nei0r0tu/index.html




####Asignación de espacio de direcciones:

0000 0000 		0000::/8	Special addresses			1/256

001				2000::/3	Global unicast				1/8

1111 110		FC00::/7	Unique local unicast(ULA)	1/128

1111 1110 10	FE80::/10	Link local addresses		1/1024

1111 1111		FF00::/8	Multicast addresses			1/256



####Talleres

#####Automatico (stateless)

ipv6 unicast-routing 


ipv6 address FE80::1 link-local 

ipv6 address 2001:DB8:0:20::1/64

ipv6 enable

no shut



######dhcp (stateless con dns)

global:

ipv6 unicast-routing 

ipv6 dhcp pool dhcp-pool

dns-server 2001:DB8:3000:3000::42

domain-name example.com


interface:

ipv6 address 2001:DB8:0:20::1/64

ipv6 nd other-config-flag

ipv6 enable

ipv6 dhcp server dhcp-pool

no shut
 

#####dhcp (statefull)

ipv6 unicast-routing 

ipv6 dhcp pool dhcpv6 

prefix-delegation pool dhcpv6pool1 lifetime 1800 600

dns-server 2001:DB8:3000:3000::42

domain-name example.com

!

ipv6 local pool dhcpv6pool1 2001:DB8:1200::/40 48



ipv6 address 2001:DB8:0:20::1/64

ipv6 enable

ipv6 nd managed-config-flag

ipv6 dhcp server dhcpv6

no shut


####Point-to-point

https://www.rfc-editor.org/rfc/pdfrfc/rfc6164.txt.pdf

A forwarding loop may occur on a point-to-point link with a prefix
length shorter than 127. This does not affect interfaces that
perform Neighbor Discovery, but some point-to-point links, which use
a medium such as the Synchronous Optical Network (SONET), do not use
Neighbor Discovery. As a consequence, configuring any prefix length
shorter than 127 bits on these links can create an attack vector in
the network.
...
By sending a continuous stream of packets to a large number of the
2^64 - 3 unassigned addresses on the link (one for each router and
one for Subnet-Router anycast), an attacker can create a large number
of neighbor cache entries and cause one of the routers to send a
large number of Neighbor Solicitation packets that will never receive
replies, thereby consuming large amounts of memory and processing
resources. Sending the packets to one of the 2^24 addresses on the
link that has the same Solicited-Node multicast address as one of the
routers also causes the victim to spend large amounts of processing
time discarding useless Neighbor Solicitation messages.
...
Routers MUST support the assignment of /127 prefixes on point-to-
point inter-router links. Routers MUST disable Subnet-Router anycast
for the prefix when /127 prefixes are used.

http://librosnetworking.blogspot.com.es/2015/10/direccionamiento-ipv6-en-enlaces-punto_20.html

Un ejemplo:
Se asigna a un segmento de red el prefijo 2001:db8:1:1::/64
Dentro de ese segmento, el ID 2001:db8:1:1:0:0:0:0 se utiliza como dirección anycast para identificar todos los puertos de routers con direccionamiento global de ese prefijo conectados a ese segmento.
No es lo mismo que la dirección FF02::2, que es la dirección multicast que identifica todos los routers que implementan IPv6, no un prefijo específico, y que sólo puede utilizarse localmente, no globalmente.

Por este motivo, inicialmente el uso de prefijos /127 en enlaces punto a punto no era posible debido al conflicto que se genera con las direcciones subnet-router anycast, lo que llevaba a utilizar prefijos /126.
Sin embargo, el RFC 6164 de abril de 2011 exige que los routers soporten la asignación de /127 en enlaces punto a punto mediante la supresión en los prefijos /127 de as direcciones subnet-router anycast.
Cisco IOS soporta prefijos /127 en enlaces punto a punto.

