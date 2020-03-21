# coding=utf-8

import time

from IPID_HCSC.collision_find import Collision_Finder


if __name__ == '__main__':
    server_mac = '00:0c:29:20:f4:8c'
    server_ip = '10.10.100.2'

    client_ip = '10.10.100.1'

    attack_bind_if = 'ens33'
    own_ip_prefix = '10.10.0.0'

    collision = Collision_Finder(client_ip=client_ip, server_ip=server_ip, server_mac_addr=server_mac,
                                 owned_prefix=own_ip_prefix, bind_iface=attack_bind_if)
    collision.run()
    collision_ip = collision.result

    print('------ Result ------')
    print(collision_ip)
