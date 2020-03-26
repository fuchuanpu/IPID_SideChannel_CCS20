# coding=utf-8

import json
import os

from IPID_HCSC.collision_prob import Collision_Prob


if __name__ == '__main__':
    server_ip = '172.21.0.12'

    attack_bind_if = 'eth0'
    own_ip_prefix = '10.10.0.0'

    collision = Collision_Prob(attack_target_server=server_ip, attack_target_network=own_ip_prefix, net_type='C',
                               bind_iface_name=attack_bind_if, block_size=200, num_thread=8, verbose=True)
    collision.run()
    collision.wait_for_res()

    jstr = json.dumps({'res': collision.result})
    path = './prob_res'
    if not os.path.exists(path):
        os.makedirs(path)

    filelist = os.listdir(path)

    with open(path + '/prob_res_' + str(len(filelist))+ '.json', 'w') as f:
        f.write(jstr)
