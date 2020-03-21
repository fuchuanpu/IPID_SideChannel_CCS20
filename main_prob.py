# coding=utf-8

from IPID_HCSC.collision_prob import Collision_Prob


if __name__ == '__main__':
    server_mac = '00:0c:29:20:f4:8c'
    server_ip = '10.10.100.2'

    client_ip = '10.10.100.1'

    attack_bind_if = 'ens33'
    own_ip_prefix = '10.10.0.0'

    collision = Collision_Prob(attack_target_server=server_ip, attack_target_network=own_ip_prefix,
                               verbose=True)
    collision.run()
    collision.wait_for_res()
